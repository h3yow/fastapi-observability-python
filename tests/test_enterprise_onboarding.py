"""企业实名开通场景测试。

覆盖：

* 嵌套对象 / 对象数组 / 别名字段 / 可选分支下的敏感输入不泄露
  （响应、日志、下游调用记录、错误统计四处）；
* 同名字段在不同子结构中的敏感级别不同（法人姓名敏感 vs 联系人姓名非敏感）；
* 大小写/下划线/连字符按同一规则识别，数组逐条不漏；
* 参数校验失败时非敏感字段仍可定位/回显、敏感字段只给路径与规则；
* 真实下游报文携带原始值（脱敏只发生在观测面），request_id 透传；
* 既有 request_id/后台任务/错误码行为不回归。

断言失败消息区分三种性质：
``[泄露]`` 原始敏感值出现在观测面；
``[口径不一致]`` 各处判定/错误码/计数对不上；
``[并发串扰]`` 并发行之间互相污染。
"""

from __future__ import annotations

import json
import uuid
from concurrent.futures import ThreadPoolExecutor

from fastapi.testclient import TestClient

from app.observability.metrics import get_mask_counts
from app.schemas_enterprise import EnterpriseOnboardingRequest
from tests.conftest import LogCapture, assert_error_response

# 一批跨类别的敏感“探针”值；任何一个出现在观测面都视为泄露。
SECRET_PROBES = {
    "legal_name": "张秘密",
    "id_number": "110101199001011234",
    "cert_number": "CERT-SECRET-0001",
    "phone1": "13800138000",
    "phone2": "13900139000",
    "email": "secret.person@example.com",
    "account_number": "6222021234567890123",
    "download_token": "SIGNED-TOKEN-SECRET-9999",
}
ALL_SECRETS = list(SECRET_PROBES.values())


def valid_body() -> dict:
    """一份结构完整、写法刻意混杂的开通请求。"""
    return {
        "EnterpriseName": "ACME有限公司",
        "credit-code": "91110000XXXXXXXXX1",
        "legalRepresentative": {
            "name": SECRET_PROBES["legal_name"],
            "ID_Number": SECRET_PROBES["id_number"],
            "certificate": {
                "cert-type": "ID_CARD",
                "certNumber": SECRET_PROBES["cert_number"],
                "Issued_Date": "2020-03-01",
            },
        },
        "contacts": [
            {
                "name": "李公开",
                "mobilePhone": SECRET_PROBES["phone1"],
                "EMAIL": SECRET_PROBES["email"],
            },
            {"Name": "王公开", "mobile": SECRET_PROBES["phone2"]},
        ],
        "bank_account": {
            "Account_Name": "ACME有限公司",
            "accountNumber": SECRET_PROBES["account_number"],
        },
        "attachments": [
            {
                "FileName": "license.jpg",
                "download_url": (
                    "https://files.example/license.jpg?token="
                    + SECRET_PROBES["download_token"]
                ),
            },
            {"filename": "idcard.jpg"},
        ],
        "remark": "note",
    }


def _log_case(case: str, *, request_id: str | None, basis: str) -> None:
    print(f"\n[用例] {case} | request_id={request_id!r} | 判定依据: {basis}")


def _assert_no_secret(text: str, *, where: str) -> None:
    for secret in ALL_SECRETS:
        assert secret not in text, (
            f"[泄露] 敏感值 {secret!r} 出现在{where}: {text[:500]}"
        )


# ---------------------------------------------------------------------------
# 成功路径：四处观测面不泄露 + 非敏感字段保留
# ---------------------------------------------------------------------------


def test_onboarding_success_redacts_everywhere(
    client: TestClient, log_capture: LogCapture
) -> None:
    rid = "ent-ok-0001"
    r = client.post(
        "/enterprise/onboarding", json=valid_body(), headers={"X-Request-ID": rid}
    )
    assert r.status_code == 200, f"开通接口异常: {r.status_code} {r.text}"

    # 1) 响应面
    _assert_no_secret(r.text, where="对外响应")
    body = r.json()
    assert body["enterprise_name"] == "ACME有限公司"
    assert body["request_id"] == rid, "[口径不一致] 响应体 request_id 与入站不同"

    # 2) 日志面（含路由日志、下游调用记录、后台任务日志）
    raw = "\n".join(log_capture.raw_lines)
    _assert_no_secret(raw, where="服务端日志")

    # 非敏感字段在日志中保留（便于排查）
    onboarding_logs = [
        rec for rec in log_capture.records_with(rid)
        if rec.get("message") == "enterprise onboarding request"
    ]
    assert onboarding_logs, "缺少开通请求日志"
    logged_body = onboarding_logs[0]["body"]
    assert logged_body["contacts"][0]["name"] == "李公开", "[口径不一致] 联系人姓名被误掩码"
    assert logged_body["attachments"][0]["filename"] == "license.jpg"
    assert logged_body["bank_account"]["account_name"] == "ACME有限公司"
    assert logged_body["legal_representative"]["name"] == "***REDACTED***"
    assert logged_body["legal_representative"]["certificate"] == "***REDACTED***"

    # 3) 下游调用记录：日志副本掩码；真实报文保留原始值并透传 request_id
    downstream_logs = [
        rec for rec in log_capture.records_with(rid)
        if rec.get("message") == "downstream call start" and rec.get("method") == "POST"
    ]
    assert downstream_logs, "缺少下游 POST 调用记录"
    _assert_no_secret(
        json.dumps(downstream_logs[0], ensure_ascii=False), where="下游调用记录"
    )
    sent = client.downstream_requests[-1]  # type: ignore[attr-defined]
    sent_text = sent.content.decode()
    for secret in (SECRET_PROBES["phone1"], SECRET_PROBES["account_number"]):
        assert secret in sent_text, (
            f"[口径不一致] 真实下游报文不应被脱敏，缺少 {secret}: {sent_text[:300]}"
        )
    assert sent.headers.get("x-request-id") == rid, "[口径不一致] 下游未透传 request_id"

    # 4) 后台任务仍带同一 request_id，且只含非敏感企业名
    audit = [
        rec for rec in log_capture.records
        if rec.get("message") == "onboarding audit note written"
        and rec.get("request_id") == rid
    ]
    assert audit, "开通后台任务日志缺失或 request_id 未传播"
    assert audit[0]["enterprise_name"] == "ACME有限公司"

    _log_case(
        "开通成功脱敏",
        request_id=rid,
        basis="响应/日志/下游记录无探针；真实报文含原始值；非敏感字段保留；rid 透传",
    )


# ---------------------------------------------------------------------------
# 同名字段不同级别
# ---------------------------------------------------------------------------


def test_same_field_name_can_differ_by_path(
    client: TestClient, log_capture: LogCapture
) -> None:
    rid = "ent-name-0001"
    r = client.post(
        "/enterprise/onboarding", json=valid_body(), headers={"X-Request-ID": rid}
    )
    assert r.status_code == 200, r.text
    logged_body = next(
        rec["body"] for rec in log_capture.records_with(rid)
        if rec.get("message") == "enterprise onboarding request"
    )
    assert logged_body["legal_representative"]["name"] == "***REDACTED***", (
        "[口径不一致] 法人姓名（实名信息）应按 id_document 掩码"
    )
    assert logged_body["contacts"][0]["name"] == "李公开", (
        "[口径不一致] 联系人姓名不是敏感字段，必须保留以便错误提示"
    )
    _assert_no_secret("\n".join(log_capture.raw_lines), where="服务端日志")
    _log_case(
        "同名字段不同级",
        request_id=rid,
        basis="legal_representative.name 掩码；contacts[].name 保留",
    )


# ---------------------------------------------------------------------------
# 写法归一：大小写/下划线/连字符 + 同义词 + 数组逐条
# ---------------------------------------------------------------------------


def test_style_variants_and_array_elements_all_recognized(
    client: TestClient, log_capture: LogCapture
) -> None:
    rid = "ent-style-0001"
    r = client.post(
        "/enterprise/onboarding", json=valid_body(), headers={"X-Request-ID": rid}
    )
    assert r.status_code == 200, (
        f"[口径不一致] camel/snake/kebab/大写写法应按同一规则解析: {r.text}"
    )
    raw = "\n".join(log_capture.raw_lines)
    # 两个不同联系人的手机号（mobilePhone / mobile 两种写法）都必须被掩码。
    logged_body = next(
        rec["body"] for rec in log_capture.records_with(rid)
        if rec.get("message") == "enterprise onboarding request"
    )
    phones = [c["phone"] for c in logged_body["contacts"]]
    assert phones == ["***REDACTED***", "***REDACTED***"], (
        f"[口径不一致] 数组中的手机号有漏网: {phones}"
    )
    for secret in (SECRET_PROBES["phone1"], SECRET_PROBES["phone2"]):
        assert secret not in raw, f"[泄露] 数组元素敏感值出现在日志: {secret}"
    _log_case(
        "写法归一与数组逐条",
        request_id=rid,
        basis="mobilePhone/mobile/EMAIL/certNumber 等写法全部命中并掩码",
    )


# ---------------------------------------------------------------------------
# 可选分支
# ---------------------------------------------------------------------------


def test_optional_branches_absent_and_present(
    client: TestClient, log_capture: LogCapture
) -> None:
    rid = "ent-opt-0001"
    body = valid_body()
    # 缺省银行账户与附件下载地址：可正常开通，缺失值不产生掩码。
    body.pop("bank_account")
    body["attachments"] = [{"filename": "only-name.jpg"}]
    body["legalRepresentative"].pop("certificate")
    r = client.post(
        "/enterprise/onboarding", json=body, headers={"X-Request-ID": rid}
    )
    assert r.status_code == 200, r.text
    logged_body = next(
        rec["body"] for rec in log_capture.records_with(rid)
        if rec.get("message") == "enterprise onboarding request"
    )
    assert logged_body["bank_account"] is None
    assert logged_body["attachments"][0]["download_url"] is None, (
        "[口径不一致] 缺省可选值应保持 None，而不是被替换为掩码"
    )
    assert logged_body["legal_representative"]["certificate"] is None
    _assert_no_secret("\n".join(log_capture.raw_lines), where="服务端日志")
    _log_case("可选分支缺省", request_id=rid, basis="缺省对象/字段保持 None，不误掩码")


# ---------------------------------------------------------------------------
# 校验失败：敏感与非敏感字段的差异化安全展示
# ---------------------------------------------------------------------------


def test_validation_failure_keeps_paths_but_hides_sensitive_input(
    client: TestClient, log_capture: LogCapture
) -> None:
    rid = "ent-422-0001"
    bad_body = {
        "enterprise_name": "A",  # 非敏感，过短：应回显 input 与规则
        "credit_code": "short",  # 非敏感，过短：应回显
        "legal_representative": {
            "name": "张三",
            "idNumber": "123",  # 敏感，过短：不得回显，仅给路径/规则
            "certificate": {"cert_number": "x"},  # 敏感且过短
        },
        "contacts": [
            {"name": "李四", "phone": "138"},  # 数组内敏感字段过短
        ],
        "bank_account": {
            "account_name": "ACME",
            "account_number": "12",  # 金融敏感过短
        },
    }
    r = client.post(
        "/enterprise/onboarding", json=bad_body, headers={"X-Request-ID": rid}
    )
    assert_error_response(
        r, expected_status=422, expected_code="VALIDATION_FAILED",
        reason="[口径不一致] 开通体校验失败应映射 VALIDATION_FAILED",
    )
    details = r.json()["error"]["details"]
    by_loc = {tuple(d["loc"]): d for d in details}

    def find(*suffix: str) -> dict:
        for loc, detail in by_loc.items():
            if tuple(loc[1:]) == suffix:  # 去掉开头的 "body"
                return detail
        raise AssertionError(f"[口径不一致] 缺少字段路径 {suffix}，实际 {list(by_loc)}")

    # 非敏感字段：路径、规则、原始输入都在，前端可提示。
    name_err = find("enterprise_name")
    assert name_err["input"] == "A", f"[口径不一致] 非敏感输入应保留: {name_err}"
    assert name_err["type"] == "string_too_short"
    credit_err = find("credit_code")
    assert credit_err["input"] == "short"

    # 敏感字段（顶层证件号 / 嵌套证件对象 / 数组手机号 / 金融账号）：
    # 只保留路径、规则；无 input/ctx，带统一安全说明。
    # 注意：before 归一器已把输入写法归一为规范字段名，错误 loc 以规范名给出，
    # 前端按规范字段路径定位即可（与提交写法无关，更稳定）。
    for suffix in (
        ("legal_representative", "id_number"),
        ("legal_representative", "certificate", "cert_number"),
        ("contacts", 0, "phone"),
        ("bank_account", "account_number"),
    ):
        err = find(*suffix)
        assert err.get("redacted") is True, f"[口径不一致] 敏感错误应带 redacted: {err}"
        assert "input" not in err and "ctx" not in err, (
            f"[泄露] 敏感字段错误保留了输入/上下文: {err}"
        )
        assert err["type"] == "string_too_short"
        assert "123" not in json.dumps(err) and '"x"' not in json.dumps(err)

    # 整个响应与日志均不得含敏感原始值
    _assert_no_secret(r.text, where="422 响应")
    _assert_no_secret("\n".join(log_capture.raw_lines), where="422 日志")

    # 审计：敏感掩码必须在 response 与 log 两个通道都计数（VALIDATION_FAILED）
    counts = get_mask_counts()
    for channel in ("response", "log"):
        assert (
            "contact", channel, "VALIDATION_FAILED"
        ) in counts, f"[口径不一致] 缺少 {channel} 通道校验脱敏计数: {counts}"
    _log_case(
        "校验失败安全明细",
        request_id=rid,
        basis="非敏感字段回显 input；敏感字段仅 loc/type/redacted；双通道审计计数",
    )


def test_missing_required_sensitive_field_is_locatable_without_value(
    client: TestClient, log_capture: LogCapture
) -> None:
    rid = "ent-422-0002"
    # 缺少法人姓名与联系人手机号：missing 类错误也要能定位且不泄露任何值。
    bad_body = {
        "enterprise_name": "ACME",
        "credit_code": "91110000XXXXXXXXX1",
        "legal_representative": {},
        "contacts": [{"name": "无电话联系人"}],
    }
    r = client.post(
        "/enterprise/onboarding", json=bad_body, headers={"X-Request-ID": rid}
    )
    assert r.status_code == 422
    locs = [tuple(d["loc"]) for d in r.json()["error"]["details"]]
    assert any(loc[-1] == "name" for loc in locs), f"[口径不一致] 缺少法人姓名定位: {locs}"
    assert any(loc[-1] == "phone" for loc in locs), f"[口径不一致] 缺少手机号定位: {locs}"
    _assert_no_secret(r.text, where="422 响应")
    _log_case(
        "缺失敏感字段可定位",
        request_id=rid,
        basis="missing 错误给出数组化字段路径，不回显任何输入",
    )


# ---------------------------------------------------------------------------
# 脱敏审计：低基数维度 + 并发不丢不串
# ---------------------------------------------------------------------------


def test_mask_audit_metrics_are_low_cardinality(client: TestClient) -> None:
    rid = "ent-metric-0001"
    client.post(
        "/enterprise/onboarding", json=valid_body(), headers={"X-Request-ID": rid}
    )
    text = client.get("/metrics").text
    lines = [
        line for line in text.splitlines()
        if line.startswith("masked_inputs_total{")
    ]
    assert lines, "没有脱敏审计指标行"
    import re
    label_re = re.compile(r'(\w+)="((?:[^"\\]|\\.)*)"')
    allowed_categories = {"credential", "id_document", "contact", "financial"}
    allowed_channels = {"log", "response", "downstream"}
    for line in lines:
        labels = dict(label_re.findall(line.split("{", 1)[1].rsplit("}", 1)[0]))
        assert set(labels) == {"field_category", "output_channel", "error_code"}, (
            f"[口径不一致] 脱敏审计标签结构错误: {line}"
        )
        assert labels["field_category"] in allowed_categories, (
            f"[口径不一致] 字段类别越界（维度可能爆炸）: {line}"
        )
        assert labels["output_channel"] in allowed_channels, line
        # 绝不能出现具体字段路径/原始值
        assert "." not in labels["field_category"] and "/" not in labels["field_category"]
    # 成功路径 error_code 为空串
    assert any('error_code=""' in line for line in lines)
    _log_case(
        "脱敏审计基数约束",
        request_id=rid,
        basis=f"仅 {len(lines)} 个低基数组合，标签封闭且无字段路径/值",
    )


def test_concurrent_onboarding_audit_counts_are_accurate_and_isolated(
    client: TestClient, log_capture: LogCapture
) -> None:
    """并发开通：脱敏计数不丢、不串；每个 request_id 的日志只含自己的内容。"""
    n_per_style = 30
    rids = [f"ent-parallel-{i:03d}-{uuid.uuid4().hex[:8]}" for i in range(n_per_style)]

    # 记录前快照：本套件与其他用例共用 client 夹具时，计数是进程累计的，
    # 这里按差值断言本用例的精确增量，避免与其他用例顺序耦合。
    before = get_mask_counts()
    before_contact_log = before.get(("contact", "log", ""), 0)
    before_contact_ds = before.get(("contact", "downstream", ""), 0)

    def call(index_rid: tuple[int, str]) -> tuple[str, str, set[str]]:
        i, rid = index_rid
        body = valid_body()
        # 让每个请求的敏感探针唯一化，便于检测串扰（11 位手机号，i 唯一故不碰撞）。
        unique_phone = f"139{i:08d}"
        unique_name = f"专属姓名{i:03d}"
        body["contacts"][0]["mobilePhone"] = unique_phone
        body["legalRepresentative"]["name"] = unique_name
        r = client.post(
            "/enterprise/onboarding", json=body, headers={"X-Request-ID": rid}
        )
        assert r.status_code == 200, (
            f"[口径不一致] 并发请求 rid={rid} 未成功: {r.status_code} {r.text}"
        )
        return rid, unique_phone, {unique_name}

    with ThreadPoolExecutor(max_workers=16) as pool:
        results = list(pool.map(call, enumerate(rids)))

    # 1) 不串扰：每个唯一探针只能出现在真实下游报文里，绝不能进日志/响应，
    #    且其他 rid 的日志里不能出现本 rid 的探针。
    raw_by_rid = {
        rid: "\n".join(rec_json for rec_json in (
            json.dumps(rec, ensure_ascii=False) for rec in log_capture.records_with(rid)
        ))
        for rid in rids
    }
    for rid, unique_phone, names in results:
        own = raw_by_rid[rid]
        assert unique_phone not in own, f"[泄露] rid={rid} 自己的手机号出现在日志"
        for name in names:
            assert name not in own, f"[泄露] rid={rid} 自己的法人姓名出现在日志"
        for other_rid, other_text in raw_by_rid.items():
            if other_rid == rid:
                continue
            assert unique_phone not in other_text, (
                f"[并发串扰] rid={rid} 的手机号出现在 rid={other_rid} 的日志中"
            )

    # 2) 不丢计数：统计本用例的精确增量。
    counts = get_mask_counts()
    contact_log = counts.get(("contact", "log", ""), 0)
    id_log = counts.get(("id_document", "log", ""), 0)
    assert contact_log - before_contact_log >= n_per_style, (
        f"[并发串扰] contact/log 计数疑似丢失: 增量 {contact_log - before_contact_log}"
    )
    assert id_log >= n_per_style, (
        f"[并发串扰] id_document/log 计数疑似丢失: 实际 {id_log}"
    )
    # 精确口径（按 contact 类别统计每请求掩码次数）：
    #   请求日志（模型序列化形态）：phone1 + email1 + phone2 = 3
    #     （第二个联系人未给 email，模型里该键为 None，不掩码也不计数）；
    #     一条日志记录无论被几路 handler 渲染，掩码动作只发生、只计数一次
    #     （渲染结果按记录缓存，见 logging.JsonFormatter）。
    #   下游调用记录日志的 json_body 是 PreRedacted 预脱敏载荷，计入
    #     downstream 通道，不再计入 log 通道。
    #   -> log 通道每请求 3；downstream 通道每请求 3。
    assert contact_log - before_contact_log == 3 * n_per_style, (
        f"[口径不一致] contact/log 增量应为 {3 * n_per_style}，"
        f"实际 {contact_log - before_contact_log}"
    )
    contact_ds = counts.get(("contact", "downstream", ""), 0)
    assert contact_ds - before_contact_ds == 3 * n_per_style, (
        f"[口径不一致] contact/downstream 增量应为 {3 * n_per_style}，"
        f"实际 {contact_ds - before_contact_ds}"
    )
    _log_case(
        "并发脱敏审计",
        request_id=f"{n_per_style} 并发",
        basis="唯一探针不跨 rid；contact log 增量 3*N（与日志路数无关）、downstream 增量 3*N",
    )


# ---------------------------------------------------------------------------
# 模型可直接解析的纯函数级保障（便于失败时定位到归一/脱敏层而非 HTTP 层）
# ---------------------------------------------------------------------------


def test_model_normalizer_accepts_kebab_and_synonyms() -> None:
    payload = {
        "enterprise-name": "ACME",
        "credit_code": "91110000XXXXXXXXX1",
        "LEGAL_REPRESENTATIVE": {"NAME": "某甲", "idNumber": "12345678"},
        "contacts": [{"name": "某乙", "mobile-phone": "13800138000"}],
    }
    model = EnterpriseOnboardingRequest.model_validate(payload)
    assert model.legal_representative.name == "某甲"
    assert model.contacts[0].phone == "13800138000"
    _log_case(
        "归一纯函数",
        request_id=None,
        basis="kebab/snake/大写/mobile-phone 全部解析到规范字段",
    )
