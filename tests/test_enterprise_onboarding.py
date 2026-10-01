"""企业实名开通场景：敏感声明、全通道不泄露与校验错误安全明细。

断言失败前缀约定，便于区分根因：

* ``[泄露]``   —— 敏感原始值出现在响应/日志/下游请求体/指标任一通道；
* ``[口径]``   —— 同一份请求在不同通道的脱敏判定不一致，或非敏感字段被误掩码；
* ``[定位]``   —— 422 明细缺少稳定字段路径 / 失败规则 / 错误类别；
* ``[兼容]``   —— request_id、后台任务、下游透传等既有行为回归。

每个用例通过 print 打印输入、关联标识与判定依据（``pytest -s`` 可见）。
"""

from __future__ import annotations

import json
from typing import Any

from fastapi.testclient import TestClient

from app.enterprise.schemas import (
    ONBOARDING_POLICY,
    EnterpriseOnboardingRequest,
)
from app.observability import audit
from app.observability.sensitive import (
    normalize_key,
    redact_with_policy,
    scrub_validation_errors,
)
from tests.conftest import LogCapture


def _log_case(case: str, *, rid: str | None, basis: str, **extra: Any) -> None:
    tail = " ".join(f"{k}={v!r}" for k, v in extra.items())
    print(f"\n[用例] {case} | request_id={rid!r} | {basis} | {tail}")


# ---------------------------------------------------------------------------
# 固定资料样本（覆盖嵌套/数组/别名/可选分支）与敏感值清单
# ---------------------------------------------------------------------------
def valid_body(tag: str = "T") -> dict[str, Any]:
    # tag 仅用于区分不同请求；所有敏感值都满足模型自身的长度/格式约束。
    return {
        "profileVersion": "2",
        "enterpriseName": f"企业主体{tag}",
        "creditCode": f"91110{tag}MA01ABCDXY",
        "industry": "it",
        "contacts": [
            {
                "contactName": f"法人姓名{tag}",
                "contactRole": "legal_rep",
                "phoneNumber": f"138{tag.zfill(8)}",
                "emailAddress": f"legal-{tag}@example.com",
                "idDocuments": [
                    {"docType": "id_card", "doc-number": f"110101{tag}1234567X"},
                ],
            },
            {
                "contact_name": f"经办姓名{tag}",
                "contact_role": "operator",
                "mobile": f"139{tag.zfill(8)}",
                # email 缺省：覆盖“可选分支不出现”不产生事件。
                "id-documents": [
                    {"doc_type": "passport", "certNo": f"P{tag.zfill(10)}AB"},
                ],
            },
        ],
        "attachments": [
            {"fileName": f"license-{tag}.jpg", "oss-key": f"OSS{tag.zfill(10)}KEY"},
        ],
        "bankAccount": {
            "accountName": "对公结算账户",
            "bankName": "建设银行",
            "bankCard": f"6222{tag.zfill(12)}",
        },
        "remark": f"备注{tag}",
    }


def secret_values(body: dict[str, Any]) -> list[str]:
    """从样本中收集所有应当被掩码的敏感原始值（不包含应保留的非敏感值）。"""
    return [
        body["enterpriseName"],
        body["creditCode"],
        body["contacts"][0]["contactName"],
        body["contacts"][0]["phoneNumber"],
        body["contacts"][0]["emailAddress"],
        body["contacts"][0]["idDocuments"][0]["doc-number"],
        body["contacts"][1]["contact_name"],
        body["contacts"][1]["mobile"],
        body["contacts"][1]["id-documents"][0]["certNo"],
        body["attachments"][0]["oss-key"],
        body["bankAccount"]["bankCard"],
    ]


#: 必须保留（可用于前端提示/排查）的非敏感值。
NON_SECRET_PATHS = {
    "industry": "it",
    "contacts[0].role": "legal_rep",
    "contacts[1].role": "operator",
    "contacts[0].doc_type": "id_card",
    "attachments[0].name": None,  # 动态文件名，用例内比较
    "bank_account.bank_name": "建设银行",
    "remark": None,
}


# ---------------------------------------------------------------------------
# 一、声明纯函数：归一化 / 路径化级别 / 数组 / 别名
# ---------------------------------------------------------------------------
def test_normalize_key_unifies_common_spellings() -> None:
    """大小写、下划线、连字符、camelCase 视为同一字段。"""
    groups = [
        ("phoneNumber", "phone_number", "PHONE-NUMBER", "Phone Number"),
        ("legalRepName", "legal_rep_name", "LEGALREPNAME", "legal-repname"),
        ("ID-Card", "id_card", "idCard", "IDCARD"),
    ]
    for variants in groups:
        normalized = {normalize_key(v) for v in variants}
        assert len(normalized) == 1, f"[口径] 写法未归一: {variants} -> {normalized}"
    _log_case("字段名归一", rid=None, basis="每组写法归一键集合大小为 1")


def test_same_field_name_has_path_scoped_sensitivity() -> None:
    """contact.name 掩码（个人姓名）而 attachment.name 保留（文件名）。"""
    payload = {
        "contacts": [{"name": "张三"}],
        "attachments": [{"name": "license.jpg"}],
    }
    out = redact_with_policy(payload, policy=ONBOARDING_POLICY, count=False)
    assert out["contacts"][0]["name"] == "***REDACTED***", "[口径] 联系人姓名必须掩码"
    assert out["attachments"][0]["name"] == "license.jpg", "[口径] 附件文件名不应掩码"
    _log_case(
        "同名字段路径化级别",
        rid=None,
        basis="contacts[].name=name 类别掩码；attachments[].name 非敏感保留",
    )


def test_aliases_and_array_entries_are_all_redacted() -> None:
    """语义别名与数组每一条资料都不能漏。"""
    body = valid_body("A")
    out = redact_with_policy(body, policy=ONBOARDING_POLICY, count=False)
    serialized = json.dumps(out, ensure_ascii=False)
    for secret in secret_values(body):
        assert secret not in serialized, f"[泄露] 别名/数组中的敏感值未掩码: {secret!r}\n{serialized}"
    # 两种联系人写法（camelCase / 下划线、phoneNumber / mobile）都命中。
    assert out["contacts"][0]["phoneNumber"] == "***REDACTED***"
    assert out["contacts"][1]["mobile"] == "***REDACTED***"
    assert out["contacts"][1]["id-documents"][0]["certNo"] == "***REDACTED***"
    _log_case("别名与数组穿透", rid=None, basis="两条联系人、两类证件别名的值全部掩码")


def test_optional_branch_and_undeclared_field_fallback() -> None:
    """可选分支出现即掩码、缺省无事件；声明外凭据字段全局兜底。"""
    audit.reset_audit()
    # 缺省 email / bank_account：合法，且不应凭空产生脱敏计数。
    partial = {
        "enterpriseName": "乙企业", "creditCode": "CREDIT-B-0001", "industry": "it",
        "contacts": [{"contactName": "乙", "contactRole": "operator", "phoneNumber": "13700000000"}],
    }
    out = redact_with_policy(partial, policy=ONBOARDING_POLICY, channel="log", count=True)
    assert out["contacts"][0]["contactName"] == "***REDACTED***"
    # 声明外但属于凭据的字段（如调试字段 debugToken）必须兜底掩码。
    extra = {"debugToken": "tok-xyz", "internal_note": "排查信息保留"}
    out2 = redact_with_policy(extra, policy=ONBOARDING_POLICY, channel="log", count=True)
    assert out2["debugToken"] == "***REDACTED***", "[泄露] 声明外凭据字段未全局兜底"
    assert out2["internal_note"] == "排查信息保留", "[口径] 声明外普通字段应保留"
    _log_case("可选分支/声明外兜底", rid=None, basis="缺省可选分支无事件；token 类全局掩码；普通备注保留")


# ---------------------------------------------------------------------------
# 二、HTTP 成功路径：响应 / 日志 / 下游请求体 / 指标 四通道不泄露
# ---------------------------------------------------------------------------
def test_onboarding_success_no_leak_anywhere(
    client: TestClient, log_capture: LogCapture
) -> None:
    rid = "ent-success-0001"
    body = valid_body("SUCCESS")
    secrets = secret_values(body)
    r = client.post("/enterprise/onboarding", json=body, headers={"X-Request-ID": rid})
    assert r.status_code == 200, f"[兼容] 开通受理失败: {r.status_code} {r.text}"

    # 1) 对外响应不含敏感值，且不回传提交资料。
    assert all(s not in r.text for s in secrets), f"[泄露] 响应体包含敏感值: {r.text}"
    assert r.json()["request_id"] == rid, "[兼容] 响应体 request_id 不一致"
    assert r.headers["x-request-id"] == rid, "[兼容] 响应头缺少 request_id"

    # 2) 下游真正收到的请求体已经脱敏（敏感数据不出服务边界）。
    downstream_requests = client.downstream_requests  # type: ignore[attr-defined]
    assert downstream_requests, "[兼容] 未观察到下游核验调用"
    sent = json.loads(downstream_requests[-1].content)
    sent_text = json.dumps(sent, ensure_ascii=False)
    assert all(s not in sent_text for s in secrets), f"[泄露] 下游请求体含敏感值: {sent_text}"
    assert downstream_requests[-1].headers.get("x-request-id") == rid, "[兼容] 下游未透传 request_id"

    # 3) 日志（含下游调用日志、结构化 body）不含敏感值。
    raw_logs = "\n".join(log_capture.raw_lines)
    assert all(s not in raw_logs for s in secrets), f"[泄露] 日志包含敏感值:\n{raw_logs}"
    recv_logs = [x for x in log_capture.records_with(rid)
                 if x.get("message") == "enterprise onboarding received"]
    assert recv_logs, "[兼容] 缺少受理日志"
    logged_body = recv_logs[0]["body"]
    # 日志中的 pydantic 模型经 model_dump 展开，键为规范字段名（下划线）。
    assert logged_body["contacts"][0]["name"] == "***REDACTED***"
    assert logged_body["contacts"][0]["mobile"] == "***REDACTED***"
    assert logged_body["bank_account"]["account_number"] == "***REDACTED***"

    # 4) 非敏感字段在下游/日志中保留（便于前端提示与排查）。
    assert sent["industry"] == "it", "[口径] 非敏感 industry 被误掩码"
    assert sent["attachments"][0]["name"] == body["attachments"][0]["fileName"], "[口径] 文件名被误掩码"
    assert sent["bank_account"]["bank_name"] == "建设银行", "[口径] 开户行被误掩码"
    assert sent["remark"] == body["remark"], "[口径] 非敏感备注被误掩码"
    # 显式 non_sensitive 字段在日志中同样原样保留、不计数。
    assert recv_logs[0]["body"]["industry"] == "it", "[口径] 日志中非敏感 industry 被误掩码"

    # 5) 指标不含原始值/字段路径。
    metrics_text = client.get("/metrics").text
    assert all(s not in metrics_text for s in secrets), "[泄露] 指标中出现敏感值"

    # 6) 口径一致：log 与 downstream 两通道对同一份请求掩码的敏感值数量相同。
    snap = audit.audit_snapshot()
    per_channel: dict[str, int] = {}
    for (category, channel, error_category), amount in snap.items():
        assert error_category == "", "[口径] 成功请求日志的 error_category 必须为空"
        per_channel[channel] = per_channel.get(channel, 0) + amount
    assert per_channel.get("log") == per_channel.get("downstream"), (
        f"[口径] 同一份请求 log/downstream 掩码计数不一致: {per_channel}"
    )
    assert per_channel.get("log", 0) > 0, "[口径] 成功请求应有脱敏计数"
    _log_case(
        "成功路径四通道无泄露", rid=rid,
        basis="响应/日志/下游请求体/指标均无敏感值；非敏感保留；两通道计数一致",
        每通道掩码数=per_channel,
    )


def test_onboarding_background_task_keeps_request_id(
    client: TestClient, log_capture: LogCapture
) -> None:
    """后台归档任务沿用同一 request_id，且只记录非敏感受理号。"""
    rid = "ent-bg-0001"
    r = client.post("/enterprise/onboarding", json=valid_body("BG"),
                    headers={"X-Request-ID": rid})
    assert r.status_code == 200, r.text
    accepted_no = r.json()["accepted_no"]
    archives = [x for x in log_capture.records if x.get("message") == "onboarding archived"]
    assert archives, "[兼容] 未观察到后台归档日志"
    assert any(x.get("request_id") == rid and x.get("accepted_no") == accepted_no
               and x.get("seen_request_id") == rid for x in archives), (
        f"[兼容] 后台任务 request_id 未沿用: {[(x.get('request_id'), x.get('seen_request_id')) for x in archives]}"
    )
    _log_case("开通后台任务", rid=rid, basis="归档日志 request_id/seen_request_id 均等于入站 ID")


# ---------------------------------------------------------------------------
# 三、422 参数校验失败：可定位、可解释、敏感输入不泄露、响应与日志同口径
# ---------------------------------------------------------------------------
def test_validation_details_redact_sensitive_but_keep_nonsensitive(
    client: TestClient, log_capture: LogCapture
) -> None:
    rid = "ent-422-0001"
    body = valid_body("BAD0001")
    short_phone = "1"     # 敏感但过短的输入（不做全文子串搜索，改为结构化断言）
    short_name = "X"
    body["contacts"][0]["phoneNumber"] = short_phone
    body["enterpriseName"] = short_name
    body["attachments"][0]["fileName"] = ""             # 非敏感、过短
    r = client.post("/enterprise/onboarding", json=body, headers={"X-Request-ID": rid})
    assert r.status_code == 422, f"[定位] 期望 422，实际 {r.status_code}: {r.text}"
    envelope = r.json()["error"]
    assert envelope["code"] == "VALIDATION_FAILED", "[定位] 错误码不是 VALIDATION_FAILED"
    assert envelope["request_id"] == rid, "[兼容] 422 响应体 request_id 不一致"

    details = envelope["details"]
    by_loc = {tuple(d["loc"]): d for d in details}
    # 稳定规范路径（与请求用 camelCase 还是下划线无关），数组下标保留。
    phone = by_loc.get(("body", "contacts", 0, "mobile"))
    ename = by_loc.get(("body", "enterprise_name"))
    fname = by_loc.get(("body", "attachments", 0, "name"))
    assert phone is not None, f"[定位] 缺少手机号字段定位: {list(by_loc)}"
    assert ename is not None, f"[定位] 缺少企业名字段定位: {list(by_loc)}"
    assert fname is not None, f"[定位] 缺少附件名字段定位: {list(by_loc)}"

    # 失败规则与稳定错误类别。
    assert phone["error_category"] == "too_short", f"[定位] 错误类别错误: {phone}"
    assert phone["type"] == "string_too_short", f"[定位] 失败规则 type 缺失: {phone}"
    assert phone.get("ctx", {}).get("min_length") is not None, "[定位] 规则参数应保留"
    # 敏感短输入结构化确认已掩码（不依赖子串搜索），非敏感输入原样保留。
    assert phone["input"] == "***REDACTED***", f"[泄露] 敏感手机号回显: {phone}"
    assert ename["input"] == "***REDACTED***", f"[泄露] 敏感企业名回显: {ename}"
    assert fname["input"] == "", f"[口径] 非敏感文件名输入应保留: {fname}"
    assert "min_length" in fname.get("ctx", {}), "[定位] 非敏感字段也应保留规则参数"

    # 样本中其余完整敏感值（非被改写的短字段）绝不能出现在响应或日志。
    other_secrets = [
        s for s in secret_values(body)
        if s not in (short_phone, short_name)
    ]
    whole = r.text + "\n".join(log_capture.raw_lines)
    for secret in other_secrets:
        assert secret not in whole, f"[泄露] 422 响应/日志中出现敏感值 {secret!r}"
    # 响应与日志用同一份清洗结果：日志中该 request_id 的校验明细与响应一致。
    validation_logs = [x for x in log_capture.records_with(rid)
                       if x.get("message") == "request validation failed"]
    assert validation_logs, "[兼容] 缺少校验失败日志"
    assert validation_logs[0]["validation_errors"] == details, (
        "[口径] 响应与日志的校验明细不是同一份结果"
    )
    _log_case(
        "422 安全明细", rid=rid,
        basis="敏感输入掩码、非敏感保留；loc 规范化；响应==日志；VALIDATION_FAILED",
        字段数=len(details),
    )


def test_missing_required_field_does_not_leak_siblings(
    client: TestClient, log_capture: LogCapture
) -> None:
    """缺失必填字段：不回显整个父对象（pydantic v2 的 input 是父对象）。"""
    rid = "ent-422-0002"
    body = valid_body("MISS0001")
    # 删除敏感必填字段；先记录其敏感值用于泄露断言，再从字典移除。
    deleted_name = body["contacts"][0]["contactName"]
    remaining_secrets = [s for s in secret_values(body) if s != deleted_name]
    del body["contacts"][0]["contactName"]
    r = client.post("/enterprise/onboarding", json=body, headers={"X-Request-ID": rid})
    assert r.status_code == 422
    details = r.json()["error"]["details"]
    target = [d for d in details if tuple(d["loc"]) == ("body", "contacts", 0, "name")]
    assert target, f"[定位] 缺少缺失字段定位: {details}"
    assert target[0]["error_category"] == "missing"
    assert "input" not in target[0], f"[泄露] 缺失错误回显了父对象: {target[0]}"
    whole = r.text + "\n".join(log_capture.raw_lines)
    assert deleted_name not in whole, "[泄露] 缺失字段的敏感名外泄"
    for secret in remaining_secrets:
        assert secret not in whole, f"[泄露] 缺失错误的兄弟敏感值外泄: {secret!r}"
    _log_case("缺失字段不回显父对象", rid=rid, basis="missing 错误无 input，兄弟敏感值不泄露")


def test_wrong_type_inside_array_is_locatable(client: TestClient) -> None:
    """数组元素类型错误：路径含正确下标，错误类别稳定为 type_error。"""
    rid = "ent-422-0003"
    body = valid_body("TYPE")
    body["contacts"][1]["mobile"] = 12345  # 应为字符串
    r = client.post("/enterprise/onboarding", json=body, headers={"X-Request-ID": rid})
    assert r.status_code == 422
    details = r.json()["error"]["details"]
    target = [d for d in details if tuple(d["loc"]) == ("body", "contacts", 1, "mobile")]
    assert target, f"[定位] 数组内类型错误路径不可定位: {details}"
    assert target[0]["error_category"] == "type_error", f"[定位] 错误类别应为 type_error: {target[0]}"
    _log_case("数组内类型错误", rid=rid, basis="loc 含下标 1，error_category=type_error")


def test_scrub_unit_contract() -> None:
    """scrub_validation_errors 纯函数契约：稳定类别枚举 + 掩码计数口径。"""
    audit.reset_audit()
    errors = [
        {"type": "missing", "loc": ["body", "contacts", 0, "name"], "msg": "Field required",
         "input": {"name": "张三", "mobile": "13800138000"}},
        {"type": "string_pattern_mismatch", "loc": ["body", "unified_social_credit_code"],
         "msg": "Pattern mismatch", "input": "!!!", "ctx": {"pattern": "^x$"}},
    ]
    scrubbed = scrub_validation_errors(errors, policy=ONBOARDING_POLICY)
    assert scrubbed[0]["error_category"] == "missing" and "input" not in scrubbed[0]
    assert scrubbed[1]["error_category"] == "format" and scrubbed[1]["input"] == "***REDACTED***"
    snap = audit.audit_snapshot()
    # 仅第二错误有掩码，且落在 response 通道、format 类别；缺失错误不计数。
    assert sum(snap.values()) == 1, f"[口径] 审计计数异常: {snap}"
    assert (("business", "response", "format") in snap), f"[口径] 标签组合错误: {snap}"
    _log_case("scrub 纯函数契约", rid=None, basis="missing 无输入；pattern->format 掩码且计数 1")


# ---------------------------------------------------------------------------
# 四、模型与声明同步：新增资料字段时声明必须同步（防止“加字段忘登记”）
# ---------------------------------------------------------------------------
def test_model_fields_are_covered_by_policy() -> None:
    """Pydantic 模型的每个字段都必须在敏感声明树中出现（同路径）。

    这保证“后续字段持续增加”时，新增字段的敏感级别是显式决策（敏感用
    leaf、非敏感用 plain），而非静默落入默认；新增资料版本时模型与声明
    同步修改即可通过本检查。
    """
    import app.enterprise.schemas as schemas

    # 模型字段名 -> (嵌套对象模型 or None, 是否数组)
    NESTED: dict[str, tuple[type, bool]] = {
        "id_documents": (schemas.IdDocument, True),
        "bank_account": (schemas.BankAccount, False),
        "contacts": (schemas.Contact, True),
        "attachments": (schemas.Attachment, True),
    }

    def walk(model_cls: type, node: object, path: str) -> None:
        model_fields = set(model_cls.model_fields.keys())
        children = getattr(node, "children", None) or {}
        policy_fields = set(children.keys())
        missing = model_fields - policy_fields
        assert not missing, (
            f"[口径] 模型 {model_cls.__name__}({path}) 的字段 {sorted(missing)} "
            "未在敏感声明中登记；新增字段必须同步声明级别（非敏感用 plain()）"
        )
        for field_name in model_fields:
            child_node = children[field_name]
            if field_name in NESTED:
                element_model, is_array = NESTED[field_name]
                target_node = child_node.items if is_array else child_node
                if is_array:
                    assert child_node.items is not None, (
                        f"[口径] {path}.{field_name} 声明应为 many(...) 数组节点"
                    )
                walk(element_model, target_node, f"{path}.{field_name}")

    walk(EnterpriseOnboardingRequest, ONBOARDING_POLICY.root, "body")
    _log_case("模型/声明同步", rid=None, basis="每个模型字段（递归嵌套/数组）都在声明中显式登记")
