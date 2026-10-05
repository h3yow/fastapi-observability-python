"""填错位置的敏感输入不外泄；脱敏审计只计实际掩码；多路日志输出与并发不影响口径。

覆盖问题场景：

* 本该是数组/对象的位置被直接填成一个敏感单值——联系人位置填手机号、
  法人/账户位置填证件号或账号、附件位置填带签名下载地址、整个请求体是
  一段字符；以及数组元素位置本应是对象却给了单值；
* 这些位置无论出现在顶层、嵌套对象、数组元素还是可选分支，原始值都
  不能出现在 422 响应详情、服务端日志或错误统计（指标标签/序列）中；
* 失败明细仍可定位字段（loc）、规则（type）与错误大类（redacted 标记）；
  同一份请求在响应/日志/指标各处口径一致；非敏感字段输入继续保留；
* 脱敏审计计数只与“实际发生的掩码”有关：在服务上多挂一路日志输出
  （第二个 handler）不改变计数；同一记录被多个 formatter 渲染也不重复计数；
* 并发开通（且每个请求都有多路日志输出）时各类别计数不丢、不串。

断言失败前缀：``[泄露]`` 观测面出现原始敏感值；``[口径不一致]``
响应/日志/指标判定或计数对不上；``[并发串扰]`` 并发行互相污染。
"""

from __future__ import annotations

import json
import logging
import uuid
from concurrent.futures import ThreadPoolExecutor

from fastapi.testclient import TestClient

from app.observability.logging import JsonFormatter, RequestIdFilter
from app.observability.metrics import get_mask_counts
from tests.conftest import LogCapture, assert_error_response

# 每个场景使用独立的、不会与别处撞值的探针；断言时整文本搜索。
PHONE_SECRET = "13755550199"
ID_SECRET = "110101199003037777"
ACCOUNT_SECRET = "6228480099112233445"
URL_TOKEN_SECRET = "SIGNED-URL-TOKEN-77771111"

NON_SENSITIVE_BASE = {
    "enterprise_name": "ACME有限公司",
    "credit_code": "91110000XXXXXXXXX1",
}


def _legal_ok(**overrides: object) -> dict:
    legal = {"name": "法人甲", "id_number": "11010119800101001X"}
    legal.update(overrides)
    body = dict(NON_SENSITIVE_BASE)
    body["legal_representative"] = legal
    return body


def _log_case(case: str, **fields: object) -> None:
    print("\n[用例] " + case + " | " + " ".join(f"{k}={v!r}" for k, v in fields.items()))


def _assert_absent(haystack: str, needle: str, *, where: str) -> None:
    assert needle not in haystack, f"[泄露] 原始敏感值 {needle!r} 出现在{where}: {haystack[:800]}"


def _post(client: TestClient, body: object, rid: str) -> object:
    if isinstance(body, (dict, list)):
        return client.post(
            "/enterprise/onboarding", json=body, headers={"X-Request-ID": rid}
        )
    # 整个 body 是标量：直接发原始 JSON 文本。
    return client.post(
        "/enterprise/onboarding",
        content=json.dumps(body, ensure_ascii=False),
        headers={"Content-Type": "application/json", "X-Request-ID": rid},
    )


# ---------------------------------------------------------------------------
# 错位置标量：422 详情/日志/指标三处一律无原始敏感值
# ---------------------------------------------------------------------------


def test_scalar_in_array_or_object_positions_is_never_echoed(
    client: TestClient, log_capture: LogCapture
) -> None:
    """联系人/法人/账户/附件位置直接填敏感单值、数组元素填单值、整体 body 填单值。"""
    cases: list[tuple[str, object, str]] = [
        ("联系人位置填手机号", {**_legal_ok(), "contacts": PHONE_SECRET}, PHONE_SECRET),
        ("法人位置填证件号", {**NON_SENSITIVE_BASE, "legal_representative": ID_SECRET}, ID_SECRET),
        ("账户位置填账号", {**_legal_ok(), "bank_account": ACCOUNT_SECRET}, ACCOUNT_SECRET),
        ("附件位置填签名地址", {**_legal_ok(), "attachments": (
            "https://files.example/a.jpg?token=" + URL_TOKEN_SECRET)}, URL_TOKEN_SECRET),
        ("数组元素位置填手机号", {**_legal_ok(), "contacts": [PHONE_SECRET]}, PHONE_SECRET),
        ("可选账户元素位置填证件号", {
            **_legal_ok(), "bank_account": [ID_SECRET]}, ID_SECRET),
        ("整个请求体是一段证件号", ID_SECRET, ID_SECRET),
        ("整个请求体是一段手机号", PHONE_SECRET, PHONE_SECRET),
    ]

    for index, (title, body, secret) in enumerate(cases):
        rid = f"misplaced-{index:02d}"
        r = _post(client, body, rid)
        assert_error_response(
            r, expected_status=422, expected_code="VALIDATION_FAILED",
            reason=f"[口径不一致] {title} 应 422/VALIDATION_FAILED",
        )
        details = r.json()["error"]["details"]
        assert details, f"[口径不一致] {title} 应返回字段级明细"

        # 1) 响应面：原始值不存在；明细仍可定位字段与规则。
        _assert_absent(r.text, secret, where=f"{title} 的 422 响应")
        for detail in details:
            assert detail.get("loc"), f"[口径不一致] {title} 明细缺少字段定位: {detail}"
            assert detail.get("type"), f"[口径不一致] {title} 明细缺少规则类型: {detail}"
            assert "input" not in detail and "ctx" not in detail, (
                f"[泄露] {title} 的敏感位置错误保留了 input/ctx: {detail}"
            )
            assert detail.get("redacted") is True, (
                f"[口径不一致] {title} 错位置敏感明细必须带 redacted=true: {detail}"
            )

        # 2) 日志面：原始值不出现在任何一条日志中。
        raw_logs = "\n".join(log_capture.raw_lines)
        _assert_absent(raw_logs, secret, where=f"{title} 的服务端日志")
        # 校验失败日志中带的明细与响应同口径（同一份清洗结果）。
        failed_logs = [
            rec for rec in log_capture.records_with(rid)
            if rec.get("message") == "request validation failed"
        ]
        assert failed_logs, f"[口径不一致] {title} 缺少校验失败日志"
        logged_details = failed_logs[0]["validation_errors"]
        assert logged_details == details, (
            f"[口径不一致] {title} 响应与日志明细不是同一份清洗结果\n"
            f"response={details}\nlog={logged_details}"
        )

        # 3) 指标面：原始值/字段路径不出现在 Prometheus 序列中。
        metrics_text = client.get("/metrics").text
        _assert_absent(metrics_text, secret, where=f"{title} 的指标输出")

        _log_case(
            title, request_id=rid,
            判定依据="422 明细仅 loc/type/redacted；响应==日志明细；指标无原始值",
        )


def test_misplaced_value_inside_nested_optional_branch_is_withheld(
    client: TestClient, log_capture: LogCapture
) -> None:
    """嵌套对象内部、可选分支里填错位置：如法人对象内 certificate 位置直接给证件号。"""
    rid = "misplaced-nested-01"
    body = {
        **NON_SENSITIVE_BASE,
        "legal_representative": {"name": "法人甲", "certificate": ID_SECRET},
    }
    r = client.post("/enterprise/onboarding", json=body, headers={"X-Request-ID": rid})
    assert_error_response(
        r, expected_status=422, expected_code="VALIDATION_FAILED",
        reason="[口径不一致] certificate 位置填单值应 422",
    )
    detail = r.json()["error"]["details"][0]
    assert tuple(detail["loc"][1:]) == ("legal_representative", "certificate"), (
        f"[口径不一致] 错误定位路径异常: {detail}"
    )
    assert detail["type"] == "model_attributes_type"
    assert detail.get("redacted") is True and "input" not in detail
    _assert_absent(r.text, ID_SECRET, where="嵌套可选分支 422 响应")
    _assert_absent("\n".join(log_capture.raw_lines), ID_SECRET, where="嵌套可选分支日志")
    _assert_absent(client.get("/metrics").text, ID_SECRET, where="嵌套可选分支指标")
    _log_case(
        "嵌套可选分支填单值", request_id=rid,
        判定依据="loc 定位到 legal_representative.certificate；type 保留；值剥离",
    )


def test_non_sensitive_misplaced_value_still_locatable_and_echoed(
    client: TestClient, log_capture: LogCapture
) -> None:
    """非敏感位置填错形状：保留 input 便于前端提示（如 enterprise_name 给了数字数组）。"""
    rid = "misplaced-nonsensitive-01"
    body = {**_legal_ok(), "enterprise_name": [1, 2, 3]}
    r = client.post("/enterprise/onboarding", json=body, headers={"X-Request-ID": rid})
    assert r.status_code == 422, r.text
    detail = next(
        d for d in r.json()["error"]["details"]
        if tuple(d["loc"][1:]) == ("enterprise_name",)
    )
    assert detail.get("redacted") is not True, (
        f"[口径不一致] 非敏感位置不应打 redacted: {detail}"
    )
    assert detail.get("input") == [1, 2, 3], (
        f"[口径不一致] 非敏感输入应继续保留以便前端提示: {detail}"
    )
    assert detail["type"] == "string_type"
    _log_case(
        "非敏感错位置保留输入", request_id=rid,
        判定依据="enterprise_name 非敏感：loc/type/input 全保留，仅敏感位置剥离",
    )


# ---------------------------------------------------------------------------
# 审计计数只与实际掩码有关：多挂一路日志输出不翻倍
# ---------------------------------------------------------------------------


def _valid_onboarding_body(*, phone: str = "13800138000") -> dict:
    return {
        **NON_SENSITIVE_BASE,
        "legal_representative": {"name": "法人甲", "id_number": "11010119800101001X"},
        "contacts": [{"name": "联系人甲", "phone": phone}],
    }


class _ListHandler(logging.Handler):
    """只渲染不解析的第二路输出（独立 formatter 实例，模拟线上多挂一路日志）。"""

    def __init__(self) -> None:
        super().__init__()
        self.setFormatter(JsonFormatter())
        self.addFilter(RequestIdFilter())
        self.lines: list[str] = []

    def emit(self, record: logging.LogRecord) -> None:
        # 显式渲染两次：证明“渲染次数”也不影响计数（快照复用）。
        self.lines.append(self.format(record))
        self.lines.append(self.format(record))


def test_extra_log_handler_does_not_double_mask_audit(
    client: TestClient, log_capture: LogCapture
) -> None:
    """在 app logger 上多挂一路输出：log 通道计数与单路完全相同。"""
    before = get_mask_counts()
    before_contact_log = before.get(("contact", "log", ""), 0)
    before_id_log = before.get(("id_document", "log", ""), 0)
    before_contact_ds = before.get(("contact", "downstream", ""), 0)

    extra = _ListHandler()
    target = logging.getLogger("app")
    target.addHandler(extra)
    try:
        rid = "multi-handler-01"
        r = client.post(
            "/enterprise/onboarding",
            json=_valid_onboarding_body(phone=PHONE_SECRET),
            headers={"X-Request-ID": rid},
        )
        assert r.status_code == 200, r.text
    finally:
        target.removeHandler(extra)

    # 两路输出都不含原始值（第二路还把每条记录渲染了两次）。
    for line in extra.lines:
        _assert_absent(line, PHONE_SECRET, where="第二路日志输出")
    _assert_absent("\n".join(extra.lines), "11010119800101001X", where="第二路日志输出")

    after = get_mask_counts()
    # 本请求实际掩码：请求日志 phone=1、id_number=1、legal.name=1；
    # 下游记录只计 downstream 通道（phone=1）；PreRedacted 不重复计数。
    assert after.get(("contact", "log", ""), 0) - before_contact_log == 1, (
        "[口径不一致] 多挂一路日志后 contact/log 被重复计数（应只与实际掩码有关）"
    )
    assert after.get(("id_document", "log", ""), 0) - before_id_log == 2, (
        f"[口径不一致] id_document/log 增量应为 2（法人姓名+证件号各一次），"
        f"实际 {after.get(('id_document', 'log', ''), 0) - before_id_log}"
    )
    assert after.get(("contact", "downstream", ""), 0) - before_contact_ds == 1, (
        "[口径不一致] contact/downstream 增量应为 1"
    )

    # 两路渲染结果的脱敏内容逐字节一致（同一份判定）。
    onboarding_lines = [
        line for line in extra.lines if "enterprise onboarding request" in line
    ]
    assert len(onboarding_lines) >= 2 and onboarding_lines[0] == onboarding_lines[1], (
        "[口径不一致] 同一条记录两次渲染结果不一致"
    )
    _log_case(
        "多路日志输出计数不翻倍",
        request_id=rid,
        判定依据="额外 handler+双次渲染后 contact/log 增量仍为 1，两路渲染一致",
    )


def test_concurrent_requests_with_multi_handlers_counts_exact_and_isolated(
    client: TestClient, log_capture: LogCapture
) -> None:
    """并发 + 每请求多一路日志输出：各类别计数精确，不丢、不串。"""
    n = 40
    rids = [f"ent-mh-{i:03d}-{uuid.uuid4().hex[:8]}" for i in range(n)]
    extra = _ListHandler()
    target = logging.getLogger("app")
    target.addHandler(extra)

    before = get_mask_counts()
    before_contact_log = before.get(("contact", "log", ""), 0)
    before_id_log = before.get(("id_document", "log", ""), 0)
    before_contact_ds = before.get(("contact", "downstream", ""), 0)

    probes: dict[str, str] = {}

    def call(item: tuple[int, str]) -> tuple[str, str]:
        i, rid = item
        unique_phone = f"136{i:08d}"
        probes[rid] = unique_phone
        body = _valid_onboarding_body(phone=unique_phone)
        r = client.post(
            "/enterprise/onboarding", json=body, headers={"X-Request-ID": rid}
        )
        assert r.status_code == 200, (
            f"[口径不一致] 并发请求 rid={rid} 未成功: {r.status_code} {r.text}"
        )
        return rid, unique_phone

    try:
        with ThreadPoolExecutor(max_workers=16) as pool:
            results = list(pool.map(call, enumerate(rids)))
    finally:
        target.removeHandler(extra)

    # 1) 不串扰：唯一手机号不能出现在任何一路日志里（无论谁的 rid）。
    all_output = "\n".join(log_capture.raw_lines + extra.lines)
    for rid, unique_phone in results:
        _assert_absent(all_output, unique_phone, where=f"并发多路日志（rid={rid}）")

    # 每个 rid 的日志只关联自己（探针层面跨 rid 检查）。
    for rid, unique_phone in results:
        own = "\n".join(
            json.dumps(rec, ensure_ascii=False)
            for rec in log_capture.records_with(rid)
        )
        assert unique_phone not in own, f"[泄露] rid={rid} 自己的手机号出现在日志"
        for other_rid in rids:
            if other_rid == rid:
                continue
            other_text = "\n".join(
                json.dumps(rec, ensure_ascii=False)
                for rec in log_capture.records_with(other_rid)
            )
            assert unique_phone not in other_text, (
                f"[并发串扰] rid={rid} 的手机号出现在 rid={other_rid} 的日志中"
            )

    # 2) 不丢不重：精确增量 == 每请求实际掩码数 × 并发数（与额外一路输出无关）。
    after = get_mask_counts()
    actual_contact_log = after.get(("contact", "log", ""), 0) - before_contact_log
    actual_id_log = after.get(("id_document", "log", ""), 0) - before_id_log
    actual_contact_ds = after.get(("contact", "downstream", ""), 0) - before_contact_ds
    assert actual_contact_log == n, (
        f"[并发串扰] 多路输出并发下 contact/log 应为 {n}（每请求 1 次掩码），"
        f"实际 {actual_contact_log}"
    )
    assert actual_id_log == 2 * n, (
        f"[并发串扰] id_document/log 应为 {2 * n}，实际 {actual_id_log}"
    )
    assert actual_contact_ds == n, (
        f"[并发串扰] contact/downstream 应为 {n}，实际 {actual_contact_ds}"
    )
    _log_case(
        "并发+多路输出计数精确",
        并发数=n,
        判定依据="contact log/downstream 各 N、id_document log 2N；唯一探针零泄露零串扰",
    )


# ---------------------------------------------------------------------------
# 未显式声明场景（基线规则，如 /login）：整体 body 或敏感键位置错填也不外泄
# ---------------------------------------------------------------------------


def test_baseline_login_scalar_body_and_wrong_shape_are_withheld(
    client: TestClient, log_capture: LogCapture
) -> None:
    """/login 没有显式场景策略：整体 body 填成一段证件号，也要按基线敏感处理。"""
    rid = "login-scalar-body-01"
    r = client.post(
        "/login",
        content=json.dumps(ID_SECRET),
        headers={"Content-Type": "application/json", "X-Request-ID": rid},
    )
    assert r.status_code == 422, r.text
    _assert_absent(r.text, ID_SECRET, where="/login 整体标量 body 的响应")
    _assert_absent("\n".join(log_capture.raw_lines), ID_SECRET, where="/login 标量 body 日志")
    detail = r.json()["error"]["details"][0]
    assert detail.get("redacted") is True and "input" not in detail, (
        f"[口径不一致] /login 整体标量 body 明细应剥离: {detail}"
    )
    assert detail["type"] == "model_attributes_type", detail
    _log_case(
        "登录整体标量body", request_id=rid,
        判定依据="基线合成策略子树判定：body 标量剥离，loc/type 保留",
    )

    # 同一接口的正常字段级失败仍可回显非敏感输入（基线合成策略不扩大误伤）。
    rid2 = "login-missing-02"
    r2 = client.post("/login", json={"username": "bob"}, headers={"X-Request-ID": rid2})
    assert r2.status_code == 422
    missing = [d for d in r2.json()["error"]["details"] if d["type"] == "missing"]
    assert any(d["loc"][-1] == "password" for d in missing), (
        f"[口径不一致] 缺少 password 的定位应保留: {missing}"
    )
    _log_case(
        "登录缺字段可定位", request_id=rid2,
        判定依据="missing 错误仅给 loc/type，不带任何值",
    )


# ---------------------------------------------------------------------------
# 纯函数级：错位置错误的清洗结果确定，且计数类别封闭
# ---------------------------------------------------------------------------


def test_scrub_misplaced_scalar_is_stable_and_counted_once() -> None:
    """直接调用 scrub：同一份错误多次清洗，结构与审计口径稳定。"""
    from app.observability import sensitivity as S
    from app.observability.metrics import reset_metrics

    reset_metrics()
    policy = S.policy_for_model(
        __import__("app.schemas_enterprise", fromlist=["EnterpriseOnboardingRequest"]).EnterpriseOnboardingRequest
    )
    assert policy is not None

    errors = [
        {"type": "list_type", "loc": ("body", "contacts"),
         "msg": "Input should be a valid list", "input": PHONE_SECRET},
        {"type": "model_attributes_type", "loc": ("body", "contacts", 0),
         "msg": "Input should be a valid dictionary", "input": PHONE_SECRET},
        {"type": "model_attributes_type", "loc": ("body",),
         "msg": "Input should be a valid dictionary", "input": ID_SECRET},
        {"type": "string_type", "loc": ("body", "enterprise_name"),
         "msg": "Input should be a valid string", "input": [1, 2]},
    ]
    body = {
        **NON_SENSITIVE_BASE,
        "legal_representative": {"name": "x"},
        "contacts": PHONE_SECRET,
    }
    first = S.scrub_validation_errors(
        [dict(e) for e in errors], body=body, policy=policy,
        channels=(S.OutputChannel.RESPONSE, S.OutputChannel.LOG),
    )
    serialized_first = json.dumps(first, ensure_ascii=False, sort_keys=True)
    _assert_absent(serialized_first, PHONE_SECRET, where="scrub 清洗结果")
    _assert_absent(serialized_first, ID_SECRET, where="scrub 清洗结果")

    # 再次清洗（模拟响应与日志若各自调用）：结果逐字节一致。
    second = S.scrub_validation_errors(
        [dict(e) for e in errors], body=body, policy=policy,
        channels=(S.OutputChannel.RESPONSE, S.OutputChannel.LOG),
    )
    assert json.dumps(second, ensure_ascii=False, sort_keys=True) == serialized_first, (
        "[口径不一致] 同一份错误两次清洗结果不同"
    )

    # 非敏感字段错误保留 input；其余三条带 redacted 且仅 loc/type/msg/url。
    by_type_loc = {(tuple(d["loc"]), d["type"]): d for d in first}
    nonsensitive = by_type_loc[(("body", "enterprise_name"), "string_type")]
    assert nonsensitive.get("input") == [1, 2] and not nonsensitive.get("redacted"), (
        f"[口径不一致] 非敏感错误应保留输入: {nonsensitive}"
    )
    for key in (
        (("body", "contacts"), "list_type"),
        (("body", "contacts", 0), "model_attributes_type"),
        (("body",), "model_attributes_type"),
    ):
        detail = by_type_loc[key]
        assert detail.get("redacted") is True, f"[口径不一致] {key} 应 redacted"
        assert set(detail) <= {"type", "loc", "msg", "redacted", "url"}, (
            f"[泄露] {key} 清洗后仍含多余键: {detail}"
        )

    counts = get_mask_counts()
    # 两次清洗 × 两通道，但每次清洗每条错误只计一次；类别只能来自封闭枚举。
    for (category, channel, error_code), value in counts.items():
        assert category in {"credential", "id_document", "contact", "financial"}, (
            f"[口径不一致] 越界脱敏类别: {category}"
        )
        assert channel in {"response", "log"}, channel
        assert error_code == "VALIDATION_FAILED", error_code
        assert value >= 1
    _log_case(
        "错位置清洗纯函数", request_id=None,
        判定依据="两次清洗逐字节一致；非敏感保留 input；敏感仅安全键；类别封闭",
    )
