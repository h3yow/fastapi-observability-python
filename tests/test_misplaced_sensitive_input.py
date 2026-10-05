"""填错位置的敏感单值：泄露防护、口径一致与审计计数测试。

场景：客户端把本该是对象/数组的位置直接填成单值（联系人位置填手机号、
法人位置填证件号、银行账户位置填账号、附件位置填签名 URL、数组某一条
是单值、可选分支填单值、整个请求体就是一段字符）。校验必然失败，但
失败明细、服务端日志、错误统计中都不得出现那段原始值。

断言失败原因区分：
``[泄露]`` 原始敏感值出现在响应/日志/指标；
``[口径不一致]`` 响应、日志、指标之间判定对不上，或非敏感字段被误掩码；
``[并发串扰]`` 并发请求之间计数丢失或内容互相污染。
"""

from __future__ import annotations

import json
import uuid

import pytest
from fastapi.testclient import TestClient

from app.observability.metrics import get_mask_counts
from tests.conftest import LogCapture, assert_error_response
from tests.test_enterprise_onboarding import valid_body

# 各填错位置使用的敏感探针值（任何一个出现在观测面都视为泄露）。
PROBE_PHONE = "13800138000"
PROBE_ID = "110101199001011234"
PROBE_ACCT = "6222021234567890123"
PROBE_URL = "https://files.example/license.jpg?token=SIGNED-TOKEN-SECRET-9999"
#: 混合数组用例中“合法元素”的敏感值：请求整体 422 时同样不得外泄。
PROBE_VALID_ELEMENT_PHONE = "13700137000"
ALL_PROBES = (PROBE_PHONE, PROBE_ID, PROBE_ACCT, PROBE_URL, PROBE_VALID_ELEMENT_PHONE)


def _base() -> dict:
    """一份除被测位置外完全合法的开通请求（非敏感字段值可预测）。"""
    body = valid_body()
    # 非敏感字段保持合法值，确保唯一的校验失败来自被测的填错位置。
    return body


def _misplaced_cases() -> dict[str, tuple[dict, str, str]]:
    """(请求体, 探针值, 期望审计类别) 的填错位置全集。"""
    return {
        "顶层联系人位置填手机号": (
            {**_base(), "contacts": PROBE_PHONE}, PROBE_PHONE, "contact",
        ),
        "联系人数组某一条是手机号": (
            {**_base(), "contacts": [PROBE_PHONE]}, PROBE_PHONE, "contact",
        ),
        "法人位置填证件号": (
            {**_base(), "legalRepresentative": PROBE_ID}, PROBE_ID, "id_document",
        ),
        "可选分支certificate填证件号": (
            {
                **_base(),
                "legalRepresentative": {"name": "张秘密", "certificate": PROBE_ID},
            },
            PROBE_ID,
            "id_document",
        ),
        "银行账户位置填账号": (
            {**_base(), "bank_account": PROBE_ACCT}, PROBE_ACCT, "financial",
        ),
        "附件位置填签名URL": (
            {**_base(), "attachments": PROBE_URL}, PROBE_URL, "credential",
        ),
        "附件数组某一条是签名URL": (
            {**_base(), "attachments": [PROBE_URL]}, PROBE_URL, "credential",
        ),
        "混合数组合法元素加填错单值": (
            {
                **_base(),
                "contacts": [
                    {"name": "李公开", "phone": PROBE_VALID_ELEMENT_PHONE},
                    PROBE_PHONE,
                ],
            },
            PROBE_PHONE,
            "contact",
        ),
    }


def _log_case(case: str, **fields: object) -> None:
    print("\n[用例] " + case + " | " + " ".join(f"{k}={v!r}" for k, v in fields.items()))


def _assert_no_probe(text: str, *, where: str) -> None:
    for probe in ALL_PROBES:
        assert probe not in text, f"[泄露] 敏感值 {probe!r} 出现在{where}: {text[:400]}"


# ---------------------------------------------------------------------------
# 填错位置：响应明细不泄露、可定位、类别正确
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "case_name",
    list(_misplaced_cases().keys()),
    ids=list(_misplaced_cases().keys()),
)
def test_misplaced_scalar_never_leaks_and_stays_locatable(
    client: TestClient, log_capture: LogCapture, case_name: str
) -> None:
    body, probe, expected_category = _misplaced_cases()[case_name]
    rid = f"misplaced-{uuid.uuid4().hex[:12]}"
    before = get_mask_counts()

    r = client.post(
        "/enterprise/onboarding", json=body, headers={"X-Request-ID": rid}
    )
    assert_error_response(
        r, expected_status=422, expected_code="VALIDATION_FAILED",
        reason=f"[口径不一致] {case_name} 应映射 VALIDATION_FAILED",
    )

    # 1) 响应明细：不含探针；敏感错误保留 loc/type/redacted 可定位。
    _assert_no_probe(r.text, where=f"422 响应（{case_name}）")
    details = r.json()["error"]["details"]
    redacted = [d for d in details if d.get("redacted") is True]
    assert redacted, f"[口径不一致] {case_name} 缺少 redacted 明细: {details}"
    for d in redacted:
        assert "input" not in d and "ctx" not in d, (
            f"[泄露] {case_name} 敏感错误仍带输入/上下文: {d}"
        )
        assert d.get("type") and d.get("loc"), (
            f"[口径不一致] {case_name} 敏感错误缺少规则/路径定位: {d}"
        )

    # 2) 日志：同 request_id 的校验失败日志同样不含探针，且明细与响应一致。
    raw = "\n".join(log_capture.raw_lines)
    _assert_no_probe(raw, where=f"服务端日志（{case_name}）")
    failure_logs = [
        rec for rec in log_capture.records_with(rid)
        if rec.get("message") == "request validation failed"
    ]
    assert failure_logs, f"[口径不一致] {case_name} 缺少校验失败日志"
    logged_errors = failure_logs[0]["validation_errors"]
    assert json.dumps(logged_errors, sort_keys=True, ensure_ascii=False) == json.dumps(
        details, sort_keys=True, ensure_ascii=False
    ), f"[口径不一致] {case_name} 日志明细与响应明细不一致"

    # 3) 指标：审计计数按期望类别在 response/log 双通道各 +1，标签无探针。
    after = get_mask_counts()
    for channel in ("response", "log"):
        key = (expected_category, channel, "VALIDATION_FAILED")
        delta = after.get(key, 0) - before.get(key, 0)
        assert delta == 1, (
            f"[口径不一致] {case_name} 审计计数 {key} 增量应为 1，实际 {delta}"
        )
    metrics_text = client.get("/metrics").text
    _assert_no_probe(metrics_text, where=f"指标暴露（{case_name}）")

    _log_case(
        case_name,
        request_id=rid,
        探针长度=len(probe),
        判定依据=f"响应/日志/指标无探针；redacted 明细可定位；{expected_category} 双通道 +1",
    )


def test_whole_body_scalar_is_withheld(
    client: TestClient, log_capture: LogCapture
) -> None:
    """整个请求体就是一段敏感字符：loc 为 body 根，同样不外泄、可定位。"""
    rid = f"misplaced-root-{uuid.uuid4().hex[:8]}"
    r = client.post(
        "/enterprise/onboarding",
        content=json.dumps(PROBE_ID),
        headers={"X-Request-ID": rid, "Content-Type": "application/json"},
    )
    assert_error_response(
        r, expected_status=422, expected_code="VALIDATION_FAILED",
        reason="[口径不一致] 根位置填错应映射 VALIDATION_FAILED",
    )
    _assert_no_probe(r.text, where="根位置 422 响应")
    details = r.json()["error"]["details"]
    assert details and all(d.get("redacted") is True for d in details), (
        f"[泄露] 根位置填错的明细未整体掩码: {details}"
    )
    assert details[0]["loc"] == ["body"], (
        f"[口径不一致] 根位置错误应定位到 body: {details}"
    )
    _assert_no_probe("\n".join(log_capture.raw_lines), where="根位置服务端日志")
    _assert_no_probe(client.get("/metrics").text, where="根位置指标暴露")
    _log_case(
        "整个请求体是敏感字符",
        request_id=rid,
        判定依据="loc=[body] 整体 redacted；响应/日志/指标均无探针",
    )


def test_non_sibling_non_sensitive_errors_still_echo_input(
    client: TestClient, log_capture: LogCapture
) -> None:
    """同一请求里：填错位置的敏感单值被掩码，非敏感字段错误仍回显 input。"""
    rid = f"misplaced-mixed-{uuid.uuid4().hex[:8]}"
    body = _base()
    body["EnterpriseName"] = "A"  # 非敏感，过短：必须继续回显
    body["contacts"] = PROBE_PHONE  # 填错位置的敏感单值：必须掩码
    r = client.post(
        "/enterprise/onboarding", json=body, headers={"X-Request-ID": rid}
    )
    assert r.status_code == 422, r.text
    _assert_no_probe(r.text, where="混合请求 422 响应")
    details = r.json()["error"]["details"]
    by_leaf = {tuple(d["loc"][-1:]): d for d in details}

    name_err = by_leaf.get(("enterprise_name",))
    assert name_err is not None, f"[口径不一致] 缺少 enterprise_name 明细: {details}"
    assert name_err.get("input") == "A", (
        f"[口径不一致] 非敏感字段输入应保留以便前端提示: {name_err}"
    )
    assert name_err.get("redacted") is not True

    contacts_err = by_leaf.get(("contacts",))
    assert contacts_err is not None, f"[口径不一致] 缺少 contacts 明细: {details}"
    assert contacts_err.get("redacted") is True, (
        f"[泄露] 填错位置的敏感单值未掩码: {contacts_err}"
    )
    assert "input" not in contacts_err

    _assert_no_probe("\n".join(log_capture.raw_lines), where="混合请求服务端日志")
    _log_case(
        "敏感掩码与非敏感回显并存",
        request_id=rid,
        判定依据="enterprise_name.input=='A' 保留；contacts 单值 redacted 且无 input",
    )


# ---------------------------------------------------------------------------
# 脱敏审计计数与日志输出路数/渲染次数无关
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("extra_handlers", [0, 1, 2], ids=["1路", "2路", "3路"])
def test_audit_count_independent_of_log_handler_count(
    client: TestClient, log_capture: LogCapture, extra_handlers: int
) -> None:
    """多挂 N 路日志输出，同一请求的掩码计数必须不变（只计实际掩码）。"""
    import io
    import logging

    from app.observability.logging import JsonFormatter, RequestIdFilter

    app_logger = logging.getLogger("app")
    added: list[logging.Handler] = []
    for _ in range(extra_handlers):
        h = logging.StreamHandler(io.StringIO())
        h.setFormatter(JsonFormatter())
        h.addFilter(RequestIdFilter())
        app_logger.addHandler(h)
        added.append(h)

    rid = f"handlers-{extra_handlers}-{uuid.uuid4().hex[:8]}"
    before = get_mask_counts()
    try:
        r = client.post(
            "/enterprise/onboarding", json=valid_body(), headers={"X-Request-ID": rid}
        )
        assert r.status_code == 200, r.text
    finally:
        for h in added:
            app_logger.removeHandler(h)

    after = get_mask_counts()
    # valid_body 的 contact 掩码恒为 3（phone1 + email1 + phone2），
    # 与日志路数无关；fixture 自带 1 路 + 根 logger 1 路 + 本用例额外 N 路。
    delta = after.get(("contact", "log", ""), 0) - before.get(("contact", "log", ""), 0)
    assert delta == 3, (
        f"[口径不一致] {extra_handlers + 2} 路日志输出下 contact/log 增量应为 3，"
        f"实际 {delta}（计数随输出路数膨胀）"
    )
    _log_case(
        "计数与日志路数无关",
        额外路数=extra_handlers,
        contact_log增量=delta,
        判定依据="同一份请求无论几路渲染，contact/log 恒为 3",
    )


def test_audit_count_independent_of_render_count() -> None:
    """同一条日志记录被重复渲染多次，掩码只发生、只计数一次。"""
    import logging

    from app.observability.logging import JsonFormatter
    from app.observability.metrics import reset_metrics

    reset_metrics()
    record = logging.LogRecord(
        name="app.test", level=logging.INFO, pathname=__file__, lineno=1,
        msg="render twice", args=(), exc_info=None,
    )
    record.body = {"phone": PROBE_PHONE, "note": "ok"}
    formatter = JsonFormatter()

    first = formatter.format(record)
    snapshot = get_mask_counts()
    after_first = snapshot.get(("contact", "log", ""), 0)
    assert after_first == 1, f"[口径不一致] 首次渲染应计 1 次掩码，实际 {after_first}"
    assert PROBE_PHONE not in first, "[泄露] 渲染结果含原始手机号"

    second = formatter.format(record)
    third = formatter.format(record)
    after_more = get_mask_counts().get(("contact", "log", ""), 0)
    assert after_more == 1, (
        f"[口径不一致] 重复渲染不应重复计数，实际累计 {after_more}"
    )
    assert PROBE_PHONE not in second and PROBE_PHONE not in third
    assert '"phone": "***REDACTED***"' in second, "[口径不一致] 缓存结果未复用脱敏值"
    _log_case(
        "计数与渲染次数无关",
        渲染次数=3,
        累计计数=after_more,
        判定依据="同一 LogRecord 重复 format，掩码计数恒为 1",
    )


# ---------------------------------------------------------------------------
# 并发填错位置：计数精确、不丢不串
# ---------------------------------------------------------------------------


def test_concurrent_misplaced_requests_counts_exact_and_isolated(
    client: TestClient, log_capture: LogCapture
) -> None:
    """并发发起一批“联系人位置填手机号”的 422 请求：

    每个请求的唯一探针不得出现在任何响应/日志/指标中；审计计数增量
    精确等于请求数（response/log 双通道各 1 次/请求），不丢不串。
    """
    from concurrent.futures import ThreadPoolExecutor

    n = 24
    rids = [f"misplaced-par-{i:03d}-{uuid.uuid4().hex[:6]}" for i in range(n)]
    probes = [f"139{i:08d}" for i in range(n)]

    before = get_mask_counts()

    def call(i: int) -> str:
        body = _base()
        body["contacts"] = probes[i]  # 填错位置的唯一探针
        r = client.post(
            "/enterprise/onboarding", json=body, headers={"X-Request-ID": rids[i]}
        )
        assert r.status_code == 422, (
            f"[口径不一致] rid={rids[i]} 应为 422，实际 {r.status_code}"
        )
        return r.text

    with ThreadPoolExecutor(max_workers=8) as pool:
        responses = list(pool.map(call, range(n)))

    # 1) 任何响应里都没有任何探针（含其他请求的探针 -> 串扰检测）。
    for i, text in enumerate(responses):
        for probe in probes:
            assert probe not in text, (
                f"[泄露] 探针 {probe} 出现在 rid={rids[i]} 的 422 响应"
            )

    # 2) 全部日志（所有 rid）都不含任何探针。
    raw = "\n".join(log_capture.raw_lines)
    for probe in probes:
        assert probe not in raw, f"[泄露] 并发探针 {probe} 出现在服务端日志"

    # 3) 每个 rid 都有可定位的校验失败日志，且明细 redacted。
    for rid in rids:
        failure = [
            rec for rec in log_capture.records_with(rid)
            if rec.get("message") == "request validation failed"
        ]
        assert failure, f"[口径不一致] rid={rid} 缺少校验失败日志（并发丢失）"
        errors = failure[0]["validation_errors"]
        assert any(e.get("redacted") is True for e in errors), (
            f"[口径不一致] rid={rid} 的填错位置未掩码: {errors}"
        )

    # 4) 审计计数精确：每请求 response/log 各 1 次 contact 掩码。
    after = get_mask_counts()
    for channel in ("response", "log"):
        key = ("contact", channel, "VALIDATION_FAILED")
        delta = after.get(key, 0) - before.get(key, 0)
        assert delta == n, (
            f"[并发串扰] {key} 增量应为 {n}，实际 {delta}（计数丢失或重复）"
        )

    # 5) 指标暴露面无任何探针。
    metrics_text = client.get("/metrics").text
    for probe in probes:
        assert probe not in metrics_text, f"[泄露] 并发探针 {probe} 出现在指标暴露"

    _log_case(
        "并发填错位置",
        并发数=n,
        判定依据="响应/日志/指标无任一唯一探针；contact 双通道增量精确 == 并发数",
    )
