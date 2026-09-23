"""脱敏与异常映射测试。

断言给出可区分原因；用例日志打印输入、关联标识与判定依据。
"""

from __future__ import annotations

import json

from fastapi.testclient import TestClient

from app.observability.logging import redact_value, sanitize_headers
from tests.conftest import LogCapture, assert_error_response

SECRETS = ["supersecret-pw", "Bearer eyJhbGciOi.JWT.token", "sk-live-1234567890", "13800138000"]


def _log_case(case: str, *, input_value: object, request_id: str | None, basis: str) -> None:
    print(f"\n[用例] {case} | 输入={input_value!r} | request_id={request_id!r} | 判定依据: {basis}")


# ---------------------------------------------------------------------------
# 脱敏纯函数
# ---------------------------------------------------------------------------

def test_redact_nested_sensitive_keys() -> None:
    """嵌套结构中的凭据/令牌/个人敏感字段整体掩码。"""
    payload = {
        "username": "bob",
        "password": "supersecret-pw",
        "token": "abc",
        "nested": {"api_key": "sk-live-1", "user": {"id_card": "110101*", "phone": "13800138000"}},
        "items": [{"accessToken": "tok-val-xyz"}, {"email": "a@b.c", "ok": 1}],
    }
    redacted = redact_value(payload)
    serialized = json.dumps(redacted, ensure_ascii=False)
    for needle in ("supersecret-pw", "abc", "sk-live-1", "110101*", "13800138000", "a@b.c", "tok-val-xyz"):
        assert needle not in serialized, f"敏感值 {needle!r} 未被脱敏: {serialized}"
    assert redacted["username"] == "bob", "非敏感字段被误脱敏"
    assert redacted["nested"]["user"]["id_card"] == "***REDACTED***"
    _log_case("嵌套脱敏", input_value=payload, request_id=None, basis="所有敏感键的值均为 ***REDACTED***，非敏感键保留")


def test_redact_sensitive_headers() -> None:
    """凭据类 HTTP 头整体掩码；普通头保留。"""
    headers = {
        "Authorization": "Bearer eyJ.secret",
        "Cookie": "session=abc123",
        "X-Api-Key": "sk-xyz",
        "X-Request-Id": "rid-1234-5678",
        "Accept": "application/json",
    }
    out = sanitize_headers(headers)
    assert out["Authorization"] == "***REDACTED***"
    assert out["Cookie"] == "***REDACTED***"
    assert out["X-Api-Key"] == "***REDACTED***"
    assert out["X-Request-Id"] == "rid-1234-5678" and out["Accept"] == "application/json"
    _log_case("请求头脱敏", input_value=list(headers), request_id=None, basis="Authorization/Cookie/X-Api-Key 掩码，其余保留")


# ---------------------------------------------------------------------------
# 日志脱敏
# ---------------------------------------------------------------------------

def test_login_logs_and_response_have_no_secrets(
    client: TestClient, log_capture: LogCapture
) -> None:
    """含密码/身份证的登录请求：响应与全部日志中均不得出现原始敏感值。"""
    rid = "login-rid-0001"
    body = {"username": "bob", "password": SECRETS[0], "id_card": "110101199001011234"}
    r = client.post("/login", json=body, headers={"X-Request-ID": rid})
    assert r.status_code == 200, f"登录接口异常: {r.status_code} {r.text}"

    assert SECRETS[0] not in r.text, "响应中泄露了密码"
    assert "110101199001011234" not in r.text, "响应中泄露了身份证号"

    rid_records = log_capture.records_with(rid)
    assert rid_records, f"未检索到 request_id={rid} 的日志"
    raw = "\n".join(log_capture.raw_lines)
    assert SECRETS[0] not in raw, f"日志中泄露密码: {raw}"
    assert "110101199001011234" not in raw, f"日志中泄露身份证号: {raw}"
    login_logs = [rec for rec in rid_records if rec.get("message") == "login request"]
    assert login_logs and login_logs[0]["body"]["password"] == "***REDACTED***", (
        f"登录日志 password 字段未脱敏: {login_logs}"
    )
    _log_case("登录脱敏", input_value=body, request_id=rid, basis="响应与 JSON 日志均不含密码/身份证，且 body.password 已掩码")


def test_unhandled_exception_keeps_internal_chain_but_hides_from_response(
    client: TestClient, log_capture: LogCapture
) -> None:
    """未处理异常：对外稳定 INTERNAL_ERROR，对内日志保留异常类型与完整堆栈。"""
    rid = "boom-rid-0001"
    r = client.get("/boom?kind=kaboom", headers={"X-Request-ID": rid})
    assert_error_response(
        r, expected_status=500, expected_code="INTERNAL_ERROR", reason="未处理异常映射"
    )
    body = r.json()
    assert "simulated unhandled failure" not in json.dumps(body), "原始异常信息泄露到响应"
    assert body["error"]["request_id"] == rid, "500 响应体 request_id 与入站不一致"
    assert r.headers["x-request-id"] == rid, "500 响应头缺少 request_id"

    err_logs = [
        rec for rec in log_capture.records_with(rid) if rec.get("message") == "unhandled exception"
    ]
    assert err_logs, "缺少内部异常日志"
    rec = err_logs[0]
    assert rec.get("exception_type") == "RuntimeError", f"异常类型记录错误: {rec.get('exception_type')}"
    assert "Traceback (most recent call last)" in rec.get("exc_info", ""), (
        "内部日志未保留原始异常堆栈链路"
    )
    assert "simulated unhandled failure" in rec.get("exc_info", ""), "堆栈中缺少原始异常消息"
    _log_case(
        "未处理异常映射",
        input_value="/boom?kind=kaboom",
        request_id=rid,
        basis="对外 code=INTERNAL_ERROR 且无原始消息；对内日志含 exception_type 与 traceback",
    )


# ---------------------------------------------------------------------------
# 错误码稳定性与可区分性
# ---------------------------------------------------------------------------

def test_error_codes_are_stable_and_distinct(client: TestClient) -> None:
    """各类失败必须映射为稳定且可区分的错误码。"""
    rid = "codes-rid-0001"
    headers = {"X-Request-ID": rid}
    cases = [
        ("POST", "/login", {"username": "bob"}, 422, "VALIDATION_FAILED"),
        ("GET", "/no/such/route/998877", None, 404, "ROUTE_NOT_FOUND"),
        ("GET", "/boom?kind=http", None, 409, "CONFLICT"),
        ("GET", "/boom?kind=other", None, 500, "INTERNAL_ERROR"),
    ]
    observed = []
    for method, path, payload, status, code in cases:
        r = client.request(method, path, json=payload, headers=headers)
        assert_error_response(r, expected_status=status, expected_code=code, reason=f"{method} {path}")
        observed.append(code)
        _log_case(
            f"错误码映射 {method} {path}",
            input_value=payload,
            request_id=r.json()["error"]["request_id"],
            basis=f"HTTP {status} -> {code}",
        )
    assert len(set(observed)) == len(observed), f"错误码之间不可区分: {observed}"


def test_validation_error_details_are_redacted(client: TestClient) -> None:
    """422 详情只包含字段定位/规则，且响应可通过 request_id 关联。"""
    rid = "validation-rid-1"
    r = client.post(
        "/login",
        json={"username": "", "password": ""},
        headers={"X-Request-ID": rid},
    )
    assert r.status_code == 422
    details = r.json()["error"]["details"]
    assert isinstance(details, list) and details, "422 必须返回字段级 details"
    fields = {tuple(d.get("loc", [])) for d in details}
    assert ("body", "username") in fields or ("body", "password") in fields, fields
    assert r.json()["error"]["request_id"] == rid
    _log_case(
        "校验失败口径",
        input_value={"username": "", "password": ""},
        request_id=rid,
        basis="422/details 含字段定位；code=VALIDATION_FAILED；带 request_id",
    )


def test_downstream_error_is_mapped_without_leaking_detail(
    client: TestClient, log_capture: LogCapture
) -> None:
    """下游 500：本服务映射稳定错误码，下游原始错误体不得透传。"""
    rid = "downstream-rid-1"
    r = client.get(
        "/downstream?url=https://downstream/fail",
        headers={"X-Request-ID": rid},
    )
    assert r.status_code == 502, f"期望 502，实际 {r.status_code}: {r.text}"
    assert r.json()["error"]["code"] == "DOWNSTREAM_ERROR", r.json()
    assert "downstream secret stack" not in r.text, "下游错误细节泄露到对外响应"

    raw = "\n".join(log_capture.raw_lines)
    assert rid in raw, "下游失败链路的日志未携带 request_id"
    _log_case(
        "下游异常映射",
        input_value="https://downstream/fail",
        request_id=rid,
        basis="502 -> DOWNSTREAM_ERROR；下游细节只进日志不进响应",
    )
