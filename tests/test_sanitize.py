"""Masking coverage for credentials, tokens and personal sensitive fields."""
from __future__ import annotations

import json

from app.sanitize import (
    SENSITIVE_HEADERS,
    is_sensitive_key,
    sanitize,
    sanitize_headers,
)
from tests.conftest import check

SECRETS = {
    "plain": "hunter2",
    "token-value": "tok.AAAA",
    "bearer": "Bearer abc.def.ghi",
    "card": "4111111111111111",
    "mail": "alice@example.com",
    "phone": "13800000000",
}


def test_credential_fields_are_masked_under_any_key_style():
    payload = {
        "password": SECRETS["plain"],
        "apiKey": SECRETS["token-value"],
        "access_token": SECRETS["token-value"],
        "X-Auth-Token": SECRETS["token-value"],
        "Authorization": SECRETS["bearer"],
        "nested": {"data": [{"password": SECRETS["plain"]}]},
    }
    out = sanitize(payload)
    serialized = json.dumps(out, ensure_ascii=False)

    for label, secret in [
        ("password", SECRETS["plain"]),
        ("apiKey", SECRETS["token-value"]),
        ("access_token", SECRETS["token-value"]),
        ("X-Auth-Token", SECRETS["token-value"]),
        ("Authorization", SECRETS["bearer"]),
        ("nested[].password", SECRETS["plain"]),
    ]:
        check(secret not in serialized,
              basis="凭据/令牌字段无论键的写法如何（大小写、连字符、下划线）或嵌套多深，值都不得出现在输出中",
              input=label, request_id="n/a", actual=serialized)
    check(out["apiKey"] == "***" and out["nested"]["data"][0]["password"] == "***",
          basis="命中字段的对外占位符固定为 ***",
          input="apiKey / nested password", request_id="n/a",
          actual=[out["apiKey"], out["nested"]["data"][0]["password"]])


def test_personal_sensitive_fields_are_masked():
    payload = {
        "id_card_no": "110101199001011234",
        "creditCard": SECRETS["card"],
        "email": SECRETS["mail"],
        "phone": SECRETS["phone"],
        "note": "contact me",
    }
    serialized = json.dumps(sanitize(payload), ensure_ascii=False)
    for label, secret in [
        ("id_card_no", "110101199001011234"),
        ("creditCard", SECRETS["card"]),
        ("email", SECRETS["mail"]),
        ("phone", SECRETS["phone"]),
    ]:
        check(secret not in serialized,
              basis="个人敏感字段（证件号/卡号/邮箱/手机号）不得出现在输出中",
              input=label, request_id="n/a", actual=serialized)
    check(sanitize(payload)["note"] == "contact me",
          basis="非敏感字段必须原样保留，避免过度脱敏",
          input="note", request_id="n/a", actual=sanitize(payload)["note"])


def test_credential_headers_are_masked():
    headers = {"Authorization": "Bearer zzz-token", "cookie": "sid=1",
               "x-request-id": "rid-1", "X-Api-Key": "k-1"}
    out = sanitize_headers(headers)
    for name, value in headers.items():
        lower = name.lower()
        if lower in SENSITIVE_HEADERS:
            check(out[lower] == "***" and value not in json.dumps(out),
                  basis="凭据类 HTTP 头必须整体掩码，原值不得出现",
                  input=name, request_id="n/a", actual=out[lower])
        else:
            check(out[lower] == value,
                  basis="非凭据头（如关联标识）必须原样保留以便排查",
                  input=name, request_id="rid-1", actual=out[lower])


def test_key_normalization_rules():
    for key in ("password", "Password", "API-KEY", "api_key", "X.Auth.Token"):
        check(is_sensitive_key(key),
              basis="键名归一化（小写并去除非字母数字）后命中敏感集合即视为敏感",
              input=key, request_id="n/a", actual=is_sensitive_key(key))


def test_embedded_bearer_in_free_text_is_redacted():
    text = "call with Bearer eyJhbGciOi.abc123 then continue"
    out = sanitize(text)
    check("eyJhbGciOi.abc123" not in out and "Bearer ***" in out,
          basis="自由文本中内嵌的 Bearer/Basic 凭据必须被正则抹除",
          input=text, request_id="n/a", actual=out)


def test_validation_error_echo_is_masked_by_loc():
    from app.sanitize import sanitize_validation_errors

    detail = [
        {"type": "int_parsing", "loc": ["body", "lifetime_token"],
         "msg": "not an int", "input": "tok-raw-secret-9"},
        {"type": "int_parsing", "loc": ["path", "item_id"],
         "msg": "not an int", "input": "abc"},
        {"type": "missing", "loc": ["body", "password"],
         "msg": "field required", "input": {"api_key": "k-1"}},
    ]
    out = sanitize_validation_errors(detail)
    serialized = json.dumps(out, ensure_ascii=False)
    check("tok-raw-secret-9" not in serialized and out[0]["input"] == "***",
          basis="loc 命中敏感字段时，input 中的原始敏感值必须掩码（位置感知脱敏）",
          input="loc=body.lifetime_token", request_id="n/a",
          actual=out[0])
    check(out[1]["input"] == "abc",
          basis="loc 为普通字段时 input 回显必须保留",
          input="loc=path.item_id", request_id="n/a", actual=out[1])
    check(out[2]["input"] == "***",
          basis="缺失的敏感字段即使 input 是对象也要整体掩码",
          input="loc=body.password", request_id="n/a", actual=out[2])
