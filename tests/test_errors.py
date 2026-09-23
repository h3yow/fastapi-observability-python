"""Exception -> stable external code mapping and envelope consistency."""
from __future__ import annotations

from fastapi.testclient import TestClient

from tests.conftest import check


def _series_for(client: TestClient, method: str, route: str) -> dict:
    for s in client.get("/metrics").json()["metrics"]:
        if s["method"] == method and s["route"] == route:
            return s
    return {}


def test_validation_failure_uses_validation_code_and_preserves_id(client):
    rid = "rid-422-aaaa"
    r = client.get("/items/not-an-int", headers={"X-Request-Id": rid})
    body = r.json()
    check(r.status_code == 422,
          basis="路径参数类型错误必须映射为 HTTP 422",
          input="GET /items/not-an-int", request_id=rid, actual=r.status_code)
    check(body["error"]["code"] == "VALIDATION_ERROR",
          basis="校验失败必须返回稳定可区分错误码 VALIDATION_ERROR",
          input="GET /items/not-an-int", request_id=rid,
          actual=body["error"]["code"])
    check(body["error"]["request_id"] == rid
          and r.headers["x-request-id"] == rid,
          basis="错误信封正文与响应头都必须携带同一关联标识",
          input="GET /items/not-an-int", request_id=rid,
          actual=(body["error"]["request_id"], r.headers.get("x-request-id")))
    check(isinstance(body["error"].get("details"), list)
          and body["error"]["details"][0]["loc"] == ["path", "item_id"],
          basis="校验错误可附结构化字段定位（loc），但不暴露内部异常",
          input="GET /items/not-an-int", request_id=rid,
          actual=body["error"].get("details"))
    s = _series_for(client, "GET", "/items/{item_id}")
    check(s.get("status_counts", {}).get("422") == 1
          and s.get("error_code_counts", {}).get("VALIDATION_ERROR") == 1,
          basis="422 必须与其他结果一样按路由模板计入指标且带 VALIDATION_ERROR 分类",
          input="metrics snapshot", request_id=rid, actual=s)


def test_unmatched_route_uses_not_found_and_bounded_label(client):
    rid = "rid-404-bbbb"
    r = client.get("/definitely/no/such/route/9f3a", headers={"X-Request-Id": rid})
    body = r.json()
    check(r.status_code == 404 and body["error"]["code"] == "NOT_FOUND",
          basis="未匹配路由必须返回 404 + 稳定码 NOT_FOUND",
          input="GET /definitely/no/such/route/9f3a", request_id=rid,
          actual=(r.status_code, body["error"]["code"]))
    check("/definitely/no/such/route/9f3a" not in str(body),
          basis="错误正文不得回显具体高基数路径",
          input="GET /definitely/no/such/route/9f3a", request_id=rid,
          actual=body)
    s = _series_for(client, "GET", "__unmatched__")
    check(s.get("count") == 1 and s.get("error_code_counts") == {"NOT_FOUND": 1},
          basis="未匹配路由指标必须归一到常量 __unmatched__，防止路径基数失控",
          input="metrics snapshot", request_id=rid, actual=s)


def test_unhandled_exception_maps_to_internal_without_leaking_detail(client):
    rid = "rid-500-cccc"
    r = client.get("/boom", headers={"X-Request-Id": rid})
    body = r.json()
    check(r.status_code == 500 and body["error"]["code"] == "INTERNAL_ERROR",
          basis="未处理异常必须映射为 500 + 稳定码 INTERNAL_ERROR",
          input="GET /boom", request_id=rid,
          actual=(r.status_code, body["error"]["code"]))
    check("boom: unexpected failure" not in r.text
          and "RuntimeError" not in r.text,
          basis="对外响应不得包含原始异常文本或异常类型",
          input="GET /boom", request_id=rid, actual=r.text)
    check(body["error"]["message"] == "Internal server error"
          and body["error"]["request_id"] == rid,
          basis="对外仅给固定文案与关联标识，排查凭 request_id 反查服务端日志",
          input="GET /boom", request_id=rid, actual=body["error"])


def test_internal_exception_chain_is_logged_with_request_id(client, log_capture):
    rid = "rid-500-log"
    client.get("/boom", headers={"X-Request-Id": rid})
    error_lines = [
        x for x in log_capture.lines_for(rid) if x["level"] == "error"
    ]
    check(len(error_lines) == 1,
          basis="每个未处理异常必须恰好产生一条服务端 error 日志",
          input="GET /boom", request_id=rid, actual=len(error_lines))
    line = error_lines[0]
    check("RuntimeError" in line.get("exc_info", "")
          and "boom: unexpected failure" in line.get("exc_info", ""),
          basis="服务端日志必须保留完整原始异常链（类型+消息+堆栈）",
          input="GET /boom", request_id=rid, actual=line.get("exc_info", "")[:200])
    check(line.get("error_type") == "RuntimeError"
          and line.get("route") == "/boom",
          basis="异常日志还需带 error_type 与路由模板，便于分类排查",
          input="GET /boom", request_id=rid,
          actual=(line.get("error_type"), line.get("route")))


def test_downstream_5xx_maps_to_upstream_error(client):
    rid = "rid-502-dddd"
    r = client.get("/downstream?fail=true", headers={"X-Request-Id": rid})
    body = r.json()
    check(r.status_code == 502 and body["error"]["code"] == "UPSTREAM_ERROR",
          basis="下游 5xx 必须映射为可与内部错误区分的 502 + UPSTREAM_ERROR",
          input="GET /downstream?fail=true", request_id=rid,
          actual=(r.status_code, body["error"]["code"]))
    check(body["error"]["details"] == {"upstream_status": 500}
          and body["error"]["request_id"] == rid,
          basis="可附上游状态码等非敏感事实，但关联标识必须保持一致",
          input="GET /downstream?fail=true", request_id=rid,
          actual=body["error"])


def test_success_uses_no_error_code_and_echoes_id(client):
    rid = "rid-200-eeee"
    r = client.get("/", headers={"X-Request-Id": rid})
    check(r.status_code == 200 and "error" not in r.json(),
          basis="正常响应不得携带错误信封",
          input="GET /", request_id=rid, actual=r.json())
    s = _series_for(client, "GET", "/")
    check(s["count"] == 1 and s["error_count"] == 0
          and s["error_code_counts"] == {},
          basis="正常请求计入指标但 error_code 为空，口径与错误请求保持同一统计通道",
          input="metrics snapshot", request_id=rid, actual=s)


def test_validation_details_are_sanitized_when_input_is_secret(client):
    secret = "super-secret-token-value-xyz"

    # pydantic echoes the offending value under details[].input; the field
    # name only appears as a value inside loc, so this proves position-aware
    # sanitization rather than generic key masking
    r = client.post("/token-probe", json={"lifetime_token": secret},
                    headers={"X-Request-Id": "rid-422-secret"})
    body = r.json()
    check(r.status_code == 422 and secret not in r.text,
          basis="校验失败时 Pydantic 在 details[].input 回显的敏感字段原值不得泄漏",
          input="POST /token-probe {lifetime_token: <secret>}",
          request_id="rid-422-secret", actual=r.text)
    detail = body["error"]["details"][0]
    check(detail["input"] == "***"
          and detail["loc"] == ["body", "lifetime_token"],
          basis="敏感回显必须整体掩码，同时保留 loc 定位信息，二者可区分",
          input="details[0]", request_id="rid-422-secret", actual=detail)

    # precision: non-sensitive echoed input must remain visible
    r2 = client.get("/items/abc", headers={"X-Request-Id": "rid-422-keep"})
    echoed = r2.json()["error"]["details"][0]["input"]
    check(echoed == "abc",
          basis="非敏感字段的回显不得被误伤，脱敏要基于 loc 精确判定",
          input="GET /items/abc", request_id="rid-422-keep", actual=echoed)

    # happy path: credential header used, password never echoed
    r3 = client.post(
        "/login",
        json={"username": "alice", "password": secret},
        headers={"X-Request-Id": "rid-200-secret",
                 "Authorization": f"Bearer {secret}"},
    )
    check(r3.status_code == 200 and secret not in r3.text,
          basis="成功响应不得回显密码或任何凭据",
          input="POST /login with password + Authorization Bearer <secret>",
          request_id="rid-200-secret", actual=r3.text)
