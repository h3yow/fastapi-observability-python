"""测试公共夹具与断言辅助。

* 每个用例前后隔离全局指标（HTTP 指标 + 脱敏审计计数）；
* 下游 HTTP 全部走 MockTransport，可模拟成功/失败并捕获透传请求头/请求体；
* 提供日志捕获 handler，便于断言“某条日志在特定 request_id 下出现/不含敏感值”；
* client 关闭 raise_server_exceptions，使 500 处理器的响应可断言。
"""

from __future__ import annotations

import json
import logging
from collections.abc import Iterator
from typing import Any

import httpx
import pytest
from fastapi.testclient import TestClient

from app.main import create_app
from app.observability import http as http_mod
from app.observability.audit import reset_audit
from app.observability.logging import JsonFormatter, RequestIdFilter
from app.observability.metrics import reset_metrics


class LogCapture(logging.Handler):
    """收集 app.* logger 输出的结构化日志记录。"""

    def __init__(self) -> None:
        super().__init__()
        self.setFormatter(JsonFormatter())
        self.addFilter(RequestIdFilter())
        self.records: list[dict[str, Any]] = []
        self.raw_lines: list[str] = []

    def emit(self, record: logging.LogRecord) -> None:
        line = self.format(record)
        self.raw_lines.append(line)
        try:
            self.records.append(json.loads(line))
        except json.JSONDecodeError:
            pass

    def records_with(self, request_id: str) -> list[dict[str, Any]]:
        return [r for r in self.records if r.get("request_id") == request_id]


@pytest.fixture
def log_capture() -> Iterator[LogCapture]:
    capture = LogCapture()
    target = logging.getLogger("app")
    target.addHandler(capture)
    try:
        yield capture
    finally:
        target.removeHandler(capture)


@pytest.fixture
def client(log_capture: LogCapture) -> Iterator[TestClient]:
    reset_metrics()
    reset_audit()

    requests_seen: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        # 缓存请求体（content 是字节，可反复读取），供用例断言下游未收到敏感值。
        _ = request.content
        requests_seen.append(request)
        if str(request.url).endswith("/fail"):
            return httpx.Response(500, json={"detail": "downstream secret stack"})
        return httpx.Response(200, json={"ok": True, "got": request.headers.get("x-request-id")})

    mock_client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    http_mod.set_client(mock_client)
    try:
        with TestClient(create_app(), raise_server_exceptions=False) as c:
            c.downstream_requests = requests_seen  # type: ignore[attr-defined]
            yield c
    finally:
        http_mod.set_client(None)


def assert_error_response(
    response: Any, *, expected_status: int, expected_code: str, reason: str
) -> None:
    """断言错误响应结构/状态码/错误码，reason 用于给出可区分的失败原因。"""
    assert response.status_code == expected_status, (
        f"{reason}: 期望状态码 {expected_status}，实际 {response.status_code}，body={response.text}"
    )
    body = response.json()
    assert "error" in body, f"{reason}: 响应缺少 error 包装，body={body}"
    assert body["error"].get("code") == expected_code, (
        f"{reason}: 期望错误码 {expected_code}，实际 {body['error'].get('code')}"
    )
    assert body["error"].get("request_id"), f"{reason}: 错误响应缺少 request_id"
    assert isinstance(body["error"].get("message"), str) and body["error"]["message"], (
        f"{reason}: 错误响应缺少安全提示信息"
    )
