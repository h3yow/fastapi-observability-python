"""下游 HTTP 调用封装：自动透传当前上下文的 request_id。

* 基于共享的 :class:`httpx.AsyncClient`（连接复用，避免每次请求新建连接
  而明显拖慢调用方）；
* 自动注入 ``X-Request-ID``：取当前上下文 request_id；上下文缺失时
  生成新标识，保证整条下游链路可关联；
* 下游 4xx/5xx 或传输异常统一包装为 :class:`DownstreamError`，
  映射对外错误码 ``DOWNSTREAM_ERROR``；下游返回体不直接透出给调用方，
  防止下游错误信息泄露；
* 调用事件与耗时写日志（请求/响应头中的凭据字段经脱敏处理）。
"""

from __future__ import annotations

import time
from typing import Any

import httpx

from app.context import REQUEST_ID_HEADER, get_request_id, new_request_id
from app.observability.logging import get_logger, sanitize_headers
from app.observability.sensitive import (
    CHANNEL_DOWNSTREAM,
    RedactedPayload,
    SensitivePolicy,
    redact_with_policy,
)

logger = get_logger("app.http")


class DownstreamError(RuntimeError):
    """下游调用失败（HTTP 错误状态或传输异常）。"""

    def __init__(self, url: str, reason: str, status_code: int | None = None) -> None:
        super().__init__(f"downstream call failed: {url} ({reason})")
        self.url = url
        self.reason = reason
        self.status_code = status_code


_client: httpx.AsyncClient | None = None


def get_client() -> httpx.AsyncClient:
    """返回进程级共享 AsyncClient（测试可通过 :func:`set_client` 替换）。"""
    global _client
    if _client is None:
        _client = httpx.AsyncClient(timeout=httpx.Timeout(5.0))
    return _client


def set_client(client: httpx.AsyncClient | None) -> None:
    """替换/关闭共享客户端（测试注入 MockTransport 后调用）。"""
    global _client
    _client = client


async def downstream_get(
    url: str,
    *,
    params: dict[str, str] | None = None,
    client: httpx.AsyncClient | None = None,
) -> dict[str, Any]:
    """携带当前 request_id 发起下游 GET，返回 JSON dict。

    :raises DownstreamError: 传输异常或下游返回非 2xx。
    """
    request_id = get_request_id() or new_request_id()
    headers = {REQUEST_ID_HEADER: request_id}
    active = client or get_client()
    start = time.perf_counter()
    logger.info(
        "downstream call start",
        extra={"url": url, "params": params, "headers": sanitize_headers(headers)},
    )
    try:
        response = await active.get(url, params=params, headers=headers)
    except httpx.HTTPError as exc:
        duration = time.perf_counter() - start
        logger.error(
            "downstream transport error",
            extra={"url": url, "duration_ms": round(duration * 1000, 3)},
            exc_info=exc,
        )
        raise DownstreamError(url, reason=type(exc).__name__) from exc

    duration = time.perf_counter() - start
    logger.info(
        "downstream call done",
        extra={
            "url": url,
            "status_code": response.status_code,
            "duration_ms": round(duration * 1000, 3),
            "response_headers": sanitize_headers(dict(response.headers)),
        },
    )
    if response.status_code >= 400:
        raise DownstreamError(url, reason="non_2xx_status", status_code=response.status_code)
    try:
        return response.json()
    except ValueError as exc:
        raise DownstreamError(url, reason="invalid_json") from exc


async def downstream_post_json(
    url: str,
    payload: dict[str, Any],
    *,
    policy: SensitivePolicy | None = None,
    client: httpx.AsyncClient | None = None,
) -> dict[str, Any]:
    """携带当前 request_id 向下游发起 JSON POST。

    下游边界统一做一次资料脱敏：**真正发送的请求体就是脱敏后的内容**，
    因此敏感输入既不会进入下游系统，也不会出现在下游调用日志/错误记录中；
    掩码事件计入 ``downstream`` 通道审计。资料策略默认取当前请求 ContextVar
    绑定的策略（由入口中间件按路由设定），无策略时退化为全局凭据规则。
    """
    request_id = get_request_id() or new_request_id()
    headers = {
        REQUEST_ID_HEADER: request_id,
        "Content-Type": "application/json",
    }
    safe_payload = redact_with_policy(
        payload, policy=policy, channel=CHANNEL_DOWNSTREAM, count=True
    )
    # 标记为“已脱敏成品”：随后的结构化日志直接记录，不重复计数。
    logged_payload = RedactedPayload(safe_payload, CHANNEL_DOWNSTREAM)
    active = client or get_client()
    start = time.perf_counter()
    logger.info(
        "downstream call start",
        extra={
            "url": url,
            "method": "POST",
            "headers": sanitize_headers(headers),
            "payload": logged_payload,
        },
    )
    try:
        response = await active.post(url, json=safe_payload, headers=headers)
    except httpx.HTTPError as exc:
        duration = time.perf_counter() - start
        logger.error(
            "downstream transport error",
            extra={"url": url, "method": "POST", "duration_ms": round(duration * 1000, 3)},
            exc_info=exc,
        )
        raise DownstreamError(url, reason=type(exc).__name__) from exc

    duration = time.perf_counter() - start
    logger.info(
        "downstream call done",
        extra={
            "url": url,
            "method": "POST",
            "status_code": response.status_code,
            "duration_ms": round(duration * 1000, 3),
            "response_headers": sanitize_headers(dict(response.headers)),
        },
    )
    if response.status_code >= 400:
        raise DownstreamError(url, reason="non_2xx_status", status_code=response.status_code)
    try:
        return response.json()
    except ValueError as exc:
        raise DownstreamError(url, reason="invalid_json") from exc
