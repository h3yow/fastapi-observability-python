"""Downstream-call helper with correlation-id propagation.

All outbound calls go through :func:`call_downstream`, which:

* injects the current ``X-Request-Id`` header (minted on the spot if the
  context somehow has none, so a downstream never sees an empty id);
* refuses to log/propagate caller-supplied credential headers verbatim in
  error details (they are sanitized before reaching logs/responses);
* translates every failure (timeout, connection error, bad status) into a
  single :class:`DownstreamError` so the middleware can map it to the
  stable ``UPSTREAM_ERROR`` code;
* emits structured start/end/error log lines carrying the same id.
"""
from __future__ import annotations

from typing import Any

import httpx

from app.context import get_request_id, new_request_id, HEADER_NAME
from app.logging_setup import get_logger
from app.sanitize import sanitize_headers

logger = get_logger("observability.downstream")


class DownstreamError(Exception):
    """Raised when a downstream call fails for any reason."""

    def __init__(
        self,
        message: str,
        *,
        upstream_status: int | None = None,
        request_headers: dict[str, str] | None = None,
    ) -> None:
        super().__init__(message)
        self.upstream_status = upstream_status
        self.request_headers = request_headers or {}


def _current_id_for_propagation() -> str:
    rid = get_request_id()
    return rid or new_request_id()


async def call_downstream(
    client: httpx.AsyncClient,
    method: str,
    url: str,
    *,
    propagate_id: bool = True,
    **kwargs: Any,
) -> httpx.Response:
    """Perform an outbound HTTP request, propagating the correlation id.

    Raises :class:`DownstreamError` on transport failure or when the
    response status is >= 500 (4xx is returned to the caller, which may
    react to business-level rejections itself).
    """
    rid = _current_id_for_propagation()
    headers = httpx.Headers(kwargs.pop("headers", None))
    if propagate_id:
        headers[HEADER_NAME] = rid

    safe_headers = sanitize_headers(headers)
    logger.info(
        "downstream request start",
        extra={
            "extra_fields": {
                "downstream_method": method.upper(),
                "downstream_url": url,
                "downstream_headers": safe_headers,
            }
        },
    )
    try:
        response = await client.request(method, url, headers=headers, **kwargs)
    except httpx.HTTPError as exc:
        logger.error(
            "downstream transport error: %s",
            type(exc).__name__,
            extra={
                "extra_fields": {
                    "downstream_method": method.upper(),
                    "downstream_url": url,
                    "error_type": type(exc).__name__,
                }
            },
        )
        raise DownstreamError(
            f"downstream transport failure: {type(exc).__name__}",
            request_headers=safe_headers,
        ) from exc

    if response.status_code >= 500:
        logger.error(
            "downstream bad status",
            extra={
                "extra_fields": {
                    "downstream_method": method.upper(),
                    "downstream_url": url,
                    "upstream_status": response.status_code,
                }
            },
        )
        raise DownstreamError(
            f"downstream responded {response.status_code}",
            upstream_status=response.status_code,
            request_headers=safe_headers,
        )

    logger.info(
        "downstream request end",
        extra={
            "extra_fields": {
                "downstream_method": method.upper(),
                "downstream_url": url,
                "upstream_status": response.status_code,
            }
        },
    )
    return response
