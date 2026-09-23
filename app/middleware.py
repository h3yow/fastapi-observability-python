"""Pure-ASGI observability middleware.

Responsibilities, applied uniformly to every HTTP request including
validation failures, unmatched routes and unhandled exceptions:

1. Resolve / mint the correlation id, bind it to the context for the whole
   downstream call (so endpoints, thread-pool work, FastAPI background
   tasks and downstream calls share it) and echo it as ``X-Request-Id``.
2. Time the request and record one metrics observation keyed by the
   *matched route template* — never the raw path.
3. Rewrite any error response (4xx/5xx produced by the framework or by a
   raised exception) into the canonical envelope from :mod:`app.errors`.
4. Log one completion line per request with the same correlation id and
   the full exception chain for 5xx-class failures.

A pure-ASGI middleware is used (instead of ``BaseHTTPMiddleware``) so that
the bound :class:`contextvars.ContextVar` demonstrably covers background
tasks executed inside the app's own response task.
"""
from __future__ import annotations

import json
import time
from typing import Any, Awaitable, Callable

from app.context import HEADER_NAME, resolve_incoming_id, set_request_id, reset_request_id
from app.downstream import DownstreamError
from app.errors import (
    METHOD_NOT_ALLOWED,
    NOT_FOUND,
    VALIDATION_ERROR,
    INTERNAL_ERROR,
    UPSTREAM_ERROR,
    ErrorCode,
    error_body,
)
from app.logging_setup import get_logger
from app.metrics import UNMATCHED_ROUTE, MetricsRegistry

logger = get_logger("observability.http")

Scope = dict[str, Any]
Receive = Callable[[], Awaitable[dict[str, Any]]]
Send = Callable[[dict[str, Any]], Awaitable[None]]

#: status -> stable error code for the framework-produced responses we rewrite
_STATUS_CODE: dict[int, str] = {
    404: NOT_FOUND,
    405: METHOD_NOT_ALLOWED,
    422: VALIDATION_ERROR,
    500: INTERNAL_ERROR,
    502: UPSTREAM_ERROR,
}


def classify_status(status: int) -> str:
    """Return the stable error code recorded in metrics for *status*.

    Success (2xx/3xx) -> ``""``; known statuses -> fixed codes; any other
    error -> bounded ``HTTP_<status>`` labels (never free text).
    """
    if status < 400:
        return ""
    return _STATUS_CODE.get(status, f"HTTP_{status}")


def _route_template(scope: Scope) -> str:
    route = scope.get("route")
    path = getattr(route, "path", None)
    return path if isinstance(path, str) else UNMATCHED_ROUTE


class ObservabilityMiddleware:
    def __init__(self, app: Any, metrics: MetricsRegistry | None = None) -> None:
        self.app = app
        self.metrics = metrics

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        # late import: metrics singleton may be replaced in tests
        from app.metrics import registry as default_registry

        metrics = self.metrics or default_registry

        raw_id = None
        for k, v in scope.get("headers", []):
            if k == HEADER_NAME.encode():
                raw_id = v.decode("latin-1", "replace")
                break
        request_id, reused = resolve_incoming_id(raw_id)
        token = set_request_id(request_id)

        start = time.perf_counter()
        state: dict[str, Any] = {
            "status": 200,
            "buffering": False,
            "chunks": [],
            "start_seen": False,
        }

        async def send_wrapper(message: dict[str, Any]) -> None:
            mtype = message["type"]
            if mtype == "http.response.start":
                state["start_seen"] = True
                status = message["status"]
                state["status"] = status
                if status >= 400:
                    # buffer the framework error body, then replace it
                    state["buffering"] = True
                    return
                headers = list(message.get("headers", []))
                headers.append(
                    (HEADER_NAME.encode(), request_id.encode("latin-1"))
                )
                await send({**message, "headers": headers})
            elif mtype == "http.response.body" and state["buffering"]:
                body = message.get("body", b"")
                if body:
                    state["chunks"].append(body)
                if not message.get("more_body", False):
                    await self._send_error_envelope(send, state, request_id)
            else:
                await send(message)

        try:
            await self.app(scope, receive, send_wrapper)
            elapsed = time.perf_counter() - start
            self._record(metrics, scope, state["status"], elapsed)
            self._log_completion(scope, state, elapsed, reused,
                                 classify_status(state["status"]))
        except DownstreamError as exc:
            elapsed = time.perf_counter() - start
            await self._send_exception(
                send, state, ErrorCode.get(UPSTREAM_ERROR), request_id,
                {"upstream_status": exc.upstream_status},
            )
            self._record(metrics, scope, ErrorCode.get(UPSTREAM_ERROR).status,
                         elapsed, UPSTREAM_ERROR)
            logger.error(
                "downstream failure surfaced as error response",
                extra={"extra_fields": {"method": scope.get("method"),
                                        "route": _route_template(scope),
                                        "upstream_status": exc.upstream_status}},
                exc_info=exc,
            )
        except Exception as exc:  # noqa: BLE001 - last-resort normalization
            elapsed = time.perf_counter() - start
            await self._send_exception(
                send, state, ErrorCode.get(INTERNAL_ERROR), request_id, None
            )
            self._record(metrics, scope, 500, elapsed, INTERNAL_ERROR)
            # full original chain preserved internally
            logger.error(
                "unhandled exception",
                extra={"extra_fields": {"method": scope.get("method"),
                                        "route": _route_template(scope),
                                        "error_type": type(exc).__name__}},
                exc_info=exc,
            )
        finally:
            reset_request_id(token)

    # -- helpers ---------------------------------------------------------

    def _record(self, metrics: MetricsRegistry, scope: Scope, status: int,
                elapsed: float, error_code: str | None = None) -> None:
        if error_code is None:
            error_code = classify_status(status)
        metrics.observe(
            route=_route_template(scope),
            method=scope.get("method", ""),
            status=status,
            error_code=error_code,
            elapsed=elapsed,
        )

    def _log_completion(self, scope: Scope, state: dict[str, Any],
                        elapsed: float, reused: bool, error_code: str) -> None:
        fields = {
            "method": scope.get("method"),
            "route": _route_template(scope),
            "status": state["status"],
            "elapsed_ms": round(elapsed * 1000.0, 3),
            "request_id_reused": reused,
        }
        if error_code:
            fields["error_code"] = error_code
        if error_code:
            logger.warning("request completed", extra={"extra_fields": fields})
        else:
            logger.info("request completed", extra={"extra_fields": fields})

    async def _send_error_envelope(
        self, send: Send, state: dict[str, Any], request_id: str
    ) -> None:
        """Rewrite a buffered framework error body into our envelope."""
        status = state["status"]
        code_name = _STATUS_CODE.get(status)
        details = None
        if code_name is None:
            code = ErrorCode(f"HTTP_{status}", status,
                             self._generic_message(state))
        else:
            code = ErrorCode.get(code_name)
            if code_name == VALIDATION_ERROR:
                details = self._validation_details(state)
        await self._emit_envelope(send, code, request_id, details)

    @staticmethod
    def _generic_message(state: dict[str, Any]) -> str:
        try:
            original = json.loads(b"".join(state["chunks"]) or b"{}")
        except (json.JSONDecodeError, UnicodeDecodeError):
            return "Request failed"
        detail = original.get("detail")
        if isinstance(detail, str) and detail:
            return detail
        return "Request failed"

    @staticmethod
    def _validation_details(state: dict[str, Any]) -> Any:
        try:
            original = json.loads(b"".join(state["chunks"]) or b"{}")
        except (json.JSONDecodeError, UnicodeDecodeError):
            return None
        from app.sanitize import sanitize_validation_errors

        return sanitize_validation_errors(original.get("detail"))

    @staticmethod
    async def _send_exception(
        send: Send, state: dict[str, Any], code: ErrorCode,
        request_id: str, details: Any,
    ) -> None:
        if state["start_seen"]:
            # headers already flushed; cannot change the response anymore
            return
        await ObservabilityMiddleware._emit_envelope(
            send, code, request_id, details
        )

    @staticmethod
    async def _emit_envelope(
        send: Send, code: ErrorCode, request_id: str, details: Any
    ) -> None:
        body = json.dumps(
            error_body(code, details=details), ensure_ascii=False
        ).encode("utf-8")
        await send(
            {
                "type": "http.response.start",
                "status": code.status,
                "headers": [
                    (b"content-type", b"application/json"),
                    (b"content-length", str(len(body)).encode()),
                    (HEADER_NAME.encode(), request_id.encode("latin-1")),
                ],
            }
        )
        await send({"type": "http.response.body", "body": body})
