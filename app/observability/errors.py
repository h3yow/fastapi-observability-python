"""异常到稳定对外错误码的映射与错误响应模型。

对外错误响应固定为::

    {"error": {"code": "<稳定错误码>", "message": "<安全提示>", "request_id": "..."}}

* 未处理异常一律映射为 ``INTERNAL_ERROR``（HTTP 500），对外不泄露异常细节；
  完整异常链路（含堆栈）仅写入内部日志，日志携带 request_id 便于关联排查；
* 参数校验失败 -> ``VALIDATION_FAILED``（422）；
* 未匹配路由/方法 -> ``ROUTE_NOT_FOUND`` / ``METHOD_NOT_ALLOWED``（404/405）；
* 显式 :class:`HTTPException` 按稳定映射表转换，未列出的状态码使用
  ``HTTP_<status>`` 兜底错误码；
* 错误码同时写入 ``request.state.error_code``，供指标中间件读取，
  保证“错误响应 / 日志 / 指标”三者口径一致。
"""

from __future__ import annotations

from typing import Any

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from starlette.exceptions import HTTPException as StarletteHTTPException

from app.context import REQUEST_ID_HEADER, get_request_id, set_request_id
from app.observability.logging import get_logger, redact_value, sanitize_headers

logger = get_logger("app.errors")

#: 稳定、可区分的错误码集合（指标与文档以此为准）。
CODE_INTERNAL = "INTERNAL_ERROR"
CODE_VALIDATION = "VALIDATION_FAILED"
CODE_ROUTE_NOT_FOUND = "ROUTE_NOT_FOUND"
CODE_METHOD_NOT_ALLOWED = "METHOD_NOT_ALLOWED"
CODE_UNAUTHORIZED = "UNAUTHORIZED"
CODE_FORBIDDEN = "FORBIDDEN"
CODE_NOT_FOUND = "NOT_FOUND"
CODE_TOO_MANY_REQUESTS = "TOO_MANY_REQUESTS"
CODE_SERVICE_UNAVAILABLE = "SERVICE_UNAVAILABLE"
CODE_DOWNSTREAM = "DOWNSTREAM_ERROR"
CODE_CONFLICT = "CONFLICT"
CODE_HTTP = "HTTP_ERROR"

_HTTP_STATUS_TO_CODE = {
    401: CODE_UNAUTHORIZED,
    403: CODE_FORBIDDEN,
    404: CODE_NOT_FOUND,
    409: CODE_CONFLICT,
    429: CODE_TOO_MANY_REQUESTS,
    502: CODE_DOWNSTREAM,
    503: CODE_SERVICE_UNAVAILABLE,
}


def _error_body(code: str, message: str, request_id: str | None) -> dict[str, Any]:
    return {"error": {"code": code, "message": message, "request_id": request_id}}


def _effective_request_id(request: Request) -> str | None:
    """取生效 request_id：优先 ContextVar，回退 scope 共享 state。

    500 处理器运行在 ServerErrorMiddleware（可观测性中间件之外），
    其 ContextVar 副本中没有标识，需要从 state 回退。
    """
    current = get_request_id()
    if current:
        return current
    from_state = getattr(request.state, "request_id", None)
    if from_state:
        # 显式写回当前上下文，使本处理器产生的日志也携带 request_id。
        set_request_id(from_state)
    return from_state


def _json_error(request: Request, status_code: int, body: dict[str, Any]) -> JSONResponse:
    """构造错误响应并统一回带 X-Request-ID（异常响应也可被调用方关联）。"""
    request_id = _effective_request_id(request)
    headers = {REQUEST_ID_HEADER: request_id} if request_id else {}
    return JSONResponse(status_code=status_code, content=body, headers=headers)


def _safe_request_context(request: Request) -> dict[str, Any]:
    """收集用于内部日志的请求上下文（头与查询参数均脱敏）。"""
    return {
        "method": request.method,
        "path": request.url.path,
        "query": redact_value(dict(request.query_params)),
        "headers": sanitize_headers(dict(request.headers)),
    }


def register_exception_handlers(app: FastAPI) -> None:
    """在应用上注册统一的异常处理器。"""

    @app.exception_handler(RequestValidationError)
    async def _on_validation_error(request: Request, exc: RequestValidationError) -> JSONResponse:
        # 仅回传字段位置与类型/规则信息；校验消息中的输入值由 pydantic 提供，
        # 这里统一走脱敏，避免原始输入（可能含敏感值）出现在响应与日志中。
        errors = redact_value(exc.errors())
        request_id = _effective_request_id(request)
        logger.warning(
            "request validation failed",
            extra={"request_ctx": _safe_request_context(request), "validation_errors": errors},
        )
        request.state.error_code = CODE_VALIDATION
        body = _error_body(
            CODE_VALIDATION,
            "Request parameters failed validation.",
            request_id,
        )
        body["error"]["details"] = errors
        return _json_error(request, 422, body)

    @app.exception_handler(StarletteHTTPException)
    async def _on_http_exception(request: Request, exc: StarletteHTTPException) -> JSONResponse:
        status_code = exc.status_code
        if status_code == 404:
            code = CODE_ROUTE_NOT_FOUND
            message = "Route not found."
        elif status_code == 405:
            code = CODE_METHOD_NOT_ALLOWED
            message = "Method not allowed."
        else:
            code = _HTTP_STATUS_TO_CODE.get(status_code, f"HTTP_{status_code}")
            message = "Request rejected."
        request_id = _effective_request_id(request)
        logger.warning(
            "http exception",
            extra={
                "request_ctx": _safe_request_context(request),
                "status_code": status_code,
                "error_code": code,
            },
        )
        request.state.error_code = code
        return _json_error(
            request, status_code, _error_body(code, message, request_id)
        )

    @app.exception_handler(Exception)
    async def _on_unhandled_exception(request: Request, exc: Exception) -> JSONResponse:
        request_id = _effective_request_id(request)
        # 原始异常链路只进日志，不进响应；extra 经日志层统一脱敏。
        logger.error(
            "unhandled exception",
            extra={"request_ctx": _safe_request_context(request), "exception_type": type(exc).__name__},
            exc_info=exc,
        )
        request.state.error_code = CODE_INTERNAL
        return _json_error(
            request, 500,
            _error_body(CODE_INTERNAL, "An internal error occurred.", request_id),
        )
