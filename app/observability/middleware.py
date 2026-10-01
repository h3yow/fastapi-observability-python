"""request_id、资料敏感策略与请求指标采集中间件。

执行顺序（该中间件是最外层 HTTP 中间件）：

1. 读取入站 ``X-Request-ID``，按 :func:`app.context.resolve_request_id`
   的确定规则沿用或替换，并写入 ContextVar；
2. 按请求路径匹配已注册的**路由模板 -> 资料敏感策略**，命中则把策略写入
   ContextVar：路由处理、422 异常处理器、后台任务、下游调用记录以及 JSON
   日志在同一个请求内读到的是同一份声明，敏感判定各处口径一致；
3. 将生效标识写回响应头 ``X-Request-ID``（异常响应同样可关联）；
4. ``try/finally`` 中计时并调用 :func:`observe_request`，正常响应、
   校验失败、未匹配路由、内部异常全部走同一条采集路径，口径一致；
5. 路由维度使用模板（``request.scope["route"]``），未匹配路由统一归为
   :data:`UNMATCHED_ROUTE`，杜绝高基数。
"""

from __future__ import annotations

import re
import time

from fastapi import FastAPI, Request
from starlette.responses import Response

from app.context import (
    REQUEST_ID_HEADER,
    get_request_id,
    reset_request_id,
    resolve_request_id,
    set_request_id,
)
from app.observability.errors import CODE_INTERNAL, register_exception_handlers
from app.observability.logging import configure_logging, get_logger
from app.observability.metrics import UNMATCHED_ROUTE, observe_request, render_prometheus
from app.observability import audit as audit_mod
from app.observability.sensitive import (
    SensitivePolicy,
    reset_active_policy,
    set_active_policy,
)

logger = get_logger("app.access")

#: 非异常路径下，按状态码兜底的错误码（异常路径以 request.state.error_code 为准）。
_STATUS_FALLBACK_CODE = {
    401: "UNAUTHORIZED",
    403: "FORBIDDEN",
    404: "NOT_FOUND",
    405: "METHOD_NOT_ALLOWED",
    422: "VALIDATION_FAILED",
    429: "TOO_MANY_REQUESTS",
    502: "DOWNSTREAM_ERROR",
    503: "SERVICE_UNAVAILABLE",
}

# ---------------------------------------------------------------------------
# 路由模板 -> 资料敏感策略注册表
# ---------------------------------------------------------------------------
#: 编译后的路由模板正则（形如 /enterprise/onboarding），与路由表模板一致。
_TEMPLATE_PARAM = re.compile(r"{[^{}]+}")
#: (编译后模板正则, 原始模板, 策略)
_policy_routes: list[tuple[re.Pattern[str], str, SensitivePolicy]] = []


def register_route_policy(route_template: str, policy: SensitivePolicy) -> None:
    """登记“路由模板 -> 资料敏感策略”。

    资料场景通过本函数声明自己的模板与策略；新增资料版本只改场景自己的
    模型/声明文件并在此登记，公共脱敏代码无需改动。
    """
    pattern = _TEMPLATE_PARAM.sub(r"[^/]+", route_template)
    compiled = re.compile(f"^{pattern}$")
    _policy_routes.append((compiled, route_template, policy))


def _match_policy(path: str) -> SensitivePolicy | None:
    for compiled, _template, policy in _policy_routes:
        if compiled.match(path):
            return policy
    return None


def _route_template(request: Request) -> str:
    route = request.scope.get("route")
    path = getattr(route, "path", None)
    return path if isinstance(path, str) else UNMATCHED_ROUTE


def _fallback_error_code(status_code: int) -> str:
    if 200 <= status_code < 400:
        return ""
    return _STATUS_FALLBACK_CODE.get(status_code, f"HTTP_{status_code}")


def install_observability(app: FastAPI) -> None:
    """配置日志、注册异常处理器、安装指标中间件并暴露 ``/metrics``。"""
    configure_logging()
    register_exception_handlers(app)

    @app.middleware("http")
    async def observability_middleware(request: Request, call_next) -> Response:
        raw = request.headers.get(REQUEST_ID_HEADER)
        request_id, source = resolve_request_id(raw)
        # 在当前请求 task 的 ContextVar 副本中显式设置，再进入下游处理；
        # 每个请求由独立 task 承载，并发请求之间互不串扰。
        set_request_id(request_id)
        # 同时写入 scope 共享状态：500 处理器运行在本中间件之外的
        # ServerErrorMiddleware，ContextVar 无法回传，state 可被其读取。
        request.state.request_id = request_id
        request.state.request_id_source = source

        # 按路由模板绑定本请求的资料敏感策略（同一请求内的路由/422 处理器/
        # 后台任务/下游记录/JSON 日志共享同一份声明；未登记路由为 None，
        # 退回全局凭据规则）。
        policy = _match_policy(request.url.path)
        if policy is not None:
            policy_token = set_active_policy(policy)
            request.state.sensitive_profile = policy.name
        else:
            policy_token = set_active_policy(None)
            request.state.sensitive_profile = None

        start = time.perf_counter()
        status_code = 500
        try:
            response = await call_next(request)
            status_code = response.status_code
            response.headers[REQUEST_ID_HEADER] = request_id
            return response
        except Exception:
            # 异常随后由最外层 ServerErrorMiddleware 的 500 处理器转成响应；
            # 中间件 finally 先于该处理器执行，故在此先固定错误码，
            # 保证指标口径与对外 INTERNAL_ERROR 一致，而不是落到 HTTP_500 兜底。
            request.state.error_code = CODE_INTERNAL
            raise
        finally:
            # call_next 内部异常已由注册的异常处理器转为响应；
            # 若仍有遗漏（如中间件链自身异常），以 500 计入，保证口径不丢。
            duration = time.perf_counter() - start
            route_template = _route_template(request)
            if route_template == UNMATCHED_ROUTE:
                # 未匹配路由统一错误码口径（处理器通常已写 state，这里双保险）。
                error_code = getattr(request.state, "error_code", "") or (
                    "ROUTE_NOT_FOUND" if status_code == 404
                    else "METHOD_NOT_ALLOWED" if status_code == 405
                    else _fallback_error_code(status_code)
                )
            else:
                error_code = (
                    getattr(request.state, "error_code", "")
                    or _fallback_error_code(status_code)
                )
            observe_request(
                request.method, route_template, status_code, duration, error_code
            )
            logger.info(
                "request completed",
                extra={
                    "method": request.method,
                    "route": route_template,
                    "path": request.url.path,
                    "status_code": status_code,
                    "duration_ms": round(duration * 1000, 3),
                    "request_id_source": source,
                    "error_code": error_code,
                    "sensitive_profile": request.state.sensitive_profile,
                    "effective_request_id": get_request_id(),
                },
            )
            reset_active_policy(policy_token)
            reset_request_id()

    @app.get("/metrics", include_in_schema=False)
    async def metrics_endpoint() -> Response:
        # HTTP 指标 + 脱敏审计计数同一端点暴露；审计指标仅含低基数标签。
        content = render_prometheus() + audit_mod.render_audit_prometheus()
        return Response(content=content, media_type="text/plain; version=0.0.4")
