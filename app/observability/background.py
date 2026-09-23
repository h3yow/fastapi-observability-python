"""后台任务封装：快照并恢复 request_id 上下文。

FastAPI/Starlette 执行 ``BackgroundTasks`` 时会复制提交时刻的
:class:`contextvars.Context`，因此协程型后台任务天然继承 request_id。
本模块提供显式封装，保证：

* 无论原函数是协程函数还是同步函数，包装结果都是 **async callable**，
  可直接放入 ``BackgroundTasks``；同步函数在线程池中执行；
* request_id 在“包装时刻”（请求处理期间）被快照，而不是任务实际
  执行时才读取，杜绝响应发送后上下文被清理导致的标识丢失；
* 同步函数在线程池上下文副本中也会显式设置一次 request_id，
  杜绝任何路径下的标识丢失。
"""

from __future__ import annotations

import functools
from collections.abc import Callable
from typing import Any, ParamSpec

from starlette.concurrency import run_in_threadpool

from app.context import get_request_id, new_request_id, reset_request_id, set_request_id
from app.observability.logging import get_logger

P = ParamSpec("P")

logger = get_logger("app.background")


def with_request_id(func: Callable[P, Any]) -> Callable[P, Any]:
    """在请求处理期间包装后台函数，快照当前 request_id 并在任务中恢复。

    若快照时上下文中没有 request_id（非请求场景调度），则生成新标识，
    保证后台执行期间日志仍可关联到同一条任务。
    """
    if not callable(func):
        raise TypeError("with_request_id must be applied to a callable")

    captured = get_request_id() or new_request_id()
    is_coro = _is_coroutine(func)

    if is_coro:

        @functools.wraps(func)
        async def awrapper(*args: P.args, **kwargs: P.kwargs) -> Any:
            set_request_id(captured)
            try:
                logger.info("background task started", extra={"task": func.__name__})
                return await func(*args, **kwargs)
            finally:
                logger.info("background task finished", extra={"task": func.__name__})
                reset_request_id()

        return awrapper

    @functools.wraps(func)
    async def wrapper(*args: P.args, **kwargs: P.kwargs) -> Any:
        def _run() -> Any:
            set_request_id(captured)
            try:
                logger.info("background task started", extra={"task": func.__name__})
                return func(*args, **kwargs)
            finally:
                logger.info("background task finished", extra={"task": func.__name__})
                reset_request_id()

        # run_in_threadpool 会把当前 contextvars 上下文复制到工作线程。
        return await run_in_threadpool(_run)

    return wrapper


def _is_coroutine(func: Callable[..., Any]) -> bool:
    import inspect

    return inspect.iscoroutinefunction(func)
