"""结构化日志、敏感字段脱敏与 request_id 注入。

* 日志以单行 JSON 输出，自动附带当前上下文 ``request_id``；
* 通过 :class:`RequestIdFilter` 注入关联标识，日志方法本身无需传参；
* 所有结构化字段在写入前经 :func:`redact_value` 递归脱敏——该函数委托给
  :mod:`app.observability.sensitivity` 的场景策略（与响应、下游调用记录、
  错误统计共用同一套判定，保证口径一致），并按 ``log`` 通道累加脱敏审计；
  凭据、令牌与个人敏感字段一律替换为 ``***REDACTED***``；
* 未处理异常记录完整异常链路（traceback），供内部排查。
"""

from __future__ import annotations

import json
import logging
import os
from collections.abc import Mapping
from datetime import datetime, timezone
from typing import Any

from app.context import get_request_id
from app.observability.sensitivity import (
    OutputChannel,
    REDACTED,
    _baseline_category,
    redact_value as _policy_redact,
)

#: 递归深度与容器规模上限的语义与 sensitivity 模块保持一致（该模块强制执行）。
#: 以下常量仅保留供本模块文档/其他工具引用。
_MAX_DEPTH = 6
_MAX_ITEMS = 100

#: logging 记录自带的标准属性，渲染 extra 字段时排除。
#: ``_observability_redacted_extras`` 是脱敏结果缓存（见 JsonFormatter），
#: 同样不作为业务字段渲染。
_RESERVED_ATTRS = frozenset(
    {
        "name", "msg", "args", "levelname", "levelno", "pathname", "filename",
        "module", "exc_info", "exc_text", "stack_info", "lineno", "funcName",
        "created", "msecs", "relativeCreated", "thread", "threadName",
        "processName", "process", "taskName", "request_id",
        "_observability_redacted_extras",
    }
)


def redact_value(value: Any, depth: int = 0) -> Any:
    """按统一敏感策略对任意值做递归脱敏（日志通道）。

    实际判定在 :mod:`app.observability.sensitivity`：裸 dict 走基线凭据/个人
    信息规则；Pydantic 模型自动解析其绑定的场景策略（路径感知、别名归一、
    数组逐条）。``depth`` 参数仅为兼容历史调用签名，递归深度由策略模块统一
    强制（>=6 一律掩码）。

    >>> redact_value({"password": "p@ss", "user": {"token": "t", "id": 1}})
    {'password': '***REDACTED***', 'user': {'token': '***REDACTED***', 'id': 1}}
    >>> redact_value([{"api_key": "k"}, "ok"])
    [{'api_key': '***REDACTED***'}, 'ok']
    """
    return _policy_redact(value, channel=OutputChannel.LOG)


def sanitize_headers(headers: Mapping[str, str]) -> dict[str, str]:
    """脱敏 HTTP 头：凭据类头整体掩码，其余头走通用规则。"""
    credential_headers = {"authorization", "cookie", "proxy-authorization", "x-api-key"}
    result: dict[str, str] = {}
    for key, value in headers.items():
        if key.lower() in credential_headers or _baseline_category(key) is not None:
            result[key] = REDACTED
        else:
            result[key] = value
    return result


class RequestIdFilter(logging.Filter):
    """为每条日志记录注入当前上下文的 ``request_id``。"""

    def filter(self, record: logging.LogRecord) -> bool:
        record.request_id = get_request_id()
        return True


#: 记录在 LogRecord 上的“已脱敏 extra 字段”缓存属性名。
#:
#: 脱敏审计计数发生在脱敏动作本身；同一条日志记录可能被多个 handler
#: 渲染（多路日志输出），或被同一路渲染多次。若每次渲染都重新脱敏，
#: 审计计数会随输出路数翻倍。这里把首次脱敏结果缓存在记录上，后续
#: 渲染直接复用——一条记录的掩码动作只发生、只计数一次，与输出路数、
#: 渲染次数无关。标准 logging 中一条记录由创建它的线程顺序经过各
#: handler，不存在并发渲染同一记录的场景。
_REDACTED_CACHE_ATTR = "_observability_redacted_extras"


class JsonFormatter(logging.Formatter):
    """将日志记录渲染为单行 JSON，extra 字段递归脱敏。

    脱敏结果按记录缓存（见 :data:`_REDACTED_CACHE_ATTR`）：多路 handler
    或重复渲染复用首次脱敏结果，脱敏审计计数与渲染次数无关。
    """

    def _redacted_extras(self, record: logging.LogRecord) -> dict[str, Any]:
        cached = getattr(record, _REDACTED_CACHE_ATTR, None)
        if cached is None:
            cached = {
                key: redact_value(value)
                for key, value in record.__dict__.items()
                if key not in _RESERVED_ATTRS
            }
            setattr(record, _REDACTED_CACHE_ATTR, cached)
        return cached

    def format(self, record: logging.LogRecord) -> str:
        payload: dict[str, Any] = {
            "ts": datetime.fromtimestamp(record.created, tz=timezone.utc)
            .isoformat()
            .replace("+00:00", "Z"),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
            "request_id": getattr(record, "request_id", None),
        }
        for key, value in self._redacted_extras(record).items():
            if key in payload:
                continue
            payload[key] = value
        if record.exc_info:
            payload["exc_info"] = self.formatException(record.exc_info)
        return json.dumps(payload, ensure_ascii=False, default=str)


_CONFIGURED = False


def configure_logging(level: str | int | None = None) -> None:
    """配置根 logger：单 handler、JSON 输出、request_id 注入。

    幂等：重复调用不会叠加 handler。
    """
    global _CONFIGURED
    if _CONFIGURED:
        return
    resolved_level = level or os.environ.get("LOG_LEVEL", "INFO")
    handler = logging.StreamHandler()
    handler.setFormatter(JsonFormatter())
    handler.addFilter(RequestIdFilter())
    root = logging.getLogger()
    root.addHandler(handler)
    root.setLevel(resolved_level)
    # 第三方库噪声降级（httpx/httpcore 自身的请求日志不进入 JSON 流）。
    for noisy in ("httpx", "httpcore", "http2"):
        logging.getLogger(noisy).setLevel(logging.WARNING)
    _CONFIGURED = True


def get_logger(name: str) -> logging.Logger:
    """返回应用 logger；确保全局日志配置至少执行过一次。"""
    if not _CONFIGURED:
        configure_logging()
    return logging.getLogger(name)
