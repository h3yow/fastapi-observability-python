"""结构化日志、敏感字段脱敏与 request_id 注入。

* 日志以单行 JSON 输出，自动附带当前上下文 ``request_id``；
* 通过 :class:`RequestIdFilter` 注入关联标识，日志方法本身无需传参；
* 所有结构化字段在写入前经 :func:`redact_value` 递归脱敏，
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

#: 脱敏后替换值（固定值，避免泄露长度等信息）。
REDACTED = "***REDACTED***"

#: 命中即脱敏的字段名（子串、大小写不敏感匹配）。
#: 覆盖凭据/令牌：password/passwd、secret、token、api_key、authorization、credential；
#: 覆盖个人敏感信息：id_card/idcard、phone/mobile、email、ssn。
import re

_SENSITIVE_PATTERN = re.compile(
    r"(pass(word|wd)?|secret|token|api[_\-]?key|authorization|credential|"
    r"id[_\-]?card|phone|mobile|email|ssn)",
    re.IGNORECASE,
)

#: 递归深度与容器规模上限，防止异常数据导致日志采集失控。
_MAX_DEPTH = 6
_MAX_ITEMS = 100

#: logging 记录自带的标准属性，渲染 extra 字段时排除。
_RESERVED_ATTRS = frozenset(
    {
        "name", "msg", "args", "levelname", "levelno", "pathname", "filename",
        "module", "exc_info", "exc_text", "stack_info", "lineno", "funcName",
        "created", "msecs", "relativeCreated", "thread", "threadName",
        "processName", "process", "taskName", "request_id",
    }
)


def _is_sensitive_key(key: Any) -> bool:
    """判断字段名是否属于敏感字段。"""
    if not isinstance(key, str):
        return False
    return bool(_SENSITIVE_PATTERN.search(key))


def redact_value(value: Any, depth: int = 0) -> Any:
    """对任意值做递归脱敏。

    dict 的敏感键整体替换为 :data:`REDACTED`；非敏感键递归处理。
    list/tuple/set 的元素递归处理；Pydantic 模型按 ``model_dump`` 展开。
    其余标量原样返回（字符串是否脱敏取决于其所属键名）。

    >>> redact_value({"password": "p@ss", "user": {"token": "t", "id": 1}})
    {'password': '***REDACTED***', 'user': {'token': '***REDACTED***', 'id': 1}}
    >>> redact_value([{"api_key": "k"}, "ok"])
    [{'api_key': '***REDACTED***'}, 'ok']
    """
    if depth >= _MAX_DEPTH:
        return REDACTED

    if isinstance(value, Mapping):
        result: dict[str, Any] = {}
        for i, (key, item) in enumerate(value.items()):
            if i >= _MAX_ITEMS:
                result["...truncated"] = True
                break
            if _is_sensitive_key(key):
                result[str(key)] = REDACTED
            else:
                result[str(key)] = redact_value(item, depth + 1)
        return result

    if hasattr(value, "model_dump") and callable(value.model_dump):
        try:
            return redact_value(value.model_dump(), depth + 1)
        except Exception:
            return "<unserializable>"

    if isinstance(value, list | tuple | set | frozenset):
        seq = list(value)[:_MAX_ITEMS]
        redacted = [redact_value(item, depth + 1) for item in seq]
        if isinstance(value, tuple):
            return tuple(redacted)
        if isinstance(value, set | frozenset):
            return set(redacted)
        return redacted

    return value


def sanitize_headers(headers: Mapping[str, str]) -> dict[str, str]:
    """脱敏 HTTP 头：凭据类头整体掩码，其余头走通用规则。"""
    credential_headers = {"authorization", "cookie", "proxy-authorization", "x-api-key"}
    result: dict[str, str] = {}
    for key, value in headers.items():
        if key.lower() in credential_headers or _is_sensitive_key(key):
            result[key] = REDACTED
        else:
            result[key] = value
    return result


class RequestIdFilter(logging.Filter):
    """为每条日志记录注入当前上下文的 ``request_id``。"""

    def filter(self, record: logging.LogRecord) -> bool:
        record.request_id = get_request_id()
        return True


class JsonFormatter(logging.Formatter):
    """将日志记录渲染为单行 JSON，extra 字段递归脱敏。"""

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
        for key, value in record.__dict__.items():
            if key in _RESERVED_ATTRS or key in payload:
                continue
            payload[key] = redact_value(value)
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
