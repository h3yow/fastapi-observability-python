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
from app.observability.sensitive import CHANNEL_LOG, RedactedPayload, redact_with_policy

#: 脱敏后替换值（固定值，避免泄露长度等信息）。
REDACTED = "***REDACTED***"

#: 仅用于 HTTP 头脱敏的凭据/个人信息匹配（结构化字段的脱敏统一走
#: app.observability.sensitive，按当前请求绑定的资料声明判定）。
import re

_SENSITIVE_PATTERN = re.compile(
    r"(pass(word|wd)?|secret|token|api[_\-]?key|authorization|credential|"
    r"id[_\-]?card|phone|mobile|email|ssn)",
    re.IGNORECASE,
)

#: 递归深度/每层元素上限由 app.observability.sensitive 的脱敏内核统一约束，
#: 此处不再单独维护，避免两套限额口径漂移。

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
    """判断字段名是否属于敏感字段（仅供 sanitize_headers 等头场景使用）。"""
    if not isinstance(key, str):
        return False
    return bool(_SENSITIVE_PATTERN.search(key))


def redact_value(value: Any) -> Any:
    """对任意值做递归脱敏（兼容既有调用的统一入口薄封装）。

    脱敏判定完全委托 :func:`app.observability.sensitive.redact_with_policy`：

    * 当前请求上下文绑定了资料策略（如企业开通）时，按路径化声明判定，
      同名字段在不同子结构可有不同级别，数组/别名/可选分支均覆盖；
    * 未绑定策略时（如 /login），退化为全局凭据/个人信息模式，
      与本函数历史行为完全一致；
    * 掩码事件按 ``log`` 通道计入脱敏审计，日志通道的 error_category 恒空。

    >>> redact_value({"password": "p@ss", "user": {"token": "t", "id": 1}})
    {'password': '***REDACTED***', 'user': {'token': '***REDACTED***', 'id': 1}}
    >>> redact_value([{"api_key": "k"}, "ok"])
    [{'api_key': '***REDACTED***'}, 'ok']
    """
    return redact_with_policy(
        value, channel=CHANNEL_LOG, error_category="", count=True
    )


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
            # 已经在输出动作处脱敏过的成品载荷：原样记录，不再二次计数。
            if isinstance(value, RedactedPayload):
                payload[key] = value.payload
                continue
            # 同一条 LogRecord 的所有 extra 共享一次审计计数：
            # redact_with_policy 内部 model_dump 会先脱敏一次 Pydantic 模型，
            # 这里再对返回结果脱敏一次（保证容器级兜底），用 record 标记去重，
            # 避免同一敏感值被计两次。
            if getattr(record, "_audit_counted", False):
                payload[key] = redact_with_policy(value, count=False)
            else:
                payload[key] = redact_value(value)
        record._audit_counted = True  # type: ignore[attr-defined]
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
