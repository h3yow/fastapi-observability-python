"""结构化日志、敏感字段脱敏与 request_id 注入。

* 日志以单行 JSON 输出，自动附带当前上下文 ``request_id``；
* 通过 :class:`RequestIdFilter` 注入关联标识，日志方法本身无需传参；
* 所有结构化字段在写入前经 :func:`redact_value` 递归脱敏——该函数委托给
  :mod:`app.observability.sensitivity` 的场景策略（与响应、下游调用记录、
  错误统计共用同一套判定，保证口径一致），并按 ``log`` 通道累加脱敏审计；
  凭据、令牌与个人敏感字段一律替换为 ``***REDACTED***``；
* **每条 LogRecord 只脱敏一次**：extra 脱敏结果缓存在记录上，服务上多挂
  一路日志输出（多个 handler/formatter）或同一条记录被渲染多次都复用同一
  快照，``log`` 通道审计计数因此与输出路数/渲染次数无关；
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
_RESERVED_ATTRS = frozenset(
    {
        "name", "msg", "args", "levelname", "levelno", "pathname", "filename",
        "module", "exc_info", "exc_text", "stack_info", "lineno", "funcName",
        "created", "msecs", "relativeCreated", "thread", "threadName",
        "processName", "process", "taskName", "request_id",
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


#: LogRecord 上缓存“本条记录 extra 脱敏快照”的属性名。
#: 脱敏审计计数只与实际发生的掩码有关：一条日志被多少路 handler 输出、
#: 被 JsonFormatter 渲染多少次，都只做一次递归脱敏、一次计数；后续渲染
#: 直接复用同一快照（快照中已是掩码值，本身也不再含可掩码的原始输入）。
_REDACTED_EXTRAS_ATTR = "_observability_redacted_extras"

#: JsonFormatter 固定输出的基础载荷键（extra 收集时排除，避免重复/覆盖）。
_PAYLOAD_BASE_KEYS = frozenset(
    {"ts", "level", "logger", "message", "request_id"}
)


def _redacted_extras(record: logging.LogRecord) -> dict[str, Any]:
    """返回（必要时首次构建并缓存）本条记录 extra 字段的脱敏快照。

    缓存放于 :class:`logging.LogRecord` 自身而非某个 formatter 实例，
    因此即使在服务上为 ``app`` logger 多挂一路输出（第二个 handler +
    第二个 formatter 实例），同一条记录的脱敏动作与 ``log`` 通道审计
    计数也恰好发生一次，与输出路数、渲染次数无关。
    """
    cached = getattr(record, _REDACTED_EXTRAS_ATTR, None)
    if cached is not None:
        return cached
    snapshot: dict[str, Any] = {}
    for key, value in record.__dict__.items():
        if key in _RESERVED_ATTRS or key in _PAYLOAD_BASE_KEYS or key == _REDACTED_EXTRAS_ATTR:
            continue
        snapshot[key] = redact_value(value)
    # LogRecord 支持任意属性挂载；同一记录在单线程 logging 调用内被各
    # handler 顺序渲染，发布后不再复用，缓存无需加锁。
    setattr(record, _REDACTED_EXTRAS_ATTR, snapshot)
    return snapshot


class JsonFormatter(logging.Formatter):
    """将日志记录渲染为单行 JSON，extra 字段递归脱敏。

    脱敏对每条 :class:`logging.LogRecord` 只执行一次（结果缓存在记录上），
    多个 handler/多次渲染复用同一份快照，审计计数不受输出路数影响。
    """

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
        payload.update(_redacted_extras(record))
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
