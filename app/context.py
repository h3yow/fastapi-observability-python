"""请求关联标识（request_id）的上下文存储与规则定义。

规则（确定性，详见 docs/observability.md）：

* 调用方可通过 ``X-Request-ID`` 请求头传入标识；
* 仅当传入值满足 8~128 字符且全部由 ``[A-Za-z0-9._-]`` 组成时才沿用
  （该字符集同时杜绝换行/空格等日志伪造与响应头注入字符）；
* 不合法（缺失、超长、含非法字符）时一律由服务端生成新标识替换；
* 内部生成标识带 ``req-`` 前缀，便于在日志中区分来源；
* 存储基于 :class:`contextvars.ContextVar`，asyncio 任务/线程之间天然隔离，
  并发请求的标识不会串扰。
"""

from __future__ import annotations

import re
import uuid
from contextvars import ContextVar

#: 合法入站 request_id 的字符集与长度：8~128，字母/数字/点/下划线/连字符。
_REQUEST_ID_PATTERN = re.compile(r"^[A-Za-z0-9._-]{8,128}$")

#: 内部生成 request_id 的固定前缀，用于区分“调用方沿用”与“服务端生成”。
_INTERNAL_PREFIX = "req-"

#: 请求/响应头名称。
REQUEST_ID_HEADER = "x-request-id"

#: 标识来源：inbound=沿用调用方；generated=服务端替换生成。
SOURCE_INBOUND = "inbound"
SOURCE_GENERATED = "generated"

_request_id_var: ContextVar[str | None] = ContextVar("request_id", default=None)


def get_request_id() -> str | None:
    """获取当前上下文的 request_id；不存在时返回 ``None``。"""
    return _request_id_var.get()


def set_request_id(request_id: str | None) -> None:
    """在当前上下文设置 request_id。"""
    _request_id_var.set(request_id)


def reset_request_id() -> None:
    """清除当前上下文的 request_id。"""
    _request_id_var.set(None)


def is_valid_request_id(value: str) -> bool:
    """按确定规则判断调用方传入的 request_id 是否可沿用。

    >>> is_valid_request_id("abc-123_XY.0")
    True
    >>> is_valid_request_id("short")
    False
    >>> is_valid_request_id("id with space")
    False
    >>> is_valid_request_id("id\\n123456")
    False
    """
    return bool(_REQUEST_ID_PATTERN.fullmatch(value))


def new_request_id() -> str:
    """生成新的内部 request_id（``req-`` + uuid4 hex，共 36 字符）。"""
    return f"{_INTERNAL_PREFIX}{uuid.uuid4().hex}"


def resolve_request_id(inbound: str | None) -> tuple[str, str]:
    """按确定规则沿用或替换调用方传入的 request_id。

    :returns: ``(生效标识, 来源)``，来源为
        :data:`SOURCE_INBOUND` 或 :data:`SOURCE_GENERATED`。
    """
    if inbound is not None and is_valid_request_id(inbound):
        return inbound, SOURCE_INBOUND
    return new_request_id(), SOURCE_GENERATED
