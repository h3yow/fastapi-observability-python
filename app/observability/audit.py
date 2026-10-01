"""脱敏审计计数：按低基数维度统计敏感输入被掩码的次数。

口径（详见 docs/observability.md）：

* 唯一指标 :data:`AUDIT_COUNTER_NAME`（Counter），一次“敏感值被掩码”累加 1；
* 标签只有三个，全部来自**有限枚举**，与字段数量、别名数量、请求数量无关：

  - ``field_category``：字段类别（credential/id_number/contact/finance/...）；
  - ``channel``：掩码发生的输出通道（log/response/downstream）；
  - ``error_category``：仅当掩码发生在 422 校验错误清洗时为稳定错误类别，
    正常请求日志/下游场景为空串。

* 绝不记录原始值、具体字段路径或请求标识——这些都是高基数且可能二次泄密；
* 单棵值树的掩码先在本地批量汇总，再以**一次加锁**刷新（锁只保护 dict
  自增，无 I/O），字段/别名组合增多只会让树更大，不会新增维度，
  也不会明显拖慢正常请求；
* :func:`record_redaction` 对未知标签值一律归一到 ``unknown``/``other``，
  防止任何调用笔误造成维度爆炸。
"""

from __future__ import annotations

import threading

# 注意：本模块不得 import app.observability.sensitive（后者在脱敏时调用本模块，
# 会形成循环导入）。标签枚举在此自持，取值与 sensitive.* 常量保持一致。

#: 合法字段类别（与 sensitive.FIELD_CATEGORIES 同口径；non_sensitive 不会计数，
#: 列入仅为保持枚举一致）。
_FIELD_CATEGORIES = frozenset(
    {"credential", "id_number", "contact", "finance", "name", "business",
     "non_sensitive", "unknown"}
)
#: 合法输出通道（与 sensitive.CHANNELS 同口径）。
_CHANNELS = frozenset({"log", "response", "downstream"})
#: 合法错误类别（与 sensitive.ERROR_CATEGORIES 同口径）。
_ERROR_CATEGORIES = frozenset(
    {"missing", "type_error", "value_rule", "format", "too_short", "too_long", "other"}
)

#: 审计指标名（Prometheus 文本暴露）。
AUDIT_COUNTER_NAME = "sensitive_redactions_total"

_lock = threading.Lock()
# (field_category, channel, error_category) -> 累计掩码次数
_counts: dict[tuple[str, str, str], int] = {}


def _normalize_field_category(category: str) -> str:
    return category if category in _FIELD_CATEGORIES else "unknown"


def _normalize_channel(channel: str) -> str:
    return channel if channel in _CHANNELS else "unknown"


def _normalize_error_category(error_category: str) -> str:
    if not error_category:
        return ""
    return error_category if error_category in _ERROR_CATEGORIES else "other"


def record_redaction(
    field_category: str,
    channel: str,
    *,
    error_category: str = "",
    amount: int = 1,
) -> None:
    """记录一次或一批脱敏计数。

    三个标签值都按有限枚举归一；``amount`` 用于一棵值树的批量刷新，
    保证 N 次掩码只加一次锁（并发下不丢、不串扰）。
    """
    if amount <= 0:
        return
    key = (
        _normalize_field_category(field_category),
        _normalize_channel(channel),
        _normalize_error_category(error_category),
    )
    with _lock:
        _counts[key] = _counts.get(key, 0) + amount


def audit_snapshot() -> dict[tuple[str, str, str], int]:
    """返回当前计数的副本（测试断言用；不暴露任何请求级细节）。"""
    with _lock:
        return dict(_counts)


def audit_total() -> int:
    """返回脱敏总次数（测试快速断言用）。"""
    with _lock:
        return sum(_counts.values())


def _escape_label(value: str) -> str:
    return value.replace("\\", "\\\\").replace("\n", "\\n").replace('"', '\\"')


def render_audit_prometheus() -> str:
    """渲染脱敏审计 Counter 的 Prometheus 文本（按字典序，输出确定可比对）。"""
    with _lock:
        items = sorted(_counts.items())
    lines = [
        f"# HELP {AUDIT_COUNTER_NAME} Total sensitive value redactions by "
        "field_category/channel/error_category (no raw values or field paths).",
        f"# TYPE {AUDIT_COUNTER_NAME} counter",
    ]
    for (field_category, channel, error_category), value in items:
        labels = (
            "{"
            f'field_category="{_escape_label(field_category)}",'
            f'channel="{_escape_label(channel)}",'
            f'error_category="{_escape_label(error_category)}"'
            "}"
        )
        lines.append(f"{AUDIT_COUNTER_NAME}{labels} {value}")
    return "\n".join(lines) + "\n"


def reset_audit() -> None:
    """清空审计计数（测试隔离用）。"""
    with _lock:
        _counts.clear()


__all__ = [
    "AUDIT_COUNTER_NAME",
    "record_redaction",
    "audit_snapshot",
    "audit_total",
    "render_audit_prometheus",
    "reset_audit",
]
