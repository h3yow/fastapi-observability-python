"""按路由模板聚合的请求指标（线程安全、Prometheus 文本格式）。

口径说明（详见 docs/observability.md）：

* 维度仅保留低基数标签：``method``（白名单归一）、``route``（路由模板，
  未匹配路由统一为 :data:`UNMATCHED_ROUTE`）、``status``、``outcome``
  （success/client_error/server_error）、``error_code``（有限错误码集合，
  成功为空）；
* 正常响应、参数校验失败、未匹配路由、内部异常都经过同一个
  :func:`observe_request`，口径完全一致；
* 采集结构为进程内计数器 + 直方图桶，锁粒度小且仅保护 dict 自增，
  不进行 I/O，对请求路径的额外开销为常数级。
"""

from __future__ import annotations

import threading

#: 未匹配路由的统一模板名，防止真实路径（含 ID/查询串）造成维度失控。
UNMATCHED_ROUTE = "__unmatched__"

#: HTTP 方法白名单；白名单外的方法归一为 OTHER（方法名本身由调用方控制）。
_METHODS = frozenset(
    {"GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS", "TRACE", "CONNECT"}
)

#: Prometheus 默认秒级直方图桶，覆盖 5ms ~ 10s。
_BUCKETS = (0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0)

_COUNTER_NAME = "http_requests_total"
_HIST_NAME = "http_request_duration_seconds"

_lock = threading.Lock()
# (method, route, status, outcome, error_code) -> 累计次数
_counters: dict[tuple[str, str, int, str, str], int] = {}
# (method, route, outcome, error_code) -> {"buckets": [c...], "sum": float, "count": int}
_histograms: dict[tuple[str, str, str, str], dict[str, object]] = {}

#: 脱敏审计计数：(字段类别, 输出通道, 错误类别) -> 掩码次数。
#: 三个标签全部取自封闭枚举/有限错误码集合，且不含字段名、路径或取值，
#: 因此维度数有硬上界（类别数 × 通道数 × 错误码数），不会随资料字段增长。
_MASK_COUNTER_NAME = "masked_inputs_total"
_mask_counters: dict[tuple[str, str, str], int] = {}


def _normalize_method(method: str | None) -> str:
    upper = (method or "").upper()
    return upper if upper in _METHODS else "OTHER"


def _outcome_for_status(status_code: int) -> str:
    if 200 <= status_code < 400:
        return "success"
    if 400 <= status_code < 500:
        return "client_error"
    return "server_error"


def observe_request(
    method: str,
    route_template: str,
    status_code: int,
    duration_s: float,
    error_code: str = "",
) -> None:
    """记录一次请求：累加计数器并落入直方图桶。

    :param method: HTTP 方法（自动大写并按白名单归一）。
    :param route_template: 路由模板，如 ``/users/{user_id}``；
        未匹配路由必须传 :data:`UNMATCHED_ROUTE`，禁止传真实路径。
    :param status_code: 最终响应状态码（含异常处理器转换后的码）。
    :param duration_s: 入口中间件测得的处理耗时（秒）。
    :param error_code: 对外错误码；成功响应传空串。
    """
    method = _normalize_method(method)
    outcome = _outcome_for_status(status_code)
    count_key = (method, route_template, int(status_code), outcome, error_code)
    hist_key = (method, route_template, outcome, error_code)

    with _lock:
        _counters[count_key] = _counters.get(count_key, 0) + 1
        hist = _histograms.get(hist_key)
        if hist is None:
            hist = {"buckets": [0] * (len(_BUCKETS) + 1), "sum": 0.0, "count": 0}
            _histograms[hist_key] = hist
        buckets = hist["buckets"]
        assert isinstance(buckets, list)
        for i, bound in enumerate(_BUCKETS):
            if duration_s <= bound:
                buckets[i] += 1
        buckets[-1] += 1  # +Inf
        hist["sum"] = float(hist["sum"]) + duration_s  # type: ignore[arg-type]
        hist["count"] = int(hist["count"]) + 1  # type: ignore[arg-type]


def observe_mask(
    field_category: str,
    output_channel: str,
    error_code: str = "",
    *,
    count: int = 1,
) -> None:
    """记录敏感输入被掩码的次数（脱敏审计）。

    :param field_category: 字段类别（必须来自封闭枚举，如 ``contact``）。
    :param output_channel: 输出通道（封闭枚举：log/response/downstream）。
    :param error_code: 关联的对外错误码；非错误路径传空串。维度仍为
        有限错误码枚举，调用方不得传入任意字符串。
    :param count: 本次累加次数（数组逐条掩码时一次提交，临界区更短）。

    临界区仅一次 dict 自增，无 I/O；标签不含原始值或字段路径。
    """
    key = (field_category, output_channel, error_code)
    with _lock:
        _mask_counters[key] = _mask_counters.get(key, 0) + count


def get_mask_counts() -> dict[tuple[str, str, str], int]:
    """返回脱敏审计计数快照（测试断言用；只暴露低基数维度与计数）。"""
    with _lock:
        return dict(_mask_counters)


def _escape_label(value: str) -> str:
    return value.replace("\\", "\\\\").replace("\n", "\\n").replace('"', '\\"')


def _labels(**kwargs: str) -> str:
    return "{" + ",".join(f'{k}="{_escape_label(v)}"' for k, v in kwargs.items()) + "}"


def render_prometheus() -> str:
    """渲染 Prometheus 文本暴露格式（确定性排序，便于比对）。"""
    with _lock:
        counter_items = sorted(_counters.items())
        hist_items = sorted(_histograms.items())
        mask_items = sorted(_mask_counters.items())

    lines: list[str] = []
    lines.append(f"# HELP {_COUNTER_NAME} Total HTTP requests by method/route/status/outcome/error_code.")
    lines.append(f"# TYPE {_COUNTER_NAME} counter")
    for (method, route, status, outcome, error_code), value in counter_items:
        labels = _labels(
            method=method, route=route, status=str(status),
            outcome=outcome, error_code=error_code,
        )
        lines.append(f"{_COUNTER_NAME}{labels} {value}")

    lines.append(f"# HELP {_HIST_NAME} HTTP request latency in seconds.")
    lines.append(f"# TYPE {_HIST_NAME} histogram")
    for (method, route, outcome, error_code), hist in hist_items:
        base_labels = {"method": method, "route": route,
                       "outcome": outcome, "error_code": error_code}
        buckets = hist["buckets"]
        assert isinstance(buckets, list)
        for i, bound in enumerate(_BUCKETS):
            labels = _labels(le=str(bound), **base_labels)
            lines.append(f'{_HIST_NAME}_bucket{labels} {buckets[i]}')
        labels = _labels(le="+Inf", **base_labels)
        lines.append(f'{_HIST_NAME}_bucket{labels} {buckets[-1]}')
        labels = _labels(**base_labels)
        lines.append(f'{_HIST_NAME}_sum{labels} {hist["sum"]:.6f}')
        lines.append(f'{_HIST_NAME}_count{labels} {hist["count"]}')

    lines.append(
        f"# HELP {_MASK_COUNTER_NAME} Total masked sensitive inputs by "
        f"field_category/output_channel/error_code (no values, no field paths)."
    )
    lines.append(f"# TYPE {_MASK_COUNTER_NAME} counter")
    for (field_category, output_channel, error_code), value in mask_items:
        labels = _labels(
            field_category=field_category,
            output_channel=output_channel,
            error_code=error_code,
        )
        lines.append(f"{_MASK_COUNTER_NAME}{labels} {value}")
    return "\n".join(lines) + "\n"


def reset_metrics() -> None:
    """清空全部指标（测试隔离用）。"""
    with _lock:
        _counters.clear()
        _histograms.clear()
        _mask_counters.clear()
