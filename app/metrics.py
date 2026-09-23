"""In-memory request metrics keyed by route *template*.

Cardinality contract
--------------------
The label set is ``(method, route, status, error_code)``:

* ``route`` is the matched route *template* (e.g. ``/items/{item_id}``),
  never the concrete path, so id-like segments cannot multiply series;
* unmatched paths are normalized to the constant
  :data:`UNMATCHED_ROUTE`;
* ``error_code`` is one of the small fixed set in :mod:`app.errors` (or
  empty for success), never exception text.

Hence the maximum series count is bounded by
``#methods x #registered_templates x #statuses x #error_codes`` regardless
of request volume.

Concurrency
-----------
All updates happen under a single short-lived lock and only touch cheap
integers / fixed-size lists (no allocation per request besides tuple keys),
so recording a request is O(1) and does not noticeably add latency.
"""
from __future__ import annotations

import threading
from dataclasses import dataclass, field

#: synthetic template label for requests that matched no route
UNMATCHED_ROUTE = "__unmatched__"

#: latency histogram bucket upper bounds, milliseconds (last is +Inf)
LATENCY_BUCKETS_MS: tuple[int, ...] = (5, 10, 25, 50, 100, 250, 500, 1000, 2500)


@dataclass
class RouteMetrics:
    route: str
    method: str
    count: int = 0
    error_count: int = 0
    total_seconds: float = 0.0
    status_counts: dict[int, int] = field(default_factory=dict)
    error_code_counts: dict[str, int] = field(default_factory=dict)
    # histogram: one counter per bound plus an +Inf bucket at the end
    buckets: list[int] = field(
        default_factory=lambda: [0] * (len(LATENCY_BUCKETS_MS) + 1)
    )


def _bucket_index(elapsed_ms: float) -> int:
    for i, bound in enumerate(LATENCY_BUCKETS_MS):
        if elapsed_ms <= bound:
            return i
    return len(LATENCY_BUCKETS_MS)  # +Inf bucket


class MetricsRegistry:
    """Thread-safe in-memory counters, one instance per application."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._series: dict[tuple[str, str], RouteMetrics] = {}

    def observe(
        self,
        *,
        route: str,
        method: str,
        status: int,
        error_code: str,
        elapsed: float,
    ) -> None:
        """Record one completed request."""
        key = (method, route)
        with self._lock:
            m = self._series.get(key)
            if m is None:
                m = RouteMetrics(route=route, method=method)
                self._series[key] = m
            m.count += 1
            m.total_seconds += elapsed
            m.status_counts[status] = m.status_counts.get(status, 0) + 1
            if error_code:
                m.error_count += 1
                m.error_code_counts[error_code] = (
                    m.error_code_counts.get(error_code, 0) + 1
                )
            m.buckets[_bucket_index(elapsed * 1000.0)] += 1

    def snapshot(self) -> list[dict]:
        """Return a consistent point-in-time, JSON-serializable view."""
        with self._lock:
            out: list[dict] = []
            for (method, route), m in sorted(self._series.items()):
                count = m.count or 1
                out.append(
                    {
                        "method": method,
                        "route": route,
                        "count": m.count,
                        "error_count": m.error_count,
                        "avg_latency_ms": round(
                            m.total_seconds / count * 1000.0, 3
                        ),
                        "status_counts": dict(sorted(m.status_counts.items())),
                        "error_code_counts": dict(
                            sorted(m.error_code_counts.items())
                        ),
                        "latency_buckets_ms": {
                            **{
                                str(b): n
                                for b, n in zip(LATENCY_BUCKETS_MS, m.buckets)
                            },
                            "+Inf": m.buckets[-1],
                        },
                    }
                )
            return out

    def reset(self) -> None:
        """Drop all series (used by tests)."""
        with self._lock:
            self._series.clear()


#: process-wide singleton used by middleware, routes tests and /metrics
registry = MetricsRegistry()
