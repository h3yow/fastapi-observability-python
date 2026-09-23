"""Metrics semantics, latency buckets and cardinality bound."""
from __future__ import annotations

from fastapi.testclient import TestClient

from app.metrics import LATENCY_BUCKETS_MS, UNMATCHED_ROUTE, registry
from tests.conftest import check


def test_bucket_assignment_is_deterministic():
    cases = [
        (0.001, "5"),
        (0.005, "5"),
        (0.006, "10"),
        (0.025, "25"),
        (0.030, "50"),
        (2.0, "2500"),
        (9.0, "+Inf"),
    ]
    registry.reset()
    for elapsed, expected_bucket in cases:
        registry.observe(route="/r", method="GET", status=200,
                         error_code="", elapsed=elapsed)
    snap = [s for s in registry.snapshot() if s["route"] == "/r"][0]
    buckets = snap["latency_buckets_ms"]
    for elapsed, expected_bucket in cases:
        check(buckets[expected_bucket] >= 1,
              basis=f"{elapsed * 1000:g}ms 必须落入 {expected_bucket}ms 桶（上界包含）",
              input=f"elapsed={elapsed}s", request_id="n/a",
              actual=buckets)
    check(sum(buckets.values()) == len(cases),
          basis="每次观测必须且只落入一个桶，桶计数之和等于请求数",
          input=f"{len(cases)} 次不同耗时观测", request_id="n/a",
          actual=sum(buckets.values()))
    check(len(buckets) == len(LATENCY_BUCKETS_MS) + 1,
          basis="桶数量固定（配置上界数 + 一个 +Inf 桶），不随请求量增长",
          input="桶集合", request_id="n/a", actual=len(buckets))


def test_high_cardinality_paths_do_not_create_series(client: TestClient):
    # 200 distinct concrete paths that all miss routing
    for i in range(200):
        client.get(f"/objects/{i}/sub/{i * 7}",
                   headers={"X-Request-Id": "x" * 32})
    # 200 distinct concrete item ids that all hit ONE template
    for i in range(200):
        client.get(f"/items/{i}", headers={"X-Request-Id": "x" * 32})
    metrics = client.get("/metrics").json()["metrics"]
    routes = {(s["method"], s["route"]) for s in metrics}
    unmatched = [s for s in metrics if s["route"] == UNMATCHED_ROUTE]
    items = [s for s in metrics if s["route"] == "/items/{item_id}"]

    check(len(unmatched) == 1 and unmatched[0]["count"] == 200,
          basis="200 个不同未匹配路径必须全部并入单个 __unmatched__ 序列",
          input="GET /objects/{i}/sub/{i*7} x200", request_id="x" * 32,
          actual=[(s["route"], s["count"]) for s in unmatched])
    check(len(items) == 1 and items[0]["count"] == 200,
          basis="200 个不同 id 必须全部聚合到同一个路由模板序列",
          input="GET /items/{i} x200", request_id="x" * 32,
          actual=[(s["route"], s["count"]) for s in items])
    expected = {("GET", UNMATCHED_ROUTE), ("GET", "/items/{item_id}")}
    check(routes == expected,
          basis="指标标签只能是已注册模板或 __unmatched__，不得出现具体路径段/具体 id",
          input="全部序列标签", request_id="x" * 32, actual=sorted(routes))


def test_metrics_consistent_across_all_outcomes(client: TestClient):
    client.get("/", headers={"X-Request-Id": "r" * 32})
    client.get("/items/bad", headers={"X-Request-Id": "r" * 32})
    client.get("/missing-route", headers={"X-Request-Id": "r" * 32})
    client.get("/boom", headers={"X-Request-Id": "r" * 32})
    metrics = {s["route"]: s for s in client.get("/metrics").json()["metrics"]}

    expectations = {
        "/": ("200", 1, 0, None),
        "/items/{item_id}": ("422", 1, 1, "VALIDATION_ERROR"),
        UNMATCHED_ROUTE: ("404", 1, 1, "NOT_FOUND"),
        "/boom": ("500", 1, 1, "INTERNAL_ERROR"),
    }
    for route, (status, count, errors, code) in expectations.items():
        s = metrics[route]
        check(s["count"] == count and s["error_count"] == errors
              and s["status_counts"].get(status) == count,
              basis=f"无论成功/校验失败/未匹配/内部异常，{route} 都必须走同一指标口径",
              input=f"route={route}", request_id="r" * 32,
              actual={"count": s["count"], "error_count": s["error_count"],
                      "status_counts": s["status_counts"]})
        if code:
            check(s["error_code_counts"].get(code) == 1,
                  basis=f"{route} 的错误分类必须是稳定码 {code}",
                  input=f"route={route}", request_id="r" * 32,
                  actual=s["error_code_counts"])
        check(s["avg_latency_ms"] >= 0,
              basis="平均耗时字段在所有结果类型下都必须可计算且非负",
              input=f"route={route}", request_id="r" * 32,
              actual=s["avg_latency_ms"])
