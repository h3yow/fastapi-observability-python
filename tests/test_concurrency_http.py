"""End-to-end correlation-id isolation under concurrent HTTP traffic.

Drives many requests with unique caller-supplied ids through the real
ASGI stack (including background tasks and in-process downstream calls)
and asserts that every observable artifact of a request carries exactly
that request's own id — never another concurrent request's.
"""
from __future__ import annotations

import threading
from collections import Counter

from fastapi.testclient import TestClient

from main import app
from app.routes import background_observations
from tests.conftest import check

N_WORKERS = 12
REQUESTS_PER_WORKER = 8


def _run_concurrently(headers_by_index: list[dict]) -> list[tuple[int, object]]:
    results: list[tuple[int, object]] = []
    lock = threading.Lock()

    def worker(start: int) -> None:
        # each worker gets its own portal/client; they all share the app
        with TestClient(app, raise_server_exceptions=False) as client:
            local: list[tuple[int, object]] = []
            for i in range(start, start + REQUESTS_PER_WORKER):
                rid = f"rid-conc-{i:04d}"
                kind = i % 4
                if kind == 0:
                    r = client.get("/", headers={"X-Request-Id": rid})
                    payload = r.json()
                    local.append((i, (r.status_code,
                                      r.headers.get("x-request-id"),
                                      payload.get("request_id"))))
                elif kind == 1:
                    r = client.get(f"/background/key-{i:04d}",
                                   headers={"X-Request-Id": rid})
                    local.append((i, (r.status_code,
                                      r.headers.get("x-request-id"),
                                      r.json().get("request_id"))))
                elif kind == 2:
                    r = client.get("/downstream",
                                   headers={"X-Request-Id": rid})
                    payload = r.json()
                    local.append((i, (r.status_code,
                                      r.headers.get("x-request-id"),
                                      payload.get("request_id"),
                                      payload.get("upstream_request_id"))))
                else:
                    r = client.get("/boom",
                                   headers={"X-Request-Id": rid})
                    payload = r.json()
                    local.append((i, (r.status_code,
                                      r.headers.get("x-request-id"),
                                      payload["error"].get("request_id"),
                                      payload["error"].get("code"))))
            with lock:
                results.extend(local)

    threads = [
        threading.Thread(target=worker, args=(w * REQUESTS_PER_WORKER,))
        for w in range(N_WORKERS)
    ]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    return results


def test_concurrent_requests_never_share_or_lose_ids():
    total = N_WORKERS * REQUESTS_PER_WORKER
    results = _run_concurrently([])
    check(len(results) == total,
          basis=f"并发 {N_WORKERS} 线程 x {REQUESTS_PER_WORKER} 请求必须全部返回，无丢失",
          input=f"{total} 并发请求", request_id="many",
          actual=len(results))

    failures: list[str] = []
    status_counter: Counter[int] = Counter()
    for i, observed in results:
        rid = f"rid-conc-{i:04d}"
        status, header_id, *ids = observed
        status_counter[status] += 1
        if header_id != rid:
            failures.append(f"i={i} 响应头 {header_id!r} != {rid!r}")
        for j, observed_id in enumerate(ids):
            # last slot of the /boom tuple is the error code, not an id
            if observed_id == "INTERNAL_ERROR":
                continue
            if observed_id != rid:
                failures.append(f"i={i} 位置{j} {observed_id!r} != {rid!r}")

    check(not failures,
          basis="每个请求的响应头、正文（含下游回传标识）必须只携带自己的 X-Request-Id；"
                "并发请求之间不得串扰或丢失",
          input=f"{total} 个并发请求（成功/后台/下游/异常混合）",
          request_id="rid-conc-*",
          actual=failures[:5] if failures else "全部一致")

    check(status_counter[200] == total * 3 // 4
          and status_counter[500] == total // 4,
          basis="混合流量的状态码分布必须与构造的请求类型数量吻合",
          input=f"{total} 个并发请求", request_id="many",
          actual=dict(status_counter))


def test_background_tasks_observed_the_originating_request_id():
    _run_concurrently([])
    failures = [
        f"{key}:{observed}"
        for i in range(N_WORKERS * REQUESTS_PER_WORKER)
        if i % 4 == 1
        for key, observed in [(f"key-{i:04d}",
                               background_observations.get(f"key-{i:04d}"))]
        if observed != f"rid-conc-{i:04d}"
    ]
    expected_bg = N_WORKERS * REQUESTS_PER_WORKER // 4
    check(len(background_observations) == expected_bg and not failures,
          basis="后台任务在请求返回后执行时仍必须读到发起请求的关联标识，且无跨请求覆盖",
          input=f"{expected_bg} 个并发后台任务",
          request_id="rid-conc-*",
          actual=(len(background_observations), failures[:5]))


def test_concurrent_metrics_counts_are_exact(client):
    """Single endpoint hit from many threads at once; counts must match."""
    repeats = 200

    def worker() -> None:
        with TestClient(app) as c:
            for k in range(repeats // 10):
                c.get("/items/1", headers={"X-Request-Id": "x" * 32})

    threads = [threading.Thread(target=worker) for _ in range(10)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    series = [
        s for s in client.get("/metrics").json()["metrics"]
        if s["route"] == "/items/{item_id}"
    ][0]
    check(series["count"] == repeats and series["error_count"] == 0,
          basis="并发下指标计数必须精确（锁保护），不多不少",
          input=f"10 线程共 {repeats} 次 GET /items/1",
          request_id="x" * 32,
          actual=(series["count"], series["error_count"]))
