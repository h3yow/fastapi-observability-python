"""并发 request_id 隔离与全链路传播测试。

每个用例的日志（通过 print 与 -s 可见）均打印：
输入、观察到的关联标识、判定依据；断言失败消息也给出可区分原因。
"""

from __future__ import annotations

import uuid
from concurrent.futures import ThreadPoolExecutor

from fastapi.testclient import TestClient

from tests.conftest import LogCapture


def _log_case(case: str, **fields: object) -> None:
    parts = " ".join(f"{k}={v!r}" for k, v in fields.items())
    print(f"\n[用例] {case} | {parts} | 判定: 见断言消息")


def test_concurrent_request_ids_are_isolated(client: TestClient) -> None:
    """并发请求各自携带唯一入站 ID：响应与响应体不得串扰或丢失。"""
    n = 50
    inputs = [f"concurrent-{i}-{uuid.uuid4().hex}" for i in range(n)]

    def call(rid: str) -> tuple[str, str, str]:
        r = client.get("/", headers={"X-Request-ID": rid})
        return rid, r.headers["x-request-id"], r.json()["request_id"]

    with ThreadPoolExecutor(max_workers=16) as pool:
        results = list(pool.map(call, inputs))

    seen_response_ids = set()
    for inbound, header_id, body_id in results:
        assert header_id == inbound, (
            f"串扰/替换异常: 入站={inbound!r} 响应头={header_id!r}（合法入站 ID 必须原样沿用）"
        )
        assert body_id == inbound, (
            f"响应体标识与入站不一致: 入站={inbound!r} 响应体={body_id!r}"
        )
        seen_response_ids.add(header_id)

    assert len(seen_response_ids) == n, (
        f"并发标识串扰：{n} 个唯一入站 ID 只观察到 {len(seen_response_ids)} 个不同响应 ID"
    )
    _log_case("并发隔离", 请求数=n, 唯一响应ID数=len(seen_response_ids), 判定依据="响应头/体 == 入站且全局唯一")


def test_concurrent_generated_ids_are_unique_when_absent(client: TestClient) -> None:
    """并发且不传 ID：服务端生成的 ID 必须全部唯一且带 req- 前缀。"""
    n = 50

    def call(_: int) -> str:
        return client.get("/").headers["x-request-id"]

    with ThreadPoolExecutor(max_workers=16) as pool:
        ids = list(pool.map(call, range(n)))

    assert all(rid.startswith("req-") for rid in ids), (
        f"存在非内部前缀的生成 ID: {[rid for rid in ids if not rid.startswith('req-')][:3]}"
    )
    assert len(set(ids)) == n, f"生成 ID 出现碰撞：{n} 次请求仅 {len(set(ids))} 个唯一 ID"
    _log_case("并发生成", 请求数=n, 唯一ID数=len(set(ids)), 判定依据="均带 req- 前缀且互不相同")


def test_inbound_id_acceptance_and_replacement_rules(client: TestClient) -> None:
    """入站 ID 沿用/替换规则：合法沿用；非法字符、过短、超长一律替换。"""
    cases = [
        ("abc-123_XY.0", True, "合法字符集且长度合规"),
        ("12345678", True, "恰好 8 字符边界"),
        ("x" * 128, True, "恰好 128 字符边界"),
        ("short", False, "短于 8 字符"),
        ("x" * 129, False, "长于 128 字符"),
        ("id with space", False, "含空格（同时可造成日志伪造）"),
        ("id\n123456", False, "含换行（CRLF 注入风险）"),
        ("bad/id!!", False, "含非法字符 / 与 !"),
        ("", False, "空字符串"),
    ]
    for inbound, expect_kept, why in cases:
        r = client.get("/", headers={"X-Request-ID": inbound})
        effective = r.headers["x-request-id"]
        if expect_kept:
            assert effective == inbound, f"[{why}] 应沿用入站 ID，但被替换为 {effective!r}"
        else:
            assert effective != inbound and effective.startswith("req-"), (
                f"[{why}] 非法入站 ID 必须替换为 req- 前缀新 ID，实际={effective!r}"
            )
        _log_case("沿用/替换", 输入=inbound[:20], 期望沿用=expect_kept, 生效ID=effective[:20], 判定依据=why)


def test_request_id_consistent_in_logs_across_concurrency(
    client: TestClient, log_capture: LogCapture
) -> None:
    """并发请求的访问日志每条都带自己的 request_id，互不串扰。"""
    n = 30
    inputs = [f"log-{i}-{uuid.uuid4().hex}" for i in range(n)]

    with ThreadPoolExecutor(max_workers=16) as pool:
        list(pool.map(lambda rid: client.get("/users/1", headers={"X-Request-ID": rid}), inputs))

    for rid in inputs:
        matched = log_capture.records_with(rid)
        assert matched, f"request_id={rid!r} 在并发日志中缺失（标识丢失）"
        assert any(rec.get("message") == "request completed" for rec in matched), (
            f"request_id={rid!r} 缺少完成日志"
        )
        # 该 ID 的日志不得带上别的请求路径（串扰检测）
        assert all(rec.get("route") == "/users/{user_id}" for rec in matched if "route" in rec), (
            f"request_id={rid!r} 的日志混入了其他路由记录，存在串扰"
        )
    _log_case("并发日志关联", 请求数=n, 判定依据="每个入站 ID 都能且只能检索到本请求的完成日志")


def test_background_task_uses_same_request_id(
    client: TestClient, log_capture: LogCapture
) -> None:
    """后台任务（线程池执行）的日志必须携带与请求相同的 request_id。"""
    rid = "bg-task-id-0001"
    r = client.get("/bg?note=audit-me", headers={"X-Request-ID": rid})
    assert r.status_code == 200, f"后台调度接口异常: {r.status_code} {r.text}"
    assert r.json()["request_id"] == rid, "响应体 request_id 与入站不一致"

    # TestClient 退出 with 前后台任务已执行；直接从捕获记录中找。
    audit = [
        rec for rec in log_capture.records
        if rec.get("message") == "audit note written"
    ]
    assert audit, "未观察到后台任务日志，后台任务可能未执行"
    assert any(rec.get("request_id") == rid and rec.get("seen_request_id") == rid for rec in audit), (
        f"后台任务 request_id 与请求不一致: {[(rec.get('request_id'), rec.get('seen_request_id')) for rec in audit]}"
    )
    _log_case("后台任务传播", 入站ID=rid, 判定依据="线程池后台日志 request_id 与 seen_request_id 均等于入站 ID")


def test_downstream_call_propagates_request_id(client: TestClient) -> None:
    """下游调用必须通过 X-Request-ID 透传当前请求标识。"""
    rid = "down-stream-id-001"
    r = client.get(
        "/downstream?url=https://downstream/ok",
        headers={"X-Request-ID": rid},
    )
    assert r.status_code == 200, f"下游接口异常: {r.status_code} {r.text}"
    assert r.json()["request_id"] == rid, "响应体 request_id 与入站不一致"

    seen = client.downstream_requests  # type: ignore[attr-defined]
    assert seen and seen[-1].headers.get("x-request-id") == rid, (
        f"下游未收到正确 X-Request-ID，实际={seen[-1].headers.get('x-request-id')!r}"
    )
    _log_case("下游透传", 入站ID=rid, 下游收到=seen[-1].headers.get("x-request-id"), 判定依据="下游请求头 == 入站 ID")


def test_error_response_echoes_effective_request_id(client: TestClient) -> None:
    """异常与校验失败响应都必须回带生效 request_id，便于调用方关联排查。"""
    rid = "error-path-id-99"
    r = client.get("/boom?kind=other", headers={"X-Request-ID": rid})
    assert r.status_code == 500
    assert r.headers["x-request-id"] == rid, "500 响应头丢失 request_id"
    assert r.json()["error"]["request_id"] == rid, "500 响应体错误结构中 request_id 不一致"

    r2 = client.post("/login", json={}, headers={"X-Request-ID": rid})
    assert r2.status_code == 422
    assert r2.json()["error"]["request_id"] == rid, "422 响应体错误结构中 request_id 不一致"
    _log_case("异常响应关联", 入站ID=rid, 判定依据="500/422 响应头与错误体均回带同一 ID")
