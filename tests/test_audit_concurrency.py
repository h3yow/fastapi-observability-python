"""脱敏审计计数：指标口径、基数约束与并发正确性。

断言失败前缀约定：

* ``[串扰]`` —— 一个请求的敏感值出现在另一请求的日志/下游/响应中；
* ``[丢计数]`` —— 并发开通后审计总数少于理论掩码次数；
* ``[基数]`` —— 指标标签出现字段名/路径/请求标识等高基数内容，或标签越界；
* ``[口径]`` —— 三个标签组合、error_category 填充规则与文档口径不符。
"""

from __future__ import annotations

import json
import time
from concurrent.futures import ThreadPoolExecutor

from fastapi.testclient import TestClient

from app.observability import audit
from app.observability.sensitive import (
    CHANNELS,
    ERROR_CATEGORIES,
    FIELD_CATEGORIES,
    SensitiveNode,
)
from tests.conftest import LogCapture
from tests.test_enterprise_onboarding import secret_values, valid_body

AUDIT_METRIC = "sensitive_redactions_total"


def _expected_redactions(body: dict) -> int:
    """依据具体请求体（经模型规范化后）展开数组/可选分支的敏感叶子出现次数。

    null 的可选字段不计（null 不携带敏感信息，与内核口径一致）。
    """
    from app.enterprise.schemas import ONBOARDING_POLICY, EnterpriseOnboardingRequest

    normalized = EnterpriseOnboardingRequest(**body).model_dump()

    def walk(node: SensitiveNode, value: object) -> int:
        if value is None:
            return 0
        if node.items is not None:
            return sum(walk(node.items, item) for item in value) if isinstance(value, list) else 0
        if node.category is not None:
            return 1 if node.category in FIELD_CATEGORIES - {"non_sensitive"} else 0
        if not node.children or not isinstance(value, dict):
            return 0
        from app.observability.sensitive import _lookup  # type: ignore[attr-defined]
        return sum(
            walk(child, item)
            for key, item in value.items()
            if (child := _lookup(node, key)) is not None
        )

    return walk(ONBOARDING_POLICY.root, normalized)


def _log_case(case: str, **fields: object) -> None:
    tail = " ".join(f"{k}={v!r}" for k, v in fields.items())
    print(f"\n[用例] {case} | {tail}")


def _audit_rows(text: str) -> list[dict[str, str]]:
    rows: list[dict[str, str]] = []
    for line in text.splitlines():
        if not line.startswith(AUDIT_METRIC + "{"):
            continue
        labels_part, _, value = line.partition("} ")
        labels: dict[str, str] = {}
        for token in labels_part[len(AUDIT_METRIC) + 1:].split(","):
            key, _, val = token.partition("=")
            labels[key] = val.strip('"')
        labels["_value"] = value
        rows.append(labels)
    return rows


def test_audit_labels_are_low_cardinality_and_well_formed(
    client: TestClient,
) -> None:
    """成功 + 422 各跑一批：审计指标只有三个合法标签，绝不含值/路径/ID。"""
    # 成功请求（log/downstream 通道，error_category 为空）。
    client.post("/enterprise/onboarding", json=valid_body("LCMETRIC1"),
                headers={"X-Request-ID": "audit-lc-0001"})
    # 422 请求（response 通道，error_category 非空）。
    bad = valid_body("LCMETRIC2")
    bad["contacts"][0]["phoneNumber"] = "1"
    client.post("/enterprise/onboarding", json=bad, headers={"X-Request-ID": "audit-lc-0002"})

    text = client.get("/metrics").text
    rows = _audit_rows(text)
    assert rows, "[基数] /metrics 未暴露脱敏审计计数"

    allowed_labels = {"field_category", "channel", "error_category", "_value"}
    allowed_categories = FIELD_CATEGORIES
    allowed_channels = CHANNELS
    allowed_errors = ERROR_CATEGORIES | {""}

    total = 0
    for row in rows:
        assert set(row.keys()) == allowed_labels, f"[基数] 标签结构越界: {set(row.keys())}"
        assert row["field_category"] in allowed_categories, f"[基数] 非法 field_category: {row}"
        assert row["channel"] in allowed_channels, f"[基数] 非法 channel: {row}"
        assert row["error_category"] in allowed_errors, f"[基数] 非法 error_category: {row}"
        total += int(row["_value"])

    # 高基数内容：请求 ID、具体字段路径、原始值都不得进入指标。
    for forbidden in ("audit-lc-0001", "contacts", "mobile", "LCMETRIC", "138"):
        assert forbidden not in text, f"[基数] 指标中混入高基数内容 {forbidden!r}"
    assert total > 0, "[口径] 应有脱敏计数"
    # response 通道必须带 error_category；其余通道 error_category 必须为空。
    for row in rows:
        if row["channel"] == "response":
            assert row["error_category"], f"[口径] 422 掩码必须带错误类别: {row}"
        else:
            assert row["error_category"] == "", f"[口径] 非 response 通道错误类别必须为空: {row}"
    _log_case("审计低基数口径", 指标行数=len(rows), 总掩码数=total)


def test_single_request_audit_count_matches_redacted_fields(client: TestClient) -> None:
    """一份请求的脱敏次数恰好等于其按声明展开的敏感叶子出现次数（跨通道各计一次）。"""
    body = valid_body("COUNT001")
    client.post("/enterprise/onboarding", json=body, headers={"X-Request-ID": "audit-count-1"})
    snap = audit.audit_snapshot()
    expected = _expected_redactions(body)
    by_channel: dict[str, int] = {}
    by_category: dict[str, int] = {}
    for (category, channel, _err), amount in snap.items():
        by_channel[channel] = by_channel.get(channel, 0) + amount
        by_category[category] = by_category.get(category, 0) + amount
    assert by_channel.get("log") == expected, f"[口径] log 计数 {by_channel.get('log')} != {expected}"
    assert by_channel.get("downstream") == expected, (
        f"[口径] downstream 计数 {by_channel.get('downstream')} != {expected}"
    )
    _log_case("单请求计数精确", 期望=expected, 分通道=by_channel, 分类别=by_category)


def test_concurrent_onboarding_audit_is_exact_and_isolated(
    client: TestClient, log_capture: LogCapture
) -> None:
    """并发开通：审计计数不丢；每个请求的敏感值不串到其他请求的任何记录中。"""
    n = 60
    tags = [f"C{i:03d}X" for i in range(n)]
    bodies = {tag: valid_body(tag) for tag in tags}
    expected_per_request = _expected_redactions(next(iter(bodies.values())))
    # 所有 tag 同构（数组长度/可选分支一致），期望次数应相同。
    assert len({_expected_redactions(b) for b in bodies.values()}) == 1

    def call(tag: str) -> tuple[str, int]:
        rid = f"audit-parallel-{tag}"
        r = client.post(
            "/enterprise/onboarding", json=bodies[tag], headers={"X-Request-ID": rid}
        )
        return rid, r.status_code

    start = time.perf_counter()
    with ThreadPoolExecutor(max_workers=16) as pool:
        results = list(pool.map(call, tags))
    elapsed = time.perf_counter() - start
    assert all(status == 200 for _, status in results), "[兼容] 存在开通失败"

    # 1) 计数不丢：每请求在 log/downstream 各掩码 expected_per_request 次。
    snap = audit.audit_snapshot()
    log_total = sum(v for (_, ch, _), v in snap.items() if ch == "log")
    down_total = sum(v for (_, ch, _), v in snap.items() if ch == "downstream")
    assert log_total == n * expected_per_request, (
        f"[丢计数] log 总数 {log_total} != {n}*{expected_per_request}={n * expected_per_request}"
    )
    assert down_total == n * expected_per_request, (
        f"[丢计数] downstream 总数 {down_total} != {n * expected_per_request}"
    )

    # 2) 不串扰：每个请求的敏感值只能出现在（其实是不应出现于）其关联记录之外。
    raw_all = "\n".join(log_capture.raw_lines)
    downstream_bodies = [json.loads(req.content) for req in client.downstream_requests]  # type: ignore[attr-defined]
    for tag in tags:
        for secret in secret_values(bodies[tag]):
            assert secret not in raw_all, f"[串扰] 请求 {tag} 的敏感值 {secret!r} 出现在日志"
            for other_body in downstream_bodies:
                # 该值在任何下游请求体里都必须已掩码（下游体全部脱敏）。
                assert secret not in json.dumps(other_body, ensure_ascii=False), (
                    f"[串扰] 请求 {tag} 的敏感值 {secret!r} 出现在下游请求体"
                )
        # request_id 与其日志严格一一对应，且每条都带正确 profile。
        own = log_capture.records_with(f"audit-parallel-{tag}")
        assert any(r.get("message") == "enterprise onboarding received" for r in own), (
            f"[串扰] 请求 {tag} 缺少自己的受理日志（标识丢失）"
        )
        assert all(r.get("sensitive_profile") in (None, "enterprise_onboarding") for r in own), (
            f"[串扰] 请求 {tag} 的日志出现非本场景 profile"
        )

    # 3) 维度不随请求数增长：标签组合数有上界（类别数 × 通道数 × 错误类别数）。
    text = client.get("/metrics").text
    rows = _audit_rows(text)
    upper_bound = len(FIELD_CATEGORIES) * len(CHANNELS) * (len(ERROR_CATEGORIES) + 1)
    assert len(rows) <= upper_bound, f"[基数] 维度数 {len(rows)} 超过理论上界 {upper_bound}"

    _log_case(
        "并发审计正确且隔离",
        请求数=n, 期望每通道=n * expected_per_request,
        log实际=log_total, downstream实际=down_total,
        审计维度数=len(rows), 维度上界=upper_bound, 耗时秒=round(elapsed, 3),
    )


def test_redaction_overhead_is_small(client: TestClient) -> None:
    """脱敏+审计不应让正常请求明显变慢：串行 30 个开通请求平均耗时设宽松上界。"""
    n = 30
    start = time.perf_counter()
    for i in range(n):
        r = client.post(
            "/enterprise/onboarding",
            json=valid_body(f"PERF{i:03d}"),
            headers={"X-Request-ID": f"perf-{i:04d}"},
        )
        assert r.status_code == 200, r.text
    elapsed = time.perf_counter() - start
    avg_ms = elapsed / n * 1000
    # TestClient + MockTransport 本地链路；100ms 为极宽松上界，仅防数量级退化。
    assert avg_ms < 100, f"[口径] 单请求平均耗时 {avg_ms:.2f}ms，脱敏导致明显变慢"
    _log_case("脱敏性能", 请求数=n, 平均耗时_ms=round(avg_ms, 3), 总耗时_s=round(elapsed, 3))


def test_concurrent_counter_primitive_never_loses() -> None:
    """对计数器原语做高并发压力：多线程自增结果必须精确。"""
    audit.reset_audit()
    threads, per_thread = 16, 500

    def bump() -> None:
        for _ in range(per_thread):
            audit.record_redaction("contact", "log")

    with ThreadPoolExecutor(max_workers=threads) as pool:
        list(pool.map(lambda _: bump(), range(threads)))

    total = audit.audit_total()
    assert total == threads * per_thread, f"[丢计数] 原语计数 {total} != {threads * per_thread}"
    _log_case("计数器原语并发", 线程=threads, 每线程=per_thread, 实际=total)
