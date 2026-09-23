"""指标口径与基数约束测试。

覆盖：正常响应 / 参数校验失败 / 未匹配路由 / 内部异常四类结果
必须走同一套标签口径；高基数实体 ID 不得进入维度；错误响应码与
指标 error_code 必须一致。
"""

from __future__ import annotations

import re

from fastapi.testclient import TestClient

METRIC_LINE = re.compile(r'http_requests_total\{(.*)\} (\d+)$')
LABEL_RE = re.compile(r'(\w+)="((?:[^"\\]|\\.)*)"')


def _parse_counter_lines(text: str) -> list[dict[str, object]]:
    rows: list[dict[str, object]] = []
    for line in text.splitlines():
        m = METRIC_LINE.fullmatch(line)
        if not m:
            continue
        labels = dict(LABEL_RE.findall(m.group(1)))
        labels["value"] = int(m.group(2))
        rows.append(labels)
    return rows


def _find(rows: list[dict[str, object]], **labels: object) -> dict[str, object] | None:
    for row in rows:
        if all(row.get(k) == v for k, v in labels.items()):
            return row
    return None


def _log_case(case: str, **fields: object) -> None:
    print(f"\n[用例] {case} | " + " ".join(f"{k}={v!r}" for k, v in fields.items()))


def test_four_outcomes_share_same_label_taxonomy(client: TestClient) -> None:
    """成功/422/404/500 四类结果的指标行标签结构完全一致、口径正确。"""
    client.get("/users/1", headers={"X-Request-ID": "m-success-001"})
    client.post("/login", json={"username": "x"}, headers={"X-Request-ID": "m-422-0001"})
    client.get("/high/cardinality/path/99887766", headers={"X-Request-ID": "m-404-0001"})
    client.get("/boom?kind=x", headers={"X-Request-ID": "m-500-0001"})

    text = client.get("/metrics").text
    rows = _parse_counter_lines(text)

    expected_keys = {"method", "route", "status", "outcome", "error_code", "value"}
    assert rows, "metrics 中没有任何计数器行"
    for row in rows:
        assert set(row.keys()) == expected_keys, f"标签结构不一致: {set(row.keys())}"

    success = _find(rows, method="GET", route="/users/{user_id}", status="200",
                    outcome="success", error_code="")
    assert success and success["value"] == 1, f"成功口径行缺失或错误: {success}"

    validation = _find(rows, method="POST", route="/login", status="422",
                       outcome="client_error", error_code="VALIDATION_FAILED")
    assert validation and validation["value"] == 1, f"校验失败口径行错误: {validation}"

    unmatched = _find(rows, route="__unmatched__", status="404",
                      outcome="client_error", error_code="ROUTE_NOT_FOUND")
    assert unmatched and unmatched["value"] == 1, f"未匹配路由口径行错误: {unmatched}"

    internal = _find(rows, route="/boom", status="500",
                     outcome="server_error", error_code="INTERNAL_ERROR")
    assert internal and internal["value"] == 1, (
        f"内部异常口径行错误（error_code 必须与对外错误码一致）: {internal}"
    )
    _log_case(
        "四类结果同口径",
        成功=success, 校验失败=validation, 未匹配=unmatched, 内部异常=internal,
        判定依据="五行标签键完全相同，status/outcome/error_code 与响应一致",
    )


def test_high_cardinality_paths_do_not_explode_dimensions(client: TestClient) -> None:
    """大量不同实体 ID 只产生一个路由模板维度；未匹配路径只产生一个兜底维度。"""
    for i in range(30):
        client.get(f"/users/{1000 + i}", headers={"X-Request-ID": f"m-user-{i:02d}"})
    for i in range(15):
        client.get(f"/random/deep/path/{i}/detail")

    text = client.get("/metrics").text
    rows = _parse_counter_lines(text)
    routes = {row["route"] for row in rows}
    assert "/users/{user_id}" in routes, f"路由模板维度缺失: {routes}"
    raw_user_paths = {r for r in routes if re.fullmatch(r"/users/\d+", str(r))}
    assert not raw_user_paths, f"真实实体 ID 进入指标维度: {raw_user_paths}"
    unmatched_rows = [r for r in rows if r["route"] == "__unmatched__"]
    assert unmatched_rows, "未匹配路由缺少兜底维度"
    assert all(r["status"] == "404" for r in unmatched_rows)
    total_unmatched = sum(int(r["value"]) for r in unmatched_rows)
    assert total_unmatched == 15, f"15 个未匹配路径应聚合为 15 次计数，实际 {total_unmatched}"

    user_row = _find(rows, route="/users/{user_id}", status="200", error_code="")
    assert user_row and user_row["value"] == 30, f"30 个实体请求应聚合到 30: {user_row}"
    _log_case(
        "基数约束",
        实体请求=30, 未匹配请求=15,
        维度数=len(routes),
        判定依据="30 个不同 ID -> 单模板计数 30；15 条随机路径 -> __unmatched__ 计数 15",
    )


def test_histogram_and_counter_are_consistent(client: TestClient) -> None:
    """直方图 count 与同标签计数器总量一致，桶边界单调非降。"""
    for _ in range(10):
        client.get("/", headers={"X-Request-ID": "m-hist-0001"})

    text = client.get("/metrics").text
    count_line = next(
        line for line in text.splitlines()
        if line.startswith("http_request_duration_seconds_count{")
        and 'route="/"' in line and 'method="GET"'
    )
    assert count_line.endswith(" 10"), f"直方图 count 应为 10: {count_line}"

    bucket_values = [
        int(line.rsplit(" ", 1)[1])
        for line in text.splitlines()
        if line.startswith("http_request_duration_seconds_bucket{")
        and 'route="/"' in line and 'method="GET"'
    ]
    assert bucket_values == sorted(bucket_values), f"直方图桶不单调: {bucket_values}"
    assert bucket_values[-1] == 10, "+Inf 桶应等于总样本数"
    _log_case("直方图口径", 样本数=10, 桶序列=bucket_values, 判定依据="count==10 且桶计数单调非降、+Inf==10")


def test_metrics_collection_is_thread_safe(client: TestClient) -> None:
    """并发采集不丢计数。"""
    from concurrent.futures import ThreadPoolExecutor

    def hit(i: int) -> None:
        client.get(f"/users/{i}", headers={"X-Request-ID": f"m-parallel-{i:03d}"})

    with ThreadPoolExecutor(max_workers=16) as pool:
        list(pool.map(hit, range(200)))

    text = client.get("/metrics").text
    rows = _parse_counter_lines(text)
    row = _find(rows, route="/users/{user_id}", status="200", error_code="")
    assert row and row["value"] == 200, f"并发计数丢失，期望 200 实际 {row and row['value']}"
    _log_case("并发采集正确性", 请求数=200, 实际计数=row["value"], 判定依据="线程并发后模板维度计数恰好 200")
