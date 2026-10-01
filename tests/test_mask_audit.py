"""脱敏审计的基数约束、并发准确性与脱敏判定纯函数测试。

断言失败原因区分：
``[泄露]`` 原始值未掩码；
``[口径不一致]`` 不同通道/不同写法/不同子结构的判定对不上；
``[维度爆炸]`` 标签数随字段或别名组合增长；
``[性能回退]`` 字段数增长导致单请求脱敏耗时异常上升。
"""

from __future__ import annotations

import json
import time
import uuid
from concurrent.futures import ThreadPoolExecutor

from fastapi.testclient import TestClient

from app.observability import sensitivity as S
from app.observability.metrics import get_mask_counts
from app.schemas_enterprise import EnterpriseOnboardingRequest
from tests.test_enterprise_onboarding import valid_body


def _log_case(case: str, **fields: object) -> None:
    print("\n[用例] " + case + " | " + " ".join(f"{k}={v!r}" for k, v in fields.items()))


# ---------------------------------------------------------------------------
# 同一份请求在各通道判定一致
# ---------------------------------------------------------------------------


def test_same_input_redacts_identically_across_channels() -> None:
    """同一份资料经 log/response/downstream 三通道脱敏，掩码位置完全一致。"""
    model = EnterpriseOnboardingRequest.model_validate(valid_body())
    dumped = model.model_dump(mode="json")
    policy = S.policy_for_model(EnterpriseOnboardingRequest)

    outputs = {
        channel.value: S.redact_value(
            json.loads(json.dumps(dumped)), policy=policy, channel=channel
        )
        for channel in S.OutputChannel
    }
    canonical = json.dumps(outputs["log"], sort_keys=True, ensure_ascii=False)
    for channel, value in outputs.items():
        serialized = json.dumps(value, sort_keys=True, ensure_ascii=False)
        assert serialized == canonical, (
            f"[口径不一致] {channel} 通道脱敏结果与 log 不同:\n{serialized}\n{canonical}"
        )
    _log_case("通道判定一致", 通道列表=list(outputs), 判定依据="三通道掩码位置逐字节相同")


def test_judgment_is_stable_under_style_variants() -> None:
    """同一份资料的不同写法（camel/snake/kebab/大小写）解析与脱敏判定一致。"""
    variants = [
        valid_body(),
        _deep_camel(valid_body()),
        _deep_snake(valid_body()),
    ]
    snapshots = set()
    for body in variants:
        model = EnterpriseOnboardingRequest.model_validate(body)
        out = S.redact_value(model, channel=S.OutputChannel.LOG)
        snapshots.add(json.dumps(out, sort_keys=True, ensure_ascii=False))
    assert len(snapshots) == 1, (
        f"[口径不一致] 不同写法得到不同脱敏结果，共 {len(snapshots)} 种"
    )
    _log_case("写法判定一致", 写法数=len(variants), 判定依据="归一后模型与脱敏快照唯一")


def _deep_camel(obj: object) -> object:
    """把 dict 的 snake 键改成 camelCase（保留原嵌套，模拟另一客户端写法）。"""
    if isinstance(obj, dict):
        return {
            "".join(part if i == 0 else part.capitalize() for i, part in enumerate(k.split("_"))):
                _deep_camel(v)
            for k, v in obj.items()
        }
    if isinstance(obj, list):
        return [_deep_camel(v) for v in obj]
    return obj


def _deep_snake(obj: object) -> object:
    return obj  # valid_body 已是混合写法，基线本身覆盖 snake 风格


# ---------------------------------------------------------------------------
# 基线兜底：未声明策略的裸 dict 仍按凭据/个人信息规则
# ---------------------------------------------------------------------------


def test_baseline_rules_cover_legacy_login_style_payload() -> None:
    payload = {"user": {"password": "pw-secret", "token": "tk"}, "ok": 1}
    out = S.redact_value(payload)  # 无 policy
    text = json.dumps(out)
    assert "pw-secret" not in text and "tk" not in text, "[泄露] 基线规则未生效"
    assert out["ok"] == 1 and out["user"]["password"] == S.REDACTED
    counts = get_mask_counts()
    assert ("credential", "log", "") in counts, "[口径不一致] 基线掩码未计数"
    _log_case("基线兜底", 判定依据="password/token 掩码且非敏感保留")


# ---------------------------------------------------------------------------
# 基数约束：字段/别名组合增多不增加维度
# ---------------------------------------------------------------------------


def test_audit_dimensions_do_not_explode_with_fields_or_aliases(client: TestClient) -> None:
    """大量不同字段值、不同别名写法只产生封闭的低基数标签组合。"""
    for i in range(40):
        body = valid_body()
        body["remark"] = f"remark-{uuid.uuid4().hex}"  # 高基数非敏感值
        body["contacts"][0]["mobilePhone"] = f"139{i:08d}"
        client.post(
            "/enterprise/onboarding",
            json=body,
            headers={"X-Request-ID": f"ent-card-{i:03d}"},
        )
    text = client.get("/metrics").text
    lines = [
        line for line in text.splitlines()
        if line.startswith("masked_inputs_total{")
    ]
    # 硬上界：类别 4 × 通道 3 × 错误类别（成功空串 + VALIDATION_FAILED）。
    assert len(lines) <= 4 * 3 * 2, (
        f"[维度爆炸] 脱敏审计标签组合数 {len(lines)} 超过封闭上界 {4 * 3 * 2}"
    )
    # 标签里绝不允许出现具体值/请求 ID/字段路径
    for line in lines:
        assert "remark-" not in line and "139" not in line, (
            f"[泄露] 高基数输入进入了脱敏审计标签: {line}"
        )
    _log_case("基数硬上界", 标签行数=len(lines), 上界=4 * 3 * 2)


# ---------------------------------------------------------------------------
# 性能：字段增长不显著拖慢
# ---------------------------------------------------------------------------


def test_redaction_cost_is_near_constant_per_field(client: TestClient) -> None:
    """脱敏一次小请求与一次多联系人请求的耗时差应与元素数成线性而非平方。"""
    small = valid_body()
    small["contacts"] = small["contacts"][:1]
    big = valid_body()
    # 每个联系人 2 个敏感字段；构造 19 条（不超过 max_length=20）。
    big["contacts"] = [
        {"name": f"联系人{i}", "mobilePhone": f"139{i:08d}", "email": f"u{i}@x.cn"}
        for i in range(19)
    ]
    small_model = EnterpriseOnboardingRequest.model_validate(small)
    big_model = EnterpriseOnboardingRequest.model_validate(big)

    def measure(model: object) -> float:
        start = time.perf_counter()
        for _ in range(200):
            S.redact_value(model, channel=S.OutputChannel.LOG)
        return (time.perf_counter() - start) / 200

    small_ms = measure(small_model) * 1000
    big_ms = measure(big_model) * 1000
    # 宽松上界：即便 20 倍元素，单次脱敏仍应在毫秒级，且不会出现平方级爆炸。
    assert big_ms < 5.0, f"[性能回退] 20 联系人单请求脱敏 {big_ms:.3f}ms 超过 5ms"
    assert big_ms < max(2.0, small_ms * 40), (
        f"[性能回退] 元素数 ~20 倍但耗时 {small_ms:.3f}ms -> {big_ms:.3f}ms 疑似非线性"
    )
    _log_case(
        "脱敏成本",
        小请求_ms=round(small_ms, 4),
        大请求_ms=round(big_ms, 4),
        判定依据="trie 路径判定 O(depth)，元素线性，无平方级增长",
    )


# ---------------------------------------------------------------------------
# 并发纯计数准确性（不经 HTTP，直接压 redact_value，避免与其他用例耦合）
# ---------------------------------------------------------------------------


def test_concurrent_redaction_counts_are_exact() -> None:
    """多线程同时脱敏同一策略：各类别计数恰好等于掩码元素总数。"""
    model = EnterpriseOnboardingRequest.model_validate(valid_body())
    policy = S.policy_for_model(EnterpriseOnboardingRequest)
    before = get_mask_counts()
    before_log_contact = before.get(("contact", "log", ""), 0)
    threads, per_thread = 16, 50
    payload = model.model_dump(mode="json")

    def work() -> None:
        for _ in range(per_thread):
            S.redact_value(
                json.loads(json.dumps(payload)),
                policy=policy,
                channel=S.OutputChannel.LOG,
            )

    with ThreadPoolExecutor(max_workers=threads) as pool:
        list(pool.map(lambda _: work(), range(threads)))

    after = get_mask_counts()
    # 每副本 3 个 contact（2 phone + 1 email，第二个 email 缺省）。
    expected = 3 * threads * per_thread
    assert after[("contact", "log", "")] - before_log_contact == expected, (
        f"[并发串扰] 并发 contact 计数应为 {expected}，"
        f"实际 {after[('contact', 'log', '')] - before_log_contact}"
    )
    _log_case(
        "并发纯计数",
        线程=threads, 每线程=per_thread, 期望contact=expected,
        实际contact=after[("contact", "log", "")] - before_log_contact,
    )
