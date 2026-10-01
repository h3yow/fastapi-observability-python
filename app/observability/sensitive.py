"""路径化敏感字段声明、统一脱敏与校验错误清洗。

设计目标（企业实名开通等“资料型场景”复用既有可观测性能力，而非另起一套）：

* **敏感范围随资料声明同步生效**：每个资料场景（profile）提供一棵
  :class:`SensitiveNode` 声明树，与 Pydantic 模型同处维护；新增资料版本时
  只需在模型与声明中同步加字段，脱敏、错误响应、日志、下游记录自动生效，
  无需修改任何公共配置；
* **同一字段名在不同子结构中可有不同敏感级别**：判定依据“声明路径”而非
  裸字段名（如联系人 ``name`` 是个人姓名，附件 ``name`` 只是文件名）；
* **写法归一**：大小写、下划线/连字符/空格、camelCase 等同一字段的常见
  写法经 :func:`normalize_key` 归一后匹配，语义别名在声明中显式登记；
* **数组穿透**：声明为数组的节点对每个元素套用同一份子声明，不会漏条目；
* **各处口径一致**：日志、422 响应、下游调用记录都调用同一个
  :func:`redact_with_policy`，并通过 ContextVar 绑定当前请求的资料策略；
* **声明外字段安全兜底**：未登记的嵌套字段仍按全局凭据/个人信息模式掩码
  （与既有 ``/login`` 的全局规则完全一致），其余输入保留以便前端提示；
* **低基数审计**：掩码事件只产出“字段类别/通道/错误类别”计数（见
  :mod:`app.observability.audit`），不记录任何原始值或具体字段路径。
"""

from __future__ import annotations

import re
from collections.abc import Mapping
from contextvars import ContextVar
from typing import Any, NamedTuple

from app.observability import audit

#: 脱敏固定掩码（与 logging.REDACTED 同一口径、固定长度，避免泄露长度信息）。
REDACTED = "***REDACTED***"

# ---------------------------------------------------------------------------
# 字段类别（有限枚举 —— 审计指标 field_category 标签的唯一合法取值）
# ---------------------------------------------------------------------------
CAT_CREDENTIAL = "credential"  # 密码/密钥/令牌/凭据
CAT_ID_NUMBER = "id_number"    # 身份证号、SSN 等法定证件号
CAT_CONTACT = "contact"        # 手机号、电话、邮箱等联系方式
CAT_FINANCE = "finance"        # 银行账号等财务信息
CAT_NAME = "name"              # 个人姓名
CAT_BUSINESS = "business"      # 企业内部业务标识（默认按内部数据处理）
CAT_NON_SENSITIVE = "non_sensitive"  # 显式声明“非敏感”：登记但保留、不计数
CAT_UNKNOWN = "unknown"        # 仅全局模式命中但无法归入上述类别

#: 全部合法字段类别（声明与审计归一以此为准，新增类别必须在此登记）。
FIELD_CATEGORIES = frozenset(
    {
        CAT_CREDENTIAL,
        CAT_ID_NUMBER,
        CAT_CONTACT,
        CAT_FINANCE,
        CAT_NAME,
        CAT_BUSINESS,
        CAT_NON_SENSITIVE,
        CAT_UNKNOWN,
    }
)

#: 参与脱敏审计的类别：``non_sensitive`` 表示“显式确认不敏感”，
#: 其值保留且不产生任何审计计数；其余类别均代表敏感掩码。
SENSITIVE_CATEGORIES = FIELD_CATEGORIES - {CAT_NON_SENSITIVE}

# ---------------------------------------------------------------------------
# 错误类别（稳定、低基数 —— 只描述失败“规则”，绝不描述输入值）
# ---------------------------------------------------------------------------
ERR_MISSING = "missing"      # 必填缺失
ERR_TYPE = "type_error"      # 类型不匹配/无法解析
ERR_VALUE = "value_rule"     # 取值规则（枚举/字面值/自定义 value_error）
ERR_FORMAT = "format"        # 格式/正则不匹配
ERR_TOO_SHORT = "too_short"  # 短于下限
ERR_TOO_LONG = "too_long"    # 长于上限
ERR_OTHER = "other"          # 其余规则的稳定兜底

ERROR_CATEGORIES = frozenset(
    {ERR_MISSING, ERR_TYPE, ERR_VALUE, ERR_FORMAT, ERR_TOO_SHORT, ERR_TOO_LONG, ERR_OTHER}
)

#: 输出通道（敏感值在何处被掩码 —— 审计指标 channel 标签的唯一合法取值）。
CHANNEL_LOG = "log"
CHANNEL_RESPONSE = "response"
CHANNEL_DOWNSTREAM = "downstream"
CHANNELS = frozenset({CHANNEL_LOG, CHANNEL_RESPONSE, CHANNEL_DOWNSTREAM})

#: 递归深度与每层元素上限（防止异常数据拖垮日志采集；正常资料远小于此）。
_MAX_DEPTH = 10
_MAX_ITEMS = 200

#: 递归时出现“声明外字段”的全局兜底模式（与历史 /login 口径一致）。
#: 归一化后键名已无分隔符，这里仍兼容可选分隔符写法。
_GLOBAL_RULES: tuple[tuple[re.Pattern[str], str], ...] = (
    (
        re.compile(r"(pass(word|wd)?|secret|token|api[_\-]?key|authorization|credential)", re.IGNORECASE),
        CAT_CREDENTIAL,
    ),
    (re.compile(r"id[_\-]?card|ssn", re.IGNORECASE), CAT_ID_NUMBER),
    (re.compile(r"phone|mobile|email", re.IGNORECASE), CAT_CONTACT),
)

#: camelCase 边界（用于把 legalRepName 拆成 legal rep name）。
_CAMEL_BOUNDARY_1 = re.compile(r"(.)([A-Z][a-z]+)")
_CAMEL_BOUNDARY_2 = re.compile(r"([a-z0-9])([A-Z])")
_SEPARATORS = re.compile(r"[\s_\-]+")


def normalize_key(key: str) -> str:
    """把字段名的各种常见写法归一为可比较的规范形式。

    规则：先按 camelCase 拆词，再去除大小写差异与 ``_``/``-``/空格分隔符。
    因此 ``idCard``、``id_card``、``ID-Card``、``id-card``、``IDCARD``
    全部归一成同一个键；语义不同的别名（如 ``repName``）需在声明中显式登记。

    >>> normalize_key("legalRepName") == normalize_key("legal_rep_name")
    True
    >>> normalize_key("ID-Card") == normalize_key("idcard")
    True
    """
    if not isinstance(key, str):
        return ""
    spaced = _CAMEL_BOUNDARY_1.sub(r"\1_\2", key)
    spaced = _CAMEL_BOUNDARY_2.sub(r"\1_\2", spaced)
    return _SEPARATORS.sub("", spaced).lower()


def _global_category(normalized_key: str) -> str | None:
    """声明外字段的全局兜底判定：命中凭据/个人信息模式时返回类别。"""
    for pattern, category in _GLOBAL_RULES:
        if pattern.search(normalized_key):
            return category
    return None


class SensitiveNode(NamedTuple):
    """敏感声明树节点。

    三种形态互斥：

    * **叶子**：``category`` 非空 —— 整个值掩码；
    * **对象**：``children`` 非空 —— 按键递归。children 的键保留**原始规范
      字段名**（作为对外 loc），匹配时经 :data:`index` 按归一化键查找；
      ``aliases`` 登记语义别名（原始名 -> 同一子节点）；
    * **数组**：``items`` 非空 —— 对列表每个元素套用 ``items`` 子声明。
    """

    category: str | None = None
    children: Mapping[str, "SensitiveNode"] | None = None
    items: "SensitiveNode | None" = None
    aliases: Mapping[str, "SensitiveNode"] | None = None
    #: 归一化键 -> 子节点（含 children 与别名，仅用于匹配，不对外暴露）。
    index: Mapping[str, "SensitiveNode"] | None = None
    #: 归一化键 -> 原始规范字段名（用于把请求写法还原成稳定 loc）。
    canonical_names: Mapping[str, str] | None = None


class SensitivePolicy(NamedTuple):
    """一份资料场景（profile）的完整敏感声明。"""

    name: str
    root: SensitiveNode


class RedactedPayload:
    """已经完成脱敏、可安全输出/记录的成品载荷。

    用途：同一份数据在“输出动作发生处”（如下游边界）脱敏并计数后，可能还要
    进入结构化日志。用本类包装后，日志层直接原样序列化、**不再二次计数**，
    保证每个输出通道对一份原始数据的一次呈现只产生一次掩码计数。
    """

    __slots__ = ("payload", "channel")

    def __init__(self, payload: Any, channel: str) -> None:
        self.payload = payload
        self.channel = channel


def leaf(category: str) -> SensitiveNode:
    """声明一个敏感叶子字段；类别非法时在导入期立即失败（fail-fast）。"""
    if category not in FIELD_CATEGORIES:
        raise ValueError(f"未知敏感字段类别: {category!r}")
    return SensitiveNode(category=category)


def plain() -> SensitiveNode:
    """声明一个**显式非敏感**叶子：值保留、不掩码、不计入脱敏审计。

    用于让“新增资料字段时必须显式决策敏感级别”可被静态检查：
    非敏感也要显式登记，而不是静默落入默认。
    """
    return SensitiveNode(category=CAT_NON_SENSITIVE)


def group(fields: Mapping[str, SensitiveNode]) -> SensitiveNode:
    """声明一个对象节点。

    :param fields: 键规格 -> 子节点。键规格形如 ``"canonical|别名1|别名2"``，
        首个名字为规范字段名（原样作为对外 loc），其余为语义别名；
        大小写/下划线/连字符/camelCase 等写法无需列出，归一化匹配自动覆盖。
    """
    children: dict[str, SensitiveNode] = {}
    raw_aliases: dict[str, SensitiveNode] = {}
    index: dict[str, SensitiveNode] = {}
    canonical_names: dict[str, str] = {}
    for key_spec, child in fields.items():
        parts = [p.strip() for p in key_spec.split("|") if p.strip()]
        if not parts:
            raise ValueError(f"非法字段声明键: {key_spec!r}")
        canonical = parts[0]
        children[canonical] = child
        # 规范名自身及其各种写法。
        index[normalize_key(canonical)] = child
        canonical_names[normalize_key(canonical)] = canonical
        for extra in parts[1:]:
            raw_aliases[extra] = child
            normalized_extra = normalize_key(extra)
            index[normalized_extra] = child
            # 别名归一后映射回规范字段名（不覆盖已登记的规范名）。
            canonical_names.setdefault(normalized_extra, canonical)
    return SensitiveNode(
        children=children,
        aliases=raw_aliases or None,
        index=index,
        canonical_names=canonical_names,
    )


def many(item: SensitiveNode) -> SensitiveNode:
    """声明一个数组节点：列表中每条资料都按 ``item`` 子声明判定。"""
    return SensitiveNode(items=item)


def build_policy(name: str, root: SensitiveNode) -> SensitivePolicy:
    """构造命名资料策略（当前仅做装配，结构在声明时已归一）。"""
    if not name:
        raise ValueError("资料策略名不能为空")
    return SensitivePolicy(name=name, root=root)


def _lookup(node: SensitiveNode | None, raw_key: Any) -> SensitiveNode | None:
    """在对象节点中按归一化键名/别名查找子声明；节点缺失时返回 None。"""
    if node is None or node.index is None or not isinstance(raw_key, str):
        return None
    return node.index.get(normalize_key(raw_key))


def _canonical_key(node: SensitiveNode | None, raw_key: str) -> str:
    """把请求写法的字段名还原为声明中的规范字段名（数组下标不在此处处理）。

    未登记/节点缺失时原样返回。
    """
    if node is None or node.canonical_names is None or not isinstance(raw_key, str):
        return raw_key
    return node.canonical_names.get(normalize_key(raw_key), raw_key)


def _subtree_has_sensitive(node: SensitiveNode | None) -> bool:
    """子树内是否存在任何敏感叶子（显式 non_sensitive 不计）。"""
    if node is None:
        return False
    if node.category is not None:
        return node.category in SENSITIVE_CATEGORIES
    if node.items is not None:
        return _subtree_has_sensitive(node.items)
    if node.children:
        return any(_subtree_has_sensitive(child) for child in node.children.values())
        # aliases 指向同一子节点对象，无需重复遍历。
    return False


def _first_category(node: SensitiveNode | None) -> str:
    """取子树内第一个敏感叶子类别（结构型错误无法精确定位时的保守归类）。"""
    if node is None:
        return CAT_UNKNOWN
    if node.category is not None:
        return node.category if node.category in SENSITIVE_CATEGORIES else CAT_UNKNOWN
    if node.items is not None:
        return _first_category(node.items)
    if node.children:
        for child in node.children.values():
            category = _first_category(child)
            if category != CAT_UNKNOWN:
                return category
    return CAT_UNKNOWN


# ---------------------------------------------------------------------------
# 当前请求的资料策略（ContextVar：asyncio 任务间天然隔离，并发不串扰）
# ---------------------------------------------------------------------------
_policy_var: ContextVar[SensitivePolicy | None] = ContextVar("sensitive_policy", default=None)


def get_active_policy() -> SensitivePolicy | None:
    """获取当前上下文生效的资料策略；未设置返回 None（走全局兜底规则）。"""
    return _policy_var.get()


def set_active_policy(policy: SensitivePolicy | None) -> object:
    """设置当前上下文的资料策略，返回 token 供 :func:`reset_active_policy` 恢复。"""
    return _policy_var.set(policy)


def reset_active_policy(token: object) -> None:
    """恢复资料策略到 set 之前的状态。"""
    _policy_var.reset(token)  # type: ignore[arg-type]


# (字段类别, 错误类别) -> 本批次掩码次数；每棵值树仅一次加锁刷新。
_Events = dict[tuple[str, str], int]


def _add_event(events: _Events | None, category: str, error_category: str, amount: int = 1) -> None:
    if events is not None and amount > 0:
        key = (category, error_category)
        events[key] = events.get(key, 0) + amount


def _flush_events(events: _Events, channel: str) -> None:
    for (category, error_category), amount in events.items():
        audit.record_redaction(category, channel, error_category=error_category, amount=amount)


def _normalize_channel(channel: str) -> str:
    return channel if channel in CHANNELS else "unknown"


def _normalize_error_category(error_category: str) -> str:
    if not error_category:
        return ""
    return error_category if error_category in ERROR_CATEGORIES else ERR_OTHER


def _redact(
    value: Any,
    node: SensitiveNode | None,
    *,
    depth: int,
    events: _Events | None,
    error_category: str,
) -> Any:
    """递归脱敏内核。

    ``node is None`` 表示当前位置没有声明（根上无策略，或走到了声明外字段）：
    退化为“仅全局凭据/个人信息模式”判定 —— 与历史 redact_value 行为一致。
    """
    if depth >= _MAX_DEPTH:
        return REDACTED

    # 已经脱敏过的成品载荷：原样返回，不重复掩码/计数。
    if isinstance(value, RedactedPayload):
        return value.payload

    # Pydantic 模型：按字段名展开（声明键即 Python 字段名）。
    if hasattr(value, "model_dump") and callable(value.model_dump):
        try:
            return _redact(value.model_dump(), node, depth=depth + 1,
                           events=events, error_category=error_category)
        except Exception:
            return "<unserializable>"

    if isinstance(value, Mapping):
        result: dict[Any, Any] = {}
        for i, (key, item) in enumerate(value.items()):
            if i >= _MAX_ITEMS:
                result["...truncated"] = True
                break
            child = _lookup(node, key)
            if child is None:
                # 声明外（或无策略）：全局模式判定当前键，子树继续仅走全局规则。
                category = _global_category(normalize_key(key)) if isinstance(key, str) else None
                if category is not None:
                    result[key] = REDACTED
                    _add_event(events, category, error_category)
                else:
                    result[key] = _redact(item, None, depth=depth + 1,
                                          events=events, error_category=error_category)
                continue
            if child.category is not None:
                if child.category == CAT_NON_SENSITIVE:
                    # 显式非敏感：值原样保留、不掩码、不计数。
                    result[key] = item
                elif item is None:
                    # 可选字段缺省为 null：不含敏感信息，原样保留且不计数。
                    result[key] = None
                else:
                    result[key] = REDACTED
                    _add_event(events, child.category, error_category)
            elif child.items is not None:
                result[key] = _redact_sequence(item, child.items, depth + 1, events, error_category)
            else:
                result[key] = _redact(item, child, depth=depth + 1,
                                      events=events, error_category=error_category)
        return result

    if isinstance(value, list | tuple | set | frozenset):
        # 值锚定在数组声明节点上（如 scrub 按 loc 锚定 list 输入）：
        # 先解包到元素声明；裸序列出现在对象节点上时元素按当前节点继续判定。
        item_node = node.items if node is not None and node.items is not None else node
        return _redact_sequence(value, item_node, depth, events, error_category)

    # 标量落在叶子声明上（含“数组元素是标量叶子”，如 ["138..."]）。
    if node is not None and node.category is not None:
        if node.category == CAT_NON_SENSITIVE or value is None:
            return value
        _add_event(events, node.category, error_category)
        return REDACTED

    return value


def _redact_sequence(
    seq: Any,
    item_node: SensitiveNode | None,
    depth: int,
    events: _Events | None,
    error_category: str,
) -> Any:
    """按数组子声明处理序列的每个元素；元素为对象时按 item 子树递归。"""
    if depth >= _MAX_DEPTH:
        return REDACTED
    if isinstance(seq, list | tuple | set | frozenset):
        items = list(seq)[:_MAX_ITEMS]
        redacted = [
            _redact(item, item_node, depth=depth + 1, events=events,
                    error_category=error_category)
            for item in items
        ]
        if isinstance(seq, tuple):
            return tuple(redacted)
        if isinstance(seq, set | frozenset):
            return set(redacted)
        return redacted
    # 非序列标量出现在数组声明位置（多为非法输入）：按元素声明直接判定。
    return _redact(seq, item_node, depth=depth, events=events,
                   error_category=error_category)


def redact_with_policy(
    value: Any,
    *,
    policy: SensitivePolicy | None = None,
    channel: str = CHANNEL_LOG,
    error_category: str = "",
    count: bool = False,
    node: SensitiveNode | None = None,
) -> Any:
    """按资料声明递归脱敏；各处（日志/响应/下游）共用的唯一入口。

    :param value: 任意值（dict/list/Pydantic 模型/标量）。
    :param policy: 显式资料策略；默认取当前 ContextVar 绑定的策略；
        两者都为空时退化为全局凭据规则（既有 /login 行为保持不变）。
    :param channel: 输出通道，见 ``CHANNEL_*``；仅在 ``count=True`` 时计入审计。
    :param error_category: 若脱敏发生在 422 清洗中，传稳定错误类别；
        正常请求日志传空串。
    :param count: 是否同时累加脱敏审计计数。
    :param node: 内部/测试用：把声明根锚定到某个子节点（如按 loc 清洗输入）。
    """
    effective_policy = policy if policy is not None else get_active_policy()
    root_node = node if node is not None else (
        effective_policy.root if effective_policy is not None else None
    )
    safe_channel = _normalize_channel(channel)
    safe_error = _normalize_error_category(error_category)
    events: _Events = {} if count else None
    try:
        return _redact(
            value, root_node, depth=0, events=events, error_category=safe_error
        )
    finally:
        if events:
            _flush_events(events, safe_channel)


# ---------------------------------------------------------------------------
# pydantic 校验错误 -> 稳定错误类别 / 安全明细
# ---------------------------------------------------------------------------
def classify_error(error: Mapping[str, Any]) -> str:
    """把 pydantic v2 错误的 ``type`` 映射为稳定错误类别。

    类别只描述“失败的是哪条规则”，与任何输入内容无关，可安全进入响应/指标。
    """
    error_type = str(error.get("type", ""))
    if error_type == "missing":
        return ERR_MISSING
    if "parsing" in error_type or error_type.endswith("_type"):
        # json_invalid/list_type/dict_type/string_type 等一切解析/类型失败。
        return ERR_TYPE
    if error_type in {"string_too_short", "too_short"}:
        return ERR_TOO_SHORT
    if error_type in {"string_too_long", "too_long"}:
        return ERR_TOO_LONG
    if "pattern" in error_type:
        return ERR_FORMAT
    if error_type.startswith("value_error") or error_type in {"enum", "literal_error", "const"}:
        return ERR_VALUE
    return ERR_OTHER


#: 敏感字段校验失败时的对外通用文案（不含输入值）。
_GENERIC_MESSAGES = {
    ERR_MISSING: "This field is required.",
    ERR_TYPE: "Invalid value type for this field.",
    ERR_VALUE: "Value is not allowed for this field.",
    ERR_FORMAT: "Value format is invalid.",
    ERR_TOO_SHORT: "Value is shorter than the allowed minimum.",
    ERR_TOO_LONG: "Value is longer than the allowed maximum.",
    ERR_OTHER: "Value is invalid for this field.",
}


def _walk_loc(root: SensitiveNode | None, loc: Any) -> tuple[SensitiveNode | None, list[Any]]:
    """按错误 loc（去掉首个 "body"）走声明树。

    :returns: ``(字段节点, 规范化 loc)``。字段名段还原为声明规范名，
        数组下标（int）原样保留，使前端拿到稳定可定位的路径；
        未登记字段段原样保留。
    """
    segments = list(loc or ())
    if segments and segments[0] == "body":
        segments = segments[1:]
    node = root
    canonical: list[Any] = []
    for segment in segments:
        if isinstance(segment, int):
            canonical.append(segment)
            node = node.items if node is not None else None
            continue
        if node is None:
            canonical.append(segment)
            continue
        canonical.append(_canonical_key(node, str(segment)))
        node = _lookup(node, str(segment))
    return node, canonical


def _last_string_segment(loc: Any) -> str:
    for segment in reversed(list(loc or ())):
        if isinstance(segment, str) and segment != "body":
            return normalize_key(segment)
    return ""


def _safe_ctx(ctx: Any) -> dict[str, Any] | None:
    """保留规则参数（min_length/pattern 等），剔除可能内嵌原始值的 error 对象。"""
    if not isinstance(ctx, Mapping):
        return None
    safe: dict[str, Any] = {}
    for key, item in ctx.items():
        if key == "error":
            continue
        safe[str(key)] = redact_with_policy(item, count=False)  # 规则参数不计数
    return safe or None


def scrub_validation_errors(
    errors: list[dict[str, Any]],
    *,
    policy: SensitivePolicy | None = None,
) -> list[dict[str, Any]]:
    """清洗 pydantic 校验错误明细，供 422 响应与日志**共用同一份结果**。

    保留：``loc``（可定位字段路径，数组下标原样保留）、``type``（失败规则）、
    新增 ``error_category``（稳定错误类别）；非敏感字段保留 ``input`` 便于
    前端提示；敏感字段的输入值一律掩码并计入 response 通道审计；
    ``ctx`` 仅保留规则参数；``url`` 与自定义异常对象一律剔除。

    同一请求的 422 响应与内部日志都取自本函数的返回值，保证两处判定一致。
    """
    effective_policy = policy if policy is not None else get_active_policy()
    root = effective_policy.root if effective_policy is not None else None
    scrubbed: list[dict[str, Any]] = []

    for error in errors:
        error_category = classify_error(error)
        raw_loc = list(error.get("loc", ()))
        node, canonical_segments = _walk_loc(root, raw_loc)
        # 对外 loc 始终带 "body" 前缀，字段名段为规范名、数组下标原样。
        loc = ["body", *canonical_segments] if canonical_segments else list(raw_loc)
        raw_input = error.get("input", None)
        raw_type = str(error.get("type", ""))

        detail: dict[str, Any] = {
            "type": raw_type,
            "loc": loc,
            "error_category": error_category,
        }

        # 缺失错误：pydantic v2 的 input 是整个父对象（可能含兄弟敏感字段），
        # 一律不回显输入，只保留定位与规则。
        if error_category == ERR_MISSING:
            detail["msg"] = _GENERIC_MESSAGES[ERR_MISSING]
            scrubbed.append(detail)
            continue

        # 1) 精确命中叶子字段：敏感类别掩码；显式 non_sensitive 保留输入。
        sensitive_category: str | None = (
            node.category
            if node is not None and node.category in SENSITIVE_CATEGORIES
            else None
        )
        # 2) 声明外字段：退回全局模式按字段名判定。
        if node is None:
            sensitive_category = _global_category(_last_string_segment(loc))
        # 3) 结构型错误（对象/数组节点收到非容器标量，无法判断输入意图）：
        #    若其子树含敏感字段则保守掩码（如 contacts 错传成一个手机号串）。
        is_scalar = not isinstance(raw_input, (Mapping, list, tuple, set, frozenset))
        structural_sensitive = (
            node is not None and node.category is None
            and is_scalar and raw_input is not None
            and _subtree_has_sensitive(node)
        )

        if sensitive_category is not None:
            detail["msg"] = _GENERIC_MESSAGES[error_category]
            detail["input"] = REDACTED
            audit.record_redaction(sensitive_category, CHANNEL_RESPONSE,
                                   error_category=error_category, amount=1)
        elif structural_sensitive:
            category = _first_category(node)
            detail["msg"] = _GENERIC_MESSAGES[error_category]
            detail["input"] = REDACTED
            audit.record_redaction(category, CHANNEL_RESPONSE,
                                   error_category=error_category, amount=1)
        else:
            # 非敏感字段：保留输入（可能是 dict/列表），但仍按声明子树清洗，
            # 防止“非敏感容器里嵌着敏感字段”时随 input 回显泄露。
            if "input" in error:
                detail["input"] = redact_with_policy(
                    raw_input, policy=effective_policy, channel=CHANNEL_RESPONSE,
                    error_category=error_category, count=True, node=node,
                )
            # value_error 文案可能内嵌任意原始值，统一替换为通用文案。
            if raw_type.startswith("value_error"):
                detail["msg"] = _GENERIC_MESSAGES[ERR_VALUE]
            else:
                detail["msg"] = str(error.get("msg", ""))

        safe_ctx = _safe_ctx(error.get("ctx"))
        if safe_ctx is not None:
            detail["ctx"] = safe_ctx
        scrubbed.append(detail)

    return scrubbed
