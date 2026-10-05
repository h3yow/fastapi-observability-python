"""场景化敏感字段策略、上下文感知脱敏与脱敏审计计数。

设计目标（企业实名开通场景在现有能力上的扩展，不另起一套）：

* **资料声明与敏感范围同源**：每个资料场景（:class:`SensitivityPolicy`）
  与对应 Pydantic 模型绑定后，自动从字段元数据内省“字段名 / alias /
  validation_alias / AliasChoices”等所有可接受写法与数组层级；新增资料
  版本只需随模型声明 ``mark(...)``，无需再人工改动公共正则配置；
* **路径感知**：同一字段名在不同子结构中可以有不同敏感级别
  （如 ``legal_representative.name`` 敏感，``contacts[].name`` 非敏感），
  判定依据是完整路径而不是裸键名；数组逐元素遍历，不漏任何一条；
* **写法归一**：大小写、下划线、连字符通过 :func:`normalize_key` 统一折叠；
* **基线兜底**：未声明场景（如 /login）继续沿用凭据/个人信息基线规则；
* **判定一致**：日志、响应、下游调用记录共用本模块同一套判定；
* **脱敏审计**：每次掩码仅按封闭低基数维度
  （字段类别 × 输出通道 × 错误类别）累加计数，绝不记录原始值或字段路径。
"""

from __future__ import annotations

import re
from collections.abc import Mapping, Sequence as AbcSequence
from enum import Enum
from typing import Any, get_args, get_origin

from pydantic import AliasChoices, AliasPath, BaseModel

from app.observability.codes import CODE_VALIDATION
from app.observability.metrics import observe_mask

#: 脱敏替换值（固定值，不保留长度信息）。
REDACTED = "***REDACTED***"

#: 递归深度与每层元素上限（与日志采集上限一致，防止异常数据拖垮处理）。
_MAX_DEPTH = 6
_MAX_ITEMS = 100

# ---------------------------------------------------------------------------
# 低基数封闭维度
# ---------------------------------------------------------------------------


class FieldCategory(str, Enum):
    """敏感字段类别：脱敏审计标签，取值集合封闭、有硬上界。"""

    CREDENTIAL = "credential"
    ID_DOCUMENT = "id_document"
    CONTACT = "contact"
    FINANCIAL = "financial"


class OutputChannel(str, Enum):
    """敏感值可能被掩码后写入的输出通道（封闭枚举）。"""

    LOG = "log"
    RESPONSE = "response"
    DOWNSTREAM = "downstream"


class PreRedacted:
    """已经按策略脱敏并完成审计计数的载荷包装器。

    用于“在写日志前就必须脱敏”的场景（如下游调用记录需要显式传入场景
    策略）。:class:`~app.observability.logging.JsonFormatter` 遇到包装器时
    直接取其快照，不再二次脱敏、二次计数，保证同一份输入在同一个输出事件里
    只掩码、只计数一次。
    """

    __slots__ = ("payload",)

    def __init__(self, payload: Any) -> None:
        self.payload = payload


# ---------------------------------------------------------------------------
# 基线规则（未声明场景的兜底；与既有 /login 等行为完全兼容）
# ---------------------------------------------------------------------------

_BASELINE_CREDENTIAL = re.compile(
    r"(pass(?:word|wd)?|secret|token|api[_\-]?key|authorization|credential)",
    re.IGNORECASE,
)
_BASELINE_ID_DOCUMENT = re.compile(r"(id[_\-]?card|ssn)", re.IGNORECASE)
_BASELINE_CONTACT = re.compile(r"(phone|mobile|email)", re.IGNORECASE)


def _baseline_category(key: Any) -> FieldCategory | None:
    """按既有基线正则判断裸键名类别；非敏感返回 None。"""
    if not isinstance(key, str):
        return None
    if _BASELINE_CREDENTIAL.search(key):
        return FieldCategory.CREDENTIAL
    if _BASELINE_ID_DOCUMENT.search(key):
        return FieldCategory.ID_DOCUMENT
    if _BASELINE_CONTACT.search(key):
        return FieldCategory.CONTACT
    return None


def normalize_key(name: Any) -> str:
    """字段名归一：转小写并删除下划线/连字符。

    因此 ``certNumber`` / ``cert_number`` / ``cert-number`` / ``CERTNUMBER``
    折叠为同一个标识 ``certnumber``，按同一规则识别。非字符串返回空串。

    >>> normalize_key("Cert-Number") == normalize_key("cert_number") == "certnumber"
    True
    """
    if not isinstance(name, str):
        return ""
    return name.lower().replace("_", "").replace("-", "")


# ---------------------------------------------------------------------------
# 路径 trie
# ---------------------------------------------------------------------------


class _Node:
    """trie 节点：children 以归一后的“所有可接受写法”为边标签。

    同一子结构通过多条边到达同一子节点（字段名 + 各种别名归一后均指向它）；
    ``array_edges`` 标记某条边是“对象数组”，数组每个元素都按该子结构遍历。

    ``subtree_category`` 在编译期计算：本子树（含自身）任一敏感类别的确定性
    代表（自身类别优先，否则按 :class:`FieldCategory` 定义顺序取最近后代）。
    用于“填错位置”场景——客户端把单值直接填在对象/数组位置（如联系人位置
    填一串手机号）时，该值按子树敏感类别整体掩码，与正常嵌套同口径。
    """

    __slots__ = ("children", "category", "subtree_category")

    def __init__(self) -> None:
        self.children: dict[str, _Edge] = {}
        self.category: FieldCategory | None = None
        self.subtree_category: FieldCategory | None = None


class _Edge:
    __slots__ = ("node", "is_array")

    def __init__(self, node: "_Node", is_array: bool) -> None:
        self.node = node
        self.is_array = is_array


# ---------------------------------------------------------------------------
# 模型内省
# ---------------------------------------------------------------------------


def _alias_names(field: Any) -> set[str]:
    """收集一个 pydantic 字段所有可接受的输入写法（原始形式）。"""
    names: set[str] = set()
    for candidate in (
        field.alias,
        field.serialization_alias,
        field.validation_alias,
    ):
        if isinstance(candidate, str):
            names.add(candidate)
        elif isinstance(candidate, AliasChoices):
            for choice in candidate.choices:
                if isinstance(choice, str):
                    names.add(choice)
                elif isinstance(choice, AliasPath):
                    # AliasPath 由路径片段组成；取其中字符串片段拼写作兼容。
                    joined = "-".join(str(p) for p in choice.path if isinstance(p, str))
                    if joined:
                        names.add(joined)
    return names


def _analyze_annotation(annotation: Any) -> tuple[list[type[BaseModel]], bool]:
    """分析字段注解，返回 (引用到的模型类们, 是否模型/对象数组)。

    支持 ``Model``、``Model | None``（可选分支）、``list[Model]``、
    以及它们的嵌套组合；联合中两个模型分支的字段会被合并内省。
    """
    origin = get_origin(annotation)
    if origin is None:
        if isinstance(annotation, type) and issubclass(annotation, BaseModel):
            return [annotation], False
        return [], False
    args = get_args(annotation)
    if origin in (list, tuple, set, frozenset, AbcSequence):
        models: list[type[BaseModel]] = []
        for arg in args:
            sub_models, _ = _analyze_annotation(arg)
            models.extend(sub_models)
        return models, bool(models)
    # Union / Optional / X | None：分支是可选对象，不是数组。
    models = []
    for arg in args:
        sub_models, _ = _analyze_annotation(arg)
        models.extend(sub_models)
    return models, False


# ---------------------------------------------------------------------------
# 场景策略
# ---------------------------------------------------------------------------


class SensitivityPolicy:
    """一个资料场景的敏感字段策略。"""

    def __init__(self, name: str) -> None:
        self.name = name
        #: 规范路径（模型字段名元组） -> 敏感类别。
        self._marks: dict[tuple[str, ...], FieldCategory] = {}
        #: 规范路径 -> 所有可接受写法（内省填充，缺省退化为字段名自身）。
        self._accepted: dict[tuple[str, ...], set[str]] = {}
        #: 模型对象数组的规范路径集合（元素继续按子结构遍历）。
        self._array_paths: set[tuple[str, ...]] = set()
        self._trie_root = _Node()
        self._dirty = True

    def mark(
        self,
        path: tuple[str, ...] | list[str],
        category: FieldCategory,
    ) -> "SensitivityPolicy":
        """声明一个规范路径为敏感字段；随资料模型一起版本化。返回自身以便链式调用。"""
        norm = tuple(path)
        self._marks[norm] = category
        self._dirty = True
        return self

    # -- 模型内省 -------------------------------------------------------

    def introspect(self, model_cls: type[BaseModel]) -> "SensitivityPolicy":
        """从模型字段元数据内省可接受写法与数组层级（幂等，可合并多模型）。"""
        seen: set[int] = set()
        self._walk_model(model_cls, (), seen)
        self._dirty = True
        return self

    def _walk_model(
        self,
        model_cls: type[BaseModel],
        prefix: tuple[str, ...],
        seen: set[int],
    ) -> None:
        if id(model_cls) in seen:
            return
        seen.add(id(model_cls))
        for attr, field in model_cls.model_fields.items():
            path = prefix + (attr,)
            accepted = _matching_keys(field, attr)
            # 合并同一路径的既有写法（多个根模型共享子结构时）。
            self._accepted.setdefault(path, set()).update(accepted)
            sub_models, is_array = _analyze_annotation(field.annotation)
            if is_array:
                self._array_paths.add(path)
            for sub in sub_models:
                self._walk_model(sub, path, seen)

    # -- 编译 -----------------------------------------------------------

    def _ensure_compiled(self) -> _Node:
        if self._dirty:
            self._compile()
        return self._trie_root

    def _compile(self) -> None:
        root = _Node()
        for path, category in self._marks.items():
            node = root
            for depth, _seg in enumerate(path, start=1):
                prefix = path[:depth]
                labels = self._accepted.get(prefix) or {normalize_key(prefix[-1])}
                is_array = prefix in self._array_paths
                # 同一字段的所有可接受写法（字段名 + 别名）必须指向同一个
                # 子节点：先查同层是否已有边，有则复用其节点；没有才新建并
                # 把同层全部写法映射过去。否则叶子类别会写到游离节点上。
                shared: _Edge | None = None
                for label in labels:
                    existing = node.children.get(label)
                    if existing is not None:
                        shared = existing
                        break
                if shared is None:
                    shared = _Edge(_Node(), is_array)
                for label in labels:
                    node.children[label] = shared
                node = shared.node
            node.category = category
        _compute_subtree_categories(root)
        self._trie_root = root
        self._dirty = False


#: 子树代表类别的确定性选取顺序（FieldCategory 定义顺序）。
_CATEGORY_ORDER = list(FieldCategory)


def _compute_subtree_categories(root: _Node) -> None:
    """后序遍历 trie，为每个节点填充 ``subtree_category``（确定性、幂等）。

    多条边可共享同一子节点（别名归一），用 memo 避免重复计算；trie 由有限
    路径编译而来，不存在环。
    """
    memo: dict[int, FieldCategory | None] = {}

    def resolve(node: _Node) -> FieldCategory | None:
        if id(node) in memo:
            return memo[id(node)]
        best = node.category
        for edge in node.children.values():
            child = resolve(edge.node)
            if child is not None and (
                best is None
                or _CATEGORY_ORDER.index(child) < _CATEGORY_ORDER.index(best)
            ):
                best = child
        node.subtree_category = best
        memo[id(node)] = best
        return best

    resolve(root)


# ---------------------------------------------------------------------------
# 注册表：场景与模型绑定
# ---------------------------------------------------------------------------

_policies: dict[str, SensitivityPolicy] = {}
_model_registry: dict[type[BaseModel], SensitivityPolicy] = {}


def register_policy(name: str) -> SensitivityPolicy:
    """声明（或复用）一个命名场景策略；重名时幂等返回同一实例。"""
    policy = _policies.get(name)
    if policy is None:
        policy = SensitivityPolicy(name)
        _policies[name] = policy
    return policy


def bind_model_policy(
    model_cls: type[BaseModel],
    policy: SensitivityPolicy | str,
) -> SensitivityPolicy:
    """把资料模型与场景策略绑定并内省字段元数据（声明即生效）。"""
    if isinstance(policy, str):
        policy = register_policy(policy)
    policy.introspect(model_cls)
    _model_registry[model_cls] = policy
    return policy


def policy_for_model(model_cls: type[BaseModel]) -> SensitivityPolicy | None:
    """按模型类查找绑定策略；未绑定返回 None（调用方退化为基线规则）。"""
    return _model_registry.get(model_cls)


# ---------------------------------------------------------------------------
# 输入归一（解析层）：大小写/分隔符写法在进入 pydantic 前统一
# ---------------------------------------------------------------------------


def _field_synonyms(field: Any) -> set[str]:
    """读取字段在 ``json_schema_extra`` 中声明的同义词（原始写法）。

    同义词用于“归一后仍不同形”的概念（如 ``mobile`` -> ``phone``）；
    大小写/下划线/连字符差异由 :func:`normalize_key` 自动覆盖，无需声明。
    """
    extra = getattr(field, "json_schema_extra", None)
    if isinstance(extra, dict):
        raw = extra.get("input_synonyms")
    elif callable(extra):
        try:
            raw = extra({}).get("input_synonyms")  # type: ignore[union-attr]
        except Exception:
            raw = None
    else:
        raw = None
    if not raw:
        return set()
    return {name for name in raw if isinstance(name, str)}


def _matching_keys(field: Any, attr: str) -> set[str]:
    """一个字段所有可匹配的归一键：字段名/别名/同义词 + 常见分隔符展开。

    例如同义词 ``mobile`` 同时产生 ``mobile`` 与 ``mobilephone`` 风格变体，
    使 ``mobile`` 与 ``mobile-phone`` 都能命中同一字段；解析与脱敏共用。
    """
    raw_names = [attr, *_alias_names(field), *_field_synonyms(field)]
    keys: set[str] = set()
    for name in raw_names:
        if not isinstance(name, str) or not name:
            continue
        # 统一识别规则：仅做“小写 + 去下划线/连字符”折叠。
        # cert_number / cert-number / certNumber / CERT_NUMBER -> certnumber。
        keys.add(normalize_key(name))
    keys.discard("")
    return keys


def _normalize_mapping(
    value: Mapping[Any, Any], model_cls: type[BaseModel]
) -> dict[Any, Any]:
    """把一个 dict 的键按模型字段归一：命中字段则输出规范字段名并递归子模型。"""
    # 归一键 -> (字段名, 字段对象)。字段名优先（输出为规范名），别名/同义词用于命中。
    fields_by_norm: dict[str, tuple[str, Any]] = {}
    for attr, field in model_cls.model_fields.items():
        for key in _matching_keys(field, attr):
            fields_by_norm.setdefault(key, (attr, field))

    result: dict[Any, Any] = {}
    for key, item in value.items():
        match = fields_by_norm.get(normalize_key(key))
        if match is None:
            # 未知键原样保留（交给 pydantic 的 extra 策略处理）。
            result[key] = item
            continue
        out_name, field = match
        sub_models, is_array = _analyze_annotation(field.annotation)
        if isinstance(item, Mapping):
            result[out_name] = _normalize_value(
                item, sub_models[0] if sub_models else None
            )
        elif isinstance(item, (list, tuple)) and is_array:
            result[out_name] = [
                _normalize_value(element, _match_branch(element, sub_models))
                for element in item
            ]
        elif isinstance(item, (list, tuple)):
            result[out_name] = list(item)
        else:
            result[out_name] = item
    return result


def _normalize_value(value: Any, model_cls: type[BaseModel] | None) -> Any:
    if isinstance(value, Mapping) and model_cls is not None:
        return _normalize_mapping(value, model_cls)
    return value


def _match_branch(
    element: Any, sub_models: list[type[BaseModel]]
) -> type[BaseModel] | None:
    """为数组/联合中的一个对象元素选择字段重合度最高的模型分支。"""
    if not isinstance(element, Mapping) or not sub_models:
        return sub_models[0] if sub_models else None
    best: type[BaseModel] | None = None
    best_score = -1
    for model_cls in sub_models:
        norms = {normalize_key(attr) for attr in model_cls.model_fields}
        score = sum(1 for key in element if normalize_key(key) in norms)
        if score > best_score:
            best, best_score = model_cls, score
    return best


def normalize_payload_for_model(
    payload: Any, model_cls: type[BaseModel]
) -> Any:
    """对外入口：按模型元数据归一输入（供 pydantic before 校验器调用）。

    与脱敏侧共用 :func:`normalize_key`，保证“能解析进来”和“判定敏感”
    使用同一条识别规则；数组逐条处理，可选分支按结构匹配。
    """
    return _normalize_value(payload, model_cls)


def policy_for_request(request: Any) -> SensitivityPolicy | None:
    """按请求路由声明的 body 模型解析生效策略。

    从 ``route.dependant.body_params`` 的字段注解反查绑定关系；
    路由未声明资料模型时返回 None，自动退化为基线规则。
    """
    route = getattr(request, "scope", {}).get("route")
    dependant = getattr(route, "dependant", None)
    for body_param in getattr(dependant, "body_params", []) or []:
        annotation = getattr(getattr(body_param, "field_info", None), "annotation", None)
        policy = _model_registry.get(annotation)
        if policy is not None:
            return policy
    return None


# ---------------------------------------------------------------------------
# 递归脱敏（场景策略 + 基线兜底 + 审计计数）
# ---------------------------------------------------------------------------


def _is_sequence(value: Any) -> bool:
    return isinstance(value, list | tuple | set | frozenset)


def _mask(counts: dict[FieldCategory, int], category: FieldCategory) -> str:
    counts[category] = counts.get(category, 0) + 1
    return REDACTED


def _redact(
    value: Any,
    node: _Node | None,
    depth: int,
    counts: dict[FieldCategory, int],
) -> Any:
    # 已脱敏载荷：原样取出，不再遍历、不再计数。
    if isinstance(value, PreRedacted):
        return value.payload

    if depth >= _MAX_DEPTH:
        return REDACTED

    # 填错位置的单值：本应是对象/数组的敏感子树位置被直接填了标量
    # （如联系人位置填手机号、附件位置填带签名 URL）。该值按子树代表类别
    # 整体掩码，与正常嵌套时同口径。depth == 0 的裸标量不在此判定
    # （错误明细里非敏感字段的标量 input 会以根节点重入，不能误掩码）。
    if (
        depth > 0
        and node is not None
        and node.subtree_category is not None
        and isinstance(value, str | int | float | bool)
    ):
        # 已是掩码标记的值保持原样，不重复掩码、不重复计数。
        if value == REDACTED:
            return REDACTED
        return _mask(counts, node.subtree_category)

    if isinstance(value, BaseModel):
        policy = policy_for_model(type(value))
        try:
            dumped = value.model_dump(mode="json")
        except Exception:
            return "<unserializable>"
        # 绑定模型按其策略根遍历；未绑定模型沿用调用方当前节点/基线。
        return _redact(dumped, policy._ensure_compiled() if policy else node, depth + 1, counts)

    if isinstance(value, Mapping):
        result: dict[str, Any] = {}
        for i, (key, item) in enumerate(value.items()):
            if i >= _MAX_ITEMS:
                result["...truncated"] = True
                break
            str_key = str(key)
            edge = node.children.get(normalize_key(key)) if node is not None else None
            if edge is not None:
                target = edge.node
                if target.category is not None:
                    # 可选分支缺省为 None：缺失值不含任何输入，保持 None，
                    # 不产生掩码替换也不计入脱敏审计。
                    if item is None:
                        result[str_key] = None
                    # 已是掩码标记的值（例如清洗后的 422 明细再次进入日志渲染）
                    # 保持原样，不重复掩码、不重复计数。
                    elif item == REDACTED:
                        result[str_key] = REDACTED
                    else:
                        result[str_key] = _mask(counts, target.category)
                elif isinstance(item, Mapping):
                    result[str_key] = _redact(item, target, depth + 1, counts)
                elif _is_sequence(item):
                    # 对象数组与标量数组都按该子结构逐元素继续判定；
                    # None 保持原样（可选数组缺省）。
                    result[str_key] = (
                        None if item is None
                        else _redact_sequence(item, target, depth + 1, counts)
                    )
                else:
                    # 标量（含 None）：交给 _redact 判定——若该位置是含敏感
                    # 子树的容器（填错位置的单值），会被整体掩码；否则原样保留。
                    result[str_key] = _redact(item, target, depth + 1, counts)
            else:
                category = _baseline_category(key)
                if category is not None:
                    result[str_key] = (
                        REDACTED if item == REDACTED
                        else _mask(counts, category)
                    )
                else:
                    result[str_key] = _redact(item, None, depth + 1, counts)
        return result

    if _is_sequence(value):
        return _redact_sequence(value, node, depth, counts)

    return value


def _redact_sequence(
    value: Any,
    node: _Node | None,
    depth: int,
    counts: dict[FieldCategory, int],
) -> Any:
    seq = list(value)[:_MAX_ITEMS]
    redacted = [_redact(item, node, depth + 1, counts) for item in seq]
    if isinstance(value, tuple):
        return tuple(redacted)
    if isinstance(value, set | frozenset):
        return set(redacted)
    return redacted


def redact_value(
    value: Any,
    *,
    policy: SensitivityPolicy | None = None,
    channel: OutputChannel = OutputChannel.LOG,
    error_code: str = "",
) -> Any:
    """按场景策略递归脱敏，并累加脱敏审计计数。

    :param value: 任意 dict/list/标量/Pydantic 模型（模型自动解析绑定策略）。
    :param policy: 显式场景策略；None 时模型自动解析、裸 dict 走基线规则。
    :param channel: 输出通道（审计维度；不影响掩码判定，保证各处口径一致）。
    :param error_code: 关联错误码（审计维度，须为稳定错误码或空串）。
    :returns: 脱敏后的同构值；计数按类别聚合成一次提交，临界区最短。

    判定本身在锁外完成（纯内存树遍历），只有最后的计数提交进入全局锁。
    """
    counts: dict[FieldCategory, int] = {}
    root = policy._ensure_compiled() if policy is not None else None
    result = _redact(value, root, 0, counts)
    for category, count in counts.items():
        observe_mask(category.value, channel.value, error_code, count=count)
    return result


# ---------------------------------------------------------------------------
# 校验错误明细清洗
# ---------------------------------------------------------------------------

#: 敏感字段校验失败时对外/日志统一使用的安全说明（不含输入与长度）。
_SAFE_VALIDATION_MESSAGE = "Sensitive field failed validation; input value withheld."


def _classify_loc(loc: Any, policy: SensitivityPolicy | None) -> FieldCategory | None:
    """按字段定位路径判定敏感性（跳过 body 前缀与数组下标；脱离 trie 走基线）。

    除叶子自身类别外，还包括“填错位置”兜底：当整条 loc 都能解析进 trie
    （落在一个含敏感后代的容器节点上，如 ``contacts`` / ``legal_representative``
    / 根 ``body``），说明该位置本应是一个含敏感资料的对象/数组，而实际提交的
    是无法对应到具体字段的单值——按子树代表类别判定为敏感，输入一律不外泄。
    loc 中有任何一段未命中 trie（如 ``enterprise_name`` 这种非敏感字段），
    不做子树兜底，避免误伤非敏感字段的输入回显。
    """
    node = policy._ensure_compiled() if policy is not None else None
    category: FieldCategory | None = None
    fully_resolved = True
    for segment in loc:
        if isinstance(segment, int) or segment == "body":
            continue
        edge = node.children.get(normalize_key(segment)) if node is not None else None
        if edge is not None:
            node = edge.node
            if node.category is not None:
                category = node.category
            continue
        fully_resolved = False
        baseline = _baseline_category(segment)
        if baseline is not None:
            category = baseline
    if category is None and fully_resolved and node is not None:
        category = node.subtree_category
    return category


def _collect_sensitive_values(
    value: Any,
    node: _Node | None,
    depth: int,
    out: set[str],
) -> None:
    """收集所有敏感叶子的标量字符串形式（用于清扫错误 msg 中的回显）。

    填错位置的单值（对象/数组位置直接填标量）同样按子树敏感类别收集，
    保证它也不会出现在任何错误消息文本里。
    """
    if depth >= _MAX_DEPTH:
        return
    if (
        node is not None
        and node.subtree_category is not None
        and isinstance(value, str | int | float | bool)
    ):
        _add_scalar(value, out)
        return
    if isinstance(value, BaseModel):
        policy = policy_for_model(type(value))
        try:
            value = value.model_dump(mode="json")
        except Exception:
            return
        node = policy._ensure_compiled() if policy else node
    if isinstance(value, Mapping):
        for i, (key, item) in enumerate(value.items()):
            if i >= _MAX_ITEMS:
                break
            edge = node.children.get(normalize_key(key)) if node is not None else None
            if edge is not None:
                target = edge.node
                if target.category is not None:
                    _add_scalar(item, out)
                elif isinstance(item, Mapping):
                    _collect_sensitive_values(item, target, depth + 1, out)
                elif _is_sequence(item):
                    for element in list(item)[:_MAX_ITEMS]:
                        _collect_sensitive_values(element, target, depth + 1, out)
                else:
                    # 填错位置的标量：由递归顶部的子树敏感子句判定收集。
                    _collect_sensitive_values(item, target, depth + 1, out)
            else:
                category = _baseline_category(key)
                if category is not None:
                    _add_scalar(item, out)
                else:
                    _collect_sensitive_values(item, None, depth + 1, out)
    elif _is_sequence(value):
        for element in list(value)[:_MAX_ITEMS]:
            _collect_sensitive_values(element, node, depth + 1, out)


def _add_scalar(item: Any, out: set[str]) -> None:
    if isinstance(item, str):
        text = item
    elif isinstance(item, int | float | bool):
        text = str(item)
    else:
        return
    # 过短值不做全局清扫，避免误伤正常文案；掩码不漏判由路径判定保证。
    if len(text) >= 4:
        out.add(text)


def scrub_validation_errors(
    errors: list[dict[str, Any]],
    *,
    body: Any = None,
    policy: SensitivityPolicy | None = None,
    channels: tuple[OutputChannel, ...] = (OutputChannel.RESPONSE, OutputChannel.LOG),
) -> list[dict[str, Any]]:
    """清洗 pydantic v2 校验错误明细。

    * 敏感字段错误：保留 ``type``/``loc``/``url``（字段路径与失败规则可定位、
      可解释），删除 ``input``/``ctx``，消息替换为不含输入的安全说明；
    * 非敏感字段错误：保留 ``input`` 与原始消息，方便前端提示，但其中嵌套的
      敏感值仍按同策略掩码，消息里若回显了任何敏感标量也一并清扫；
    * 同一份判定结果同时供响应与日志使用，天然一致，并按给定通道计数。
    """
    root = policy._ensure_compiled() if policy is not None else None

    sensitive_values: set[str] = set()
    if body is not None:
        _collect_sensitive_values(body, root, 0, sensitive_values)

    counts: dict[FieldCategory, int] = {}
    cleaned: list[dict[str, Any]] = []
    for error in errors:
        loc = error.get("loc", ())
        category = _classify_loc(loc, policy)
        if category is not None:
            counts[category] = counts.get(category, 0) + 1
            safe = {
                "type": error.get("type"),
                "loc": list(loc),
                "msg": _SAFE_VALIDATION_MESSAGE,
                "redacted": True,
            }
            if error.get("url"):
                safe["url"] = error["url"]
            cleaned.append(safe)
            continue

        safe = dict(error)
        if "input" in safe:
            safe["input"] = _redact(safe["input"], root, 0, counts)
        if "ctx" in safe and isinstance(safe["ctx"], Mapping):
            safe["ctx"] = _redact(dict(safe["ctx"]), None, 0, counts)
        msg = safe.get("msg")
        if isinstance(msg, str) and sensitive_values:
            for secret in sorted(sensitive_values, key=len, reverse=True):
                if secret in msg:
                    msg = msg.replace(secret, REDACTED)
            safe["msg"] = msg
        cleaned.append(safe)

    for channel in channels:
        for category, count in counts.items():
            observe_mask(
                category.value, channel.value, CODE_VALIDATION, count=count
            )
    return cleaned


def reset_sensitivity() -> None:
    """清空策略与模型注册表（仅供需要隔离注册表的测试使用）。

    注意：资料声明是进程内静态配置，常规测试隔离只需 ``reset_metrics()``
    清空审计计数；调用本函数后需要重新执行声明/绑定。
    """
    _policies.clear()
    _model_registry.clear()
