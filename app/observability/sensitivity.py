"""场景化敏感字段策略、上下文感知脱敏与脱敏审计计数。

设计目标（企业实名开通场景在现有能力上的扩展，不另起一套）：

* **资料声明与敏感范围同源**：每个资料场景（:class:`SensitivityPolicy`）
  与对应 Pydantic 模型绑定后，自动从字段元数据内省“字段名 / alias /
  validation_alias / AliasChoices”等所有可接受写法与数组层级；新增资料
  版本只需随模型声明 ``mark(...)``，无需再人工改动公共正则配置；
* **路径感知**：同一字段名在不同子结构中可以有不同敏感级别
  （如 ``legal_representative.name`` 敏感，``contacts[].name`` 非敏感），
  判定依据是完整路径而不是裸键名；数组逐元素遍历，不漏任何一条；
* **结构错配也安全**：trie 为每个节点汇总子树敏感类别，客户端在本该是
  数组/对象的位置（顶层、嵌套、数组元素、可选分支，乃至整个 body）直接
  填一个敏感单值而导致校验失败时，错误明细、日志、错误统计都不带原始值；
* **写法归一**：大小写、下划线、连字符通过 :func:`normalize_key` 统一折叠；
* **基线兜底**：未声明场景（如 /login）继续沿用凭据/个人信息基线规则；
* **判定一致**：日志、响应、下游调用记录共用本模块同一套判定；
  422 明细清洗一次，响应与日志复用同一份结果；
* **脱敏审计**：每次掩码仅按封闭低基数维度
  （字段类别 × 输出通道 × 错误类别）累加计数，绝不记录原始值或字段路径；
  计数只与实际掩码有关——日志侧对同一条记录只脱敏一次（快照缓存在
  LogRecord 上），多挂输出 handler、formatter 多次渲染均不重复计数
  （见 :mod:`app.observability.logging`）。
"""

from __future__ import annotations

import re
import threading
from collections.abc import Mapping, Sequence as AbcSequence
from enum import Enum
from typing import Any, get_args, get_origin

from pydantic import AliasChoices, AliasPath, BaseModel

from app.observability.codes import CODE_VALIDATION
from app.observability.metrics import observe_mask

#: 脱敏替换值（固定值，不保留长度信息）。
REDACTED = "***REDACTED***"

#: “调用方未提供该参数”的内部哨兵（None 本身是合法输入，不能当缺省值）。
_UNSET: Any = object()

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

    ``category`` 是该节点自身（叶子）的敏感类别；``subtree_category`` 是
    “该节点自身或其任意后代被声明为敏感”时的代表类别，用于客户端把
    数组/对象位置错填成单值等形状错误——此时无法继续下钻，但该位置本应
    承载的结构里含敏感字段，原始值必须按敏感处理，不能回显。
    """

    __slots__ = ("children", "category", "subtree_category", "is_array_node")

    def __init__(self) -> None:
        self.children: dict[str, _Edge] = {}
        self.category: FieldCategory | None = None
        self.subtree_category: FieldCategory | None = None
        # 该节点是否由一条“对象数组”边到达（数组元素节点）。
        self.is_array_node: bool = False


class _Edge:
    __slots__ = ("node", "is_array")

    def __init__(self, node: "_Node", is_array: bool) -> None:
        self.node = node
        self.is_array = is_array


#: 仅保护 trie 重编译发布（进程生命周期内至多发生极少次）。
_COMPILE_LOCK = threading.Lock()


def _propagate_subtree_category(root: "_Node") -> None:
    """后序遍历：把“后代含敏感声明”的代表类别汇总到每个节点。

    节点自身有 ``category`` 时以自身为准（叶子判定精确）；否则取所有出边
    子节点子树类别中按枚举序最靠前的一个，保证同一结构编译结果确定、
    与 dict 迭代顺序无关。数组边与对象边一样参与传播（数组元素位置填错
    单值时同样要按元素结构的敏感级别处理）。
    """
    # 共享子节点去重（同一节点可能经多个别名边到达）。
    visited: set[int] = set()

    def walk(node: "_Node") -> FieldCategory | None:
        if id(node) in visited:
            return node.subtree_category
        visited.add(id(node))
        candidates: list[FieldCategory] = []
        seen_children: set[int] = set()
        for edge in node.children.values():
            child = edge.node
            if id(child) in seen_children:
                continue
            seen_children.add(id(child))
            child_sub = walk(child)
            if child_sub is not None:
                candidates.append(child_sub)
        if node.category is not None:
            node.subtree_category = node.category
        elif candidates:
            node.subtree_category = min(candidates, key=lambda c: c.value)
        return node.subtree_category

    walk(root)


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
        # 编译结果是不可变快照：加锁只保护“重编译发布”这一步，读多写少，
        # 避免并发首次使用时看到 subtree 传播尚未完成的半成品 trie。
        if self._dirty:
            with _COMPILE_LOCK:
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
                if is_array:
                    shared.node.is_array_node = True
                for label in labels:
                    node.children[label] = shared
                node = shared.node
            node.category = category
        _propagate_subtree_category(root)
        self._trie_root = root
        self._dirty = False


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

    优先返回模型显式绑定的场景策略（如企业开通）；未显式绑定但 body 是
    Pydantic 模型（如 /login）时，按基线凭据/个人信息规则为该模型**合成**
    一份等价策略——这样整体 body 被错填成单值等“结构位置错误”也能被 trie
    子树判定覆盖，而不是在无路径可走时漏过原始值；路由完全没声明 body
    模型时返回 None，调用方继续按裸基线规则处理。
    """
    model_cls = _request_body_model(request)
    if model_cls is None:
        return None
    explicit = _model_registry.get(model_cls)
    if explicit is not None:
        return explicit
    return _baseline_policy_for_model(model_cls)


def _request_body_model(request: Any) -> type[BaseModel] | None:
    """从路由 body 参数注解中取出（可能的）Pydantic 模型类。"""
    route = getattr(request, "scope", {}).get("route")
    dependant = getattr(route, "dependant", None)
    for body_param in getattr(dependant, "body_params", []) or []:
        annotation = getattr(getattr(body_param, "field_info", None), "annotation", None)
        model_cls = _first_model_annotation(annotation)
        if model_cls is not None:
            return model_cls
    return None


def _first_model_annotation(annotation: Any) -> type[BaseModel] | None:
    """从 ``Model`` / ``Model | None`` / ``list[Model]`` 等注解里取首个模型类。"""
    if isinstance(annotation, type) and issubclass(annotation, BaseModel):
        return annotation
    origin = get_origin(annotation)
    if origin is not None:
        for arg in get_args(annotation):
            found = _first_model_annotation(arg)
            if found is not None:
                return found
    return None


#: 未显式绑定模型的基线策略缓存（模型类 -> 合成策略）；模型类是进程内
#: 静态声明，缓存条目数量等于未绑定的 body 模型数，有硬上界。
_baseline_policy_cache: dict[type[BaseModel], SensitivityPolicy] = {}


def _baseline_policy_for_model(model_cls: type[BaseModel]) -> SensitivityPolicy:
    """按基线键名正则为模型（含嵌套）合成一份与裸基线等价的场景策略。

    内省可接受写法与数组层级后，凡字段名/别名命中基线凭据或个人信息
    正则的路径一律 mark；合成结果与 :func:`_baseline_category` 在逐键
    遍历时的判定一致，因此正常嵌套请求脱敏结果不变，只是额外获得
    “结构位置错填单值”时的子树覆盖能力。
    """
    cached = _baseline_policy_cache.get(model_cls)
    if cached is not None:
        return cached
    policy = SensitivityPolicy(f"__baseline__:{model_cls.__qualname__}")
    seen: set[int] = set()

    def mark_baseline_fields(cls: type[BaseModel], prefix: tuple[str, ...]) -> None:
        if id(cls) in seen:
            return
        seen.add(id(cls))
        for attr, field in cls.model_fields.items():
            path = prefix + (attr,)
            category: FieldCategory | None = _baseline_category(attr)
            if category is None:
                for alias in _alias_names(field):
                    category = _baseline_category(alias)
                    if category is not None:
                        break
            if category is not None:
                policy.mark(path, category)
            sub_models, _is_array = _analyze_annotation(field.annotation)
            for sub in sub_models:
                mark_baseline_fields(sub, path)

    mark_baseline_fields(model_cls, ())
    policy.introspect(model_cls)
    _baseline_policy_cache[model_cls] = policy
    return policy


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
                    result[str_key] = item
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


def _classify_loc(
    loc: Any,
    policy: SensitivityPolicy | None,
    *,
    raw_input: Any = _UNSET,
) -> FieldCategory | None:
    """按字段定位路径判定错误明细的敏感性。

    返回值为该条错误应按敏感处理时的字段类别（审计口径），否则 None。

    两类命中：

    1. **精确命中**：路径终点自身就是被 mark 的敏感字段（叶子类别），
       覆盖正常嵌套、数组某一条、可选分支内的字段级失败；
    2. **结构位置错填**：路径终点本应是一个对象/数组（其子树含敏感
       声明），但客户端在该位置给了形状不对的值（如联系人位置直接给
       一串手机号、法人位置给证件号、附件位置给签名 URL、整个 body
       是一段字符、数组元素位置给单值）。此时无法继续下钻定位到字段，
       但该位置承载的结构里含敏感资料，原始值一律按敏感剥离。

    形状正常（dict 在对象位、list 在数组位）时即使落在含敏感字段的
    结构上也不在此命中——结构能继续下钻，具体敏感与否交给字段级错误
    逐条精确判定，非敏感字段错误因此仍可回显 input。
    """
    node = policy._ensure_compiled() if policy is not None else None

    exact: FieldCategory | None = None
    cur = node
    last_edge_is_array = False
    string_segments: list[str] = []
    for segment in loc:
        if segment == "body":
            continue
        if isinstance(segment, int):
            # 数组下标：保持当前节点（数组元素与数组边共享子结构），
            # 并记录“上一步走到了数组元素位置”。
            last_edge_is_array = True
            continue
        last_edge_is_array = False
        string_segments.append(segment)
        edge = cur.children.get(normalize_key(segment)) if cur is not None else None
        if edge is not None:
            cur = edge.node
            last_edge_is_array = edge.is_array
            if cur.category is not None:
                exact = cur.category
        else:
            baseline = _baseline_category(segment)
            if baseline is not None:
                exact = baseline
            cur = None

    if exact is not None:
        return exact

    # loc 仅为 ("body",)：整个请求体本身错形（整体 body 是一段字符等）。
    if not string_segments:
        target_node = node
        position_is_array = False
    else:
        target_node = cur
        position_is_array = last_edge_is_array

    if (
        target_node is not None
        and target_node.subtree_category is not None
        and raw_input is not _UNSET
        and not _input_shape_matches_position(
            raw_input, target_node, position_is_array, string_segments
        )
    ):
        return target_node.subtree_category
    return None


def _input_shape_matches_position(
    raw_input: Any,
    node: _Node,
    position_is_array: bool,
    string_segments: list[str],
) -> bool:
    """判断错误输入的形状是否与 loc 终点期望的结构位置相符。

    相符（返回 True）表示还能按结构继续下钻，字段级错误自行精确判定；
    不符（返回 False）表示客户端把结构位置错填成了别的形状，该位置
    子树又含敏感声明，原始输入必须整体按敏感处理。
    """
    # 整个 body 位置：策略存在即说明期望模型对象（Mapping）。
    if not string_segments:
        return isinstance(raw_input, Mapping)
    if position_is_array or node.is_array_node:
        return _is_sequence(raw_input)
    # 对象位置（有子字段的节点）：期望 dict；给标量/list 都属错形。
    if node.children:
        return isinstance(raw_input, Mapping)
    # 叶子标量位置：任何标量都算形状相符，具体规则（长度/格式）由
    # 字段级错误与精确路径判定处理。
    return not isinstance(raw_input, Mapping | list | tuple | set | frozenset)


def _collect_sensitive_values(
    value: Any,
    node: _Node | None,
    depth: int,
    out: set[str],
) -> None:
    """收集所有敏感叶子的标量字符串形式（用于清扫错误 msg 中的回显）。"""
    if depth >= _MAX_DEPTH:
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
                        if target.subtree_category is not None and not isinstance(
                            element, Mapping
                        ):
                            # 数组元素位置本应是（含敏感字段的）对象，却给了
                            # 标量等错形值：该值按敏感收集，供 msg 全局清扫。
                            _add_scalar(element, out, min_length=1)
                        else:
                            _collect_sensitive_values(element, target, depth + 1, out)
                elif target.subtree_category is not None:
                    # 对象位置本应是（含敏感字段的）dict，却给了标量/list：
                    # 无论长短都收集，避免短证件号等因长度阈值漏清扫。
                    _add_scalar(item, out, min_length=1)
            else:
                category = _baseline_category(key)
                if category is not None:
                    _add_scalar(item, out)
                else:
                    _collect_sensitive_values(item, None, depth + 1, out)
    elif _is_sequence(value):
        for element in list(value)[:_MAX_ITEMS]:
            if (
                node is not None
                and node.subtree_category is not None
                and not isinstance(element, Mapping)
            ):
                _add_scalar(element, out, min_length=1)
            else:
                _collect_sensitive_values(element, node, depth + 1, out)


def _add_scalar(item: Any, out: set[str], *, min_length: int = 4) -> None:
    if isinstance(item, str):
        text = item
    elif isinstance(item, int | float | bool):
        text = str(item)
    else:
        return
    # 常规叶子只收集较长值，避免误伤正常文案；错填到敏感结构位置的值
    # （min_length=1）不受长度阈值限制——掩码不漏判由路径/子树判定保证，
    # 这里的集合仅用于错误 msg 的全局替换清扫。
    if len(text) >= min_length:
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
        # 整个请求体被错填成标量（body 位置期望模型对象）：loc 判定会
        # 剥离该错误的 input；这里同步把根标量纳入 msg 全局清扫集合。
        if (
            root is not None
            and root.subtree_category is not None
            and not isinstance(body, Mapping)
        ):
            _add_scalar(body, sensitive_values, min_length=1)

    counts: dict[FieldCategory, int] = {}
    cleaned: list[dict[str, Any]] = []
    for error in errors:
        loc = error.get("loc", ())
        category = _classify_loc(loc, policy, raw_input=error.get("input", _UNSET))
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
    _baseline_policy_cache.clear()
