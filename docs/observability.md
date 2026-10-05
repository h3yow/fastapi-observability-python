# 本地可观测性能力说明

本服务在 FastAPI 上内置了一套无需外部组件即可本地验证的可观测性能力：
**关联标识（request_id）贯穿、按路由模板聚合的指标、日志/错误响应脱敏与异常映射、
场景化敏感字段策略与脱敏审计**。
它们共享同一入口中间件、错误码口径与同一套敏感判定，保证“日志、指标、
对外错误响应、下游调用记录”一致且可解释。

- 应用入口：`app/main.py`（根目录 `main.py` 保留兼容，`uvicorn main:app` 可用）
- 核心代码：`app/context.py`、`app/observability/`（含 `sensitivity.py`
  场景策略/脱敏/审计、`codes.py` 稳定错误码）
- 企业实名开通场景：`app/schemas_enterprise.py`、路由 `POST /enterprise/onboarding`
- 测试：`tests/`（48 个用例，覆盖并发隔离、脱敏、异常映射、指标口径、
  企业开通场景、填错位置防护与脱敏审计）

---

## 1. 关联标识（request_id）传播规则

### 1.1 入站标识的沿用与替换（确定规则）

调用方通过请求头 **`X-Request-ID`** 传入标识。入口中间件
（`app/observability/middleware.py`）调用 `resolve_request_id()` 做**确定性**判定：

| 入站值情况 | 处理 | 生效标识 |
|---|---|---|
| 缺失 | 服务端生成 | `req-<uuid4 hex>`（36 字符） |
| 长度 8~128 且全部匹配 `[A-Za-z0-9._-]` | **原样沿用** | 入站值 |
| 过短（<8）、过长（>128）、含空格/换行/其他非法字符 | **替换** | `req-<uuid4 hex>` |

规则要点：

- 字符集白名单同时杜绝了日志伪造（换行）与响应头注入（CRLF）字符；
- 内部生成标识统一带 `req-` 前缀，日志字段 `request_id_source` 标记
  `inbound`（沿用）或 `generated`（替换），可审计“沿用还是替换”；
- 生效标识通过**响应头 `X-Request-ID`** 与错误响应体 `error.request_id` 回带，
  调用方可据此与服务端日志关联；
- 判定只依据“字符集 + 长度”，不做任何网络查询，开销为一次正则匹配。

### 1.2 全链路传播

```
调用方 ──X-Request-ID──▶ [入口中间件: resolve + 写入上下文]
                              │
              ┌───────────────┼──────────────────────────┐
              ▼               ▼                          ▼
         同步路由处理     BackgroundTasks           下游 HTTP 调用
       (ContextVar 读取)  (提交时快照, 线程池恢复)  (X-Request-ID 透传)
```

- **同步处理**：生效标识写入 `contextvars.ContextVar`。每个请求运行在独立
  asyncio 任务、拥有独立的 Context 副本，因此**并发请求之间标识天然隔离，
  不会串扰或丢失**。路由中直接 `get_request_id()` 即可读取。
- **后台任务**：在请求处理期间用 `with_request_id(func)` 包装，
  **在包装时刻快照**当前 request_id（而非任务实际执行时才读取——此时响应可能
  已发送）。同步函数经 `run_in_threadpool` 执行时，会在工作线程的上下文副本中
  再显式设置一次快照值；协程函数则在自身任务中恢复。
  非请求场景调度且无上下文时，会生成新的 `req-` 标识，保证日志仍可关联。
- **下游调用**：`app/observability/http.py` 的 `downstream_get()` 自动在请求头
  注入 `X-Request-ID: <当前标识>`；上下文缺失时生成新标识。下游 4xx/5xx 与传输
  异常统一包装为 `DownstreamError`，下游返回体不直接透出给调用方。
- **异常响应**：500 处理器运行在 Starlette 最外层 `ServerErrorMiddleware`
  （位于本中间件之外，读不到其 ContextVar），因此生效标识同时写入
  `request.state`（底层即共享的 `scope["state"]`），异常处理器按
  “ContextVar 优先、state 回退”获取，保证 500/422/404 响应都能回带同一标识。

---

## 2. 指标口径与基数约束

指标在 `app/observability/metrics.py` 中以进程内结构采集，
通过 `GET /metrics` 以 **Prometheus 文本格式（0.0.4）** 暴露。

### 2.1 指标与标签

| 指标 | 类型 | 含义 |
|---|---|---|
| `http_requests_total` | Counter | 请求总数 |
| `http_request_duration_seconds` | Histogram | 请求处理耗时（秒），桶 `0.005 … 10.0` + `+Inf`，含 `_sum`/`_count` |

标签集合（计数器与直方图口径一致）：

| 标签 | 取值 | 基数控制 |
|---|---|---|
| `method` | `GET/POST/...` 白名单归一，白名单外为 `OTHER` | 固定 ≤10 |
| `route` | **路由模板**（如 `/users/{user_id}`）；未匹配路由统一为 `__unmatched__` | = 路由数，与流量无关 |
| `status` | 最终响应状态码（含异常处理器转换后的码） | 有限 |
| `outcome` | `success`(2xx/3xx) / `client_error`(4xx) / `server_error`(5xx) | 3 |
| `error_code` | 对外错误码（见第 4 节）；成功为空串 | 有限枚举 |

### 2.2 四类结果使用同一条采集路径

入口中间件在 `try/finally` 中对**每次**请求调用一次 `observe_request()`，
无论结果是：

- 正常响应（2xx）；
- 参数校验失败（422 `VALIDATION_FAILED`，由 FastAPI/异常处理器产生）；
- 未匹配路由（404 `ROUTE_NOT_FOUND`，`route=__unmatched__`）；
- 内部异常（500 `INTERNAL_ERROR`：中间件 `except` 中先固定错误码再抛出，
  保证先执行的指标记录与后执行的 500 处理器**口径一致**，不会落到 `HTTP_500` 兜底）。

因此四类结果的标签结构完全相同，`status/outcome/error_code` 与实际错误响应一一对应。
`error_code` 由异常处理器写入 `request.state.error_code`，中间件读取，
从而保证“对外错误码 == 指标错误码 == 日志错误码”。

### 2.3 基数约束（防止维度失控）

- **绝不使用真实路径**：`/users/1001` 与 `/users/1002` 都聚合到
  `route="/users/{user_id}"`；实体 ID、查询参数均不进入标签；
- 未匹配任何路由的请求**无论路径是什么**都聚合到单一 `__unmatched__`；
- 标签值经过转义（`\`、`"`、换行），渲染按字典序排序，输出确定、可比对；
- 维度总量为 `方法数 × 路由数 × 状态/错误码数`，与请求条数无关。

### 2.4 并发正确性与性能

- 计数器与直方图由单一 `threading.Lock` 保护，临界区仅做 dict 自增与桶累加
  （常数次内存操作，无 I/O）；测试以 16 线程 × 200 请求验证计数不丢失；
- 采集动作是一次计时 + 一次加锁自增，不发起网络/磁盘操作，
  不会明显拖慢请求；直方图桶为定长 12 个。

### 2.5 脱敏审计计数器

除 HTTP 指标外，`/metrics` 还暴露脱敏审计计数器 `masked_inputs_total`
（Counter），用于统计敏感输入被掩码的次数。其标签口径与基数约束详见
**第 3.5 节**；这里仅说明与 HTTP 指标的关系：

- 两者共用同一个全局锁与渲染端点，渲染均按字典序排序、输出确定；
- 脱敏审计**不使用** `route`、真实路径、字段名或任何输入值，
  因此它的基数甚至低于 HTTP 指标（路由数量不影响审计维度）。

---

## 3. 脱敏：场景策略、匹配范围与写法识别

脱敏判定与递归遍历统一收敛在 `app/observability/sensitivity.py`，
日志（`logging.py`）、422 错误明细（`errors.py`）、下游调用记录（`http.py`）
都委托给它，**不各自维护一份敏感字段清单**。

### 3.1 两层判定模型

| 层 | 作用 | 适用范围 |
|---|---|---|
| **基线规则** | 凭据/令牌与个人信息键名的大小写不敏感正则 | 未声明场景的载荷（如 `/login`），以及任何场景中“路径 trie 之外”的键 |
| **场景策略** | 与 Pydantic 模型同源、按**完整路径**声明的敏感字段 | 企业实名开通等结构化资料（`enterprise_onboarding`） |

命中任一层即按对应**字段类别**整体掩码为固定值 `***REDACTED***`
（不保留长度信息）。基线正则覆盖：

- 凭据/令牌：`password`/`passwd`、`secret`、`token`、`api_key`（含 `apikey`）、
  `authorization`、`credential`
- 个人敏感信息：`id_card`（身份证）、`ssn`、`phone`/`mobile`、`email`

字段类别是封闭枚举，只有四种：`credential` / `id_document` / `contact` /
`financial`，同时用作脱敏审计标签（见 3.5）。

### 3.2 场景敏感字段如何声明（与资料同源，新增版本免改公共配置）

企业开通场景在 `app/schemas_enterprise.py` 内完成“资料 + 敏感范围”声明，
二者同文件、同版本：

```python
policy = register_policy("enterprise_onboarding")

# 按规范字段路径声明敏感类别；同一字段名可在不同路径有不同级别
policy.mark(("legal_representative", "name"), FieldCategory.ID_DOCUMENT)
policy.mark(("legal_representative", "certificate"), FieldCategory.ID_DOCUMENT)
policy.mark(("contacts", "phone"), FieldCategory.CONTACT)
policy.mark(("bank_account", "account_number"), FieldCategory.FINANCIAL)
policy.mark(("attachments", "download_url"), FieldCategory.CREDENTIAL)
# contacts[].name 故意不声明 -> 非敏感（与法人姓名同名但不同级）

bind_model_policy(EnterpriseOnboardingRequest, policy)  # 内省字段元数据
```

`bind_model_policy` 会自动从 Pydantic 元数据内省：

- **嵌套对象层级**：字段注解里的 `Model`、`Model | None`（可选分支）、
  `list[Model]`（对象数组）都会递归展开成一棵路径 trie；
- **数组逐条**：`contacts` / `attachments` 是数组时，**每一条**元素都按同一
  子结构判定，不因在数组里而漏判；标量数组与对象数组都支持；
- **可选分支**：`bank_account`、`certificate` 等缺省为 `None` 时，缺失值
  保持 `None`，**不**替换为掩码、也**不**计入脱敏审计（没有真实输入被掩码）。

新增资料字段/新版本资料时，只需：扩展模型字段 + 补一条 `policy.mark(...)`，
无需修改 `logging.py` 等任何公共配置；未显式 mark 的新字段默认非敏感
（安全默认是“可观测”，敏感必须显式声明，评审时一眼可见）。

### 3.3 写法归一：大小写、下划线、连字符按同一规则识别

解析侧与脱敏侧共用同一个折叠函数：

```
normalize_key(s) = s.lower().replace("_", "").replace("-", "")
```

因此 `certNumber` / `cert_number` / `cert-number` / `CERT_NUMBER` 都折叠为
`certnumber`，按同一字段识别。为让**解析层**（Pydantic 绑定）也接受这些写法，
顶层模型挂了一个 `model_validator(mode="before")`，进入校验前按字段元数据
递归归一键名（数组逐条、可选分支按结构匹配），错误明细中的字段路径因此以
**规范字段名**给出，前端按规范路径定位即可，不受客户端具体写法影响。

- 折叠只解决“大小写 + 分隔符”差异；对于折叠后仍不同形的同义词
  （如 `mobile` 与 `phone`），在字段的
  `json_schema_extra={"input_synonyms": [...]}` 中显式声明，随字段同源；
- `AliasChoices` / `validation_alias` / `serialization_alias` 中的写法同样
  被内省为可接受写法。

### 3.4 匹配范围与判定一致性

- 递归深度上限 6、每层最多 100 项（超出截断标记，防止异常数据拖垮采集）；
  Pydantic 模型经 `model_dump(mode="json")` 展开后判定；
- **同一份请求在各处的判定必须一致**：路由日志记录的是模型对象，日志层自动
  解析其绑定策略；下游调用记录显式传入同一策略；422 明细按“路由声明的 body
  模型”反查策略。因此一个手机号要么在日志、响应、下游记录里全部被掩码，
  要么全部保留，不会出现一处掩码一处明文；
- HTTP 请求头中 `Authorization`、`Cookie`、`Proxy-Authorization`、`X-Api-Key`
  整体掩码；
- 真实发给下游的业务报文**不脱敏**（下游需要原始资料），脱敏只发生在
  “下游调用的日志记录副本”上；测试同时断言“记录无原始值”与“真实报文含原始值”。

### 3.4.1 填错位置的单值（对象/数组位置被直接填成标量）

客户端有时把本该是对象/数组的位置直接填成一个单值：联系人位置填一串
手机号、法人/银行账户位置填一个证件号/账号、附件位置填一段带签名的下载
地址，甚至整个请求体就是一段字符。这些位置声明的子树里含有敏感字段，
填进来的单值**按敏感资料处理**，与正常嵌套时同口径：

- **判定依据**：场景策略编译 trie 时为每个节点预计算“子树敏感类别”
  （自身类别优先，否则按字段类别定义顺序取最近后代，确定性选择）。
  递归脱敏与 422 明细清洗遇到“落在含敏感后代容器节点上的标量”
  （顶层、嵌套对象、数组某一条、可选分支、根 `body` 均覆盖）时，
  按该子树类别整体掩码；
- **不外泄**：这类单值不会出现在 422 响应明细、服务端日志或错误统计中；
  错误明细只保留 `loc`/`type` 与 `redacted: true`，前端仍能定位到
  填错的位置与违反的规则（如 `list_type`/`model_attributes_type`）；
- **不误伤**：`loc` 中有任何一段未命中 trie（如 `enterprise_name` 这类
  非敏感字段本身的校验失败）不做子树兜底，非敏感字段的 `input` 继续原样
  回显；可选分支缺省 `None` 依旧保持 `None`、不计数；
- **口径一致**：同一份请求在响应、日志、错误统计中使用同一份清洗结果/
  同一套判定，不会出现一处掩码一处明文。

### 3.5 脱敏审计计数（低基数，不记值、不记路径）

新增 Prometheus 计数器 `masked_inputs_total`，在 `GET /metrics` 暴露：

```
masked_inputs_total{field_category="contact",output_channel="log",error_code=""} 3
```

| 标签 | 取值 | 基数约束 |
|---|---|---|
| `field_category` | `credential`/`id_document`/`contact`/`financial` | 固定 4 |
| `output_channel` | `log`/`response`/`downstream` | 固定 3 |
| `error_code` | 成功为空串；校验失败为 `VALIDATION_FAILED`（其余稳定错误码同理） | 有限错误码枚举 |

口径与约束：

- 计数含义是“敏感输入**被掩码的次数**”：同一份敏感体出现在多个输出事件
  （如请求日志 + 下游调用记录）会分别计数，因为它们是独立的掩码动作；
  同一事件内已掩码的载荷经 `PreRedacted` 包装透传，**不会二次计数**；
- **与日志输出路数、渲染次数无关**：日志的脱敏发生在记录首次渲染时，
  结果缓存在该条 `LogRecord` 上（`JsonFormatter`），多挂一路 handler、
  或同一记录被重复渲染，都复用首次结果——一条日志记录的掩码只发生、
  只计数一次（测试以 1/2/3 路输出与同一记录 3 次渲染验证计数不变）；
- **绝不记录原始值、字段名或字段路径**，因此无法从指标反推任何个人信息；
- 维度组合数有硬上界 `4 × 3 × 错误码数`，字段和别名组合增多、请求条数增多
  都不会让维度增长（测试以 40 个含不同值/别名的请求验证标签数不超过上界）；
- 判定是锁外的纯内存 trie 遍历（每字段 O(路径深度)），仅在按类别聚合计数后
  一次进入全局锁，临界区为常数次自增；测试验证 19 个联系人的请求单次脱敏
  仍在毫秒级，16 线程 × 50 次并发计数精确无丢失，24 并发“填错位置”
  请求的审计增量精确等于请求数。

### 3.6 日志与响应的边界

- **日志**：单行 JSON 到 stderr，固定字段 `ts/level/logger/message/request_id`，
  所有 `extra` 字段递归脱敏；未处理异常记录 `exception_type` 与**完整 traceback**
  （`exc_info`），供内部排查——原始异常链路只进日志。
- **对外响应**：成功响应的模型本身不回传敏感字段（开通响应只含
  status/request_id/非敏感企业名）；错误响应只包含稳定的
  `code/message/request_id`（422 另附字段级 details，见第 4.1 节），
  **绝不包含原始异常消息、堆栈或下游返回体**。

---

## 4. 稳定对外错误码

错误响应统一结构：

```json
{"error": {"code": "VALIDATION_FAILED", "message": "Request parameters failed validation.", "request_id": "..."}}
```

| HTTP | code | 触发场景 |
|---|---|---|
| 422 | `VALIDATION_FAILED` | 请求参数/体校验失败 |
| 404 | `ROUTE_NOT_FOUND` | 未匹配路由 |
| 405 | `METHOD_NOT_ALLOWED` | 方法不允许 |
| 401 | `UNAUTHORIZED` | 未认证 |
| 403 | `FORBIDDEN` | 被禁止 |
| 404 | `NOT_FOUND` | 显式 HTTPException(404) |
| 409 | `CONFLICT` | 冲突 |
| 429 | `TOO_MANY_REQUESTS` | 限流 |
| 502 | `DOWNSTREAM_ERROR` | 下游调用失败（细节不透出） |
| 503 | `SERVICE_UNAVAILABLE` | 服务不可用 |
| 500 | `INTERNAL_ERROR` | **一切未处理异常**的唯一对外码 |
| 其他 | `HTTP_<status>` | 兜底，保证仍可区分 |

错误码稳定、互相可区分；同一种失败永远得到同一个 code，不受底层异常文案影响。

### 4.1 参数校验失败（422）明细的安全展示与兼容边界

422 响应体在统一错误包装外附 `error.details`（Pydantic v2 错误列表）。
处理器（`app/observability/errors.py`）调用 `scrub_validation_errors()`，
按当前路由资料模型的同一份场景策略逐条清洗：

| 字段是否敏感 | 保留内容 | 去除/替换内容 |
|---|---|---|
| **敏感字段**（路径命中策略/基线） | `loc`（字段定位，含数组下标）、`type`（失败规则）、`url`，并加 `"redacted": true` | 删除 `input` 与 `ctx`；`msg` 统一替换为不含输入的安全说明 `Sensitive field failed validation; input value withheld.` |
| **填错位置的单值**（对象/数组位置填了标量，含根 `body`） | 同上：`loc` 定位到填错的位置、`type` 表明期望的结构（如 `list_type`）、`redacted: true` | 同上：输入一律不外泄（见 3.4.1） |
| **非敏感字段** | 完整保留 `loc`/`type`/`msg`/`url`/`input`/`ctx`，前端可据此定位并回显用户输入 | 仅当 `input`/`ctx` 内部嵌套了敏感值时才掩码；`msg` 若回显了任何敏感标量也会被清扫 |

要点：

- **可定位**：无论字段多深、是否在数组或可选分支下，`loc` 始终给出
  `body → 规范字段名（→ 数组下标）` 的完整路径；字段路径以**规范名**给出
  （before 归一器先把 camel/snake/kebab 写法统一），对前端稳定；
- **可解释**：`type`（如 `string_too_short`/`missing`）与 `url` 保留，
  前端能知道失败的是哪条规则；敏感字段额外用固定安全文案，不泄露长度/取值；
- **零泄露**：清洗后的同一份 `details` 同时用于响应与内部日志，敏感输入不会
  出现在响应体、日志或错误统计中；并按 `response` 与 `log` 两个通道分别计入
  脱敏审计（错误类别固定为 `VALIDATION_FAILED`）；
- **兼容边界**：details 仍是 Pydantic v2 错误对象的子集（字段名 `type/loc/msg/
  url/input/ctx` 未变），既有按这些键消费的前端不受影响；新增的仅为
  `redacted: true` 布尔标记（额外字段，向后兼容）；稳定错误码与
  `VALIDATION_FAILED` 不变。

---

## 5. 示例接口

| 方法 & 路径 | 用途 |
|---|---|
| `GET /` | 正常同步响应，响应体含当前 request_id |
| `POST /login` | 含 password/id_card，验证日志与响应脱敏（基线规则） |
| `POST /enterprise/onboarding` | **企业实名开通**：嵌套/数组/别名/可选分支资料，验证场景策略、422 明细与脱敏审计 |
| `GET /users/{user_id}` | 路径参数，验证指标按模板聚合 |
| `GET /bg?note=` | 调度线程池后台任务，验证 request_id 快照传播 |
| `GET /downstream?url=` | 下游 GET，验证 `X-Request-ID` 透传（测试用 MockTransport） |
| `GET /boom?kind=http\|other` | 显式 HTTPException(409) 或未处理异常(500) |
| `GET /metrics` | Prometheus 文本指标（含 `masked_inputs_total` 脱敏审计） |

---

## 6. 本地验证方法

### 6.1 准备

```bash
uv sync                       # 安装依赖（含 pytest 开发依赖）
```

### 6.2 启动并手工验证

```bash
.venv/bin/uvicorn main:app --reload
```

另开终端：

```bash
# 1) 沿用合法入站标识；响应头原样回带
curl -i -H 'X-Request-ID: my-trace-id-001' http://127.0.0.1:8000/

# 2) 非法标识被替换（含空格/换行/过短），响应得到 req- 前缀新 ID
curl -i -H 'X-Request-ID: bad id' http://127.0.0.1:8000/

# 3) 脱敏：服务端日志中 password/id_card 显示为 ***REDACTED***，响应不含敏感值
curl -s -X POST http://127.0.0.1:8000/login \
  -H 'Content-Type: application/json' \
  -d '{"username":"bob","password":"supersecret","id_card":"110101199001011234"}'

# 3b) 企业实名开通：刻意混用 camel/snake/kebab/大写写法；
#     响应只回非敏感企业名；服务端日志里法人姓名/证件号/手机号/邮箱/账号/
#     附件签名 URL 全部显示为 ***REDACTED***，联系人姓名/文件名/开户名保留；
#     真实下游报文（测试环境为 MockTransport）仍携带原始资料。
curl -s -X POST http://127.0.0.1:8000/enterprise/onboarding \
  -H 'Content-Type: application/json' -H 'X-Request-ID: ent-demo-0001' \
  -d '{
    "EnterpriseName": "ACME有限公司",
    "credit-code": "91110000XXXXXXXXX1",
    "legalRepresentative": {
      "name": "张三",
      "idNumber": "110101199001011234",
      "certificate": {"certNumber": "CERT-99998877","issued_date": "2020-01-01"}
    },
    "contacts": [
      {"name": "李四", "mobilePhone": "13800138000", "EMAIL": "li@example.com"},
      {"name": "王五", "mobile": "13900139000"}
    ],
    "bank_account": {"accountName": "ACME有限公司", "account_number": "6222021234567890123"},
    "attachments": [{"FileName": "license.jpg", "download-url": "https://o/f?token=SIGSECRET99"}]
  }'

# 3c) 开通校验失败：非敏感字段（enterprise_name/credit_code）保留 input；
#     敏感字段只给 loc/type 与固定安全文案（redacted=true），无 input/ctx。
curl -s -X POST http://127.0.0.1:8000/enterprise/onboarding \
  -H 'Content-Type: application/json' -H 'X-Request-ID: ent-demo-422' \
  -d '{"enterprise_name":"A","credit_code":"short",
       "legal_representative":{"name":"张三","idNumber":"123"},
       "contacts":[{"name":"李四","phone":"138"}],
       "bank_account":{"account_name":"ACME","account_number":"12"}}'

# 3d) 填错位置：联系人位置直接填一串手机号（本应是对象数组）。
#     响应明细只给 loc/type/redacted，响应、日志、指标里都搜不到该手机号；
#     同请求的非敏感字段错误（enterprise_name 过短）仍回显 input。
curl -s -X POST http://127.0.0.1:8000/enterprise/onboarding \
  -H 'Content-Type: application/json' -H 'X-Request-ID: ent-demo-423' \
  -d '{"enterprise_name":"A","credit_code":"91110000XXXXXXXXX1",
       "legal_representative":{"name":"张三","idNumber":"110101199001011234"},
       "contacts":"13800138000"}'

# 4) 校验失败 / 未匹配路由 / 内部异常的稳定错误码
curl -s -X POST http://127.0.0.1:8000/login -H 'Content-Type: application/json' -d '{"username":"bob"}'
curl -s http://127.0.0.1:8000/no/such/path/12345
curl -s http://127.0.0.1:8000/boom?kind=other

# 5) 后台任务：响应后服务端日志仍打印同一 request_id
curl -s -H 'X-Request-ID: bg-demo-0001' 'http://127.0.0.1:8000/bg?note=hi'

# 6) 指标：注意 /users/1 与 /users/2 只有一个 route="/users/{user_id}" 维度；
#    masked_inputs_total 只按 字段类别×通道×错误类别 聚合，没有字段名/路径/值。
curl -s http://127.0.0.1:8000/users/1 >/dev/null
curl -s http://127.0.0.1:8000/users/2 >/dev/null
curl -s http://127.0.0.1:8000/metrics | grep masked_inputs_total
```

期望结果（要点）：

- 3b 的 HTTP 响应：`{"status":"accepted","request_id":"ent-demo-0001",
  "enterprise_name":"ACME有限公司"}`，不含任何证件号/手机号/账号；
  服务端 JSON 日志中所有敏感字段值均为 `***REDACTED***`，联系人姓名
  （`李四`/`王五`）、文件名、开户名、企业名等非敏感值保留；
- 3c 的 422 响应：`error.code` 恒为 `VALIDATION_FAILED`；`enterprise_name`、
  `credit_code` 的错误带原始 `input`（`"A"`/`"short"`），而 `idNumber`、
  `contacts[0].phone`、`account_number` 的错误只有 `loc/type/redacted`，
  响应与日志里都搜不到 `123`、`138` 等敏感输入；
- 3d 的 422 响应：`contacts` 位置的错误为
  `{"type":"list_type","loc":["body","contacts"],"redacted":true,...}`，
  无 `input`；`enterprise_name` 的错误仍带 `"input":"A"`；响应、服务端日志
  与 `/metrics` 中都搜不到 `13800138000`，而
  `masked_inputs_total{field_category="contact",...,error_code="VALIDATION_FAILED"}`
  在 `response` 与 `log` 两个通道各 +1（与日志输出路数无关）；
- `/metrics` 中 `masked_inputs_total` 形如
  `masked_inputs_total{field_category="contact",output_channel="log",error_code=""} N`，
  标签值只能是 4 个类别、3 个通道与有限错误码。

### 6.3 自动化测试

```bash
.venv/bin/python -m pytest -s
```

- `-s` 会打印每个用例的**输入、关联标识与判定依据**（`[用例] ...` 行）；
- 断言失败消息均带可区分原因（期望/实际值与场景说明）。

测试分布（共 48 个用例）：

- `tests/test_concurrency.py`：50 并发标识隔离、并发生成唯一性、
  沿用/替换 9 个边界、并发日志关联、后台任务、下游透传、异常响应关联；
- `tests/test_sanitization.py`：嵌套脱敏、请求头脱敏、登录日志/响应无泄露、
  未处理异常“对外 500 + 对内完整堆栈”、错误码稳定可区分、422 详情、下游 502；
- `tests/test_metrics.py`：四类结果同口径、高基数路径维度聚合、
  直方图与计数一致、16 线程 × 200 请求并发计数正确；
- `tests/test_enterprise_onboarding.py`（9 个）：开通成功路径四处观测面
  （响应/日志/下游记录/错误统计）无探针泄露、同名字段按路径分级、
  camel/snake/kebab/大写与同义词归一、数组逐条、可选分支缺省不误掩码、
  422 敏感/非敏感明细差异化展示、缺失敏感字段可定位、脱敏审计低基数、
  30 并发请求计数不丢不串（唯一探针跨 request_id 检测）；
- `tests/test_mask_audit.py`（6 个）：三通道同输入判定逐字节一致、
  不同写法判定一致、基线规则兜底、40 请求标签组合不超封闭上界（维度爆炸）、
  19 联系人请求脱敏毫秒级（性能回退）、16×50 纯并发计数精确；
- `tests/test_misplaced_sensitive_input.py`（15 个）：填错位置全集
  （顶层/嵌套对象/数组某一条/可选分支/混合数组/整个请求体是字符）——
  响应、日志、指标均无原始值，敏感错误可定位（loc/type/redacted），
  同请求非敏感字段错误仍回显 input，日志明细与响应明细逐字节一致；
  审计计数与日志输出路数（1/2/3 路）和渲染次数无关；
  24 并发填错请求的唯一探针不泄露、不串 request_id、计数精确。

新用例的失败断言带三类可区分前缀：`[泄露]`（原始值出现在观测面）、
`[口径不一致]`（不同通道/写法/路径的判定或计数对不上）、
`[并发串扰]`（并发行之间互相污染或丢计数）。
