# 本地可观测性能力说明

本服务在 FastAPI 上内置了一套无需外部组件即可本地验证的可观测性能力：
**关联标识（request_id）贯穿、按路由模板聚合的指标、日志/错误响应/下游调用脱敏、
异常到稳定错误码的映射、资料型场景（企业实名开通）的路径化敏感声明与脱敏审计**。
所有能力共享同一入口中间件、同一份资料声明与错误码口径，保证“日志、指标、
对外错误响应、下游调用记录”一致且可解释。

- 应用入口：`app/main.py`（根目录 `main.py` 保留兼容，`uvicorn main:app` 可用）
- 核心代码：`app/context.py`、`app/observability/`
- 企业实名开通场景：`app/enterprise/`（模型 + 敏感声明 + 路由同包维护）
- 测试：`tests/`（34 个用例，覆盖并发隔离、脱敏、异常映射、指标口径、
  企业开通嵌套/数组/别名/可选分支不泄露、脱敏审计并发正确性）

> **设计原则：扩展而非另起一套。** 新增资料场景时，只需在自己的包里提供
> Pydantic 模型 + 一棵敏感声明树，并在 `create_app()` 登记一行
> “路由模板 → 策略”；脱敏、422 安全明细、下游边界、审计计数立即生效，
> 不需要改动任何公共脱敏/指标代码。

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
| `sensitive_redactions_total` | Counter | 敏感值被掩码的次数（仅 `field_category`/`channel`/`error_category` 三个低基数标签，口径见 4.4） |

标签集合（计数器与直方图口径一致）：

| 标签 | 取值 | 基数控制 |
|---|---|---|
| `method` | `GET/POST/...` 白名单归一，白名单外为 `OTHER` | 固定 ≤10 |
| `route` | **路由模板**（如 `/users/{user_id}`）；未匹配路由统一为 `__unmatched__` | = 路由数，与流量无关 |
| `status` | 最终响应状态码（含异常处理器转换后的码） | 有限 |
| `outcome` | `success`(2xx/3xx) / `client_error`(4xx) / `server_error`(5xx) | 3 |
| `error_code` | 对外错误码（见第 5 节）；成功为空串 | 有限枚举 |

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

---

## 3. 脱敏范围

脱敏的统一入口是 `app/observability/sensitive.py` 的 `redact_with_policy()`；
日志（`logging.py` 的 `redact_value`）、422 错误明细（`errors.py`）、
下游调用（`http.py`）都调用它，因此同一字段在任何通道的判定完全一致。

### 3.1 两种判定来源

1. **资料声明（路径化，优先）**：请求命中已登记的资料路由时，入口中间件
   把对应 `SensitivePolicy` 绑定到当前请求的 ContextVar，之后按**声明路径**
   判定（见第 4 节）。同一字段名在不同子结构中可以有不同级别。
2. **全局凭据模式（兜底）**：未登记资料策略的路由（如 `/login`），或声明
   树之外出现的字段，仍按字段名子串/大小写不敏感模式命中即掩码：
   - 凭据/令牌：`password`/`passwd`、`secret`、`token`、`api_key`（含 `apikey`）、
     `authorization`、`credential`
   - 个人敏感信息：`id_card`（身份证）、`phone`/`mobile`、`email`、`ssn`

两种来源对同一字段冲突时，声明优先；声明外的凭据类字段仍由全局模式兜底，
其余声明外字段输入保留，便于前端提示与排查。

处理范围：

- dict / list / tuple / set **递归脱敏**（深度上限 10、每层 200 项，防止异常数据
  拖垮采集）；Pydantic 模型经 `model_dump()` 展开后同样脱敏；
- HTTP 请求头中 `Authorization`、`Cookie`、`Proxy-Authorization`、`X-Api-Key`
  整体掩码（记录错误上下文时使用）；
- 可选字段缺省为 `null` 时原样保留、不掩码也不计数（null 不携带敏感信息）。

### 3.2 日志与响应的边界

- **日志**：单行 JSON 到 stderr，固定字段 `ts/level/logger/message/request_id`，
  所有 `extra` 字段递归脱敏；未处理异常记录 `exception_type` 与**完整 traceback**
  （`exc_info`），供内部排查——原始异常链路只进日志。
- **对外响应**：成功响应的模型本身不回传敏感字段（如登录只返回 status/request_id，
  开通受理只返回 status/accepted_no/request_id）；错误响应只包含稳定的
  `code/message/request_id`（422 另附字段级定位 details，见 4.2），
  **绝不包含原始异常消息、堆栈或下游返回体**。

---

## 4. 企业实名开通：路径化敏感声明

企业实名开通请求体允许多层嵌套对象、数组、别名字段与可选分支，联系人、证件、
附件都可能是数组，且字段会随资料版本持续增加。相关代码在 `app/enterprise/`，
核心机制在 `app/observability/sensitive.py`。

### 4.1 敏感字段声明方式（随资料版本同步生效）

资料模型与敏感声明**同文件维护**（`app/enterprise/schemas.py`）：

- `leaf("<category>")` 声明一个**敏感叶子**，其值整体替换为固定掩码
  `***REDACTED***`（不保留长度信息）；
- `plain()` 声明一个**显式非敏感**字段，值保留、不掩码、不计数；
- `group({...})` 声明对象；键规格形如 `"规范名|别名1|别名2"`，
  首个名字是规范字段名（也是 422 `loc` 对外路径），其余是语义别名；
- `many(node)` 声明数组，对**每一条**元素套用同一份子声明，不会漏条目。

字段类别（`field_category`，有限枚举）：

| 类别 | 含义 | 企业开通中的例子 |
|---|---|---|
| `credential` | 密码/密钥/令牌/凭据 | 声明外的 `debugToken` 等全局兜底 |
| `id_number` | 法定证件号 | 联系人证件 `doc_number`/`cert_no` |
| `contact` | 联系方式 | `mobile`/`phone`/`email` |
| `finance` | 财务账号 | `bank_account.account_number` |
| `name` | 个人/主体姓名 | `enterprise_name`、联系人 `name` |
| `business` | 企业内部业务标识（按内部数据处理） | 统一社会信用代码、影像 `file_id`/`image_id` |
| `non_sensitive` | 显式非敏感，保留不计数 | `industry`、附件文件名、开户行、备注 |
| `unknown` | 仅全局模式命中但无法归类的兜底类别 | — |

**同名字段不同级别由路径决定**，例如：

- `contacts[].name` 是联系人**个人姓名** → `leaf("name")` 掩码；
- `attachments[].name` 是**文件名** → `plain()` 保留（前端要回显）。

### 4.2 匹配范围：归一化、别名、数组、可选分支

- **写法归一**：`normalize_key()` 先按 camelCase 拆词，再忽略大小写与
  `_`/`-`/空格分隔符。因此 `phoneNumber`、`phone_number`、`PHONE-NUMBER`、
  `Phone Number` 是同一个字段；入站 Pydantic 侧用 `AliasChoices` 接受同样的
  写法集合，两侧覆盖一致。
- **语义别名**：需要把写法差异很大的字段视为同一字段时，在声明里显式登记
  （如 `mobile|phone|phoneNumber`、`file_id|oss_key`）。
- **数组穿透**：`contacts`/`id_documents`/`attachments` 为 `many(...)`，
  每个元素独立按子声明判定，任意下标都不漏。
- **可选分支**：`email`、`bank_account`、`attachments`、`id_documents` 可缺省；
  出现即按声明处理，缺省不产生任何事件。
- **声明外字段**：凭据类（token/password/...）仍由全局模式兜底掩码，
  普通字段保留。

新增资料字段的流程：在 `schemas.py` 的模型里加字段 → 在同一文件的声明树里
用 `leaf()` 或 `plain()` 登记级别 →（若是新路由）在 `app/main.py` 登记一行
模板与策略。`tests/test_enterprise_onboarding.py` 的
`test_model_fields_are_covered_by_policy` 会递归核对“模型每个字段都已在
声明中登记”，**漏登记会直接导致测试失败**，无需人工维护公共配置。

### 4.3 422 校验错误明细的安全展示与兼容边界

参数校验失败仍返回 `422 VALIDATION_FAILED`，`error.details` 为字段级数组，
每条只保留**可定位、可解释但不泄密**的信息：

| 字段 | 内容 | 安全说明 |
|---|---|---|
| `loc` | 稳定字段路径，如 `["body","contacts",0,"mobile"]` | 字段名统一为**规范名**（与请求用 camelCase 还是下划线无关），数组下标保留；`body` 前缀保留 |
| `type` | pydantic 失败规则（如 `string_too_short`） | 只描述规则，不含值 |
| `error_category` | 稳定错误类别（见下） | 有限枚举，可直接用于前端文案/统计 |
| `msg` | 安全提示 | 敏感字段与 `value_error` 用通用文案，不回显输入 |
| `input` | 非敏感字段保留原始输入；敏感字段为 `***REDACTED***` | 便于前端对非敏感字段提示与回填 |
| `ctx` | 仅保留规则参数（如 `min_length`/`pattern`） | 剔除内嵌的异常对象 |
| `url` | — | 一律剔除 |

稳定错误类别（`error_category`）：`missing`（必填缺失，不回显 input，因为
pydantic v2 缺失错误的 input 是整个父对象，可能含兄弟敏感字段）、
`type_error`（类型/JSON 解析失败）、`value_rule`（枚举/字面值/自定义校验）、
`format`（正则格式）、`too_short`、`too_long`、`other`（兜底）。

结构型错误（如把 `contacts` 对象数组错传成一个手机号字符串）无法判断输入意图，
只要该子树含敏感字段就**保守掩码**。422 的对外明细与内部日志使用
`scrub_validation_errors()` 返回的**同一份结果**，保证两处判定一致、掩码只计一次。

兼容边界：既有 `/login` 的 422 行为保持兼容——字段定位、规则、request_id
不变；只是底层换成统一清洗函数，其输入在无策略时走全局凭据模式。

### 4.4 脱敏审计：指标口径与基数约束

新增 Counter 指标 `sensitive_redactions_total`，与 HTTP 指标同在
`GET /metrics` 暴露（`app/observability/audit.py`）。**一次“敏感值被掩码”
累加 1**，标签只有三个、全部来自有限枚举：

| 标签 | 取值 | 基数 |
|---|---|---|
| `field_category` | 4.1 表中的类别（不含 `non_sensitive`，它不计数） | 固定枚举 |
| `channel` | `log`（结构化日志）/ `response`（422 明细）/ `downstream`（下游请求体） | 3 |
| `error_category` | 仅 `response` 通道为 4.2 的错误类别；成功请求日志/下游为空串 | 固定枚举 + 空 |

口径要点：

- **绝不记录原始值、具体字段路径或 request_id**——这些要么高基数、要么可能
  二次泄密；标签归一化对未知值兜底为 `unknown`/`other`，任何调用笔误都不会
  造成新维度。
- 同一份数据的一次“呈现”每通道计数一次：接收日志计 `log`，下游发送前的脱敏
  计 `downstream`；已经脱敏的成品载荷进入下游调用日志时用 `RedactedPayload`
  标记，**不重复计数**。
- 维度总数 ≤ `类别数 × 通道数 × (错误类别数 + 1)`，与字段数量、别名数量、
  请求数量无关——字段/别名组合增多只会让声明树变大，不增加指标维度。
- 并发正确性：计数器由单把 `threading.Lock` 保护；一棵值树内的多次掩码先在
  请求本地批量汇总，再**一次加锁**刷新。测试以 16 线程 × 60 个开通请求验证
  计数不丢（每通道总数精确等于请求数 × 每请求敏感叶子数）、不串扰
  （每个请求的敏感值不出现在任何其他请求的日志/下游体中）。

### 4.5 下游边界

`downstream_post_json()` 在发送前统一脱敏：**真正发出的请求体就是脱敏后的
内容**，敏感输入既不进入下游系统、也不出现在下游调用日志里；`X-Request-ID`
透传规则与既有 GET 调用一致。本地测试用 httpx `MockTransport`，可直接检查
下游“实际收到”的请求体。

---

## 5. 稳定对外错误码

错误响应统一结构：

```json
{"error": {"code": "VALIDATION_FAILED", "message": "Request parameters failed validation.", "request_id": "..."}}
```

| HTTP | code | 触发场景 |
|---|---|---|
| 422 | `VALIDATION_FAILED` | 请求参数/体校验失败（明细安全展示规则见 4.3） |
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

---

## 6. 示例接口

| 方法 & 路径 | 用途 |
|---|---|
| `GET /` | 正常同步响应，响应体含当前 request_id |
| `POST /login` | 含 password/id_card，验证日志与响应脱敏 |
| `GET /users/{user_id}` | 路径参数，验证指标按模板聚合 |
| `GET /bg?note=` | 调度线程池后台任务，验证 request_id 快照传播 |
| `GET /downstream?url=` | 下游 GET 调用，验证 `X-Request-ID` 透传（测试用 MockTransport） |
| `GET /boom?kind=http\|other` | 显式 HTTPException(409) 或未处理异常(500) |
| `POST /enterprise/onboarding` | 企业实名开通：嵌套/数组/别名/可选分支资料，验证路径化脱敏、422 安全明细、下游边界与脱敏审计 |
| `GET /metrics` | Prometheus 文本指标（HTTP 指标 + `sensitive_redactions_total` 审计） |

---

## 7. 本地验证方法

### 7.1 准备

```bash
uv sync                       # 安装依赖（含 pytest 开发依赖）
```

### 7.2 启动并手工验证

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

# 4) 校验失败 / 未匹配路由 / 内部异常的稳定错误码
curl -s -X POST http://127.0.0.1:8000/login -H 'Content-Type: application/json' -d '{"username":"bob"}'
curl -s http://127.0.0.1:8000/no/such/path/12345
curl -s http://127.0.0.1:8000/boom?kind=other

# 5) 后台任务：响应后服务端日志仍打印同一 request_id
curl -s -H 'X-Request-ID: bg-demo-0001' 'http://127.0.0.1:8000/bg?note=hi'

# 6) 指标：注意 /users/1 与 /users/2 只有一个 route="/users/{user_id}" 维度
curl -s http://127.0.0.1:8000/users/1 >/dev/null
curl -s http://127.0.0.1:8000/users/2 >/dev/null
curl -s http://127.0.0.1:8000/metrics
```

企业实名开通（第 7 节场景；观察服务端日志与 `/metrics`，敏感值均显示为
`***REDACTED***`，而 `industry`/文件名/备注等非敏感值保留）：

```bash
# 7) 开通成功：响应只回 status/accepted_no/request_id；
#    下游核验请求体（本地由 MockTransport 接管）与日志中的资料均已脱敏
curl -s -X POST http://127.0.0.1:8000/enterprise/onboarding \
  -H 'Content-Type: application/json' -H 'X-Request-ID: onboard-demo-0001' \
  -d '{
    "profileVersion": "2",
    "enterpriseName": "示例科技有限公司",
    "creditCode": "91110000MA01ABCDXY",
    "industry": "it",
    "contacts": [{
      "contactName": "张三", "contactRole": "legal_rep",
      "phoneNumber": "13800138000", "emailAddress": "legal@example.com",
      "idDocuments": [{"docType": "id_card", "doc-number": "110101199001011234"}]
    }],
    "attachments": [{"fileName": "license.jpg", "oss-key": "OSS00000001KEY"}],
    "bankAccount": {"accountName": "对公结算账户", "bankName": "建设银行", "bankCard": "6222020000000001"},
    "remark": "加急"
  }'

# 8) 校验失败：loc 为规范字段路径（与写法无关），敏感输入掩码、非敏感输入保留
curl -s -X POST http://127.0.0.1:8000/enterprise/onboarding \
  -H 'Content-Type: application/json' \
  -d '{"enterpriseName":"X","creditCode":"91110000MA01ABCDXY","industry":"it",
       "contacts":[{"contactName":"李四","contactRole":"operator","phoneNumber":"1"}],
       "attachments":[{"fileName":"","fileId":"OSS00000002KEY"}]}'

# 9) 脱敏审计：仅 field_category/channel/error_category 三个低基数标签
curl -s http://127.0.0.1:8000/metrics | grep sensitive_redactions_total
```

期望结果：

- 第 7 步响应为 `200`，返回 `accepted_no` 与回带的 `X-Request-ID: onboard-demo-0001`；
  服务端日志 `enterprise onboarding received` 与下游 `payload` 中，联系人姓名/
  手机号/邮箱/证件号/银行账号/信用代码/影像 ID 全部为 `***REDACTED***`，
  `industry=it`、`name=license.jpg`（成功样本）、`bank_name=建设银行`、`remark` 保留；
- 第 8 步响应为 `422 VALIDATION_FAILED`，`details` 中手机号路径为
  `body.contacts[0].mobile`（不随 `phoneNumber` 写法变化）、错误类别
  `too_short`、`input` 为 `***REDACTED***`；附件文件名路径为
  `body.attachments[0].name`，`input` 原样保留为 `""`；
- 第 9 步每个标签组合一行计数，标签值不含任何请求 ID、字段路径或原始值。

### 7.3 自动化测试

```bash
.venv/bin/python -m pytest -s          # 全量（打印输入/关联ID/判定依据）
.venv/bin/python -m pytest tests/test_enterprise_onboarding.py -s
.venv/bin/python -m pytest tests/test_audit_concurrency.py -s
```

- `-s` 会打印每个用例的**输入、关联标识与判定依据**（`[用例] ...` 行）；
- 断言失败消息均带可区分前缀：`[泄露]`（敏感值外泄）、`[口径]`（不同通道判定
  不一致或误掩码）、`[定位]`（422 明细不可定位/不可解释）、`[串扰]`（并发下
  跨请求污染）、`[丢计数]`（并发计数缺失）、`[基数]`（维度失控）、
  `[兼容]`（既有 request_id/后台/下游行为回归）。

测试分布（共 34 个用例）：

- `tests/test_concurrency.py`：50 并发标识隔离、并发生成唯一性、
  沿用/替换 9 个边界、并发日志关联、后台任务、下游透传、异常响应关联；
- `tests/test_sanitization.py`：嵌套脱敏、请求头脱敏、登录日志/响应无泄露、
  未处理异常“对外 500 + 对内完整堆栈”、错误码稳定可区分、422 详情、下游 502；
- `tests/test_metrics.py`：四类结果同口径、高基数路径维度聚合、
  直方图与计数一致、16 线程 × 200 请求并发计数正确；
- `tests/test_enterprise_onboarding.py`：字段名归一、同名字段路径化级别、
  别名/数组/可选分支不泄露、成功路径四通道（响应/日志/下游/指标）无泄露、
  非敏感字段保留、422 明细（敏感掩码/非敏感保留/规范 loc/稳定错误类别）、
  缺失字段不回显父对象、数组内类型错误可定位、scrub 纯函数契约、
  模型与声明同步漂移检查、后台任务沿用 request_id；
- `tests/test_audit_concurrency.py`：审计标签低基数且合法、单请求计数精确、
  16 线程 × 60 开通请求并发不丢计数不串扰且维度有上界、计数器原语 16×500
  压力精确、脱敏开销不明显拖慢请求。
