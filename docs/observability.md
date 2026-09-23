# 本地可观测性能力说明

本服务在 FastAPI 上内置了一套无需外部组件即可本地验证的可观测性能力：
**关联标识（request_id）贯穿、按路由模板聚合的指标、日志/错误响应脱敏与异常映射**。
三者共享同一入口中间件与错误码口径，保证“日志、指标、对外错误响应”一致且可解释。

- 应用入口：`app/main.py`（根目录 `main.py` 保留兼容，`uvicorn main:app` 可用）
- 核心代码：`app/context.py`、`app/observability/`
- 测试：`tests/`（18 个用例，覆盖并发隔离、脱敏、异常映射、指标口径）

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

---

## 3. 脱敏范围

脱敏逻辑在 `app/observability/logging.py`，对日志与对外信息分别处理。

### 3.1 敏感字段（键名子串、大小写不敏感匹配）

命中以下任一模式的**字段名**，其整个值被替换为固定掩码 `***REDACTED***`
（不保留长度信息）：

- 凭据/令牌：`password`/`passwd`、`secret`、`token`、`api_key`（含 `apikey`）、
  `authorization`、`credential`
- 个人敏感信息：`id_card`（身份证）、`phone`/`mobile`、`email`、`ssn`

处理范围：

- dict / list / tuple / set **递归脱敏**（深度上限 6、每层 100 项，防止异常数据
  拖垮采集）；Pydantic 模型经 `model_dump()` 展开后同样脱敏；
- HTTP 请求头中 `Authorization`、`Cookie`、`Proxy-Authorization`、`X-Api-Key`
  整体掩码（记录错误上下文时使用）；
- 校验错误（422）详情经同一脱敏函数处理，避免 pydantic 回显的原始输入泄露。

### 3.2 日志与响应的边界

- **日志**：单行 JSON 到 stderr，固定字段 `ts/level/logger/message/request_id`，
  所有 `extra` 字段递归脱敏；未处理异常记录 `exception_type` 与**完整 traceback**
  （`exc_info`），供内部排查——原始异常链路只进日志。
- **对外响应**：成功响应的模型本身不回传敏感字段（如登录只返回 status/request_id）；
  错误响应只包含稳定的 `code/message/request_id`（422 另附字段级定位 details），
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

---

## 5. 示例接口

| 方法 & 路径 | 用途 |
|---|---|
| `GET /` | 正常同步响应，响应体含当前 request_id |
| `POST /login` | 含 password/id_card，验证日志与响应脱敏 |
| `GET /users/{user_id}` | 路径参数，验证指标按模板聚合 |
| `GET /bg?note=` | 调度线程池后台任务，验证 request_id 快照传播 |
| `GET /downstream?url=` | 下游调用，验证 `X-Request-ID` 透传（测试用 MockTransport） |
| `GET /boom?kind=http\|other` | 显式 HTTPException(409) 或未处理异常(500) |
| `GET /metrics` | Prometheus 文本指标 |

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

### 6.3 自动化测试

```bash
.venv/bin/python -m pytest -s
```

- `-s` 会打印每个用例的**输入、关联标识与判定依据**（`[用例] ...` 行）；
- 断言失败消息均带可区分原因（期望/实际值与场景说明）。

测试分布：

- `tests/test_concurrency.py`：50 并发标识隔离、并发生成唯一性、
  沿用/替换 9 个边界、并发日志关联、后台任务、下游透传、异常响应关联；
- `tests/test_sanitization.py`：嵌套脱敏、请求头脱敏、登录日志/响应无泄露、
  未处理异常“对外 500 + 对内完整堆栈”、错误码稳定可区分、422 详情、下游 502；
- `tests/test_metrics.py`：四类结果同口径、高基数路径维度聚合、
  直方图与计数一致、16 线程 × 200 请求并发计数正确。
