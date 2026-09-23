# fastapi-observability-python

在 FastAPI 服务中补齐的一套**本地即可验证**的可观测性能力：贯穿全链路的关联标识、
按路由模板聚合的请求指标、脱敏的结构化日志与稳定的对外错误码。日志、指标、错误响应
三者通过同一个 `request_id` 与同一套错误码保持一致、可互相解释。

## 目录结构

```
app/
  context.py          # 关联标识：生成、入站裁决、ContextVar 绑定
  middleware.py       # 纯 ASGI 中间件：标识注入、计时、指标、错误信封归一
  metrics.py          # 线程安全的内存指标注册表（计数/错误分类/耗时分桶）
  sanitize.py         # 敏感字段与凭据头脱敏
  errors.py           # 稳定错误码与统一错误信封
  logging_setup.py    # JSON 结构化日志（自动带 request_id，输出前脱敏）
  downstream.py       # 下游调用封装：传播标识、异常归一为 DownstreamError
  routes.py           # 演示接口（成功/校验/异常/后台任务/下游/指标）
  main.py             # 应用工厂
tests/                # 并发隔离、脱敏、异常映射等测试
```

## 1. 关联标识（Correlation ID）传播规则

- **载体**：HTTP 请求头 `X-Request-Id`（收发同名，见 `app/context.py:HEADER_NAME`）。
- **入站裁决（确定性规则，二选一）**：
  1. 调用方传入的值去除首尾空白后，满足
     `^[A-Za-z0-9][A-Za-z0-9._-]{7,127}$`（字母/数字开头，长度 8–128，
     仅允许字母数字 `.` `_` `-`）→ **原样沿用**，并在完成日志中记录
     `request_id_reused=true`；
  2. 缺失、为空或不满足规则 → 服务端**替换**为新生成的 32 位小写十六进制 UUID
     （`uuid4().hex`），不回显非法原值。
  - 字符白名单 + 长度上限确保入站标识无法注入日志伪造内容或造成头滥用。
- **传播范围**：中间件在请求入口把标识绑定到 `contextvars.ContextVar`，
  因而同一请求在以下位置读到的都是同一个值：
  - async 处理器、**同步处理器**（经 anyio 线程池，线程池复制上下文运行）；
  - FastAPI `BackgroundTasks` 后台任务（与响应在同一 app 任务上下文内执行）；
  - 通过 `app.downstream.call_downstream` 发起的下游 HTTP 调用
    （自动注入 `X-Request-Id`；上下文意外为空时现场补生成，绝不向下游传空值）。
- **并发隔离**：`ContextVar` 的值随 asyncio Task / 工作线程的上下文复制而隔离，
  绑定在 `finally` 中 reset；并发请求之间不会串扰，请求结束后不污染外层上下文。
- **对外可观测**：每个响应（含 4xx/5xx）都回写 `X-Request-Id` 响应头；错误信封
  正文内的 `error.request_id` 与之相同，客户端可凭此值要求服务端排查。

## 2. 指标口径与基数约束

- **端点**：`GET /metrics` 输出 JSON 快照。
- **序列标签**：`(method, route, status, error_code)`。
  - `route` 取匹配到的**路由模板**（如 `/items/{item_id}`），永远不取具体路径；
    未匹配路由统一记为常量 `__unmatched__`，因此 200 个不同的 404 路径只产生 1 条序列。
  - `error_code` 来自固定错误码集合（成功为空），不使用异常文本等自由值。
- **每个序列记录**：请求数 `count`、错误数 `error_count`、平均耗时
  `avg_latency_ms`、按状态码计数、按错误码计数，以及固定边界的耗时直方图
  （桶上界 ms：5/10/25/50/100/250/500/1000/2500，加一个 `+Inf` 桶；
  上界包含，每次观测恰好落入一个桶）。
- **统一口径**：正常响应、参数校验失败（422）、未匹配路由（404）、内部异常（500）
  走完全相同的采集通道——每个请求恰好产生一条观测，中间件在异常分支也保证记账。
- **基数上界**：序列总数 ≤ 方法数 × 已注册模板数 × 状态码数 × 错误码数，
  与请求量、路径形态无关，维度不会失控。
- **并发与开销**：所有更新在一把短生命周期锁内完成，仅做整数/定长列表运算（O(1)）；
  压测下含完整 ASGI 与 JSON 日志开销约 0.6ms/请求（TestClient，参考值）。

> 说明：演示用的 `/downstream` 通过 ASGI 内网传输调用本应用，下游请求是一次
> 独立入口调用，会单独计入一条指标序列（生产中对应下游服务各自统计自己的入口）。

## 3. 脱敏范围

- **结构化字段**（日志 `extra_fields` 与错误信封 `details` 输出前统一过
  `sanitize()`）：键名先做归一化（转小写、剔除所有非 `[a-z0-9]` 字符），
  命中精确集合或以受控凭据后缀结尾即整体替换为 `***`：
  - 凭据/令牌：`password`/`passwd`/`pwd`/`secret`/`token`/`apiKey`/
    `access_token`/`refresh_token`/`authorization`/`credentials`/`privateKey`
    （后缀匹配覆盖 `x-auth-token`、`db_password` 等变体）；
  - 个人敏感信息（精确匹配）：`id_card`/`passport`/`ssn`/`credit_card`/
    `card_no`/`cvv`/`phone`/`mobile`/`email`/`address`。
  - 字典、列表、元组递归处理；循环引用与超过 8 层深度的结构有防护。
- **凭据头**：`Authorization`、`Proxy-Authorization`、`Cookie`、`Set-Cookie`、
  `X-Api-Key`、`X-Auth-Token` 记录时整体掩码（`X-Request-Id` 等非密头保留）。
- **自由文本**：内嵌的 `Bearer <token>` / `Basic <cred>` 由正则抹除。
- **校验错误回显**：Pydantic 会把非法原值放在错误明细的 `input`（及 `ctx`）里，
  而字段名只作为 `loc` 列表中的值出现。通用键名脱敏覆盖不到，因此对校验明细做
  **位置感知脱敏**：只要某条错误的 `loc` 命中敏感字段，其 `input`/`ctx` 整体掩码
  （见 `/token-probe` 演示与 `test_validation_error_echo_is_masked_by_loc`），
  普通字段的回显（如 `GET /items/abc` 中的 `abc`）原样保留。
- **错误响应**：`POST /login` 的响应不回显密码；`/boom` 的响应不包含异常类型、
  异常消息或堆栈——这些只出现在服务端日志（`level=error`，带完整 `exc_info`
  原始异常链、`error_type`、路由模板与 `request_id`）。

## 4. 错误码映射

所有 4xx/5xx 响应统一为信封：

```json
{"error": {"code": "STABLE_CODE", "message": "固定文案",
           "request_id": "…", "details": { /* 可选，已脱敏 */ }}}
```

| 场景 | HTTP | code | 内部留存 |
|---|---|---|---|
| 正常 | 2xx/3xx | 无错误信封 | access 日志 |
| 请求体/参数校验失败 | 422 | `VALIDATION_ERROR` | access 日志（warning）+ 结构化 loc 明细 |
| 路由未匹配 | 404 | `NOT_FOUND` | 路由归一为 `__unmatched__`，不回显路径 |
| 方法不允许 | 405 | `METHOD_NOT_ALLOWED` | access 日志 |
| 下游传输失败 / 下游 5xx | 502 | `UPSTREAM_ERROR` | 完整异常链 + 上游状态码 |
| 未处理异常 | 500 | `INTERNAL_ERROR` | **完整原始异常链**（error 日志 + exc_info） |
| 其他错误状态 | 对应状态 | `HTTP_<status>` | access 日志 |

`UPSTREAM_ERROR` 与 `INTERNAL_ERROR` 对外稳定可区分，客户端可据此分支处理；
原始异常永不出现在响应中，只能凭 `request_id` 在服务端日志反查。

## 5. 本地验证方法

```bash
# 环境（Python 3.14，uv）
uv sync

# 跑全部测试：并发标识隔离、脱敏、异常映射、指标口径/基数
uv run pytest -q -s          # -s 可看到每条断言打印的 输入/request_id/判定依据

# 启动服务
uv run uvicorn main:app --reload

# 手工验证
curl -s localhost:8000/ -H 'X-Request-Id: my-trace-001' -i   # 沿用调用方标识
curl -s localhost:8000/items/abc -i                          # 422 VALIDATION_ERROR
curl -s -X POST localhost:8000/token-probe \
  -H 'content-type: application/json' \
  -d '{"lifetime_token":"tok-raw-secret-9"}'                 # 422 明细中的敏感回显被掩码
curl -s localhost:8000/no/such/path/123 -i                   # 404 NOT_FOUND
curl -s localhost:8000/boom -i                               # 500 INTERNAL_ERROR（不泄漏异常）
curl -s localhost:8000/downstream -H 'X-Request-Id: t-1' -i  # 下游收到同一标识
curl -s localhost:8000/downstream?fail=true -i               # 502 UPSTREAM_ERROR
curl -s localhost:8000/metrics | python -m json.tool         # 按模板聚合的指标
curl -s -X POST localhost:8000/login -H 'content-type: application/json' \
  -d '{"username":"alice","password":"s3cr3t"}' -i           # 密码不回显；服务端日志已掩码
```

服务端 stderr 输出每行一条 JSON 日志，字段包含 `ts/level/request_id/message`
及业务字段（已脱敏）；错误日志额外含 `error_type` 与 `exc_info`。
