# fastapi-observability-python

FastAPI 服务的本地可观测性 bootstrap：请求关联标识贯穿（同步处理 / 后台任务 /
下游调用）、按路由模板聚合的 Prometheus 指标、日志与错误响应脱敏、未处理异常
到稳定错误码的映射，并内置**企业实名开通**资料场景：路径化敏感声明（嵌套 /
数组 / 别名 / 可选分支，同名字段可按子结构区分级别）、422 安全明细与
脱敏审计低基数计数。新增资料字段只需在场景包内同步模型与声明，无需改公共配置。

## 快速开始

```bash
uv sync
.venv/bin/uvicorn main:app --reload     # 启动服务
.venv/bin/python -m pytest -s           # 运行测试（打印每个用例的输入/关联ID/判定依据）
```

## 目录

- `app/context.py` — request_id 的上下文存储与沿用/替换规则
- `app/observability/middleware.py` — 入口中间件（标识解析、资料策略绑定、计时、统一指标）
- `app/observability/metrics.py` — 线程安全计数器/直方图与 `/metrics`
- `app/observability/audit.py` — 脱敏审计计数器（field_category/channel/error_category 低基数）
- `app/observability/sensitive.py` — 路径化敏感声明、归一化匹配、统一脱敏、422 明细清洗
- `app/observability/logging.py` — JSON 结构化日志与敏感字段脱敏
- `app/observability/errors.py` — 异常 → 稳定对外错误码
- `app/observability/background.py` — 后台任务 request_id 快照
- `app/observability/http.py` — 下游调用 request_id 透传与边界脱敏（GET/POST JSON）
- `app/enterprise/` — 企业实名开通场景：资料模型 + 敏感声明（同文件）+ 受理路由
- `tests/` — 并发隔离 / 脱敏 / 异常映射 / 指标口径 / 企业开通 / 脱敏审计并发 测试

完整规则与本地验证步骤见 [docs/observability.md](docs/observability.md)。
