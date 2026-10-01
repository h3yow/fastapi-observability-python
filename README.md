# fastapi-observability-python

FastAPI 服务的本地可观测性 bootstrap：请求关联标识贯穿（同步处理 / 后台任务 /
下游调用）、按路由模板聚合的 Prometheus 指标、日志与错误响应脱敏、未处理异常
到稳定错误码的映射，以及**企业实名开通等结构化资料场景的路径感知脱敏与
低基数脱敏审计**（敏感声明随资料模型同源，新增字段/版本免改公共配置）。

## 快速开始

```bash
uv sync
.venv/bin/uvicorn main:app --reload     # 启动服务
.venv/bin/python -m pytest -s           # 运行测试（打印每个用例的输入/关联ID/判定依据）
```

## 目录

- `app/context.py` — request_id 的上下文存储与沿用/替换规则
- `app/observability/middleware.py` — 入口中间件（标识解析、计时、统一指标）
- `app/observability/metrics.py` — 线程安全计数器/直方图、脱敏审计与 `/metrics`
- `app/observability/sensitivity.py` — 场景化敏感策略、写法归一、递归脱敏与审计
- `app/observability/logging.py` — JSON 结构化日志（委托统一脱敏判定）
- `app/observability/errors.py` — 异常 → 稳定对外错误码（422 明细安全清洗）
- `app/observability/codes.py` — 稳定错误码常量（单一事实来源）
- `app/observability/background.py` — 后台任务 request_id 快照
- `app/observability/http.py` — 下游调用 request_id 透传与请求体脱敏记录
- `app/schemas.py` / `app/schemas_enterprise.py` — 登录 / 企业实名开通资料模型与敏感声明
- `tests/` — 并发隔离 / 脱敏 / 异常映射 / 指标口径 / 企业开通场景 / 脱敏审计测试

完整规则与本地验证步骤见 [docs/observability.md](docs/observability.md)。
