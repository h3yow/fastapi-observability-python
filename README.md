# fastapi-observability-python

FastAPI 服务的本地可观测性 bootstrap：请求关联标识贯穿（同步处理 / 后台任务 /
下游调用）、按路由模板聚合的 Prometheus 指标、日志与错误响应脱敏、未处理异常
到稳定错误码的映射。

## 快速开始

```bash
uv sync
.venv/bin/uvicorn main:app --reload     # 启动服务
.venv/bin/python -m pytest -s           # 运行测试（打印每个用例的输入/关联ID/判定依据）
```

## 目录

- `app/context.py` — request_id 的上下文存储与沿用/替换规则
- `app/observability/middleware.py` — 入口中间件（标识解析、计时、统一指标）
- `app/observability/metrics.py` — 线程安全计数器/直方图与 `/metrics`
- `app/observability/logging.py` — JSON 结构化日志与敏感字段脱敏
- `app/observability/errors.py` — 异常 → 稳定对外错误码
- `app/observability/background.py` — 后台任务 request_id 快照
- `app/observability/http.py` — 下游调用 request_id 透传
- `tests/` — 并发隔离 / 脱敏 / 异常映射 / 指标口径测试

完整规则与本地验证步骤见 [docs/observability.md](docs/observability.md)。
