"""应用入口：装配全部可观测性能力并挂载示例路由。"""

from __future__ import annotations

from fastapi import FastAPI

from app.observability.middleware import install_observability
from app.routes import router as demo_router


def create_app() -> FastAPI:
    """创建并配置 FastAPI 应用实例。"""
    app = FastAPI(title="fastapi-observability-python", version="0.1.0")
    install_observability(app)
    app.include_router(demo_router)
    return app


app = create_app()
