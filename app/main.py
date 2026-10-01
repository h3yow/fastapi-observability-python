"""应用入口：装配全部可观测性能力并挂载路由。"""

from __future__ import annotations

from fastapi import FastAPI

from app.enterprise.routes import router as enterprise_router
from app.enterprise.schemas import ONBOARDING_POLICY
from app.observability.middleware import install_observability, register_route_policy
from app.routes import router as demo_router


def create_app() -> FastAPI:
    """创建并配置 FastAPI 应用实例。"""
    app = FastAPI(title="fastapi-observability-python", version="0.1.0")
    install_observability(app)

    # 登记资料场景：路由模板 -> 敏感策略。新增资料版本只需在场景包内
    # 更新模型/声明并在此登记一行，公共脱敏/指标代码无需修改。
    register_route_policy("/enterprise/onboarding", ONBOARDING_POLICY)

    app.include_router(demo_router)
    app.include_router(enterprise_router)
    return app


app = create_app()
