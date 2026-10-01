"""示例路由：同步处理、后台任务、下游调用、参数校验、异常。

所有路由都处于可观测性中间件之后（中间件在 create_app 中先安装），
因此 request_id 在路由函数、线程池后台任务、下游调用中保持一致。
"""

from __future__ import annotations

from fastapi import APIRouter, BackgroundTasks, HTTPException

from app.context import get_request_id
from app.observability.background import with_request_id
from app.observability.http import DownstreamError, downstream_get, downstream_post
from app.observability.logging import get_logger
from app.observability.sensitivity import policy_for_model
from app.schemas import LoginRequest, LoginResponse
from app.schemas_enterprise import (
    EnterpriseOnboardingRequest,
    EnterpriseOnboardingResponse,
)

logger = get_logger("app.routes")

router = APIRouter()


@router.get("/")
async def read_root() -> dict[str, str]:
    """正常同步响应；request_id 由响应头返回。"""
    return {"status": "ok", "request_id": get_request_id() or ""}


@router.post("/login", response_model=LoginResponse)
async def login(body: LoginRequest) -> LoginResponse:
    """登录示例：密码/身份证等敏感字段可进入日志层并被脱敏。

    响应体本身不回传敏感字段；日志 extra 中的请求体经统一脱敏。
    """
    logger.info("login request", extra={"body": body})
    return LoginResponse(status="accepted", request_id=get_request_id() or "")


@router.post(
    "/enterprise/onboarding",
    response_model=EnterpriseOnboardingResponse,
)
async def enterprise_onboarding(
    body: EnterpriseOnboardingRequest,
    background_tasks: BackgroundTasks,
) -> EnterpriseOnboardingResponse:
    """企业实名开通：多层嵌套/数组/别名/可选分支资料。

    敏感判定来自与模型同源的场景策略：

    * 日志记录的是模型对象，日志层自动解析绑定策略后递归脱敏
      （路径感知、写法归一、数组逐条），各处共用同一判定；
    * 下游实名校验调用只在**调用记录**中写入脱敏后的请求体副本，
      真实报文照常发送；
    * 响应模型只含非敏感汇总字段；
    * 校验失败由统一 422 处理器按同策略清洗（见 observability/errors.py）。
    """
    logger.info("enterprise onboarding request", extra={"body": body})
    try:
        await downstream_post(
            "https://verification.invalid/verify",
            json_body=body.model_dump(mode="json"),
            # 下游调用记录按同一资料场景策略脱敏，口径与日志/响应一致。
            policy=policy_for_model(EnterpriseOnboardingRequest),
        )
    except DownstreamError as exc:
        logger.warning("verification downstream failed", extra={"reason": exc.reason})
        raise HTTPException(status_code=502, detail="verification unavailable") from exc

    background_tasks.add_task(
        with_request_id(_write_onboarding_audit),
        body.enterprise_name,
    )
    return EnterpriseOnboardingResponse(
        status="accepted",
        request_id=get_request_id() or "",
        enterprise_name=body.enterprise_name,
    )


def _write_onboarding_audit(enterprise_name: str) -> None:
    """开通后台审计任务：只记录非敏感企业名，request_id 快照传播。"""
    logger.info(
        "onboarding audit note written",
        extra={"enterprise_name": enterprise_name, "seen_request_id": get_request_id()},
    )


@router.get("/users/{user_id}")
async def get_user(user_id: int) -> dict[str, object]:
    """路径参数示例：路由模板为 /users/{user_id}，高基数实体 ID 不进入指标维度。"""
    return {"user_id": user_id, "request_id": get_request_id()}


def _write_audit_note(note: str) -> None:
    """同步后台函数：在线程池中执行，须能看到提交时快照的 request_id。"""
    seen = get_request_id()
    logger.info("audit note written", extra={"note": note, "seen_request_id": seen})


@router.get("/bg")
async def background_demo(background_tasks: BackgroundTasks, note: str = "hi") -> dict[str, str]:
    """调度一个线程池后台任务；任务日志与请求共享同一 request_id。"""
    request_id = get_request_id()
    # 在请求上下文中包装，快照当前 request_id。
    background_tasks.add_task(with_request_id(_write_audit_note), note)
    logger.info("background task scheduled", extra={"note": note})
    return {"status": "scheduled", "request_id": request_id or ""}


@router.get("/downstream")
async def downstream_demo(url: str = "https://example.com/") -> dict[str, object]:
    """下游调用示例：request_id 透传到下游 X-Request-ID 头。

    本地使用 httpx MockTransport 验证（见 tests）；默认 URL 在无外网时
    会返回稳定的 DOWNSTREAM_ERROR，不会泄露下游细节。
    """
    try:
        payload = await downstream_get(url)
    except DownstreamError as exc:
        logger.warning("downstream failed in route", extra={"reason": exc.reason})
        raise HTTPException(status_code=502, detail="downstream unavailable") from exc
    return {"downstream_ok": True, "request_id": get_request_id(), "payload_keys": list(payload)[:10]}


@router.get("/boom")
async def boom(kind: str = "error") -> dict[str, str]:
    """显式/隐式异常示例：kind=http 抛 HTTPException，其余抛未处理异常。"""
    if kind == "http":
        raise HTTPException(status_code=409, detail="simulated conflict")
    raise RuntimeError("simulated unhandled failure")
