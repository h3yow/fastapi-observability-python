"""企业实名开通路由（复用通用关联标识/脱敏/指标/后台/下游能力）。

* 路由处理前，入口中间件已按模板把 :data:`ONBOARDING_POLICY` 绑定到
  当前请求的 ContextVar，因此这里的一切结构化日志、422 错误明细、
  下游调用记录都自动按同一份资料声明脱敏，判定口径一致；
* 结构化日志记录完整请求体（供排查），敏感值在日志层掩码；
* 下游实名核验调用走 :func:`downstream_post_json`，**真正发送的请求体
  已经过脱敏**——敏感输入不进入下游系统、不进入下游调用日志；
* 后台归档任务经 :func:`with_request_id` 包装，沿用同一 request_id，
  且只记录受理号等非敏感信息。
"""

from __future__ import annotations

import uuid

from fastapi import APIRouter, BackgroundTasks, HTTPException

from app.context import get_request_id
from app.enterprise.schemas import (
    EnterpriseOnboardingRequest,
    EnterpriseOnboardingResponse,
)
from app.observability.background import with_request_id
from app.observability.http import DownstreamError, downstream_post_json
from app.observability.logging import get_logger

logger = get_logger("app.enterprise")

router = APIRouter(prefix="/enterprise", tags=["enterprise"])

#: 下游实名核验地址（本地测试由 MockTransport 接管，不会真正出网）。
_VERIFY_URL = "https://verification.internal/enterprise/verify"


def _archive_accepted(accepted_no: str) -> None:
    """后台归档：只记录受理号（非敏感），验证 request_id 快照传播。"""
    logger.info(
        "onboarding archived",
        extra={"accepted_no": accepted_no, "seen_request_id": get_request_id()},
    )


@router.post("/onboarding", response_model=EnterpriseOnboardingResponse)
async def submit_onboarding(
    body: EnterpriseOnboardingRequest,
    background_tasks: BackgroundTasks,
) -> EnterpriseOnboardingResponse:
    """受理企业实名开通申请。"""
    request_id = get_request_id() or ""
    # 完整资料进结构化日志；敏感字段在日志层按资料声明掩码（log 通道计数）。
    logger.info("enterprise onboarding received", extra={"body": body})

    # 下游核验：发送内容在 http 层统一脱敏（downstream 通道计数）。
    try:
        await downstream_post_json(_VERIFY_URL, body.model_dump(by_alias=True))
    except DownstreamError as exc:
        logger.warning("onboarding verification unavailable", extra={"reason": exc.reason})
        raise HTTPException(status_code=502, detail="verification service unavailable") from exc

    accepted_no = f"ACC-{uuid.uuid4().hex[:16].upper()}"
    background_tasks.add_task(with_request_id(_archive_accepted), accepted_no)
    logger.info(
        "enterprise onboarding accepted",
        extra={"accepted_no": accepted_no, "contacts_count": len(body.contacts)},
    )
    return EnterpriseOnboardingResponse(
        status="accepted", accepted_no=accepted_no, request_id=request_id
    )
