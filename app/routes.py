"""Demo routes exercising every observability path.

* ``GET  /``                 - normal success
* ``POST /login``            - request body incl. a password field
* ``GET  /items/{item_id}``  - typed path parameter (422 on bad input)
* ``GET  /background/{key}`` - schedules a background task
* ``GET  /boom``             - raises an unhandled exception (500)
* ``GET  /downstream``       - performs a downstream HTTP call (id propagated)
* ``GET  /metrics``          - dumps the in-memory metrics snapshot
"""
from __future__ import annotations

import httpx
from fastapi import APIRouter, Request
from fastapi.background import BackgroundTasks
from pydantic import BaseModel

from app.context import HEADER_NAME, get_request_id
from app.downstream import call_downstream
from app.logging_setup import get_logger
from app.metrics import registry

logger = get_logger("observability.routes")

router = APIRouter()

#: key -> correlation id observed *inside* the background task
background_observations: dict[str, str] = {}


class LoginBody(BaseModel):
    username: str
    password: str


class TokenProbe(BaseModel):
    # constrained integer: sending a string here makes pydantic echo the
    # raw (secret-looking) input back in the validation details, proving
    # the middleware sanitizes details, not just happy-path bodies.
    # Field name ends in "token", so it is a masked credential field.
    lifetime_token: int


@router.get("/")
def read_root() -> dict:
    return {"hello": "world", "request_id": get_request_id()}


@router.post("/login")
def login(body: LoginBody) -> dict:
    # Logging the raw body on purpose: the logging pipeline must mask it.
    logger.info(
        "login attempt",
        extra={"extra_fields": {"body": body.model_dump()}},
    )
    # password is deliberately never echoed back
    return {"username": body.username, "request_id": get_request_id()}


@router.get("/items/{item_id}")
def get_item(item_id: int) -> dict:
    return {"item_id": item_id, "request_id": get_request_id()}


@router.post("/token-probe")
def token_probe(body: TokenProbe) -> dict:
    return {"lifetime_token": body.lifetime_token,
            "request_id": get_request_id()}


def _record_background_observation(key: str) -> None:
    """Background work: capture whichever id the task context carries."""
    background_observations[key] = get_request_id()
    logger.info(
        "background task finished",
        extra={"extra_fields": {"bg_key": key}},
    )


@router.get("/background/{key}")
async def background_demo(key: str, bg: BackgroundTasks) -> dict:
    bg.add_task(_record_background_observation, key)
    return {"scheduled": key, "request_id": get_request_id()}


@router.get("/boom")
def boom() -> dict:
    # The raw exception chain is logged server-side; the caller only gets
    # the stable INTERNAL_ERROR envelope.
    raise RuntimeError("boom: unexpected failure")


@router.get("/downstream")
async def downstream_demo(request: Request, fail: bool = False) -> dict:
    # Transport stays in-process so the demo works with no other server.
    transport = httpx.ASGITransport(app=request.app)
    path = "/boom" if fail else "/"
    async with httpx.AsyncClient(
        transport=transport, base_url="http://downstream.local"
    ) as client:
        response = await call_downstream(client, "GET", path)
    return {
        "request_id": get_request_id(),
        "upstream_status": response.status_code,
        "upstream_request_id": response.headers.get(HEADER_NAME),
    }


@router.get("/metrics")
def metrics_view() -> dict:
    return {"metrics": registry.snapshot()}
