"""请求/响应数据模型（含敏感字段，用于验证脱敏）。"""

from __future__ import annotations

from pydantic import BaseModel, Field


class LoginRequest(BaseModel):
    username: str = Field(min_length=1, max_length=64)
    password: str = Field(min_length=1, max_length=128)
    id_card: str | None = Field(default=None, pattern=r"^[0-9A-Za-z*]+$")


class LoginResponse(BaseModel):
    status: str
    request_id: str
