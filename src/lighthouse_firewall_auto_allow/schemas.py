from __future__ import annotations

from pydantic import BaseModel, Field


class ReportRequest(BaseModel):
    hostname: str = Field(min_length=1, max_length=255)
    ipv4: str | None = Field(default=None, max_length=64)
    ipv6: str | None = Field(default=None, max_length=128)
    agent_version: str | None = Field(default=None, max_length=32)


class ReportResponse(BaseModel):
    status: str
    action: str | None = None
