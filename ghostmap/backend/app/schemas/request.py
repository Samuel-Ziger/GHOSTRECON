from __future__ import annotations

from datetime import datetime
from typing import Any
from uuid import UUID

from pydantic import BaseModel, Field


class HttpRequestOut(BaseModel):
    id: UUID
    session_id: UUID
    project_id: UUID
    method: str
    url: str
    host: str
    path: str
    query: dict[str, Any] | None
    req_headers: dict[str, Any] | None
    req_body_text: str | None
    status: int | None
    resp_headers: dict[str, Any] | None
    resp_body_text: str | None
    duration_ms: int | None
    is_xhr: bool
    is_graphql: bool
    graphql_op: str | None
    tags: list[str] = Field(default_factory=list)
    occurred_at: datetime

    model_config = {"from_attributes": True}


class RequestList(BaseModel):
    items: list[HttpRequestOut]
    total: int


class ReplayCreate(BaseModel):
    add_headers: dict[str, str] = Field(default_factory=dict)
    remove_headers: list[str] = Field(default_factory=list)
    method_override: str | None = None
    url_override: str | None = None
    body_override_b64: str | None = None
    json_pointer_patches: list[dict[str, Any]] = Field(default_factory=list)
    label: str | None = None


class ReplayOut(BaseModel):
    id: UUID
    project_id: UUID
    original_id: UUID | None
    method: str
    url: str
    status: int | None
    duration_ms: int | None
    label: str | None
    occurred_at: datetime
    model_config = {"from_attributes": True}
