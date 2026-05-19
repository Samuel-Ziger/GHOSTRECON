from __future__ import annotations

from datetime import datetime
from typing import Any
from uuid import UUID

from pydantic import BaseModel, Field


class SessionCreate(BaseModel):
    id: UUID | None = None
    project_id: UUID
    role_id: UUID | None = None
    label: str
    meta: dict[str, Any] = Field(default_factory=dict)


class SessionOut(BaseModel):
    id: UUID
    project_id: UUID
    role_id: UUID | None
    label: str
    started_at: datetime
    ended_at: datetime | None
    meta: dict[str, Any]
    model_config = {"from_attributes": True}
