from __future__ import annotations

from datetime import datetime
from typing import Any
from uuid import UUID

from pydantic import BaseModel, Field


class ProjectCreate(BaseModel):
    name: str
    target_scope: dict[str, Any] = Field(default_factory=lambda: {"domains": [], "exclude": []})


class ProjectOut(BaseModel):
    id: UUID
    name: str
    target_scope: dict[str, Any]
    created_at: datetime
    updated_at: datetime
    model_config = {"from_attributes": True}


class RoleCreate(BaseModel):
    name: str
    description: str | None = None
    auth_hint: dict[str, Any] | None = None
    color: str = "#7c3aed"


class RoleOut(BaseModel):
    id: UUID
    project_id: UUID
    name: str
    description: str | None
    auth_hint: dict[str, Any] | None
    color: str
    created_at: datetime
    model_config = {"from_attributes": True}
