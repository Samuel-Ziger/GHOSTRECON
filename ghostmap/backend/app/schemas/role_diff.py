from __future__ import annotations

from typing import Any
from uuid import UUID

from pydantic import BaseModel, Field


class RoleDiffRequest(BaseModel):
    project_id: UUID
    baseline_role_id: UUID  # ex.: "guest"
    candidate_role_ids: list[UUID]  # ex.: ["user", "admin"]


class EndpointDiff(BaseModel):
    endpoint_id: str
    host: str
    method: str
    path: str
    seen_in_roles: list[str]  # nomes
    only_in: list[str]        # nomes
    status_codes_by_role: dict[str, list[int]] = Field(default_factory=dict)
    param_delta: dict[str, list[str]] = Field(default_factory=dict)  # role -> params unicos
    suspicion: str | None = None    # "potential_idor" | "privesc_path" | ...
    confidence: float = 0.0


class RoleDiffResponse(BaseModel):
    project_id: UUID
    baseline: str
    candidates: list[str]
    differences: list[EndpointDiff]
    summary: dict[str, Any] = Field(default_factory=dict)
