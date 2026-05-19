from __future__ import annotations

from typing import Any, Literal
from uuid import UUID

from pydantic import BaseModel, Field

AgentName = Literal[
    "flow_analyzer", "trust_boundary_detector",
    "hypothesis_generator", "heatmap_classifier",
]


class AIRequest(BaseModel):
    project_id: UUID
    agent: AgentName
    context: dict[str, Any] = Field(default_factory=dict)
    request_ids: list[UUID] = Field(default_factory=list)
    redact: bool = True


class AIResponse(BaseModel):
    agent: AgentName
    provider: str
    model: str
    output: dict[str, Any]
    duration_ms: int
    cost_usd: float | None = None
    tokens_in: int | None = None
    tokens_out: int | None = None
