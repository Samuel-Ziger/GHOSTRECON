from __future__ import annotations

from typing import Any, Literal
from uuid import UUID

from pydantic import BaseModel, Field

NodeLabel = Literal[
    "Page", "Endpoint", "ApiOperation", "GraphQLOperation", "Param",
    "JWT", "Cookie", "User", "Role", "Upload", "File", "Bucket",
    "Integration", "Host",
]


class GraphNode(BaseModel):
    id: str
    label: NodeLabel
    title: str
    project_id: UUID | None = None
    props: dict[str, Any] = Field(default_factory=dict)
    # heatmap_score em [0,1] — alimentado pelo HeatmapService
    heat: float = 0.0
    cluster: str | None = None


class GraphEdge(BaseModel):
    id: str
    source: str
    target: str
    type: str
    props: dict[str, Any] = Field(default_factory=dict)


class GraphResponse(BaseModel):
    nodes: list[GraphNode]
    edges: list[GraphEdge]
    stats: dict[str, int] = Field(default_factory=dict)


class GraphFilter(BaseModel):
    project_id: UUID
    role_ids: list[UUID] | None = None
    labels: list[str] | None = None
    hosts: list[str] | None = None
    min_heat: float = 0.0
    limit_nodes: int = 1000
