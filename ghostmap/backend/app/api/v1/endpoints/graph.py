from __future__ import annotations

from uuid import UUID

from fastapi import APIRouter, Depends, Query

from app.schemas.graph import GraphFilter, GraphResponse
from app.schemas.role_diff import RoleDiffRequest, RoleDiffResponse
from app.services.graph_service import GraphService
from app.services.heatmap_service import HeatmapService
from app.services.role_diff_service import RoleDifferentialService

router = APIRouter(prefix="/projects/{project_id}/graph")


def get_graph_service() -> GraphService:
    return GraphService()


def get_heatmap_service() -> HeatmapService:
    return HeatmapService()


def get_role_diff_service() -> RoleDifferentialService:
    return RoleDifferentialService()


@router.get("", response_model=GraphResponse)
async def fetch_graph(
    project_id: UUID,
    labels: list[str] | None = Query(default=None),
    hosts: list[str] | None = Query(default=None),
    min_heat: float = 0.0,
    limit: int = Query(1000, le=10000),
    svc: GraphService = Depends(get_graph_service),
) -> GraphResponse:
    return await svc.fetch_graph(GraphFilter(
        project_id=project_id, labels=labels, hosts=hosts,
        min_heat=min_heat, limit_nodes=limit,
    ))


@router.post("/heatmap/recompute")
async def recompute_heatmap(
    project_id: UUID, svc: HeatmapService = Depends(get_heatmap_service),
) -> dict[str, int]:
    n = await svc.recompute_project(project_id)
    return {"endpoints_updated": n}


@router.post("/role-diff", response_model=RoleDiffResponse)
async def role_diff(
    project_id: UUID, body: RoleDiffRequest,
    svc: RoleDifferentialService = Depends(get_role_diff_service),
) -> RoleDiffResponse:
    body.project_id = project_id  # forca consistencia com URL
    return await svc.diff(body)


@router.delete("")
async def reset_graph(project_id: UUID, svc: GraphService = Depends(get_graph_service)) -> dict[str, str]:
    await svc.reset_project(project_id)
    return {"status": "ok"}
