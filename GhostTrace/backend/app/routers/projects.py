from __future__ import annotations

from fastapi import APIRouter, HTTPException

from ..database import delete_project, get_bundle, list_projects, upsert_bundle
from ..schemas import ProjectBundle, ProjectListResponse, SyncResponse

router = APIRouter(prefix="/projects", tags=["projects"])


@router.get("", response_model=ProjectListResponse)
def get_projects():
    return ProjectListResponse(projects=list_projects())


@router.get("/{project_id}", response_model=ProjectBundle)
def get_project(project_id: str):
    bundle = get_bundle(project_id)
    if not bundle:
        raise HTTPException(status_code=404, detail="Projeto não encontrado")
    return bundle


@router.put("/{project_id}/sync", response_model=SyncResponse)
def sync_project(project_id: str, bundle: ProjectBundle):
    if bundle.project.id != project_id:
        raise HTTPException(status_code=400, detail="project.id não corresponde à URL")
    updated = upsert_bundle(bundle)
    return SyncResponse(projectId=project_id, updatedAt=updated)


@router.delete("/{project_id}")
def remove_project(project_id: str):
    if not delete_project(project_id):
        raise HTTPException(status_code=404, detail="Projeto não encontrado")
    return {"ok": True}
