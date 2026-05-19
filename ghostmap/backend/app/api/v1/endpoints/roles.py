from __future__ import annotations

from uuid import UUID

from fastapi import APIRouter, Depends, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.postgres import get_session
from app.models import Role
from app.schemas import RoleCreate, RoleOut

router = APIRouter(prefix="/projects/{project_id}/roles")


@router.get("", response_model=list[RoleOut])
async def list_roles(project_id: UUID, db: AsyncSession = Depends(get_session)) -> list[Role]:
    return list((await db.execute(select(Role).where(Role.project_id == project_id))).scalars())


@router.post("", response_model=RoleOut, status_code=status.HTTP_201_CREATED)
async def create_role(project_id: UUID, body: RoleCreate, db: AsyncSession = Depends(get_session)) -> Role:
    r = Role(project_id=project_id, **body.model_dump())
    db.add(r)
    await db.commit()
    await db.refresh(r)
    return r
