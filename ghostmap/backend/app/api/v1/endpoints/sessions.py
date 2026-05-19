from __future__ import annotations

from uuid import UUID, uuid4

from fastapi import APIRouter, Depends, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.exceptions import NotFoundError
from app.db.postgres import get_session
from app.models import Session
from app.schemas import SessionCreate, SessionOut

router = APIRouter(prefix="/sessions")


@router.post("", response_model=SessionOut, status_code=status.HTTP_201_CREATED)
async def create_session(body: SessionCreate, db: AsyncSession = Depends(get_session)) -> Session:
    s = Session(
        id=body.id or uuid4(),
        project_id=body.project_id, role_id=body.role_id,
        label=body.label, meta=body.meta,
    )
    db.add(s)
    await db.commit()
    await db.refresh(s)
    return s


@router.get("/{session_id}", response_model=SessionOut)
async def get_session_by_id(session_id: UUID, db: AsyncSession = Depends(get_session)) -> Session:
    s = (await db.execute(select(Session).where(Session.id == session_id))).scalar_one_or_none()
    if s is None:
        raise NotFoundError("session not found")
    return s
