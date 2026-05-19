from __future__ import annotations

from uuid import UUID

from fastapi import APIRouter, Depends
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.postgres import get_session
from app.schemas import ReplayCreate, ReplayOut
from app.services.replay_service import ReplayService

router = APIRouter(prefix="/requests/{request_id}/replay")


@router.post("", response_model=ReplayOut)
async def replay(
    request_id: UUID, body: ReplayCreate,
    db: AsyncSession = Depends(get_session),
) -> ReplayOut:
    svc = ReplayService(db)
    try:
        replay = await svc.replay(request_id, body)
    finally:
        await svc.aclose()
    return ReplayOut.model_validate(replay)
