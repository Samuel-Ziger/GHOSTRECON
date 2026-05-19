from __future__ import annotations

from fastapi import APIRouter, Depends
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.postgres import get_session
from app.schemas import AIRequest, AIResponse
from app.services.ai_service import AIService

router = APIRouter(prefix="/ai")


@router.post("/run", response_model=AIResponse)
async def run_agent(body: AIRequest, db: AsyncSession = Depends(get_session)) -> AIResponse:
    svc = AIService(db)
    return await svc.run(body)
