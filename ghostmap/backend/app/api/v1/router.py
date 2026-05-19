"""Agrega todos os routers v1 num unico APIRouter."""
from fastapi import APIRouter

from app.api.v1.endpoints import ai, graph, projects, replay, requests, roles, sessions, ws

router = APIRouter(prefix="/api/v1")
router.include_router(projects.router, tags=["projects"])
router.include_router(roles.router, tags=["roles"])
router.include_router(sessions.router, tags=["sessions"])
router.include_router(requests.router, tags=["requests"])
router.include_router(graph.router, tags=["graph"])
router.include_router(replay.router, tags=["replay"])
router.include_router(ai.router, tags=["ai"])
# WS fica fora do /v1 (montado em /ws)
ws_router = ws.router
