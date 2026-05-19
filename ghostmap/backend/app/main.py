"""
FastAPI entry point — montagem de routers, CORS, error handlers e
background tasks (WS broadcaster).
"""
from __future__ import annotations

import asyncio
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.api.v1 import endpoints  # noqa: F401 — garante import time effects
from app.api.v1.router import router as v1_router, ws_router
from app.api.v1.endpoints.ws import ws_broadcaster_loop
from app.config import get_settings
from app.core.exceptions import DomainError, domain_error_handler
from app.core.logging import configure_logging, get_logger
from app.db.redis_client import close_redis

configure_logging("INFO")
log = get_logger("main")


@asynccontextmanager
async def lifespan(app: FastAPI):
    # background: WS broadcaster
    bcast_task = asyncio.create_task(ws_broadcaster_loop(), name="ws-broadcaster")
    log.info("ghostmap api up", env=get_settings().env)
    try:
        yield
    finally:
        bcast_task.cancel()
        try: await bcast_task
        except asyncio.CancelledError: pass
        await close_redis()


app = FastAPI(
    title="GhostMap API",
    version="0.1.0",
    description="Visual application mapping for offensive security",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=get_settings().cors_origins + ["*"],  # dev-friendly
    allow_methods=["*"], allow_headers=["*"], allow_credentials=True,
)

app.add_exception_handler(DomainError, domain_error_handler)
app.include_router(v1_router)
app.include_router(ws_router)


@app.get("/health")
async def health() -> dict[str, str]:
    return {"status": "ok"}
