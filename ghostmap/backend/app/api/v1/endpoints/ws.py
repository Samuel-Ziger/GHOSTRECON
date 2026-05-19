"""
WebSocket gateway — assina o stream gm:ui:broadcast e empurra eventos para
clientes (frontend). Tambem aceita comandos do frontend (ex: ping, subscribe).

Topologia:
  capture -> persistor -> graph_projector -> publish em gm:ui:broadcast
                                          -> WS gateway -> browser
"""
from __future__ import annotations

import asyncio
import logging
from typing import Any

import orjson
from fastapi import APIRouter, WebSocket, WebSocketDisconnect

from app.core.events import EventBus, Streams
from app.config import get_settings

router = APIRouter()
log = logging.getLogger("ws")


class ConnectionManager:
    def __init__(self) -> None:
        self._conns: set[WebSocket] = set()
        self._lock = asyncio.Lock()

    async def connect(self, ws: WebSocket) -> None:
        await ws.accept()
        async with self._lock:
            self._conns.add(ws)

    async def disconnect(self, ws: WebSocket) -> None:
        async with self._lock:
            self._conns.discard(ws)

    async def broadcast(self, msg: dict[str, Any]) -> None:
        async with self._lock:
            dead: list[WebSocket] = []
            payload = orjson.dumps(msg).decode("utf-8")
            for ws in self._conns:
                try:
                    await ws.send_text(payload)
                except Exception:
                    dead.append(ws)
            for d in dead:
                self._conns.discard(d)


manager = ConnectionManager()


@router.websocket("/ws")
async def ws_endpoint(ws: WebSocket) -> None:
    await manager.connect(ws)
    try:
        while True:
            # mantemos o socket aberto recebendo pings/no-ops do client
            msg = await ws.receive_text()
            if msg == "ping":
                await ws.send_text("pong")
    except WebSocketDisconnect:
        await manager.disconnect(ws)


async def ws_broadcaster_loop() -> None:
    """Roda como background task no main: consome gm:ui:broadcast e empurra."""
    bus = EventBus(get_settings().redis_url)
    await bus.connect()
    group = "ui-gateway"
    consumer = "ui-1"
    try:
        async for m in bus.consume(Streams.UI_BROADCAST, group, consumer):
            await manager.broadcast(m.event)
            await bus.ack(Streams.UI_BROADCAST, group, m.msg_id)
    except asyncio.CancelledError:
        log.info("ws broadcaster cancelled")
    finally:
        await bus.aclose()
