"""
Event Bus — abstracao em cima do Redis Streams.

Por que abstrair?
  * Trocavel para Kafka/NATS sem mexer em consumers.
  * Encapsula consumer groups, ack, replay e idempotencia.
  * Schema padronizado (Pydantic CaptureEvent).
"""
from __future__ import annotations

import asyncio
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, AsyncIterator, Callable, Literal
from uuid import UUID

import orjson
import redis.asyncio as redis
from pydantic import BaseModel, Field
from ulid import ULID

from app.core.logging import get_logger

log = get_logger("events")


# ---------- streams ----------
class Streams:
    CAPTURE_HTTP = "gm:capture:http"
    CAPTURE_BROWSER = "gm:capture:browser"
    CAPTURE_WS = "gm:capture:websocket"
    ANALYSIS_REQUESTS = "gm:analysis:requests"
    UI_BROADCAST = "gm:ui:broadcast"


EventKind = Literal[
    "http", "websocket", "navigation", "fetch", "xhr", "mutation",
    "storage_change", "cookie_change", "redirect", "script_load",
    "websocket_event",
]


class CaptureEvent(BaseModel):
    event_id: str = Field(default_factory=lambda: str(ULID()))
    schema_: str = Field(alias="schema", default="gm.event/1")
    project_id: UUID | None = None
    session_id: UUID | None = None
    kind: str
    occurred_at: datetime = Field(default_factory=lambda: datetime.now(tz=timezone.utc))
    received_at: datetime | None = None
    payload: dict[str, Any] = Field(default_factory=dict)

    model_config = {"populate_by_name": True}


@dataclass
class StreamMessage:
    msg_id: str  # ID do Redis (timestamp-seq), usado para XACK
    event: dict[str, Any]


class EventBus:
    """API minima para publish + consume via groups."""

    def __init__(self, url: str) -> None:
        self._url = url
        self._r: redis.Redis | None = None

    async def connect(self) -> None:
        self._r = redis.from_url(self._url, decode_responses=False)
        await self._r.ping()

    async def aclose(self) -> None:
        if self._r is not None:
            await self._r.aclose()

    @property
    def r(self) -> redis.Redis:
        if self._r is None:
            raise RuntimeError("EventBus not connected")
        return self._r

    async def publish(self, stream: str, event: dict[str, Any], *, maxlen: int = 100_000) -> str:
        return await self.r.xadd(stream, {b"d": orjson.dumps(event)}, maxlen=maxlen, approximate=True)

    async def ensure_group(self, stream: str, group: str) -> None:
        try:
            await self.r.xgroup_create(name=stream, groupname=group, id="0", mkstream=True)
        except redis.ResponseError as e:
            # BUSYGROUP = ja existe
            if "BUSYGROUP" not in str(e):
                raise

    async def consume(
        self,
        stream: str,
        group: str,
        consumer: str,
        *,
        block_ms: int = 5000,
        count: int = 64,
    ) -> AsyncIterator[StreamMessage]:
        await self.ensure_group(stream, group)
        while True:
            try:
                resp = await self.r.xreadgroup(
                    groupname=group, consumername=consumer,
                    streams={stream: ">"}, count=count, block=block_ms,
                )
            except asyncio.CancelledError:
                raise
            except Exception:
                log.exception("xreadgroup failed")
                await asyncio.sleep(0.5)
                continue
            if not resp:
                continue
            for _stream, items in resp:
                for msg_id, fields in items:
                    raw = fields.get(b"d") if isinstance(fields, dict) else None
                    if raw is None:
                        await self.r.xack(stream, group, msg_id)
                        continue
                    try:
                        event = orjson.loads(raw)
                    except orjson.JSONDecodeError:
                        log.warning("bad event payload", msg_id=msg_id.decode())
                        await self.r.xack(stream, group, msg_id)
                        continue
                    yield StreamMessage(msg_id=msg_id.decode(), event=event)

    async def ack(self, stream: str, group: str, msg_id: str) -> None:
        await self.r.xack(stream, group, msg_id)


# convenience: tipo do callback de consumer
ConsumerFn = Callable[[StreamMessage], "asyncio.Future[None] | None"]
