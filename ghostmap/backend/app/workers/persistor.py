"""
Persistors — consomem gm:capture:http e gm:capture:browser e gravam em Postgres.
Tambem republicam um sumario no stream UI para refresh em tempo real.
"""
from __future__ import annotations

import base64
import logging
from datetime import datetime, timezone
from uuid import UUID

from app.core.events import EventBus, Streams
from app.db.postgres import session_scope
from app.models import DomEvent, HttpRequest, WsFrame

log = logging.getLogger("worker.persistor")


async def run_http_persistor(bus: EventBus) -> None:
    group, consumer = "persist-http", "p1"
    async for m in bus.consume(Streams.CAPTURE_HTTP, group, consumer):
        ev = m.event
        try:
            row = await _persist_http(ev)
            if row is None:
                await bus.ack(Streams.CAPTURE_HTTP, group, m.msg_id)
                continue
            await bus.publish(Streams.UI_BROADCAST, {
                "type": "http_request",
                "data": _http_summary(ev, row_id=str(row.id)),
            })
            await bus.publish(Streams.ANALYSIS_REQUESTS, ev)
            await bus.ack(Streams.CAPTURE_HTTP, group, m.msg_id)
        except Exception:
            log.exception("persistor http error event_id=%s", ev.get("event_id"))


async def run_browser_persistor(bus: EventBus) -> None:
    group, consumer = "persist-browser", "p1"
    async for m in bus.consume(Streams.CAPTURE_BROWSER, group, consumer):
        ev = m.event
        try:
            await _persist_browser(ev)
            await bus.publish(Streams.UI_BROADCAST, {"type": "browser_event", "data": {
                "kind": ev.get("kind"), "occurred_at": ev.get("occurred_at"),
                "session_id": ev.get("session_id"),
            }})
        except Exception:
            log.exception("persistor browser error event_id=%s", ev.get("event_id"))
        finally:
            await bus.ack(Streams.CAPTURE_BROWSER, group, m.msg_id)


# ---------- helpers ----------
async def _persist_http(ev: dict) -> HttpRequest | None:
    if not ev.get("project_id") or not ev.get("session_id"):
        return None
    req = ev.get("request", {}) or {}
    resp = ev.get("response", {}) or {}
    headers_dict = {k: v for k, v in (req.get("headers") or [])}
    resp_headers_dict = {k: v for k, v in (resp.get("headers") or [])} if resp else None
    req_body = base64.b64decode(req["body_b64"]) if req.get("body_b64") else None
    resp_body = base64.b64decode(resp["body_b64"]) if resp.get("body_b64") else None
    row = HttpRequest(
        session_id=UUID(ev["session_id"]),
        project_id=UUID(ev["project_id"]),
        method=req.get("method", "GET"),
        url=req.get("url", ""),
        host=req.get("host", ""),
        path=req.get("path", "/"),
        query=req.get("query") or {},
        req_headers=headers_dict,
        req_body=req_body,
        req_body_text=req.get("body_text"),
        status=resp.get("status"),
        resp_headers=resp_headers_dict,
        resp_body=resp_body,
        resp_body_text=resp.get("body_text"),
        duration_ms=ev.get("duration_ms"),
        is_xhr=bool(req.get("is_xhr")),
        is_graphql=bool(req.get("is_graphql")),
        graphql_op=req.get("graphql_op"),
        occurred_at=_dt(ev.get("occurred_at")),
    )
    async with session_scope() as s:
        s.add(row)
        await s.flush()
    return row


async def _persist_browser(ev: dict) -> None:
    if not ev.get("session_id"):
        return
    kind = ev.get("kind", "unknown")
    payload = ev.get("payload", {})
    async with session_scope() as s:
        if kind == "websocket_event":
            s.add(WsFrame(
                session_id=UUID(ev["session_id"]),
                url=payload.get("url", ""),
                direction=payload.get("direction", "server_to_client"),
                payload=None,
                payload_text=payload.get("payload"),
                occurred_at=_dt(ev.get("occurred_at")),
            ))
        else:
            s.add(DomEvent(
                session_id=UUID(ev["session_id"]),
                kind=kind, payload=payload,
                occurred_at=_dt(ev.get("occurred_at")),
            ))


def _http_summary(ev: dict, *, row_id: str) -> dict:
    req = ev.get("request", {}) or {}
    resp = ev.get("response", {}) or {}
    return {
        "id": row_id,
        "event_id": ev.get("event_id"),
        "session_id": ev.get("session_id"),
        "project_id": ev.get("project_id"),
        "method": req.get("method"), "url": req.get("url"),
        "status": resp.get("status"), "duration_ms": ev.get("duration_ms"),
        "host": req.get("host"), "path": req.get("path"),
        "is_xhr": req.get("is_xhr"), "is_graphql": req.get("is_graphql"),
        "occurred_at": ev.get("occurred_at"),
    }


def _dt(s: str | None) -> datetime:
    """Postgres usa TIMESTAMP WITHOUT TIME ZONE — normaliza para UTC naive."""
    if not s:
        return datetime.now(timezone.utc).replace(tzinfo=None)
    try:
        dt = datetime.fromisoformat(s.replace("Z", "+00:00"))
        if dt.tzinfo is not None:
            dt = dt.astimezone(timezone.utc).replace(tzinfo=None)
        return dt
    except ValueError:
        return datetime.now(timezone.utc).replace(tzinfo=None)
