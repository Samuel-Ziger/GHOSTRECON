"""
GraphProjector — consome gm:capture:http e projeta no grafo Neo4j via GraphService.
Tambem infere chains temporais simples por session (request t -> request t+dt da
mesma session forma uma aresta CHAINS_INTO).
"""
from __future__ import annotations

import logging
from datetime import datetime, timezone
from uuid import UUID

from app.core.events import EventBus, Streams
from app.services.graph_service import GraphService

log = logging.getLogger("worker.graph_projector")

# memoria curta: ultima ep por session para inferir chain
_LAST: dict[str, tuple[str, datetime]] = {}


async def run_graph_projector(bus: EventBus) -> None:
    svc = GraphService()
    group, consumer = "graph-projector", "g1"
    async for m in bus.consume(Streams.CAPTURE_HTTP, group, consumer):
        ev = m.event
        try:
            await _project(svc, ev)
            await bus.publish(Streams.UI_BROADCAST, {
                "type": "graph_update",
                "data": {"project_id": ev.get("project_id")},
            })
        except Exception:
            log.exception("projection failed event_id=%s", ev.get("event_id"))
        finally:
            await bus.ack(Streams.CAPTURE_HTTP, group, m.msg_id)


async def _project(svc: GraphService, ev: dict) -> None:
    req = ev.get("request") or {}
    if not ev.get("project_id"):
        return
    pid = UUID(ev["project_id"])
    occurred = _dt(ev.get("occurred_at"))
    ep_id = await svc.upsert_http_request(
        project_id=pid,
        role_id=None, role_name=None,
        method=req.get("method", "GET"),
        url=req.get("url", ""),
        status=(ev.get("response") or {}).get("status"),
        query=req.get("query"),
        headers={k: v for k, v in (req.get("headers") or [])},
        graphql_op=req.get("graphql_op"),
        occurred_at=occurred,
    )
    sid = str(ev.get("session_id"))
    last = _LAST.get(sid)
    if last:
        prev_ep, prev_ts = last
        if (occurred - prev_ts).total_seconds() <= 5.0 and prev_ep != ep_id:
            await svc.link_chain(prev_ep, ep_id)
    _LAST[sid] = (ep_id, occurred)


def _dt(s: str | None) -> datetime:
    if not s:
        return datetime.now(timezone.utc).replace(tzinfo=None)
    try:
        dt = datetime.fromisoformat(s.replace("Z", "+00:00"))
        if dt.tzinfo is not None:
            dt = dt.astimezone(timezone.utc).replace(tzinfo=None)
        return dt
    except ValueError:
        return datetime.now(timezone.utc).replace(tzinfo=None)
