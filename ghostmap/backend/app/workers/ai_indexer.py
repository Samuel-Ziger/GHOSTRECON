"""
AIIndexer — consome gm:analysis:requests, atualiza heatmap heuristico
para o projeto a cada N eventos (batching).

Mantemos esse worker simples e seguro: NAO faz attack, NAO toca endpoint
externo. Apenas re-pontua o grafo localmente.
"""
from __future__ import annotations

import asyncio
import logging
from uuid import UUID

from app.core.events import EventBus, Streams
from app.services.heatmap_service import HeatmapService

log = logging.getLogger("worker.ai_indexer")

BATCH = 50
INTERVAL_SEC = 10.0


async def run_ai_indexer(bus: EventBus) -> None:
    svc = HeatmapService()
    group, consumer = "ai-indexer", "i1"
    pending: set[UUID] = set()
    last_flush = asyncio.get_event_loop().time()

    async for m in bus.consume(Streams.ANALYSIS_REQUESTS, group, consumer):
        ev = m.event
        try:
            pid_raw = ev.get("project_id")
            if pid_raw:
                pending.add(UUID(pid_raw))
            now = asyncio.get_event_loop().time()
            if len(pending) > 0 and (len(pending) >= BATCH or (now - last_flush) > INTERVAL_SEC):
                for pid in list(pending):
                    n = await svc.recompute_project(pid)
                    log.info("heatmap recomputed project=%s endpoints=%d", pid, n)
                pending.clear()
                last_flush = now
        except Exception:
            log.exception("indexer error")
        finally:
            await bus.ack(Streams.ANALYSIS_REQUESTS, group, m.msg_id)
