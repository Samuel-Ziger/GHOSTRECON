"""
Runner dos consumers (HTTP persistor, browser persistor, graph projector,
ai indexer). Roda em processo separado (`worker` no compose).
"""
from __future__ import annotations

import asyncio
import signal

from app.config import get_settings
from app.core.events import EventBus
from app.core.logging import configure_logging, get_logger
from app.workers.persistor import run_browser_persistor, run_http_persistor
from app.workers.graph_projector import run_graph_projector
from app.workers.ai_indexer import run_ai_indexer

configure_logging("INFO")
log = get_logger("workers")


async def main() -> None:
    settings = get_settings()
    bus = EventBus(settings.redis_url)
    await bus.connect()

    stopping = asyncio.Event()

    def _stop(*_: object) -> None:
        log.info("stop signal received")
        stopping.set()

    loop = asyncio.get_event_loop()
    for sig in (signal.SIGINT, signal.SIGTERM):
        try: loop.add_signal_handler(sig, _stop)
        except NotImplementedError: pass  # windows

    tasks = [
        asyncio.create_task(run_http_persistor(bus), name="http-persistor"),
        asyncio.create_task(run_browser_persistor(bus), name="browser-persistor"),
        asyncio.create_task(run_graph_projector(bus), name="graph-projector"),
        asyncio.create_task(run_ai_indexer(bus), name="ai-indexer"),
    ]
    log.info("workers up", count=len(tasks))
    await stopping.wait()
    for t in tasks: t.cancel()
    await asyncio.gather(*tasks, return_exceptions=True)
    await bus.aclose()
    log.info("workers down")


if __name__ == "__main__":
    asyncio.run(main())
