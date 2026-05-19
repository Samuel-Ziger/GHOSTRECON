"""
ReplayService — re-executa requests armazenados com mutacoes.
Persistencia em `replays`.
"""
from __future__ import annotations

import base64
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.exceptions import NotFoundError
from app.models import HttpRequest, Replay
from app.schemas.request import ReplayCreate
# Importamos o motor do pacote `capture` para reaproveitar a mesma logica do
# proxy. Em prod, o `capture/` esta no PYTHONPATH (montado em docker-compose).
from capture.proxy.replay_engine import ReplayEngine, ReplayMutation  # type: ignore


class ReplayService:
    def __init__(self, db: AsyncSession) -> None:
        self.db = db
        self._engine = ReplayEngine(timeout=15.0, http2=True, verify=False)

    async def aclose(self) -> None:
        await self._engine.aclose()

    async def replay(self, request_id: UUID, mut: ReplayCreate) -> Replay:
        original = (await self.db.execute(select(HttpRequest).where(HttpRequest.id == request_id))).scalar_one_or_none()
        if original is None:
            raise NotFoundError(f"http_request {request_id} not found")

        body_override = base64.b64decode(mut.body_override_b64) if mut.body_override_b64 else None
        mutation = ReplayMutation(
            method_override=mut.method_override,
            url_override=mut.url_override,
            add_headers=mut.add_headers,
            remove_headers=mut.remove_headers,
            body_override=body_override,
            json_pointer_patches=mut.json_pointer_patches,
        )
        # cabecalhos no banco vem como dict {name: value}; normalizamos para lista
        headers_list = [(k, v) for k, v in (original.req_headers or {}).items()]
        result = await self._engine.replay(
            method=original.method, url=original.url,
            headers=headers_list, body=original.req_body, mutation=mutation,
        )
        replay = Replay(
            original_id=original.id, project_id=original.project_id,
            method=mutation.method_override or original.method,
            url=mutation.url_override or original.url,
            req_headers={k: v for k, v in headers_list},
            req_body=body_override or original.req_body,
            status=result.status,
            resp_headers={k: v for k, v in result.headers},
            resp_body=base64.b64decode(result.body_b64),
            duration_ms=result.duration_ms,
            label=mut.label,
        )
        self.db.add(replay)
        await self.db.commit()
        await self.db.refresh(replay)
        return replay
