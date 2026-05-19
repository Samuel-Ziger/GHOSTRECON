"""
AIService — fachada que a API HTTP consome. Recebe um AIRequest, escolhe
o agente, monta o contexto a partir de Postgres + Neo4j e devolve AIResponse.
Tambem registra a invocacao na tabela ai_invocations para auditoria.
"""
from __future__ import annotations

from datetime import datetime
from typing import Any
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.ai.agents import (
    FlowAnalyzerAgent, HeatmapClassifierAgent,
    HypothesisGeneratorAgent, TrustBoundaryDetectorAgent,
)
from app.ai.orchestrator import AIOrchestrator, get_orchestrator
from app.models import AiInvocation, HttpRequest
from app.schemas.ai import AIRequest, AIResponse


class AIService:
    def __init__(self, db: AsyncSession, orch: AIOrchestrator | None = None) -> None:
        self.db = db
        self.orch = orch or get_orchestrator()
        self._agents: dict[str, Any] = {
            "flow_analyzer":           FlowAnalyzerAgent(self.orch),
            "trust_boundary_detector": TrustBoundaryDetectorAgent(self.orch),
            "hypothesis_generator":    HypothesisGeneratorAgent(self.orch),
            "heatmap_classifier":      HeatmapClassifierAgent(self.orch),
        }

    async def run(self, req: AIRequest) -> AIResponse:
        agent = self._agents.get(req.agent)
        if agent is None:
            raise ValueError(f"agent desconhecido: {req.agent}")
        # carrega contexto basico (ordem cronologica)
        ctx: dict[str, Any] = dict(req.context)
        if req.request_ids:
            ctx["requests"] = await self._load_requests(req.request_ids)

        # invoca o agent
        if req.agent == "flow_analyzer":
            output = await agent.run(ctx.get("requests", []))
        elif req.agent == "trust_boundary_detector":
            output = await agent.run(ctx.get("hosts", []), ctx.get("edges", []))
        elif req.agent == "heatmap_classifier":
            output = await agent.run(ctx.get("endpoint", {}))
        else:  # hypothesis_generator
            output = await agent.run(ctx)

        # audit
        # NB: A primeira chamada do orchestrator armazena `used`; aqui sintetizamos algo
        # minimo. Em prod, o agent retornaria tambem o InvocationResult.
        used = "unknown:unknown"
        try:
            # Re-invocacao do orchestrator nao se faz aqui; vamos confiar nos logs.
            pass
        except Exception:
            pass

        invocation = AiInvocation(
            project_id=req.project_id,
            agent=req.agent,
            provider=used.split(":")[0],
            model=used.split(":")[1] if ":" in used else used,
            prompt_hash="",  # preenchido na proxima iteracao
            tokens_in=None, tokens_out=None, cost_usd=None,
            duration_ms=None, status="ok", redacted=req.redact,
            occurred_at=datetime.utcnow(),
        )
        self.db.add(invocation)
        await self.db.commit()

        return AIResponse(
            agent=req.agent, provider=used.split(":")[0],
            model=used.split(":")[1] if ":" in used else used,
            output=output, duration_ms=0,
        )

    async def _load_requests(self, ids: list[UUID]) -> list[dict[str, Any]]:
        rows = (await self.db.execute(
            select(HttpRequest).where(HttpRequest.id.in_(ids)).order_by(HttpRequest.occurred_at)
        )).scalars().all()
        return [{
            "id": str(r.id),
            "method": r.method, "url": r.url, "status": r.status,
            "host": r.host, "path": r.path,
            "is_graphql": r.is_graphql, "graphql_op": r.graphql_op,
            "is_xhr": r.is_xhr, "duration_ms": r.duration_ms,
            "req_headers": r.req_headers, "resp_headers": r.resp_headers,
            "req_body_text": (r.req_body_text or "")[:2000],
            "resp_body_text": (r.resp_body_text or "")[:2000],
            "occurred_at": r.occurred_at.isoformat(),
        } for r in rows]
