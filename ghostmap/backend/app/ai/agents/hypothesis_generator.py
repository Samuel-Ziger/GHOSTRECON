"""
HypothesisGenerator — propoe hipoteses ofensivas (NUNCA executa).

Recebe contexto reduzido sobre um endpoint, role diff e fluxos relacionados,
e devolve hipoteses estruturadas: o que checar manualmente, com base nas
evidencias observadas.

Output JSON:
{ "hypotheses": [
    {"title": str, "category": "idor|bac|auth_bypass|ssrf|...",
     "evidence": [str], "manual_steps": [str], "confidence": 0..1 }
] }
"""
from __future__ import annotations

import json
from typing import Any

from app.ai.base import ChatMessage
from app.ai.orchestrator import AIOrchestrator


SYSTEM = (
    "Voce e um pentester sênior que ajuda um hunter humano. "
    "Dado o contexto, formule HIPOTESES ofensivas. NAO escreva exploits prontos, "
    "NAO disparar payloads. Liste evidencias (o que voce viu) e passos manuais "
    "que o hunter deveria checar. Seja preciso e nao alucine. JSON apenas."
)


class HypothesisGeneratorAgent:
    NAME = "hypothesis_generator"

    def __init__(self, orch: AIOrchestrator) -> None:
        self.orch = orch

    async def run(self, context: dict[str, Any]) -> dict[str, Any]:
        body = json.dumps(context, ensure_ascii=False, indent=2)[:22000]
        msgs = [
            ChatMessage("system", SYSTEM),
            ChatMessage(
                "user",
                "Contexto (endpoint, role diff observada, headers, params):\n" + body
                + "\n\nDevolva: { \"hypotheses\": [...] }"
            ),
        ]
        out = await self.orch.run(self.NAME, msgs)
        try:
            return json.loads(out.response.text)
        except json.JSONDecodeError:
            return {"hypotheses": [], "raw": out.response.text[:2000]}
