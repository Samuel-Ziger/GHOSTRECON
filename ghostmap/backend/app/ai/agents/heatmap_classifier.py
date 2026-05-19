"""
HeatmapClassifier — recebe um endpoint + sumario de body e retorna
score de risco ofensivo (0..1) + tags. Pensado para rodar local (Ollama)
em alto volume.

Output JSON: { "score": 0..1, "tags": [...], "rationale": str }
"""
from __future__ import annotations

import json
from typing import Any

from app.ai.base import ChatMessage
from app.ai.orchestrator import AIOrchestrator


SYSTEM = (
    "Classifique este endpoint quanto a risco ofensivo (0=baixo, 1=alto). "
    "Considere: admin/internal/debug, uploads, integracao externa, exposicao de "
    "tokens em query, GraphQL com operacoes administrativas. JSON apenas: "
    "{\"score\": float, \"tags\": [string], \"rationale\": string}"
)


class HeatmapClassifierAgent:
    NAME = "heatmap_classifier"

    def __init__(self, orch: AIOrchestrator) -> None:
        self.orch = orch

    async def run(self, endpoint: dict[str, Any]) -> dict[str, Any]:
        body = json.dumps(endpoint, ensure_ascii=False)[:6000]
        msgs = [ChatMessage("system", SYSTEM), ChatMessage("user", body)]
        out = await self.orch.run(self.NAME, msgs)
        try:
            data = json.loads(out.response.text)
            data["score"] = max(0.0, min(1.0, float(data.get("score", 0))))
            return data
        except (json.JSONDecodeError, ValueError, TypeError):
            return {"score": 0.0, "tags": [], "rationale": out.response.text[:500]}
