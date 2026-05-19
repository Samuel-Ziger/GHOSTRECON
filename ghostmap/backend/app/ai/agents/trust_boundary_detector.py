"""
TrustBoundaryDetector — identifica onde a aplicacao cruza fronteiras de
confianca (sub-dominios, integracoes externas, callbacks, webhooks).

Output JSON:
{
  "boundaries": [{"from": "host", "to": "host", "kind": "external_api"|"webhook"|"third_party_redirect", "evidence": str}],
  "suspicious_patterns": [str]
}
"""
from __future__ import annotations

import json
from typing import Any

from app.ai.base import ChatMessage
from app.ai.orchestrator import AIOrchestrator


SYSTEM = (
    "Voce e um especialista em arquitetura ofensiva. Dado um grafo simplificado "
    "de hosts e endpoints chamados, identifique trust boundaries. "
    "NAO recomende exploits. JSON apenas."
)


class TrustBoundaryDetectorAgent:
    NAME = "trust_boundary_detector"

    def __init__(self, orch: AIOrchestrator) -> None:
        self.orch = orch

    async def run(self, hosts: list[str], edges: list[dict[str, Any]]) -> dict[str, Any]:
        body = json.dumps({"hosts": hosts, "edges": edges}, ensure_ascii=False)[:18000]
        msgs = [ChatMessage("system", SYSTEM), ChatMessage("user", body)]
        out = await self.orch.run(self.NAME, msgs)
        try:
            return json.loads(out.response.text)
        except json.JSONDecodeError:
            return {"boundaries": [], "suspicious_patterns": [out.response.text[:1500]]}
