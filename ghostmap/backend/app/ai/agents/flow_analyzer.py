"""
FlowAnalyzer — recebe uma sequencia de requests/responses e descreve
o fluxo de aplicacao (login -> 2FA -> dashboard -> action).

Output JSON:
{
  "flow": [{"step": "...", "endpoint": "GET /...", "purpose": "...", "auth": "..."}],
  "observations": [...],
  "key_state_transitions": [...]
}
"""
from __future__ import annotations

import json
from typing import Any

from app.ai.base import ChatMessage
from app.ai.orchestrator import AIOrchestrator


SYSTEM = (
    "Voce e um analista ofensivo. Dado um conjunto de requests/responses, "
    "descreva o fluxo da aplicacao web em alto nivel. NAO sugira exploits. "
    "Foco em transicoes de estado, autenticacao e relacao entre endpoints. "
    "Responda APENAS em JSON valido no schema fornecido."
)

SCHEMA_HINT = (
    "Schema:\n"
    '{ "flow": [{"step": str, "endpoint": str, "purpose": str, "auth": str|null}], '
    '"observations": [str], "key_state_transitions": [str] }'
)


class FlowAnalyzerAgent:
    NAME = "flow_analyzer"

    def __init__(self, orch: AIOrchestrator) -> None:
        self.orch = orch

    async def run(self, requests_summary: list[dict[str, Any]]) -> dict[str, Any]:
        ctx = json.dumps(requests_summary, ensure_ascii=False, indent=2)[:24000]
        msgs = [
            ChatMessage("system", SYSTEM + "\n" + SCHEMA_HINT),
            ChatMessage("user", f"Requests (em ordem):\n{ctx}"),
        ]
        result = await self.orch.run(self.NAME, msgs)
        try:
            return json.loads(result.response.text)
        except json.JSONDecodeError:
            return {"flow": [], "observations": [result.response.text[:2000]], "key_state_transitions": []}
