"""
HeatmapService — atribui score [0..1] a cada Endpoint indicando risco/atractividade
ofensiva. Combina heuristicas + sinal da AI (heatmap_classifier).

Heuristicas (deterministicas, rapidas):
  * path contem palavras sensiveis (admin, internal, debug, upload, export, impersonate)
  * metodo de escrita (POST/PUT/PATCH/DELETE) em path com :id
  * resposta com headers de upload (multipart) ou content-type binario
  * presenca de tokens em query (?token=, ?key=)
  * GraphQL com operationName "admin*"

Score final = clip( sum(h_i * w_i) + ai_signal, 0, 1 )
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any
from uuid import UUID

from app.db.neo4j_client import Neo4jClient, get_neo4j

SENSITIVE_TOKENS = re.compile(
    r"\b(admin|internal|debug|console|impersonat|sudo|root|export|backup|"
    r"upload|invoice|export|webhook|integration|secret|private)\b", re.I,
)
RISKY_PARAMS = re.compile(r"\b(token|key|secret|password|admin|role|impersonate|userid)\b", re.I)


@dataclass
class Heuristic:
    name: str
    weight: float


HEURISTICS: list[Heuristic] = [
    Heuristic("sensitive_path", 0.30),
    Heuristic("write_on_id",    0.20),
    Heuristic("risky_param",    0.15),
    Heuristic("graphql_admin",  0.20),
    Heuristic("upload_like",    0.15),
]


class HeatmapService:
    def __init__(self, client: Neo4jClient | None = None) -> None:
        self.client = client or get_neo4j()

    def score(self, ep: dict[str, Any], params: list[str], graphql_ops: list[str]) -> float:
        s = 0.0
        path = ep.get("path", "")
        method = ep.get("method", "GET").upper()
        if SENSITIVE_TOKENS.search(path):
            s += 0.30
        if method in ("POST", "PUT", "PATCH", "DELETE") and ":id" in path:
            s += 0.20
        if any(RISKY_PARAMS.search(p) for p in params):
            s += 0.15
        if any(op and op.lower().startswith(("admin", "internal", "debug")) for op in graphql_ops):
            s += 0.20
        if "upload" in path.lower() or "/files" in path.lower():
            s += 0.15
        return max(0.0, min(1.0, s))

    async def recompute_project(self, project_id: UUID) -> int:
        rows = await self.client.run(
            """
            MATCH (e:Endpoint {project_id: $pid})
            OPTIONAL MATCH (e)-[:USES_PARAM]->(p:Param)
            OPTIONAL MATCH (e)-[:HAS_GRAPHQL_OP]->(g:GraphQLOperation)
            RETURN e, collect(DISTINCT p.name) AS params, collect(DISTINCT g.name) AS ops
            """,
            {"pid": str(project_id)},
        )
        updates = []
        for r in rows:
            ep = dict(r["e"])
            score = self.score(ep, r["params"] or [], r["ops"] or [])
            updates.append({"id": ep.get("id"), "heat": score})
        if updates:
            await self.client.write(
                "UNWIND $u AS row MATCH (e:Endpoint {id: row.id}) SET e.heat = row.heat",
                {"u": updates},
            )
        return len(updates)
