"""
RoleDifferentialService — A funcionalidade central do GhostMap.

Compara N roles contra uma baseline e retorna endpoints onde:
  * a role candidata acessa mas a baseline NAO acessa  -> visibilidade extra
  * a baseline recebe 401/403 mas candidata recebe 200 -> potencial BAC
  * mesmo endpoint expoe parametros adicionais para certas roles -> mass assignment
  * candidatas + baseline acessam mas status diferem por path com :id -> potencial IDOR

A heuristica de "suspicion" e conservadora: e um aviso, NAO um disparo automatico.
O hunter ainda valida via Replay tab.
"""
from __future__ import annotations

from typing import Any
from uuid import UUID

from app.db.neo4j_client import Neo4jClient, get_neo4j
from app.schemas.role_diff import EndpointDiff, RoleDiffRequest, RoleDiffResponse


CYPHER_FETCH = """
MATCH (r:Role {project_id: $pid})-[obs:OBSERVED_AT]->(e:Endpoint)
WHERE r.id IN $role_ids
OPTIONAL MATCH (e)-[:USES_PARAM]->(p:Param)
RETURN
  e.id     AS ep_id,
  e.host   AS host,
  e.method AS method,
  e.path   AS path,
  r.id     AS role_id,
  r.name   AS role_name,
  coalesce(obs.statuses, [obs.first_status]) AS statuses,
  collect(DISTINCT p.name)                   AS params
"""


class RoleDifferentialService:
    def __init__(self, client: Neo4jClient | None = None) -> None:
        self.client = client or get_neo4j()

    async def diff(self, req: RoleDiffRequest) -> RoleDiffResponse:
        all_roles = [req.baseline_role_id, *req.candidate_role_ids]
        rows = await self.client.run(CYPHER_FETCH, {
            "pid": str(req.project_id),
            "role_ids": [str(r) for r in all_roles],
        })

        # ep_id -> {host, method, path, by_role: {name: {statuses, params}}}
        bucket: dict[str, dict[str, Any]] = {}
        role_id_to_name: dict[str, str] = {}
        for r in rows:
            ep_id = r["ep_id"]
            role_id_to_name[r["role_id"]] = r["role_name"]
            slot = bucket.setdefault(ep_id, {
                "host": r["host"], "method": r["method"], "path": r["path"], "by_role": {},
            })
            slot["by_role"][r["role_name"]] = {
                "statuses": [s for s in (r["statuses"] or []) if s is not None],
                "params":   list(r["params"] or []),
            }

        baseline_name = role_id_to_name.get(str(req.baseline_role_id), "baseline")
        candidates_names = [role_id_to_name.get(str(c), "candidate") for c in req.candidate_role_ids]

        diffs: list[EndpointDiff] = []
        for ep_id, data in bucket.items():
            seen = list(data["by_role"].keys())
            only_in = [r for r in seen if r != baseline_name and baseline_name not in seen]
            statuses_by_role = {role: info["statuses"] for role, info in data["by_role"].items()}
            params_by_role = {role: info["params"] for role, info in data["by_role"].items()}
            param_delta = self._delta(params_by_role, baseline_name)
            suspicion, confidence = self._suspect(
                path=data["path"], method=data["method"],
                statuses_by_role=statuses_by_role,
                baseline=baseline_name, candidates=candidates_names,
                only_in=only_in, param_delta=param_delta,
            )
            diffs.append(EndpointDiff(
                endpoint_id=ep_id, host=data["host"], method=data["method"], path=data["path"],
                seen_in_roles=seen, only_in=only_in,
                status_codes_by_role={k: list(set(v)) for k, v in statuses_by_role.items()},
                param_delta=param_delta,
                suspicion=suspicion, confidence=confidence,
            ))

        diffs.sort(key=lambda d: d.confidence, reverse=True)
        summary = self._summary(diffs)
        return RoleDiffResponse(
            project_id=req.project_id,
            baseline=baseline_name,
            candidates=candidates_names,
            differences=diffs,
            summary=summary,
        )

    @staticmethod
    def _delta(params_by_role: dict[str, list[str]], baseline: str) -> dict[str, list[str]]:
        base = set(params_by_role.get(baseline, []))
        return {
            role: sorted(set(plist) - base)
            for role, plist in params_by_role.items()
            if role != baseline and set(plist) - base
        }

    @staticmethod
    def _suspect(
        *, path: str, method: str,
        statuses_by_role: dict[str, list[int]],
        baseline: str, candidates: list[str], only_in: list[str],
        param_delta: dict[str, list[str]],
    ) -> tuple[str | None, float]:
        # privilege escalation: baseline so ve 401/403, candidata ve 2xx
        base_codes = statuses_by_role.get(baseline, [])
        base_denied = bool(base_codes) and all(c in (401, 403, 404) for c in base_codes)
        any_2xx_in_candidate = any(
            any(200 <= c < 300 for c in statuses_by_role.get(c_name, []))
            for c_name in candidates
        )
        if base_denied and any_2xx_in_candidate:
            return "privilege_escalation", 0.8

        # IDOR-ish: path tem :id e statuses divergentes entre candidatas
        if ":id" in path and len({tuple(sorted(set(v))) for v in statuses_by_role.values() if v}) > 1:
            return "potential_idor", 0.55

        # endpoint exclusivo a candidata privilegiada
        if only_in and method in ("GET", "POST", "PUT", "PATCH", "DELETE"):
            return "hidden_endpoint", 0.5

        # mass assignment-ish: parametro novo apenas em role privilegiada
        if any(p for p in param_delta.values() if p):
            return "mass_assignment_candidate", 0.45

        return None, 0.0

    @staticmethod
    def _summary(diffs: list[EndpointDiff]) -> dict[str, Any]:
        out: dict[str, Any] = {"total_endpoints_compared": len(diffs), "by_suspicion": {}}
        for d in diffs:
            if d.suspicion:
                out["by_suspicion"][d.suspicion] = out["by_suspicion"].get(d.suspicion, 0) + 1
        return out
