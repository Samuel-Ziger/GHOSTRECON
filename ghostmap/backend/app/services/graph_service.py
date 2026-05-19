"""
GraphService — projeta requests Postgres em grafo Neo4j e responde queries
para a UI.

Modelo:
  (Host) -[:HOSTS]-> (Endpoint {host, method, path})
  (Page) -[:NAVIGATES_TO]-> (Page)
  (Page) -[:CALLS]-> (Endpoint)
  (Endpoint) -[:USES_PARAM]-> (Param)
  (Endpoint) -[:AUTH_BY]-> (JWT|Cookie)
  (Role)    -[:OBSERVED_AT]-> (Endpoint)
  (Endpoint)-[:CHAINS_INTO]-> (Endpoint)
  (Endpoint)-[:INTEGRATES_WITH]-> (Integration)
  (Endpoint)-[:UPLOADS_TO]-> (Bucket)

Idempotencia: MERGE por chave natural (project_id + label + identidade unica).
"""
from __future__ import annotations

import hashlib
from datetime import datetime
from typing import Any
from uuid import UUID
from urllib.parse import urlparse

from app.db.neo4j_client import Neo4jClient, get_neo4j
from app.schemas.graph import GraphEdge, GraphFilter, GraphNode, GraphResponse


def _norm_path(path: str) -> str:
    """Substitui IDs numericos/UUIDs por ':id' para agrupar mesmo endpoint."""
    parts = []
    for seg in path.split("/"):
        if not seg:
            parts.append(seg); continue
        if seg.isdigit() or len(seg) >= 30 or _looks_uuid(seg):
            parts.append(":id")
        else:
            parts.append(seg)
    return "/".join(parts)


def _looks_uuid(s: str) -> bool:
    return len(s) == 36 and s.count("-") == 4


def _endpoint_id(project_id: UUID, host: str, method: str, norm_path: str) -> str:
    raw = f"{project_id}|{host}|{method}|{norm_path}"
    return "ep_" + hashlib.sha1(raw.encode("utf-8")).hexdigest()[:16]


class GraphService:
    """Operacoes contra Neo4j."""

    def __init__(self, client: Neo4jClient | None = None) -> None:
        self.client = client or get_neo4j()

    # ---------- projection ----------
    async def upsert_http_request(self, *, project_id: UUID, role_id: UUID | None, role_name: str | None,
                                  method: str, url: str, status: int | None,
                                  query: dict[str, Any] | None, headers: dict[str, Any] | None,
                                  graphql_op: str | None, occurred_at: datetime) -> str:
        u = urlparse(url)
        host = u.netloc.split(":")[0]
        norm = _norm_path(u.path or "/")
        ep_id = _endpoint_id(project_id, host, method.upper(), norm)
        params = list((query or {}).keys())

        cypher = """
        MERGE (h:Host {id: $host_id}) ON CREATE SET h.project_id = $pid, h.name = $host
        MERGE (e:Endpoint {id: $ep_id})
          ON CREATE SET e.project_id = $pid, e.host = $host, e.method = $method,
                        e.path = $path, e.first_seen = $ts, e.hits = 1
          ON MATCH  SET e.last_seen = $ts, e.hits = coalesce(e.hits,0) + 1
        MERGE (h)-[:HOSTS]->(e)
        WITH e
        FOREACH (p IN $params |
            MERGE (pp:Param {id: e.id + ':' + p})
              ON CREATE SET pp.name = p, pp.project_id = $pid
            MERGE (e)-[:USES_PARAM]->(pp)
        )
        WITH e
        FOREACH (_ IN CASE WHEN $role_id IS NULL THEN [] ELSE [1] END |
            MERGE (r:Role {id: $role_id})
              ON CREATE SET r.project_id = $pid, r.name = $role_name
            MERGE (r)-[obs:OBSERVED_AT]->(e)
              ON CREATE SET obs.first_status = $status, obs.hits = 1
              ON MATCH  SET obs.hits = obs.hits + 1
            FOREACH (s IN CASE WHEN $status IS NULL THEN [] ELSE [$status] END |
                SET obs.statuses = coalesce(obs.statuses, []) + s
            )
        )
        WITH e
        FOREACH (op IN CASE WHEN $graphql_op IS NULL THEN [] ELSE [$graphql_op] END |
            MERGE (g:GraphQLOperation {id: e.id + ':gql:' + op})
              ON CREATE SET g.name = op, g.project_id = $pid
            MERGE (e)-[:HAS_GRAPHQL_OP]->(g)
        )
        RETURN e.id AS id
        """
        rows = await self.client.run(cypher, {
            "pid": str(project_id),
            "host_id": f"host_{project_id}_{host}",
            "host": host,
            "ep_id": ep_id,
            "method": method.upper(),
            "path": norm,
            "ts": occurred_at.isoformat(),
            "params": params,
            "role_id": str(role_id) if role_id else None,
            "role_name": role_name,
            "status": status,
            "graphql_op": graphql_op,
        })
        return rows[0]["id"] if rows else ep_id

    async def link_chain(self, src_ep_id: str, dst_ep_id: str) -> None:
        """Marca que src foi chamado e logo em seguida dst (chain inferido por proximidade temporal)."""
        await self.client.write(
            "MATCH (a:Endpoint {id: $a}), (b:Endpoint {id: $b}) "
            "MERGE (a)-[r:CHAINS_INTO]->(b) "
            "ON CREATE SET r.hits = 1 ON MATCH SET r.hits = r.hits + 1",
            {"a": src_ep_id, "b": dst_ep_id},
        )

    # ---------- read ----------
    async def fetch_graph(self, f: GraphFilter) -> GraphResponse:
        cypher_nodes = """
        MATCH (n)
        WHERE n.project_id = $pid
          AND ($labels IS NULL OR any(l IN labels(n) WHERE l IN $labels))
          AND ($hosts  IS NULL OR n.host IS NULL OR n.host IN $hosts)
          AND coalesce(n.heat, 0.0) >= $min_heat
        RETURN n, labels(n) AS lbls
        LIMIT $limit
        """
        nodes_rows = await self.client.run(cypher_nodes, {
            "pid": str(f.project_id),
            "labels": f.labels,
            "hosts": f.hosts,
            "min_heat": f.min_heat,
            "limit": f.limit_nodes,
        })
        node_ids = [r["n"].get("id") for r in nodes_rows]
        cypher_edges = """
        MATCH (s)-[r]->(t)
        WHERE s.id IN $ids AND t.id IN $ids
        RETURN s.id AS s, t.id AS t, type(r) AS ty, properties(r) AS p
        """
        edges_rows = await self.client.run(cypher_edges, {"ids": node_ids})

        nodes: list[GraphNode] = []
        for r in nodes_rows:
            n = r["n"]
            lbls = r["lbls"]
            primary = lbls[0] if lbls else "Endpoint"
            title = n.get("name") or n.get("path") or n.get("url") or n.get("id")
            nodes.append(GraphNode(
                id=n.get("id"),
                label=primary,           # validated by Literal in schema; provide best-effort
                title=str(title),
                props={k: v for k, v in n.items() if k != "id"},
                heat=float(n.get("heat", 0.0)),
                cluster=n.get("cluster"),
            ))
        edges = [
            GraphEdge(
                id=f"{r['s']}->{r['t']}:{r['ty']}",
                source=r["s"], target=r["t"], type=r["ty"], props=r["p"] or {},
            )
            for r in edges_rows
        ]
        return GraphResponse(
            nodes=nodes, edges=edges,
            stats={"nodes": len(nodes), "edges": len(edges)},
        )

    async def reset_project(self, project_id: UUID) -> None:
        await self.client.write(
            "MATCH (n {project_id: $pid}) DETACH DELETE n",
            {"pid": str(project_id)},
        )
