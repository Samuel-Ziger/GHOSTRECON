# GhostMap — Data Flow

Este documento descreve o caminho de um único request HTTP capturado, do navegador do hunter até aparecer como um node no grafo da UI.

## 1. Captura (mitmproxy addon)

```python
def response(flow):
    if scope.matches(flow.request.host):
        ev = build_http_event(flow, duration_ms)
        redis.xadd("gm:capture:http", {"d": orjson.dumps(ev)})
```

Schema do evento:

```jsonc
{
  "event_id": "01HXAB...",          // ULID; chave de idempotência
  "schema":   "gm.capture.http/1",
  "project_id": "uuid",
  "session_id": "uuid",
  "occurred_at": "2026-05-19T16:21:03Z",
  "flow_id":  "<mitm flow id>",
  "request":  { "method", "url", "host", "path", "query", "headers", "body_b64", "body_text", "is_xhr", "is_graphql", "graphql_op" },
  "response": { "status", "headers", "body_b64", "body_text" } | null,
  "duration_ms": 142,
  "client": { "ip": "..." }
}
```

## 2. Bus (Redis Streams)

```
XADD gm:capture:http * d <json>   MAXLEN ~ 100000
```

`MAXLEN` aproximado garante que o stream não cresce indefinidamente. `XADD` é sub-ms localmente; o addon não bloqueia.

## 3. Consumer: persistor (Postgres)

```python
async for m in bus.consume("gm:capture:http", group="persist-http", consumer="p1"):
    await persist_http(m.event)                       # INSERT em http_requests
    await bus.publish("gm:analysis:requests", m.event)  # fan-out p/ analise
    await bus.publish("gm:ui:broadcast", _summary(m.event))  # fan-out p/ UI
    await bus.ack(stream, group, m.msg_id)
```

Garantia: **at-least-once**. Em caso de crash entre `persist_http` e `ack`, o evento é reprocessado — `INSERT` daria conflict de PK porque usamos UUID novo, então usamos uma chave de deduplicação adicional (na v2). Para v1 aceitamos duplicação rara em caso de crash, porque o impacto é apenas um row extra rastreável.

## 4. Consumer paralelo: graph_projector (Neo4j)

```cypher
MERGE (e:Endpoint { id: $ep_id })
  ON CREATE SET e.project_id=$pid, e.host=$host, e.method=$method, e.path=$norm_path, e.first_seen=$ts, e.hits=1
  ON MATCH  SET e.last_seen=$ts, e.hits=e.hits+1
```

A chave natural do endpoint é `sha1(project|host|method|normalized_path)`. Path normalizado substitui IDs (`/users/42` -> `/users/:id`), garantindo que requests ao mesmo recurso colidam no mesmo node.

Por proximidade temporal (≤5s na mesma session), o projector também cria edges `CHAINS_INTO` entre endpoints consecutivos — reconstrói automaticamente fluxos de navegação.

## 5. Consumer terciário: ai_indexer (heatmap)

```python
pending.add(project_id)
if len(pending) >= 50 or time_since_flush > 10s:
    for pid in pending:
        await heatmap_service.recompute_project(pid)
    pending.clear()
```

Reduz N requests em 1 query batched de heatmap por projeto. A heurística determinística (admin/internal, write-on-id, risky params, GraphQL admin, upload) atribui score [0..1] a cada endpoint e grava em `e.heat` no Neo4j.

## 6. WS broadcast (UI)

```python
async for m in bus.consume("gm:ui:broadcast", "ui-gateway", "ui-1"):
    await connection_manager.broadcast(m.event)
```

O frontend mantém um WebSocket aberto em `/ws`. Mensagens chegam como `{type, data}`:
- `http_request` -> push no `useProxyStore` -> tabela atualiza
- `graph_update` -> debounce 300ms -> `api.fetchGraph` -> `useGraphStore` -> ReactFlow re-renderiza
- `browser_event` -> reservado para timeline futura

## 7. Render no GhostGraph

```ts
useEffect(() => {
  api.fetchGraph(project.id, { min_heat }).then(setData);
}, [project.id, min_heat]);

const laid = layoutDagre(toRFNodes(data), toRFEdges(data), "LR");
<ReactFlow nodes={laid.nodes} edges={laid.edges} nodeTypes={{ ghost: GhostNode }} fitView />
```

Cada node renderiza com cor por label e borda por heat (low/mid/high). Filtros (busca, min_heat) operam client-side; para grafos > 5k nodes, mover filtros para o backend.

## Latências esperadas (local)

| Etapa                              | Latência típica |
|------------------------------------|-----------------|
| addon -> Redis XADD                | < 2 ms          |
| Redis -> persistor INSERT          | 5–15 ms         |
| persistor -> Neo4j MERGE           | 10–30 ms        |
| Neo4j MERGE -> WS broadcast        | 5 ms            |
| WS -> UI render (debounced)        | 300 ms          |
| **Total p95 user-visible**         | **≈ 350 ms**    |

Para alvos com bursts (centenas de req/s), o gargalo passa a ser o Neo4j MERGE — endereçável com batching no projector.

## Replay (caminho oposto)

```
UI (Replay tab)
  -> POST /api/v1/requests/{id}/replay { add_headers, remove_headers, ... }
     -> ReplayService carrega http_request original do Postgres
        -> ReplayEngine (httpx HTTP/2) dispara contra o alvo
           -> persiste em `replays`
              -> retorna ReplayOut para a UI
```

O replay é **explícito**, iniciado pelo hunter. Nada na pipeline automática re-dispara requests.
