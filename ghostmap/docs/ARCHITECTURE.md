# GhostMap — Architecture

## Visão de alto nível

GhostMap segue um modelo **event-driven** com bounded contexts isolados, comunicando exclusivamente via **Redis Streams**. Não há chamadas síncronas entre serviços de captura e processamento; isso garante backpressure natural, replay, e desacoplamento.

```
              ┌─────────────────┐         ┌───────────────────┐
              │   Browser do    │  HTTP   │     mitmproxy     │
   hunter ──> │   hunter        │ ──────> │   (capture/proxy) │ ──┐
              │ (Playwright OU  │         └───────────────────┘   │ XADD
              │  normal)        │                                  │  gm:capture:http
              └────────┬────────┘                                  │  gm:capture:websocket
                       │ JS hooks injetados                        │
                       v                                           │
              ┌─────────────────┐                                  │
              │ Playwright      │ ─────────────────────────────────┤
              │ instrumenter    │   XADD gm:capture:browser        │
              └─────────────────┘                                  │
                                                                   v
                                          ┌──────────────────────────────┐
                                          │       Redis Streams          │
                                          │ (event bus, consumer groups) │
                                          └──┬──────────┬──────────┬─────┘
                                             │          │          │
                ┌────────────────────────────┘          │          └────────────────────┐
                │ persistor                              │ graph_projector              │ ai_indexer
                v                                        v                              v
        ┌──────────────┐                       ┌──────────────────┐            ┌────────────────┐
        │  PostgreSQL  │                       │      Neo4j       │            │ HeatmapService │
        │ (raw store)  │                       │  (topologia)     │            │   (re-score)   │
        └──────┬───────┘                       └────────┬─────────┘            └────────────────┘
               │                                        │
               │  REST (FastAPI)                        │  Cypher (GraphService, RoleDiff)
               v                                        v
                       ┌──────────────────────────────────────┐
                       │              Backend API             │
                       │   /api/v1/*  +  /ws  (broadcaster)   │
                       └────────────────┬─────────────────────┘
                                        │ HTTP + WebSocket
                                        v
                       ┌──────────────────────────────────────┐
                       │       Frontend Next.js (UI)          │
                       │  GhostGraph, Proxy, Replay, Roles    │
                       └──────────────────────────────────────┘
```

## Bounded contexts

### 1. Capture (capture/)
Produtores de eventos. Não tocam em Postgres ou Neo4j diretamente — apenas publicam em Redis. Substituíveis (poderíamos plugar um proxy mobile no futuro).

- `capture/proxy/mitm_addon.py` — addon mitmproxy
- `capture/proxy/replay_engine.py` — replay HTTP/2 com mutações JSON Patch
- `capture/proxy/har_exporter.py` — HAR 1.2
- `capture/browser/instrumenter.py` — Playwright + scripts JS injetados + CDP

### 2. Event bus (backend/app/core/events.py)
Abstração `EventBus` em cima de Redis Streams. Streams:

- `gm:capture:http`, `gm:capture:websocket`, `gm:capture:browser`
- `gm:analysis:requests` (re-published pelo persistor para análise)
- `gm:ui:broadcast` (saída para WebSocket gateway)

Consumer groups garantem que múltiplos workers do mesmo serviço dividem trabalho. `MAXLEN ~100k` controla memória.

### 3. Persistence (backend/app/workers/persistor.py)
Consome capture streams e grava em Postgres (raw store). Pós-commit, republica em `gm:analysis:requests` e `gm:ui:broadcast`.

### 4. Graph projection (backend/app/workers/graph_projector.py + services/graph_service.py)
Consome `gm:capture:http` e faz `MERGE` no Neo4j. Idempotente via chave natural `sha1(project|host|method|norm_path)`. Infere `CHAINS_INTO` por proximidade temporal (≤5s na mesma session).

### 5. Heatmap & AI (backend/app/services/heatmap_service.py + workers/ai_indexer.py + ai/)
- Heurística determinística: re-pontua endpoints (admin/internal, write-on-id, risky params, GraphQL admin, upload).
- AI layer multi-provider: 4 agentes, cada um com policy YAML declarando ordem de preferência de modelos e limite de custo.
- Política de **no-attack**: agentes apenas analisam e hipotetizam.

### 6. API & WebSocket (backend/app/api/ + main.py)
FastAPI com routers v1 (projects, sessions, requests, graph, replay, roles, ai). WebSocket gateway consome `gm:ui:broadcast` e empurra para os clientes — frontend atualiza grafo e tabela de requests em tempo real.

### 7. UI (frontend/)
Next.js 14 (App Router) + TypeScript + Tailwind + Zustand. GhostGraph usa ReactFlow com layout dagre, minimap e filtros (label, host, heat). Páginas: Projects, Proxy (live), Graph, Roles (diff), Replay, AI.

## Princípios de design

1. **Event sourcing leve.** Postgres é canônico para tráfego bruto. Neo4j é projeção — sempre rebuildável a partir do Postgres.
2. **At-least-once + idempotência.** Cada evento tem `event_id` (ULID). Projetores usam `MERGE`. Consumidores fazem `XACK` só após commit.
3. **Abstrações encapsuladas.** `EventBus`, `LLMProvider`, `GraphService` têm interfaces estáveis — implementação substituível (Kafka, novo provider, Memgraph).
4. **Soberania.** Ollama local para análises sensíveis. Redaction obrigatória para providers externos.
5. **Hunter no controle.** Nenhuma ação ofensiva é automática.

## Escalabilidade

- **Vertical primeiro.** Postgres + Neo4j single-node atendem até dezenas de milhões de requests por projeto. Particionar `http_requests` por `project_id` quando passar disso.
- **Horizontal de consumers.** Basta subir mais réplicas do `worker`. Consumer groups balanceiam.
- **Frontend.** Para grafos > 5k nodes, mudar de dagre client-side para clustering server-side (`apoc.algo.louvain`) + pageamento.

## Observabilidade (próxima iteração)

Hooks já presentes:
- `structlog` JSON em todos os processos
- `ai_invocations` audita toda chamada para provider externo
- Stream lengths e consumer lag são visíveis via `XINFO STREAM` / `XPENDING`

Próximos: Prometheus exporters + dashboards Grafana para event lag, tempo de projeção, e gasto de IA.
