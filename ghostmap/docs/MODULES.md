# GhostMap — Modules

Mapa rápido por módulo, com responsabilidade, dependências e quando estender.

## capture/proxy/

| Arquivo            | Responsabilidade |
|--------------------|------------------|
| `mitm_addon.py`    | Hooks mitmproxy (request/response/ws). Publica eventos no Redis. Scope filtering por host. |
| `replay_engine.py` | Re-executa requests com mutações (add/remove headers, body override, JSON Patch). HTTP/2. |
| `har_exporter.py`  | Converte requests internos para HAR 1.2 (compatível Burp/ZAP). |

Estenda quando: adicionar suporte a HTTP/3, proxy mobile, ou hooks para outros protocolos.

## capture/browser/

| Arquivo            | Responsabilidade |
|--------------------|------------------|
| `instrumenter.py`  | Wrap Playwright. Injeta JS (storage hooks, MutationObserver, fetch/XHR monkey-patch). CDP para WS frames. Diff de cookies. |
| `runner.py`        | Entry point standalone. |

Estenda quando: capturar eventos específicos do framework do alvo (ex: store Redux do app).

## backend/app/core/

| Arquivo        | Responsabilidade |
|----------------|------------------|
| `config.py`    | Pydantic Settings (env). |
| `events.py`    | `EventBus`, `Streams`, `CaptureEvent`. Abstração trocável (Kafka/NATS no futuro). |
| `security.py`  | JWT introspection (sem verify), redaction de tokens/PII para prompts. |
| `exceptions.py`| `DomainError` e handlers HTTP. |
| `logging.py`   | structlog JSON. |

## backend/app/db/

| Arquivo            | Responsabilidade |
|--------------------|------------------|
| `postgres.py`      | SQLAlchemy 2.0 async engine + `session_scope()`. |
| `neo4j_client.py`  | Driver Neo4j async + helpers `run`/`write`. |
| `redis_client.py`  | Singleton Redis async. |

## backend/app/models/

| Modelo                   | Tabela | Notas |
|--------------------------|--------|-------|
| `Project`, `Role`        | `projects`, `roles` | Multi-tenant lite. |
| `Session`                | `sessions` | Captura agrupada (1 role = 1+ session). |
| `HttpRequest`, `WsFrame`, `DomEvent` | `http_requests`, `ws_frames`, `dom_events` | Raw store. |
| `Finding`, `AiInvocation`| `findings`, `ai_invocations` | Heatmap output + auditoria de IA. |
| `Replay`                 | `replays` | Histórico de replays disparados. |

## backend/app/services/

| Service                    | Quem usa | Faz o quê |
|----------------------------|----------|-----------|
| `GraphService`             | `graph.py`, `graph_projector` | Upsert no Neo4j (MERGE idempotente), fetch para a UI, link de chains. |
| `HeatmapService`           | `graph.py`, `ai_indexer` | Recalcula scores de risco por projeto. |
| `RoleDifferentialService`  | `graph.py` | Compara baseline vs candidates; gera `EndpointDiff` com suspicion. |
| `ReplayService`            | `replay.py` | Re-executa request via `ReplayEngine` e persiste em `replays`. |
| `AIService`                | `ai.py` | Fachada para `AIOrchestrator` + audit. |

## backend/app/ai/

| Item                            | Responsabilidade |
|---------------------------------|------------------|
| `base.py`                       | `LLMProvider`, `ChatMessage`, `LLMResponse`, `ProviderSpec`. |
| `providers/anthropic_provider.py` | Anthropic Messages API. |
| `providers/gemini_provider.py`  | Google `google-generativeai`. |
| `providers/openrouter_provider.py` | OpenRouter (OpenAI-compatible). Vários modelos = várias entradas de policy. |
| `providers/ollama_provider.py`  | Ollama local. Tem `embed()` para embeddings. |
| `orchestrator.py`               | `AIOrchestrator` com routing, fallback, redaction, max_cost. |
| `policies/*.yaml`               | Policy por agente: `prefer` / `fallback`, custo, JSON mode, redaction. |
| `agents/flow_analyzer.py`       | Descreve fluxos da app. |
| `agents/trust_boundary_detector.py` | Identifica trust boundaries. |
| `agents/hypothesis_generator.py`| Gera hipóteses ofensivas (sem atacar). |
| `agents/heatmap_classifier.py`  | Classifica risco de endpoint (roda local). |

## backend/app/api/v1/

| Endpoint base                                 | Operações principais |
|-----------------------------------------------|----------------------|
| `/projects`                                   | GET/POST/GET-by-id |
| `/projects/{id}/roles`                        | GET/POST |
| `/sessions`                                   | POST/GET-by-id |
| `/projects/{id}/requests`                     | GET (filtros), GET-by-id, GET export/har |
| `/projects/{id}/graph`                        | GET fetch, POST heatmap/recompute, POST role-diff, DELETE reset |
| `/requests/{id}/replay`                       | POST |
| `/ai/run`                                     | POST (qualquer agente) |
| `/ws`                                         | WebSocket gateway |

## backend/app/workers/

| Worker             | Stream que consome | O que faz |
|--------------------|--------------------|-----------|
| `http_persistor`   | `gm:capture:http`  | INSERT em `http_requests`. Republica para análise + UI. |
| `browser_persistor`| `gm:capture:browser` | INSERT em `dom_events`/`ws_frames`. |
| `graph_projector`  | `gm:capture:http`  | MERGE no Neo4j. Infere chains. |
| `ai_indexer`       | `gm:analysis:requests` | Re-score heatmap batched. |

`runner.py` é o entry point do container `worker`.

## frontend/

| Caminho                            | Responsabilidade |
|------------------------------------|------------------|
| `src/app/layout.tsx`               | Layout root (Sidebar + TopBar + WSBridge). |
| `src/app/page.tsx`                 | Landing. |
| `src/app/projects/page.tsx`        | CRUD básico de projetos. |
| `src/app/proxy/page.tsx`           | Live tabela de requests + filtros + export HAR. |
| `src/app/graph/page.tsx`           | GhostGraph (mount). |
| `src/app/roles/page.tsx`           | Diff de roles (baseline vs candidates). |
| `src/app/replay/page.tsx`          | Disparo manual de replay com mutações. |
| `src/app/ai/page.tsx`              | UI dos 4 agentes. |
| `src/components/graph/GhostGraph.tsx` | ReactFlow + dagre + minimap + filtros. |
| `src/components/graph/GhostNode.tsx`  | Node custom (cor por label, border por heat). |
| `src/components/layout/WSBridge.tsx`  | Listener WS global que despacha para stores. |
| `src/lib/api.ts`                   | Cliente REST. |
| `src/lib/ws.ts`                    | WebSocket com reconexão exponencial. |
| `src/store/*.ts`                   | Zustand stores (session, proxy, graph, ai). |

## migrations/

- `postgres/001_initial.sql` — schemas + extensões (pgcrypto, pg_trgm) + índices.
- `neo4j/001_constraints.cypher` — uniqueness por id + índices de busca.
