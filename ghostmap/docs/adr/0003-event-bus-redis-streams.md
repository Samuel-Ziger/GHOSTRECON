# ADR-0003 — Event Bus: Redis Streams

## Status
Accepted — 2026-05-19

## Context
GhostMap tem múltiplos **produtores** de eventos (mitmproxy addon, Playwright instrumenter) e múltiplos **consumidores** (persistor Postgres, projector Neo4j, broadcaster WebSocket, analisador AI). O fluxo precisa ser:

- realtime (latência < 100ms do request ao node aparecer no grafo);
- replay-friendly (consumer pode reprocessar do início);
- com consumer groups (vários workers do mesmo consumer dividem trabalho);
- sem operar Kafka/RabbitMQ em produção desde dia 1.

## Decision
Adotamos **Redis Streams** como event bus único. Stream por bounded context:

| Stream                  | Produtor                  | Consumers                                       |
|-------------------------|---------------------------|-------------------------------------------------|
| `gm:capture:http`       | mitmproxy addon           | persistor, graph_projector, ws_broadcaster      |
| `gm:capture:browser`    | playwright instrumenter   | persistor, graph_projector, ws_broadcaster      |
| `gm:capture:websocket`  | mitmproxy addon           | persistor, ws_broadcaster                       |
| `gm:analysis:requests`  | persistor (post-commit)   | ai_orchestrator, heatmap_classifier             |
| `gm:ui:broadcast`       | qualquer service          | websocket gateway -> browser clients            |

Schema de evento padronizado (`backend/app/core/events.py`):

```python
class CaptureEvent(BaseModel):
    event_id: str          # ULID
    project_id: UUID
    session_id: UUID
    kind: Literal["http", "websocket", "dom", "storage", ...]
    occurred_at: datetime  # source clock
    received_at: datetime  # bus clock
    payload: dict
```

Garantias: **at-least-once** com idempotência via `event_id` (ULID). Consumidores guardam o último `event_id` processado.

## Consequences
- **+** Um único serviço novo (Redis) — já usaremos para cache de sessions/JWT introspection.
- **+** XADD/XREADGROUP têm latência sub-ms localmente.
- **+** `MAXLEN ~ 100000` controla memória.
- **−** Sem garantias multi-region — aceitável para v1.
- **−** Migração futura para NATS JetStream ou Kafka é provável -> por isso encapsulamos em `core/events.py` com interface `EventBus`.

## Alternativas Consideradas
- **Kafka**: poderoso demais para o estágio atual, custo operacional alto.
- **RabbitMQ**: bom, mas sem replay nativo (precisaríamos de plugin).
- **NATS JetStream**: forte candidato; manteremos `EventBus` abstrato para migração futura.
