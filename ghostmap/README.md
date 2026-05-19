# GhostMap

> Visual application mapping for offensive security — bug bounty & pentest.

GhostMap **não é um scanner automático**. Ele é uma plataforma visual que ajuda o hunter a entender uma aplicação: navegar com browser instrumentado, capturar tudo (HTTP/WS/DOM/storage), montar um grafo vivo da aplicação, comparar comportamento entre roles, e usar IA como copiloto analítico (sem nunca atacar sozinho).

## Quick start

```bash
git clone <repo> ghostmap && cd ghostmap
cp .env.example .env                  # edite secrets se quiser
./scripts/bootstrap.sh                # sobe tudo + migrations
```

Em seguida:

| Componente   | URL                                 |
|--------------|-------------------------------------|
| UI           | http://localhost:3000               |
| API          | http://localhost:8000/docs          |
| mitmweb      | http://localhost:8081               |
| Neo4j browser| http://localhost:7474               |

Configure seu navegador para usar o proxy `http://localhost:8080` e instale o cert do mitmproxy em `http://mitm.it` após conectar uma vez.

## Stack

| Camada      | Tecnologia                                         |
|-------------|----------------------------------------------------|
| Frontend    | Next.js 14, TypeScript, Tailwind, ReactFlow, Zustand |
| Backend     | FastAPI 0.115, SQLAlchemy 2.0 async, WebSocket    |
| Eventos     | Redis Streams (consumer groups + replay)          |
| Captura     | mitmproxy 11 addon + Playwright 1.48              |
| Banco       | PostgreSQL 16 + Neo4j 5 (APOC)                    |
| IA          | Anthropic, Gemini, OpenRouter (n modelos), Ollama  |

## Documentação

- [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) — visão de alto nível, princípios e bounded contexts
- [docs/DATA_FLOW.md](docs/DATA_FLOW.md) — pipeline event-driven do request bruto ao grafo
- [docs/MODULES.md](docs/MODULES.md) — responsabilidade de cada módulo
- [docs/adr/](docs/adr/) — Architecture Decision Records (ADRs)

## Princípios

1. **Hunter no comando.** A IA correlaciona, sugere e classifica — **nunca** dispara payload, fuzz, ou modifica request sem o hunter pedir replay.
2. **Soberania de dados.** Por padrão usamos Ollama local para análises sensíveis. Providers externos recebem prompts redacted (JWT, cookies, API keys).
3. **Idempotência por design.** Postgres é a fonte de verdade do tráfego bruto. Neo4j é uma projeção derivada — sempre rebuildável.
4. **Modular e escalável.** Cada bounded context tem seu Dockerfile, suas deps, sua interface. Sem monolito.

## Estrutura

```
ghostmap/
├── backend/         # FastAPI: API + workers + AI orchestrator
├── capture/         # mitmproxy addon + Playwright instrumenter
├── frontend/        # Next.js UI
├── docs/            # ARCHITECTURE, DATA_FLOW, MODULES, ADRs
├── migrations/      # Postgres SQL + Neo4j Cypher
├── scripts/         # bootstrap.sh
└── docker-compose.yml
```

## Estado atual (v0.1)

Implementado:
- Proxy Engine completo (HTTP/HTTPS/WS, HAR export, replay com HTTP/2)
- Browser Instrumentation (Playwright + CDP)
- Event Bus (Redis Streams) com consumer groups
- Backend FastAPI com 7 routers + WebSocket gateway
- Graph Engine Neo4j com 14 tipos de nodes
- Role Differential Engine com 4 heurísticas de suspeita
- AI Layer: 4 providers, 4 agentes, policies YAML
- Frontend: 7 páginas, GhostGraph ReactFlow com dagre, dark cyberpunk

Próximas iterações: clustering server-side para grafos 10k+, embeddings semânticos via Ollama, replay batch, suporte a HTTP/3, plugins de auth flows pré-configurados.

## Licença

Research preview. Uso responsável — só rode contra alvos que você está autorizado a testar.
