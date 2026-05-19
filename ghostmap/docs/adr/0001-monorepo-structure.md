# ADR-0001 — Monorepo Layout

## Status
Accepted — 2026-05-19

## Context
GhostMap é composto por múltiplos serviços heterogêneos (Python/FastAPI, Python/mitmproxy, Python/Playwright, TypeScript/Next.js) que precisam compartilhar contratos, schemas e protocolos de evento. Repositórios separados aumentam o atrito de evolução de contratos e a deriva entre módulos.

## Decision
Adotamos um **monorepo** organizado por **bounded contexts** (DDD light), não por camada técnica:

```
ghostmap/
├── backend/        # API, services, models, eventos (FastAPI)
├── capture/        # Proxy + Browser instrumentation (produtores de eventos)
├── frontend/       # UI Next.js
├── docs/           # ADRs, diagramas, documentação técnica
├── migrations/     # Schemas (Postgres + Neo4j)
├── scripts/        # Bootstrap, seed, utilitários
└── docker-compose.yml
```

Cada bounded context possui seu próprio `Dockerfile` e gestão de dependências (pyproject.toml / package.json).

## Consequences
- **+** Refactor de contratos atômico (schemas/eventos mudam num único commit).
- **+** CI compartilhado, lint unificado, versionamento sincronizado.
- **+** Onboarding mais simples: 1 clone, 1 `docker compose up`.
- **−** Build cache mais difícil de gerenciar — mitigado com BuildKit cache mounts.
- **−** Repositório cresce rápido; convencionamos `git lfs` para artefatos binários (HARs grandes, dumps).

## Alternativas Consideradas
- **Polyrepo**: rejeitado pelo overhead de coordenação de contratos.
- **Monorepo com Nx/Turborepo**: prematuro neste estágio; adicionável depois sem refactor estrutural.
