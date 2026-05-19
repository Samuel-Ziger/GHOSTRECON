# ADR-0002 — Dual Database: Postgres + Neo4j

## Status
Accepted — 2026-05-19

## Context
GhostMap precisa armazenar dois tipos fundamentalmente distintos de dados:

1. **Dados transacionais e tabulares** — projetos, sessions, requests/responses brutos, replays, findings, configs de usuário, audit log. Pesquisa por filtros, paginação, full-text.
2. **Topologia da aplicação alvo** — relações complexas entre páginas, endpoints, parâmetros, tokens, roles e trust boundaries. Queries de caminho, padrões e diferencial entre subgrafos (role diff).

Tentar resolver os dois em um único banco gera tradeoffs ruins: SQL para grafo profundo é doloroso (recursive CTEs explodem); um grafo puro para histórico transacional perde maturidade de ferramental (migrations, backups, particionamento).

## Decision
Usamos **dois bancos especializados**:

- **PostgreSQL 16** — fonte de verdade para entidades transacionais. SQLAlchemy 2.0 + Alembic. Particionamento por `project_id` quando volume crescer.
- **Neo4j 5** — fonte de verdade para o **grafo da aplicação**. Cypher para queries de padrão, `shortestPath`, projeções GDS para clustering, comparação de subgrafos para Role Differential.

Os dois bancos **não compartilham consistência transacional**. A regra é:
- Postgres é canônico para `Request` cru.
- Neo4j é uma **projeção derivada** construída pelo `GraphProjector` (consumer de Redis Streams).
- Se Neo4j ficar inconsistente, reprojetamos a partir do Postgres — Postgres é o sistema de registro.

## Consequences
- **+** Cada banco brilha no que faz bem.
- **+** Role Diff vira uma query Cypher elegante em vez de 200 linhas de SQL.
- **+** Posso rebuildar o grafo a partir do histórico bruto (idempotência por design).
- **−** Operação dupla (backup, monitor, upgrade).
- **−** Necessário garantir idempotência no projector — mitigado com chaves naturais (`MERGE` por hash de URL+método).

## Alternativas Consideradas
- **PostgreSQL + extensão Apache AGE**: maturidade ainda insuficiente para o volume de relações que esperamos.
- **ArangoDB**: multi-modelo, mas ecossistema menor; preferimos especialistas.
