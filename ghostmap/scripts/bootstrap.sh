#!/usr/bin/env bash
# Bootstrap GhostMap: cria .env (se não existir), sobe stack, espera healthchecks,
# roda migrations e seeds.

set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

log() { printf "\033[1;35m[ghostmap]\033[0m %s\n" "$*"; }

if [[ -f .env ]]; then
  set -a
  # shellcheck disable=SC1091
  source .env
  set +a
fi

if [[ ! -f .env ]]; then
  log "criando .env a partir de .env.example"
  cp .env.example .env
  # gera secret aleatorio se openssl existir
  if command -v openssl &>/dev/null; then
    SECRET=$(openssl rand -hex 32)
    sed -i.bak "s|GHOSTMAP_SECRET=.*|GHOSTMAP_SECRET=${SECRET}|" .env && rm -f .env.bak
  fi
fi

log "subindo stack docker-compose (aguarda healthchecks)"
docker compose up -d --wait postgres neo4j redis

log "rodando migrations postgres"
docker compose run --rm backend alembic upgrade head || true

log "rodando constraints neo4j"
docker compose exec -T neo4j cypher-shell -u neo4j -p "${NEO4J_PASSWORD:-ghostmap_neo4j}" \
  < migrations/neo4j/001_constraints.cypher || true

log "subindo backend, worker, mitmproxy, frontend"
docker compose up -d backend worker mitmproxy frontend

log "pronto."
log "  UI:        http://localhost:3000"
log "  API:       http://localhost:8000/docs"
log "  mitmweb:   http://localhost:8081"
log "  neo4j:     http://localhost:7474  (user: neo4j)"
log ""
log "configure seu browser para usar o proxy http://localhost:8080"
log "instale o cert do mitmproxy em http://mitm.it apos conectar"
