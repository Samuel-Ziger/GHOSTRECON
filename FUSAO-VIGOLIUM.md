# Plano de fusão GHOSTRECON + Vigolium

Documento técnico e estratégico para incorporar o motor Vigolium (Go) no monorepo GHOSTRECON, com reescrita gradual em Node em paralelo.

**Gerado em:** 2026-06-17  
**Estado do repo:** Vigolium clonado em `vigolium/` (fork upstream com `.git` próprio)  
**Princípio:** um produto, dois runtimes (Node orquestra + Go ataca), uma UI, um CLI.

---

## 1. Visão e objectivo

### O que queres

```
ghostrecon scan -t https://alvo.com
```

…e no terminal + UI correr **tudo** o que o GHOSTRECON já faz (OSINT, workflow bug bounty, Tor, playbooks) **mais** o que o Vigolium faz melhor (DAST nativo, OAST, spider SPA, auth multi-sessão, auditoria de código com Codex/Claude Code).

### Estratégia em duas faixas

| Faixa | Prazo | Acção |
|-------|-------|-------|
| **A — Motor Go** | Semanas → meses | Manter `vigolium/` no monorepo, rebrand interno, bridge Node↔Go, findings unificados |
| **B — Reescrita Node** | Meses → anos | Portar para `server/modules/` só o que fizer sentido customizar (Tor, opsec, bounty context) |

### O que esta fusão **não** é

- Não é reescrever 2.700 ficheiros Go em JavaScript de uma vez.
- Não é apagar copyright — o código Vigolium permanece **AGPL-3.0** com atribuição (ver secção 8).
- Não é substituir o ecossistema GhostTrace/GhostMap/GhostDesk — é **potenciá-lo**.

---

## 2. Inventário GHOSTRECON (estado actual)

### 2.1 Arquitectura actual

```
bin/ghostrecon.mjs
    → POST /api/recon/stream (server/routes/recon-stream.mjs)
        → runPipeline (server/pipeline/run-pipeline.mjs)
            → 9 fases → finalize (score, Shannon, PentestGPT, saveRun, IA)
    → SQLite | Postgres | Supabase (server/modules/db.js)
```

| Componente | Caminho | Métrica |
|------------|---------|---------|
| Servidor HTTP | `server/index.js` | ~171 linhas (pós-refactor) |
| Rotas | `server/routes/` | 11 ficheiros |
| Pipeline | `server/pipeline/phases/` | 9 fases (~4.271 linhas) |
| Módulos | `server/modules/` | **~147** implementações + 19 CLI |
| Registry modular | `module-registry.mjs` | **10** módulos com `run()` |
| Testes | `server/tests/` | **76** ficheiros |
| Playbooks | `playbooks/` | 11 JSON |
| UI principal | `index.html` | ~68 checkboxes de módulos |

### 2.2 Fases do pipeline Node

| # | Fase | Ficheiro | Domínio |
|---|------|----------|---------|
| 1 | input | `input.mjs` | Validação alvo, OPSEC, escopo |
| 2 | fingerprint | `fingerprint.mjs` | Lovable, Supabase, Firebase |
| 3 | discovery | `discovery.mjs` | Subs, CT, RDAP, DNS, VT, email |
| 4 | probe | `probe.mjs` | HTTP alive, WAF, headers, Shodan |
| 5 | content-discovery | `content-discovery.mjs` | Wayback, CC, JS, secrets, GitHub |
| 6 | validation | `validation.mjs` | verify, sqlmap, authz, OOB, cred spray |
| 7 | aggressive | `aggressive.mjs` | Kali: nmap, nuclei, ffuf, dalfox… |
| 8 | asset-discovery | `asset-discovery.mjs` | Takeover, cloud bruteforce, Navegation |
| 9 | finalize | `finalize.mjs` | Score, chaining, Shannon, PentestGPT, DB, IA |

### 2.3 Módulos por domínio (GHOSTRECON)

| Domínio | Qtd. aprox. | Exemplos |
|---------|-------------|----------|
| Recon / OSINT passivo | ~22 | `subdomains`, `wayback`, `github`, `ct-monitor`, `origin-discovery` |
| HTTP / superfície | ~18 | `probe`, `security-headers`, `cors-audit`, `openapi-harvest` |
| JS / client-side | ~3 | `js-analyzer`, `js-crawler`, `js-intel` |
| Secrets | ~4 | `secrets`, `secret-validation`, `secrets-context-ranker` |
| Auth / identidade | ~11 | `authz-matrix`, `jwt-lab`, `cookie-session-audit` |
| Active scan / validação | ~18 | `verify`, `sqlmap-runner`, `dom-xss-verify`, `oob-collaborator` |
| Kali / externo | ~7 | `kali-scan.js` (1742 linhas), `wpscan`, `mysql-nmap-intel` |
| Cloud / BaaS | ~4 | `supabase-audit`, `firebase-audit`, `lovable-fingerprint` |
| IA | ~5 | `ai-dual-report`, `shannon-runner`, `pentestgpt-local` |
| Tor / OPSEC | ~7 | `navegation`, `tor-strict`, `proxy-capture`, `opsec` |
| Workflow / bounty | ~22 | engagements, diff, chaining, purple-team, webhooks |
| Integrações | ~5 | GhostDesk, GhostMap, GhostTrace proxies |

### 2.4 CLI actual

```bash
ghostrecon run -t example.com --modules rdap,subdomains --playbook quick-triage
```

14 comandos: `run`, `runs`, `diff`, `playbooks`, `schedule`, `export`, `projects`, `engagement`, `narrative`, `purple`, `team`, `replay`, `obsidian`, `phish-infra`.

### 2.5 IA actual (GHOSTRECON)

| Integração | Papel | Limitação vs Vigolium |
|------------|-------|------------------------|
| `ai-dual-report.js` | Relatórios pós-run (Gemini/OpenRouter/LM Studio/Claude API) | Não conduz o scan; só resume |
| Shannon (`shannon-runner.js`) | White-box em clones GitHub (Temporal) | Externo, pesado, só repos clonados |
| PentestGPT (`pentestgpt-local.js`) | Validação pós-recon via HTTP bridge | Não audita código-fonte do cliente |
| ghost-local-v5 | RAG local Ollama/ChromaDB | Chat, não pipeline de audit multi-fase |

### 2.6 Satélites (manter)

| Projeto | Caminho | Papel na fusão |
|---------|---------|----------------|
| GhostTrace | `GhostTrace/` | Recebe findings unificados + handoff |
| GhostMap | `ghostmap/` | Grafo visual; pode ingerir HTTP records |
| GhostDesk | `GhostDesk/` | Gestão clientes/scans |
| ghost-local-v5 | `ghost-local-v5/` | IA offline complementar |
| IAs/ | `IAs/` | Shannon/PentestGPT clones |

### 2.7 Onde o GHOSTRECON é **único** (não sacrificar)

1. Workflow bug bounty (engagements, OPSEC, team locks, diff entre runs)
2. OSINT profundo (GitHub clone, paste, Google CSE, dorks, Lovable/Supabase/Firebase)
3. Tor/Navigator como cidadão de primeira classe
4. Priorização v2 + chaining + MITRE/OWASP + bounty context
5. Ecossistema satélite acoplado
6. RBAC + CSRF + rate-limit nativos
7. Playbooks JSON + scheduler CLI

---

## 3. Inventário Vigolium (estado em `vigolium/`)

### 3.1 Arquitectura

```
cmd/vigolium/main.go
    → pkg/cli (scan | run | agent | server | ingest)
        → internal/runner (fases)
            → pkg/deparos | pkg/spitolas | pkg/modules | pkg/knownissuescan | pkg/oast
        → pkg/agent (swarm | autopilot | audit)
            → pkg/olium (runtime IA in-process)
            → platform/vigolium-audit (SAST multi-agente, Bun)
```

| Camada | Caminho | Métrica |
|--------|---------|---------|
| Go core | `vigolium/pkg/` | ~50 pacotes |
| Módulos scanner | `pkg/modules/` | **273** registados (171 activos + 102 passivos) |
| Agent runtime | `pkg/olium/` | Providers: Codex OAuth, Claude Code, Anthropic API, Vertex, OpenAI |
| SAST harness | `platform/vigolium-audit/` | Pipeline multi-fase (advisories → candidatos → verificação) |
| JS link scanner | `platform/jsscan/` | Análise estática de bundles (embutido em Deparos) |
| UI workbench | `platform/vigolium-workbench/`, `public/ui/` | Dashboard React embutido |
| Build | Go 1.26 + Bun 1.3.11+ | `make build`, Chromium opcional embutido |

### 3.2 Fases native scan (Vigolium)

| Ordem | Fase | Alias | Pacote |
|-------|------|-------|--------|
| 0 | Heuristics | — | Pré-flight WAF/redirect/tech |
| 1 | External harvest | — | `pkg/harvester/` (Wayback, CC, OTX, URLScan, VT) |
| 2 | Spidering | `spitolas` | `pkg/spitolas/` — Chromium/CDP, SPA, forms, SSO |
| 3 | Discovery | `deparos` | `pkg/deparos/` — fuzz adaptativo + jsscan |
| 4 | Known issue scan | `kis`, `cve` | Nuclei v3 SDK + Kingfisher |
| 5 | Dynamic assessment | `dast`, `audit` | 273 módulos activos/passivos + DiffScan |
| 6 | Extension | `ext` | JS/YAML custom (Sobek) |

**Estratégias:** `lite` (só DAST) | `balanced` (default) | `deep` (+ harvest) | `whitebox` (source-aware)

### 3.3 Módulos Vigolium por categoria (trazer)

#### Activos — injection & RCE (GHOSTRECON fraco ou ausente)

- XSS light (URL params, path, param discovery) + DOM confirm + stored
- SQLi error-based, boolean blind, time-based
- NoSQLi error + operator injection
- SSTI reflected + diff-based + CSTI (Angular/Vue)
- LFI generic + path traversal avançado
- RCE echo + OAST + timing
- XXE, CRLF, insecure deserialization
- LDAP injection, command injection variants

#### Activos — SSRF & OAST (GHOSTRECON: `oob_collaborator` manual)

- `active-ssrf-detection`, blind SSRF, filter bypass, protocol smuggling
- `active-oast-probe`, proxy pingback
- Correlação automática via `pkg/oast/` + interactsh

#### Activos — access control (GHOSTRECON: `authz_matrix` básico)

- `authz-compare` — IDOR/BOLA multi-sessão nativo
- BFLA, race conditions, rate-limit bypass

#### Activos — frameworks & cloud (GHOSTRECON superficial)

- WordPress/Drupal/Joomla/CMS (20+ módulos)
- Spring actuators, Jolokia, H2 console
- Next.js server actions, Nuxt, Remix
- Firebase, Express, Django, Rails, FastAPI, ASP.NET
- MCP security (9 módulos activos)
- GraphQL injection, WebSocket, JSONP, open redirect
- Cloud storage misconfig, subdomain takeover
- File upload, default creds, cache poisoning

#### Passivos — secrets & headers (parcial overlap)

- `secret_detect` + Kingfisher batch
- CSP/HSTS/SRI, cookie flags, CSRF passive
- DOM XSS taint analysis, SSR hydration issues
- Framework fingerprint (20+ stacks)
- API spec/pagination anomalies

### 3.4 Modos agenticos (prioridade alta para ti)

| Modo | CLI | O que faz | Providers |
|------|-----|-----------|-----------|
| **Query** | `vigolium agent query` | Code review one-shot | Codex, Claude Code, API keys |
| **Audit** | `vigolium agent audit` | SAST multi-fase no repo | `platform/vigolium-audit` |
| **Swarm** | `vigolium agent swarm` | IA planeia → gera extensões JS → scan → triage → rescan | olium in-process |
| **Autopilot** | `vigolium agent autopilot` | Sessão longa autónoma | olium in-process |

**Fases do Swarm** (`pkg/agent/swarm_agent_phases.go`):

```
normalize → auth → source-analysis → code-audit → discover → recon → plan → extension → scan → triage → rescan
```

**Providers olium** (`pkg/olium/provider/`):

- `codex.go` — ChatGPT Codex OAuth (o que gostaste)
- `claudecode.go` — Claude Code CLI
- `anthropic.go` — Anthropic API
- `openai.go` — OpenAI API
- `google_vertex.go` — Vertex

### 3.5 Server mode (referência para bridge)

| Endpoint | Uso na fusão |
|----------|--------------|
| `POST /api/scans/run` | Disparar scan Go em background |
| `POST /api/ingest-http` | GhostMap/Navegation alimentam o motor |
| `POST /api/agent/run/swarm` | Auditoria IA via API |
| `POST /api/agent/run/audit` | SAST no repo |
| `GET /api/findings` | Pull findings para normalizar |
| `GET /api/oast-interactions` | OAST dashboard |

### 3.6 Build requirements

```bash
# Pré-requisitos
Go 1.26+
Bun 1.3.11+  # vigolium-audit, jsscan, workbench
# Opcional: Chromium embutido (make deps-chrome && make build-embedded)
make build   # → bin/vigolium
```

---

## 4. Matriz de gap — o que trazer, manter, deprecar

### 4.1 Trazer do Vigolium (Go — fase A)

| Capacidade Vigolium | Substituir / complementar no GHOSTRECON | Prioridade |
|---------------------|----------------------------------------|------------|
| **273 módulos DAST** | `validation.mjs` + `aggressive.mjs` (parcial) | P0 |
| **OAST interactsh** | `oob-collaborator.mjs` | P0 |
| **Spitolas (spider SPA)** | Katana + Navegation (limitado) | P0 |
| **Deparos (discovery)** | ffuf/dirsearch via Kali | P1 |
| **authz-compare multi-sessão** | `authz-matrix.mjs` | P0 |
| **DiffScan + mutação semântica** | `payload-mutator.mjs` | P1 |
| **Known issue (Nuclei SDK + Kingfisher)** | `kali_nuclei` spawn | P1 |
| **olium agent (Codex/Claude Code)** | Shannon + PentestGPT (papéis diferentes) | P0 |
| **vigolium-audit (SAST repo)** | Ausente no GHOSTRECON | P0 |
| **Extensões JS/YAML** | Módulos Node plugáveis | P2 |
| **Server + ingest** | `proxy-capture.mjs` | P1 |
| **Inputs ricos** (OpenAPI, Postman, Burp, HAR) | `openapi-harvest` parcial | P1 |

### 4.2 Manter no GHOSTRECON (Node — não tocar)

| Capacidade | Razão |
|------------|-------|
| Pipeline 9 fases + OPSEC gating | Workflow único |
| OSINT profundo (GitHub, paste, CSE, dorks) | Vigolium não cobre igual |
| Lovable/Supabase/Firebase fingerprint | Especialização vossa |
| Tor strict + Navegation + proxychains | Vigolium não tem |
| Bounty context (scope, estimator, diff, scheduler) | Core produto |
| GhostTrace/GhostMap/GhostDesk/ghost-local | Ecossistema |
| RBAC, CSRF, engagements, purple-team | Operacional |
| MITRE/OWASP tagging + chaining | Intel proprietária |
| Playbooks + CLI madura | UX existente |

### 4.3 Overlap — coexistir depois decidir

| Área | GHOSTRECON | Vigolium | Decisão futura |
|------|------------|----------|----------------|
| Wayback / Common Crawl | `content-discovery.mjs` | `external-harvest` | Node em deep; Go em active-only |
| VirusTotal subs | `discovery.mjs` | harvester | Manter Node |
| Nuclei | `kali_nuclei` spawn | SDK nativo | Preferir Go quando motor activo |
| XSS/SQLi | dalfox, sqlmap, micro_exploit | 20+ módulos nativos | Go primário em `--active` |
| Secrets | `secrets.js` + ranker | secret_detect + Kingfisher | Ambos; dedupe no finalize |
| GraphQL | `graphql_recon.mjs` | módulos activos/passivos | Go complementa |
| JWT | `jwt-lab.mjs` | módulos JWT | Manter ambos |
| Relatórios IA | `ai-dual-report.js` | triage no swarm | Unificar provider config |

### 4.4 Deprecar gradualmente (após Go estável)

| Módulo GHOSTRECON | Quando | Condição |
|-------------------|--------|----------|
| `kali_nuclei` (spawn) | Fase C | Go KIS cobre templates |
| `micro_exploit` heurístico | Fase C | Go DAST confirma |
| `dom-xss-verify` parcial | Fase D | Spitolas + módulos XSS Go |
| `oob-collaborator` manual | Fase B | OAST Go activo |
| ffuf/dirsearch Kali-only | Fase C | Deparos cobre |

---

## 5. Arquitectura alvo

### 5.1 Monorepo

```
GHOSTRECON/
├── server/                    # Node — orquestrador, OSINT, workflow (mantém)
├── bin/ghostrecon.mjs         # CLI unificado (expandir)
├── index.html                 # UI unificada (novas secções)
├── vigolium/                  # Go engine (fork AGPL, submodule ou subtree)
│   ├── cmd/vigolium/
│   ├── pkg/
│   ├── platform/vigolium-audit/
│   └── Makefile
├── bridge/                    # NOVO — integração Node↔Go
│   ├── vigolium-runner.mjs    # spawn/API client
│   ├── findings-normalizer.mjs
│   └── agent-bridge.mjs       # swarm/audit → NDJSON
├── engines/                   # NOVO (opcional) — binários compilados
│   └── vigolium               # symlink ou artefacto CI
└── docs/FUSAO-VIGOLIUM.md     # este documento
```

### 5.2 Fluxo unificado

```
┌─────────────────────────────────────────────────────────────────┐
│  ghostrecon scan -t URL  │  index.html UI  │  POST /api/recon/stream │
└────────────────────────────┬────────────────────────────────────┘
                             ▼
┌─────────────────────────────────────────────────────────────────┐
│  runPipeline (Node) — fases 1-5 OSINT + superfície              │
│  • input → fingerprint → discovery → probe → content-discovery    │
└────────────────────────────┬────────────────────────────────────┘
                             ▼
┌─────────────────────────────────────────────────────────────────┐
│  runGoEnginePhase (NOVO) — bridge/vigolium-runner.mjs           │
│  • strategy: lite | balanced | deep                             │
│  • inputs: urlCorpus, probeResults, auth sessions, OpenAPI        │
│  • vigolium scan -t … --format jsonl OR server /api/scans/run   │
└────────────────────────────┬────────────────────────────────────┘
                             ▼
┌─────────────────────────────────────────────────────────────────┐
│  findings-normalizer.mjs → addFinding() com provenance vigolium:* │
└────────────────────────────┬────────────────────────────────────┘
                             ▼
┌─────────────────────────────────────────────────────────────────┐
│  runPipeline (Node) — fases restantes                           │
│  • validation (módulos Node não cobertos) → aggressive (Kali)   │
│  • asset-discovery → finalize (score, IA, persistência)           │
└────────────────────────────┬────────────────────────────────────┘
                             ▼
                    NDJSON stream → UI / GhostTrace / DB
```

### 5.3 Fase IA unificada (opcional no mesmo run)

```
ghostrecon scan -t URL --source ./repo --agent swarm
```

```
Node finalize pré-scan
    → bridge/agent-bridge.mjs
        → vigolium agent swarm -t URL --source ./repo --format jsonl
    → findings SAST + DAST → mesmo schema
    → Shannon/PentestGPT só se módulos explícitos activos
```

### 5.4 Schema de findings unificado

| Campo GHOSTRECON | Origem Vigolium JSONL | Notas |
|------------------|----------------------|-------|
| `type` | `category` / `template-id` | mapa em `findings-normalizer.mjs` |
| `prio` | `severity` | critical→high, high→high, medium→med… |
| `score` | score heurístico | reutilizar `sevToScore()` |
| `value` | `name` + `matched-at` | |
| `meta` | `description`, `confidence` | prefix `source=vigolium:MODULE_ID` |
| `url` | `url` | |
| `owasp` | tags OWASP | se presente |

---

## 6. CLI unificado

### 6.1 Comandos alvo

```bash
# Scan completo (OSINT Node + DAST Go + finalize Node)
ghostrecon scan -t https://alvo.com

# Só motor Go (equivalente vigolium scan)
ghostrecon scan -t https://alvo.com --engine go --strategy balanced

# Só pipeline Node actual
ghostrecon scan -t https://alvo.com --engine node

# Com auditoria de código (Codex / Claude Code)
ghostrecon scan -t https://alvo.com --source ./app --agent audit

# Swarm completo
ghostrecon scan -t https://alvo.com --source ./app --agent swarm

# Alias retrocompatível
ghostrecon run -t https://alvo.com   # mantém comportamento actual até flag --engine
```

### 6.2 Flags novas (proposta)

| Flag | Tipo | Default | Descrição |
|------|------|---------|-----------|
| `--engine` | `node\|go\|both` | `both` | Qual motor corre |
| `--strategy` | `lite\|balanced\|deep` | `balanced` | Estratégia Vigolium |
| `--agent` | `none\|query\|audit\|swarm\|autopilot` | `none` | Modo agentico |
| `--source` | path | — | Repo para SAST |
| `--auth-file` | path | — | Sessões YAML (formato Vigolium) |
| `--vigolium-modules` | csv | — | Filtro `-m` no Go |
| `--skip-go-phases` | csv | — | ex: `spidering,external-harvest` |

### 6.3 Implementação CLI

1. `server/modules/cli/commands/scan.mjs` — novo comando (ou evoluir `run.mjs`)
2. Delega para `POST /api/recon/stream` com body expandido
3. `recon-stream.mjs` passa `engine`, `strategy`, `agent` para `createPipelineState()`

---

## 7. UI unificada

### 7.1 Secções novas em `index.html`

| Secção UI | Conteúdo |
|-----------|----------|
| **Motor** | Radio: Node only / Go DAST / Ambos |
| **Estratégia Go** | lite / balanced / deep |
| **Agente IA** | off / audit / swarm / autopilot + path `--source` |
| **Provider IA** | codex-oauth / claude-code / anthropic-api (herda env Vigolium) |
| **OAST** | Status interactsh, callbacks ao vivo (proxy `GET /api/vigolium/oast`) |

### 7.2 Pipes NDJSON novos

Emitir no stream (compatível com `pipeline-stages.mjs`):

```
pipe: vigolium_engine → active | done | skip
pipe: vigolium_spitolas → active | done
pipe: vigolium_dast → active | done
pipe: vigolium_agent → active | done
pipe: vigolium_audit → active | done
progress: 0-100 durante fase Go
finding: { …, meta: "source=vigolium:active-xss-light-url-params" }
```

### 7.3 Capabilities endpoint

Expandir `GET /api/capabilities` com:

```json
{
  "vigolium": {
    "installed": true,
    "version": "x.y.z",
    "binary": "engines/vigolium",
    "modules": 273,
    "agents": ["query", "audit", "swarm", "autopilot"],
    "providers": ["codex-oauth", "claude-code", "anthropic-api"]
  }
}
```

---

## 8. Conformidade legal (AGPL-3.0)

### 8.1 Obrigatório ao fundir

| Acção | Ficheiro |
|-------|----------|
| Manter LICENSE AGPL em `vigolium/LICENSE` | ✅ já existe |
| Adicionar `NOTICE` na raiz GHOSTRECON | Listar código derivado Vigolium |
| Manter `THIRD_PARTY_NOTICES.md` | Copiar/adaptar de vigolium |
| Atribuição no README | Secção "Motor DAST baseado em Vigolium" |
| Documentar modificações | CHANGELOG por fork |

### 8.2 Implicações práticas

- **Uso local / Kali pessoal:** fork + atribuição = OK.
- **Distribuição do monorepo:** incluir source Vigolium ou pointer ao fork.
- **SaaS com modificações no motor Go:** AGPL §13 — disponibilizar source das alterações aos utilizadores da rede.
- **Reescrita Node inspirada (sem copy-paste):** código novo pode ter licença diferente se não for derivado literal.

### 8.3 Recomendação

1. Definir licença do GHOSTRECON (hoje **sem LICENSE** na raiz).
2. Opção conservadora: **AGPL-3.0 para o monorepo inteiro** se incluir Vigolium linkado/embutido.
3. Opção híbrida: AGPL só em `vigolium/` + MIT/Apache no Node (complexo juridicamente — validar com advogado se comercial).

---

## 9. Plano de implementação por fases

### Fase 0 — Fundação legal e repo (1 semana)

- [x] `NOTICE` + secção README (NOTICE na raiz)
- [x] `vigolium/` no monorepo
- [ ] Submodule git formal (`.git` nested ainda presente em vigolium/)
- [x] `.gitignore`: `vigolium/bin/`, `engines/`
- [ ] CI: `make -C vigolium build`

### Fase 1 — Bridge mínima (2-3 semanas)

- [x] `bridge/vigolium-runner.mjs` — spawn `vigolium scan`
- [x] `bridge/findings-normalizer.mjs` — JSONL → `addFinding()`
- [x] `server/pipeline/phases/go-engine.mjs`
- [x] Módulo `vigolium_dast` no registry
- [x] Teste: `server/tests/vigolium-bridge.test.js`
- [x] Env: `GHOSTRECON_VIGOLIUM_*` em `.env.example`
- [x] CLI: `ghostrecon scan` + `--engine` / `--strategy`
- [x] `/api/capabilities` expõe `vigolium`

### Fase 2 — UI + capabilities ✅

- [x] Secção motor em `index.html`
- [x] Pipes `vigolium_dast`, `vigolium_agent`
- [x] `/api/capabilities` expõe `vigolium`

### Fase 4 — Agent + audit ✅

- [x] `bridge/agent-bridge.mjs`
- [x] `go-agent.mjs` no pipeline
- [x] Módulos `vigolium_audit`, `vigolium_swarm`

### Runtime em `engines/` (remover `vigolium/` fonte)

- [x] `engines/vigolium` binário + `engines/LICENSE.AGPL`
- [x] `scripts/install-vigolium-engine.sh` / `build-vigolium-engine.sh`
- [x] `npm run engine:install` / `engine:build`
- [x] `vigolium/` no `.gitignore` (apagar pasta local após install)
- [x] CI `.github/workflows/vigolium-engine.yml`

### Fase 5 — Server mode opcional (2-3 semanas)

- [ ] `vigolium server` como sidecar (porta 9002)
- [ ] GhostMap ingest → `/api/ingest-http`
- [ ] Proxy MITM GHOSTRECON → ingest Vigolium

### Fase 6 — Convergência e deprecação (contínuo)

- [ ] Matriz overlap: desligar módulos Node redundantes por playbook
- [ ] Reescrita Node módulo-a-módulo (prioridade: OAST wrapper, authz-compare simplificado)
- [ ] Renomear internamente: "GHOSTRECON Active Engine" na UI, créditos no código

---

## 10. Mapa de reescrita Node (faixa B — paralelo)

Prioridade de portar para `server/modules/` (inspirado, não copy-paste):

| # | Módulo Vigolium | Esforço | Valor para customização |
|---|-----------------|---------|-------------------------|
| 1 | OAST correlator | Médio | Integrar Tor/opsec |
| 2 | authz-compare | Alto | Bounty multi-user flows |
| 3 | XSS light URL params | Médio | Watermark headers |
| 4 | secret_detect heuristics | Baixo | Já tens `secrets.js` |
| 5 | Value-aware mutation | Alto | `payload-mutator` upgrade |
| 6 | OpenAPI ingest completo | Médio | Playbooks API-first |
| 7 | olium provider abstraction | Alto | Unificar com `ai-dual-report` |

**Não portar para Node (manter Go):** Spitolas, Deparos completo, 150+ módulos activos, Nuclei SDK, Kingfisher batch.

---

## 11. Variáveis de ambiente (proposta)

```bash
# Motor Go
GHOSTRECON_VIGOLIUM_BIN=./engines/vigolium          # ou vigolium/ no PATH
GHOSTRECON_VIGOLIUM_STRATEGY=balanced               # lite | balanced | deep
GHOSTRECON_VIGOLIUM_SERVER=http://127.0.0.1:9002  # opcional: server mode
GHOSTRECON_VIGOLIUM_API_KEY=                        # se server com auth

# Agent / audit (herda Vigolium)
VIGOLIUM_PROVIDER=openai-codex-oauth                # ou anthropic-cli, etc.
ANTHROPIC_API_KEY=
# Codex: ~/.codex/auth.json

# Módulos
GHOSTRECON_ENGINE=both                              # node | go | both
GHOSTRECON_VIGOLIUM_MODULES=                        # csv override
```

---

## 12. Riscos e mitigações

| Risco | Impacto | Mitigação |
|-------|---------|-----------|
| Binário Go não compilado no ambiente | Scan falha | `install.sh` compila; capabilities reporta ausência |
| AGPL em produto comercial | Legal | NOTICE + counsel; reescrita Node do que for crítico |
| Duplicação de findings | Ruído | Dedupe semântico no finalize + provenance |
| Dois runtimes = ops complexo | Manutenção | Docker image com Node+Go pré-build |
| Agent audit horas de runtime | UX | Módulo opcional; progress SSE; timeout |
| vigolium/ nested `.git` | Confusão git | Submodule ou subtree formal |
| Chromium embutido (+100MB) | Deploy | Build opcional; usar Chrome do sistema |

---

## 13. Decisões em aberto (para ti)

1. **Licença do monorepo:** AGPL total vs híbrida?
2. **Default `--engine`:** `both` ou `node` até Go estável?
3. **Shannon/PentestGPT:** manter paralelo ao swarm ou consolidar num só fluxo IA?
4. **UI workbench Vigolium:** integrar `public/ui/` ou só pipes NDJSON no index.html?
5. **Submodule:** `vigolium/` fica fork vosso no GitHub ou cópia vendor?

---

## 14. Métricas de sucesso

| Métrica | Alvo Fase 1 | Alvo Fase 4 |
|---------|-------------|-------------|
| `ghostrecon scan -t example.com` | Emite `done` com findings Go | + audit opcional |
| Testes CI | bridge test verde | + smoke agent mock |
| Módulos activos únicos | +50 findings types vs hoje | +150 |
| Tempo scan balanced | < 2× scan Node só | Aceitável com strategy lite em CI |
| UI | Pipes vigolium visíveis | Secção agent + OAST |

---

## 15. Referências no repo

| Documento | Conteúdo |
|-----------|----------|
| `ANALISE-PROJETO.md` | Diagnóstico GHOSTRECON |
| `REFATORACAO.md` | Refactor Node (fases 0-4) |
| `vigolium/README.md` | Upstream Vigolium |
| `vigolium/HACKING.md` | Build e desenvolvimento Go |
| `vigolium/docs/` | Documentação completa |
| `vigolium/platform/vigolium-audit/README.md` | SAST multi-agente |
| `vigolium/LICENSE` | AGPL-3.0 |

---

## 16. Resumo executivo

**É possível e faz sentido** fundir os dois projectos como:

- **GHOSTRECON** = cérebro operacional (Node): OSINT, workflow, UI, bounty, Tor, ecossistema.
- **vigolium/** = músculo de ataque (Go): 273 módulos DAST, OAST, spider, SAST com Codex/Claude Code.
- **bridge/** = coluna vertebral que unifica findings e CLI `ghostrecon scan -t`.

A reescrita Node corre **em paralelo** só onde precisas de controlar IP (Tor, opsec, bounty context) — não tentes portar o motor inteiro.

**Próximo passo concreto:** Fase 0 (legal + git) + Fase 1 (`bridge/vigolium-runner.mjs` + fase `go-engine.mjs`).
