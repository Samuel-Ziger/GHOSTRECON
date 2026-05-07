# GHOSTRECON

Framework local de **OSINT, recon, validação e priorização** para bug bounty e pentest autorizado, com pipeline em streaming, UI operacional, CLI headless e camada de IA (cloud + local).

> Localhost-first, single-process, NDJSON streaming. Sem cloud obrigatório. Sem ferramentas externas obrigatórias além de Node 18+ — o resto é opcional e descoberto automaticamente em `/api/capabilities`.

---

## Sumário

1. [O que é esta ferramenta](#o-que-é-esta-ferramenta)
2. [O que ele faz na prática](#o-que-ele-faz-na-prática)
3. [Componentes principais](#componentes-principais)
4. [Como usar em poucos minutos](#como-usar-em-poucos-minutos)
5. [Arquitetura](#arquitetura)
6. [Estrutura do repositório](#estrutura-do-repositório)
7. [Fluxo de execução ponta a ponta](#fluxo-de-execução-ponta-a-ponta)
8. [Camadas funcionais do pipeline](#camadas-funcionais-do-pipeline)
9. [Painéis HTML](#painéis-html)
10. [API HTTP](#api-http)
11. [Auth + RBAC (P0)](#auth--rbac-p0)
12. [Roteamento Tor (anti-leak)](#roteamento-tor-anti-leak)
13. [Proxy capture / MITM](#proxy-capture--mitm)
14. [Ghost local (FastAPI)](#ghost-local-fastapi)
15. [Persistência](#persistência)
16. [IA em cascata e fallback](#ia-em-cascata-e-fallback)
17. [CLI headless (`ghostrecon`)](#cli-headless-ghostrecon)
18. [Scheduler, diff e alertas new-only](#scheduler-diff-e-alertas-new-only)
19. [Playbooks](#playbooks)
20. [Engagements, OPSEC e Purple Team](#engagements-opsec-e-purple-team)
21. [Multi-operador (team locks + audit trail)](#multi-operador-team-locks--audit-trail)
22. [Evidências ricas com Playwright](#evidências-ricas-com-playwright)
23. [CVE enrichment (versão → exploit)](#cve-enrichment-versão--exploit)
24. [Inbound webhooks (hub)](#inbound-webhooks-hub)
25. [Projects (multi-alvo)](#projects-multi-alvo)
26. [Workflow export (Linear/Jira/GitHub/Markdown)](#workflow-export-linearjiragithubmarkdown)
27. [Instalação por perfil](#instalação-por-perfil)
28. [Scripts NPM](#scripts-npm)
29. [Testes automatizados](#testes-automatizados)
30. [Docker](#docker)
31. [Variáveis de ambiente](#variáveis-de-ambiente)
32. [Proxychains-ng + rotação de IP](#proxychains-ng--rotação-de-ip)
33. [Troubleshooting rápido](#troubleshooting-rápido)
34. [Limites e uso responsável](#limites-e-uso-responsável)

---

## O que é esta ferramenta

O `GHOSTRECON` é uma central de investigação de superfície de ataque. Em vez de executar dezenas de ferramentas separadas e depois tentar juntar tudo manualmente, ele organiza todo o ciclo em um fluxo único: **descobrir ativos, encontrar sinais de falha, validar o que realmente importa, priorizar por risco e transformar isso em inteligência acionável**.

Em termos simples: você aponta um alvo autorizado e a stack devolve **visibilidade**, **contexto**, **prioridade** e **material pronto para decisão técnica**.

---

## O que ele faz na prática

- Mapeia a superfície digital (subdomínios, URLs históricas, headers, DNS, metadados, certificados).
- Procura sinais relevantes (possíveis XSS/SQLi/LFI/SSRF/IDOR/Open-redirect, leaks, exposição de serviços, JWT, GraphQL).
- Cruza dados e reduz ruído (dedupe semântico, score, tags **OWASP Top 10** + **MITRE ATT&CK**).
- Separa o que é apenas ruído do que merece tempo do analista (priorização v2 com bounty-context).
- Captura **evidência rica** (screenshot + DOM + headers + console) por finding com Playwright.
- Cruza versões com **OSV / NVD / ExploitDB / Nuclei templates**.
- Ajuda a transformar achados em narrativa técnica (reportes, anotações, relatórios IA, narrative attack-graph, purple-team).
- Roda em modo **passivo**, **stealth** ou **aggressive** com gating OPSEC explícito.

---

## Componentes principais

### 1) `GHOSTRECON` (núcleo)
Motor principal: recebe o alvo, executa os módulos de recon, transmite o progresso ao vivo (NDJSON) e salva o resultado para comparações futuras (diff between runs).

### 2) `GhostMap`
Painel visual de risco/tática: mostra o que foi encontrado com leitura orientada por **MITRE/OWASP** para facilitar entendimento rápido.

### 3) `Cortex`
"Cérebro" da operação. Organiza conhecimento validado em categorias, liga achados por fingerprint e transforma descobertas em base reutilizável.

### 4) `Reporter`
Área de validação manual. Aqui o analista marca o que realmente confirmou, reduz ruído e gera material de reporte com foco no que importa.

### 5) `Anotação`
Editor de anotações técnicas com apoio de IA para acelerar a redação e consolidar aprendizado operacional do run.

### 6) `Ghost Intelligence` (`ghost-local-v5`)
Camada de IA local (FastAPI + Ollama + ChromaDB + SQLite) para chat, memória, ingestão de runs e análise guiada. Expõe um endpoint **OpenAI-compatible** local em `/v1/chat/completions`.

### 7) `HTTP History`, `Post-Exploitation`, `Tor Validator`
Painéis auxiliares para inspecionar tráfego (proxy MITM), planejar pós-exploração e validar a saída pela rede Tor antes de rodar.

---

## Como usar em poucos minutos

```bash
npm install
cp .env.example .env       # ajuste pelo menos AUTH_API_KEYS e (se quiser) DATABASE_URL
npm start
```

Depois:

- UI principal: <http://127.0.0.1:3847/>
- Ghost local (GUI): <http://127.0.0.1:8000/gui/>
- Endpoint OpenAI-compatible local: <http://127.0.0.1:8000/v1/chat/completions>

Sem `AUTH_API_KEYS` configurado a API responde 401 nas rotas privilegiadas. Em `127.0.0.1` é possível usar `AUTH_DISABLE=1` para bypass de loopback (apenas dev). Veja [Auth + RBAC](#auth--rbac-p0).

---

## Arquitetura

```text
┌──────────────────────────┐                ┌──────────────────────────┐
│ UI principal (index.html)│                │ Ghost Intelligence       │
│ + GhostMap / Cortex /    │                │ (ghost-local-v5)         │
│ Reporter / Anotação /    │                │ FastAPI + Ollama + Chroma│
│ HTTP-History / Tor       │                │ /chat /memory /v1/...    │
└──────────┬───────────────┘                └──────────────┬───────────┘
           │ POST /api/recon/stream (NDJSON)               │ /v1/chat/completions
           ▼                                               ▼
┌──────────────────────────────────────────────────────────────────────┐
│                  API Node / Express  (server/index.js)               │
│  ┌────────────┐ ┌─────────────┐ ┌────────────┐ ┌─────────────────┐   │
│  │ AUTH+RBAC  │ │ CSRF / RL   │ │ Tor strict │ │ Proxy capture   │   │
│  └────────────┘ └─────────────┘ └────────────┘ └─────────────────┘   │
│  ┌─────────────────────── runPipeline() ──────────────────────────┐  │
│  │ recon → enrich → validate → kali (opt) → correlate → priorize  │  │
│  │      → diff vs baseline → IA cascade → webhook → KB sync       │  │
│  └────────────────────────────────────────────────────────────────┘  │
└────────┬─────────────────┬─────────────────┬────────────────┬────────┘
         ▼                 ▼                 ▼                ▼
   SQLite/Postgres    Webhooks/Inbound   IA cloud      Ferramentas
   /Supabase          (HMAC)             Gemini /      externas (Kali)
                                         OpenRouter /  nmap, nuclei,
                                         Claude /      ffuf, sqlmap,
                                         LM Studio     wpscan, dalfox…
```

---

## Estrutura do repositório

```text
GHOSTRECON/
├─ server/
│  ├─ index.js                          # entrypoint Node/Express (~4400 linhas)
│  ├─ config.js                         # rate-limits, limites por módulo
│  ├─ load-env.js                       # bootstrap dotenv
│  ├─ modules/                          # 120+ módulos (recon, IA, db, correlação, RT)
│  │  ├─ cli/                           # parser + commands da CLI headless
│  │  └─ playbooks/                     # loader de playbooks JSON/YAML
│  ├─ scripts/                          # MITRE bundle, PentestGPT bridge, smoke IA
│  └─ tests/                            # 60+ testes (node --test)
├─ bin/ghostrecon.mjs                   # binário da CLI (npx ghostrecon)
├─ scripts/start-stack.sh               # sobe Ghost local + API Node
├─ ghost-local-v5/
│  ├─ start
│  └─ ghost-local/
│     ├─ backend/main.py                # FastAPI (chat/memory/ingest/codescan)
│     └─ frontend/index.html            # Ghost Intelligence GUI
├─ playbooks/                           # api-first, wordpress, cloud-takeover, etc.
├─ tools/Navegation/                    # configurador Tor (torrc + proxychains)
├─ Xss/xss_vibes/                       # scanner auxiliar Python
├─ supabase/                            # schema e migrations (project_id=gosthrecon)
├─ docs/
│  ├─ AUTH-RBAC.md                      # matriz role × scope
│  └─ TOR.md                            # rota Tor + ControlPort + isolation
├─ index.html                           # cockpit operacional principal
├─ mitre-map.html                       # GhostMap (MITRE/OWASP)
├─ cortex.html                          # Cortex (KB validada)
├─ reporte.html                         # Reporter (validação manual)
├─ anotacao.html                        # Anotações com IA
├─ history.html                         # HTTP History (inspector)
├─ post-exploitation.html               # Pós-exploração
├─ tor-validator.html                   # Tor Validator
├─ como-usar.html                       # guia de uso UI
├─ install.sh                           # instalador por perfil
├─ Dockerfile                           # imagem mínima da API
└─ .env.example                         # configuração completa documentada
```

---

## Fluxo de execução ponta a ponta

1. `npm start` executa `scripts/start-stack.sh`.
2. O script tenta subir o **Ghost local** em `:8000` e valida `/health`.
3. Em seguida, sobe a API Node (`server/index.js`) em `:3847` (default `HOST=127.0.0.1`).
4. A UI (`index.html`) faz `GET /api/csrf-token` e dispara `POST /api/recon/stream` recebendo **NDJSON**.
5. `runPipeline()` orquestra as fases:
   - normalização de alvo/escopo + carregamento de engagement;
   - **OPSEC gate** (recusa módulos intrusivos sem autorização explícita);
   - enumeração de superfície;
   - extração e enriquecimento (DNS/RDAP/TLS/Wayback/CommonCrawl/Archive Tools);
   - validações de evidência (XSS/SQLi/LFI/Redirect/IDOR/SSRF/Race);
   - módulo Kali opcional (gateado por capabilities + role `red`);
   - correlação/priorização (score + dedupe semântico + OWASP/MITRE);
   - persistência + diff fingerprint vs baseline;
   - **IA em cascata** (cloud + local) gerando relatório + próximos passos;
   - webhook (Discord/Slack/JSON) e sync para Ghost KB.
6. Cliente recebe os eventos `kind=` ao vivo (`progress`, `finding`, `module_done`, `summary`, `done`, `error`).

---

## Camadas funcionais do pipeline

### Recon / enumeração passiva
- `crtsh`, `virustotal`, `wayback`, `commoncrawl`, `archive-tools`
- `rdap`, `dns-enrichment`, `wellknown` (security.txt, openid-configuration)
- `tls-cert`, `security-headers`, `header-intel`, `robots-sitemap`
- `tech` (fingerprint), `tech-versions`, `lovable-fingerprint`
- `openapi-harvest` + `graphql-recon`
- `js-crawler` (Katana), `js-analyzer`, `js-intel`

### Leak / código
- `github` code/repo search, `github-clone` (clones efêmeros), `github-manual-repos`
- `secrets` + `secret-validation` (com `secret-project-peers` para correlação cross-projeto)
- `dorks`, `google-cse`

### Validação / evidência
- `verify` (sinais SQLi/LFI/XSS/redirect/SSRF/IDOR), `dom-xss-verify`, `browser-xss-verify` (Playwright)
- `webshell-probe`, `ftp-anon-write-probe`, `mysql-config-correlation`, `mysql-nmap-intel`
- `sqlmap-runner`, `payload-mutator`, `oob-collaborator` (DNS/HTTP OOB)
- `cve-enrichment` (OSV + NVD + ExploitDB + Nuclei templates)

### Modo Kali (intrusivo, opcional)
- `nmap`, `ffuf`, `dirsearch`, `nuclei`, `dalfox`, `xss_vibes`, `whois`
- `subfinder`, `amass`, `wpscan`, `sqlmap`, `wafw00f`
- Profundidade depende do perfil (`standard | stealth | aggressive`) e ferramentas no PATH.

### Correlação / priorização
- `correlation`, `prioritization` v2 (com bounty-context), `scoring`
- `semantic-dedupe`, `chaining` (cadeias entre findings)
- `owasp-top10`, `mitre-recon` (tags ATT&CK)
- `recheck-high` (recheck HTTP rápido em achados HIGH)

### Red Team / OPSEC
- `engagement`, `opsec` (gating de módulos), `team-concurrency` (locks)
- `attack-narrative`, `purple-team`, `replay-tabletop`
- `phishing-infra`, `cred-spray`, `cloud-bruteforce`
- `authz-matrix`, `jwt-lab`, `race-harness`, `origin-discovery`

### Anonimato / saída
- `tor-control` (NEWNYM/GETINFO via ControlPort)
- `tor-strict` (anti-leak central, força proxychains nas tools)
- `socks5-dispatcher` (undici Agent SOCKS5 com isolation por target)
- `identity-controller`, `identity-surface`
- `proxy-capture` (MITM nativo)

---

## Painéis HTML

| Arquivo | Painel | Função |
|---------|--------|--------|
| `index.html` | Cockpit | Configuração de run, stream ao vivo, filtros, export |
| `mitre-map.html` | **GhostMap** | Visualização MITRE/OWASP com feed ao vivo |
| `cortex.html` | **Cortex** | Base de conhecimento de findings validados |
| `reporte.html` | **Reporter** | Checklist manual + consolidação de validações |
| `anotacao.html` | Anotações | Notas técnicas estruturadas + geração com IA |
| `history.html` | HTTP History | Inspector dos requests interceptados pelo proxy MITM |
| `post-exploitation.html` | Pós-exploração | Planejamento de pós-exploração |
| `tor-validator.html` | Tor Validator | Valida saída pela rede Tor antes do run |
| `como-usar.html` | Guia | Manual de uso da UI |

---

## API HTTP

> CSRF protege rotas mutantes. Pegue o token em `GET /api/csrf-token` e envie `X-CSRF-Token: <token>`. Auth: ver [Auth + RBAC](#auth--rbac-p0).

### Recon / runtime
- `POST /api/recon/stream` — pipeline streaming NDJSON
- `GET  /api/csrf-token`
- `GET  /api/health`
- `GET  /api/capabilities` — quais ferramentas Kali e IAs estão disponíveis
- `POST /api/tool-path-refresh` (admin)
- `GET  /api/searchsploit` — busca local exploit-db
- `GET  /api/history/recon` — histórico HTTP capturado

### Runs / diff / intel
- `GET  /api/runs`
- `GET  /api/runs/:id`
- `GET  /api/runs/:newerId/diff/:baselineId`
- `GET  /api/runs/:newerId/diff-summary/:baselineId?minSeverity=&onlyNew=1`
- `GET  /api/runs/:id/narrative` — attack-narrative gerada do run
- `GET  /api/runs/:id/purple` — relatório Purple Team
- `GET  /api/intel/:target`
- `GET  /api/project-secret-peers?project=...`

### Cortex / validação manual
- `GET  /api/brain/categories`
- `POST /api/brain/categories` (CSRF, `brain.write`)
- `POST /api/brain/categories/:id/description` (CSRF, `brain.write`)
- `POST /api/brain/link` (CSRF, `brain.write`)
- `GET  /api/brain/category/:id`
- `GET  /api/manual-validations/:target`
- `POST /api/manual-validations` (CSRF, `validation.write`)
- `POST /api/manual-validations/ai-report`
- `POST /api/manual-validations/annotations-ai`

### Anotações
- `GET  /api/anotacao-handoff/:id`
- `POST /api/anotacao-handoff` (CSRF, `notes.write`)

### Integrações IA
- `POST /api/ai-reports` (CSRF, `ai.run`) — gera relatório dual (Gemini → OpenRouter → Claude → LM Studio/Ghost)
- `POST /api/pentestgpt-ping` (CSRF, `ai.run`)
- `POST /api/shannon/prep` (CSRF, `shannon.run`)
- `GET  /api/ai/lmstudio-check`

### Engagements / OPSEC / Team
- `GET  /api/engagements`, `GET /api/engagements/:id`
- `POST /api/engagements`, `POST /api/engagements/:id/close`, `POST /api/engagements/checklist`
- `POST /api/opsec/gate` (admin)
- `GET  /api/team/locks`, `GET /api/team/trail`
- `POST /api/team/lock`, `POST /api/team/unlock`, `POST /api/team/force-unlock` (admin)

### Playbooks / Projects / CVE / Evidence
- `GET  /api/playbooks`, `GET /api/playbooks/:name`
- `GET  /api/projects`, `GET /api/projects/:name`
- `POST /api/projects` (CSRF), `DELETE /api/projects/:name` (admin)
- `POST /api/cve/enrich` (CSRF, `cve.enrich`)
- `POST /api/evidence/capture/:runId` (CSRF, `evidence.capture`)

### Tor / Tunnel / Proxy
- `GET  /api/tunnel/status`, `GET /api/tunnel/validate`, `GET /api/tunnel/health`
- `GET  /api/tunnel/strict-check`, `GET /api/tunnel/telemetry/:runId`
- `POST /api/tunnel/enable` (admin), `POST /api/tunnel/disable` (admin)
- `POST /api/tunnel/newnym` (`recon.run`)
- `GET  /api/proxy/status`, `POST /api/proxy/start`, `POST /api/proxy/stop`, `POST /api/proxy/mitm`
- `GET  /api/proxy/ca.crt` — baixa o root CA do proxy MITM

### Inbound webhooks (auth própria por HMAC)
- `POST /api/inbound/:source` — eventos de Subfinder/Amass/Nuclei/custom
- `GET  /api/inbound/:source/:target` — leitura (Bearer token)

---

## Auth + RBAC (P0)

A API usa **API keys** por padrão. JWT (HS256/RS256) é alternativa para SSO/OIDC. Audit log NDJSON 1 ficheiro/dia em `./logs`.

```bash
# 1. Gerar uma API key forte
node -e "console.log(require('crypto').randomBytes(32).toString('base64url'))"

# 2. Configurar no .env
AUTH_MODE=apikey
AUTH_API_KEYS=<key>:red:laptop|<outra>:admin:ci-runner

# 3. Chamar a API
curl -H "Authorization: Bearer <key>" -H "X-CSRF-Token: <csrf>" \
     -X POST http://127.0.0.1:3847/api/recon/stream \
     -d '{"domain":"example.com","modules":["dns","probe"]}'
```

**Roles**:

| Role | Inclui |
|------|--------|
| `viewer` | `recon.read` |
| `operator` | viewer + `recon.run`, `brain.write`, `notes.write`, `validation.write`, `evidence.capture`, `cve.enrich` |
| `red` | operator + `recon.intrusive`, `ai.run`, `shannon.run`, `project.write`, `engagement.write`, `team.lock` |
| `admin` | `*` (wildcard, inclui ações destrutivas) |

`recon.intrusive` é exigido automaticamente quando o body inclui `kaliMode=true`, `opsecProfile='aggressive'`, ou módulos como `kali_*`, `sqlmap`, `cloud_bruteforce`, `cred_spray`, `shannon_whitebox`.

`AUTH_DISABLE=1` faz bypass **só em loopback** (127.0.0.1/::1). Detalhes completos em `docs/AUTH-RBAC.md`.

---

## Roteamento Tor (anti-leak)

Quando programa exige anonimato, todo o pipeline pode sair via Tor com **circuit isolado por target** (IsolateSOCKSAuth). O playbook `tools/Navegation/navegation.{sh,py}` configura `/etc/tor/torrc` automaticamente.

```bash
# .env
GHOSTRECON_TOR_REQUIRED=1                      # aborta se tunnel falhar
GHOSTRECON_PROXY_POOL=socks5h://127.0.0.1:9050
GHOSTRECON_TOR_ISOLATE=1                       # user/pass único por run/target
GHOSTRECON_TOR_STRICT=1                        # liga proxychains4 em TODAS as tools externas
```

Modo **strict** (anti-leak central):
- Locka Node DNS para `127.0.0.1:5353` (DNSPort do Tor).
- Escreve `proxychains.conf` efémero com `strict_chain` + `proxy_dns`.
- Wraps automáticos para `nmap`, `sqlmap`, `curl`, `dig`, `ffuf`, `nuclei`, `dirsearch`, `dalfox`, `whois`, `wpscan`.
- `refuse_to_run` se `proxychains4`, ControlPort, DNSPort ou SOCKS faltarem.
- Header hygiene Tor Browser-like nos `fetch`s do Node.

Endpoints de saúde: `/api/tunnel/status`, `/api/tunnel/validate`, `/api/tunnel/strict-check`, `/api/tunnel/telemetry/:runId`.
Detalhes completos em `docs/TOR.md`.

---

## Proxy capture / MITM

Proxy nativo (default `:8080`) captura todo o tráfego do pipeline e dos browsers configurados, exposto no painel `history.html`.

```bash
# .env
GHOSTRECON_PROXY_CAPTURE_PORT=8080
GHOSTRECON_PROXY_MITM=1
```

Baixe o root CA: `GET /api/proxy/ca.crt` e instale no browser/sistema.
Controle via `POST /api/proxy/start | /api/proxy/stop | /api/proxy/mitm`.

---

## Ghost local (FastAPI)

`ghost-local-v5/ghost-local/backend/main.py` expõe (em `:8000`):

- `POST /chat/stream` — chat streaming via Ollama
- `POST /v1/chat/completions` — endpoint **OpenAI-compatible** (cascata GHOSTRECON usa esse como fallback final)
- `GET  /v1/models`
- `GET|POST /memory/*` — KB local (ChromaDB) com teach/feedback/search/export
- `POST /ghostrecon/ingest/{run,findings,sqlite,ndjson}` — ingestão nativa
- `POST /ghostrecon/analyze` — análise guiada
- `GET  /ghostrecon/{runs,runs/{id},findings/{id}}`
- `POST /codescan/{repo,file,snippet,disasm}`, `GET /codescan/rules`
- `GET  /hexstrike/{status,health}`, `POST /hexstrike/relay` — bridge para HexStrike AI
- `POST /sessions/save`, `GET /sessions[/{id}]`
- `GET  /gui/` — Ghost Intelligence (frontend)

---

## Persistência

Camadas suportadas (auto-detectadas):

| Camada | Quando | Como configurar |
|--------|--------|-----------------|
| **SQLite local** (default) | Sem `DATABASE_URL` nem `SUPABASE_*` | `data/bugbounty.db` (criado automático). Override via `GHOSTRECON_DB`. |
| **Postgres direto** | Quer Postgres self-hosted ou Supabase via DB | `DATABASE_URL=postgresql://...` |
| **Supabase API** | Sem expor Postgres direto | `SUPABASE_URL` + `SUPABASE_SERVICE_ROLE_KEY` (ou anon/publishable) |

Schema/migrations em `supabase/migrations/`. Aplicar:

```bash
npm run db:link            # liga ao projeto (project_id=gosthrecon)
npm run db:push            # aplica migrations
npm run db:migration:new   # cria nova migration
```

Snapshots completos de findings podem ser salvos em `runs.findings_json` (Postgres requer `ALTER TABLE runs ADD COLUMN findings_json jsonb;`). Limite: `GHOSTRECON_FINDINGS_SNAPSHOT_MAX_BYTES`.

---

## IA em cascata e fallback

Fluxo de relatório IA (`runDualAiReports`):

1. **Gemini** (`GEMINI_API_KEY` ou `GOOGLE_AI_API_KEY`) — modelo via `GHOSTRECON_GEMINI_MODEL`.
2. **OpenRouter** (`OPENROUTER_API_KEY`) — slug em `GHOSTRECON_OPENROUTER_MODEL`.
3. **Claude direto** (`ANTHROPIC_API_KEY`) — só se OpenRouter vazio.
4. **LM Studio / Ghost local** (`GHOSTRECON_LMSTUDIO_*`) — fallback final OpenAI-compatible.

Retentativas configuráveis (`*_MAX_RETRIES`, respeita `Retry-After`/backoff). Espera fixa entre tentativas: `GHOSTRECON_AI_FALLBACK_WAIT_SEC`.

---

## CLI headless (`ghostrecon`)

Toda a pipeline é acessível em modo headless pela CLI, sem necessidade de UI. Útil para CI/CD, cron jobs e integração com outros stacks. A CLI reaproveita 100% do pipeline via `/api/recon/stream` (HTTP+NDJSON), sem forkar lógica.

```bash
# Após npm install
npx ghostrecon run --target example.com --modules crtsh,http,github --output run.json
npx ghostrecon run --target api.example.com --playbook api-first
npx ghostrecon runs --target example.com --limit 10
npx ghostrecon diff --baseline 12 --newer 18 --format summary
npx ghostrecon playbooks
npx ghostrecon playbooks --show api-first
npx ghostrecon export --run 42 --to github --repo myorg/myrepo --severity high
npx ghostrecon projects --add --name acme --description "Acme bounty program"
npx ghostrecon projects --name acme --scope-add "*.acme.com"
npx ghostrecon schedule --target api.acme.com --interval 6h --only-new
npx ghostrecon engagement --create --target acme.com --scope "*.acme.com"
npx ghostrecon narrative --run 42
npx ghostrecon purple --run 42
npx ghostrecon team --lock acme.com
npx ghostrecon chains --run 42
npx ghostrecon obsidian --run 42 --vault ~/vault
npx ghostrecon oob --domain example.com
npx ghostrecon phish-infra --target acme.com
npx ghostrecon replay --run 42
```

### Comandos disponíveis

| Comando | Função |
|---------|--------|
| `run` | Roda recon completo (alvo + módulos/playbook) |
| `runs` | Lista runs por target |
| `diff` | Compara dois runs (full ou summary) |
| `schedule` | Recon periódico com alerta new-only |
| `playbooks` | Lista/inspeciona playbooks |
| `projects` | CRUD de projetos multi-alvo |
| `engagement` | Cria/encerra engagement (escopo + checklist) |
| `narrative` | Gera attack-narrative do run |
| `purple` | Exporta relatório Purple Team |
| `team` | Lock/unlock + audit trail multi-operador |
| `chains` | Encadeamento entre findings |
| `obsidian` | Exporta findings como notas Obsidian |
| `oob` | Gera payloads OOB (DNS/HTTP collaborator) |
| `phish-infra` | Mapeia infra de phishing relacionada ao alvo |
| `replay` | Replay tabletop de um run |
| `export` | GitHub Issues / Linear / Jira / Markdown |

### Principais opções de `run`

| Opção | Descrição |
|-------|-----------|
| `--target` | Domínio alvo (obrigatório) |
| `--modules` | CSV de módulos (ex.: `crtsh,http,github`) |
| `--playbook` | Perfil pré-configurado (ver `playbooks/`) |
| `--profile` | `standard` · `stealth` · `aggressive` |
| `--output FILE` | Grava JSON agregado final |
| `--format` | `json` · `ndjson` · `summary` |
| `--exact-match` | Subs apenas do alvo exato |
| `--kali` | Módulos Kali (requer ferramentas locais + role `red`) |
| `--auth-header K=V` | Repetível — headers extras |
| `--auth-cookie` | Cookie bruto para requests autenticadas |
| `--project NAME` | Atribui o run a um projeto |
| `--start-server` | Auto-spawn do API em background |
| `--timeout SEC` | Timeout global (default 1800) |

A CLI usa CSRF token automaticamente e faz auto-start do server local se `--start-server` for passado (ou erra com mensagem clara caso contrário). Auth via `GHOSTRECON_API_KEY` ou `Authorization` header.

---

## Scheduler, diff e alertas new-only

O subcomando `schedule` roda recons periódicos e, usando `compareRuns` + o diff-engine interno, alerta **apenas quando há findings novos** (dedupe por fingerprint SHA-1 dos achados). Evita ruído de "mesmo alerta todo dia".

```bash
ghostrecon schedule \
  --target api.example.com \
  --interval 6h \
  --playbook api-first \
  --webhook https://discord.com/api/webhooks/XXXXX/YYYYY \
  --min-severity high \
  --only-new
```

- Estado persistido em `.ghostrecon-schedule/<target>.json` (última runId, fingerprints vistos, histórico).
- Suporta Discord (embeds nativos), Slack (`text` mrkdwn) e webhook genérico.
- `--once` roda uma única iteração (útil em cron externo). `--max-runs N` limita o número total de iterações.
- Interval aceita `30s`, `15m`, `6h`, `2d`.

Endpoint equivalente: `GET /api/runs/:newerId/diff-summary/:baselineId?minSeverity=medium&onlyNew=1`.

---

## Playbooks

Playbooks são ficheiros JSON (ou YAML minimalista) em `playbooks/` que pré-selecionam módulos e perfil de pipeline para cenários comuns.

| Nome | Uso |
|------|-----|
| `api-first` | Superfície API (OpenAPI, GraphQL, params) |
| `wordpress` | WordPress — wpscan, temas, plugins, xmlrpc |
| `cloud-takeover` | CNAMEs órfãos em S3/Azure/GitHub Pages |
| `subdomain-hunt` | Enumeração agressiva (crtsh + VT + amass + subfinder) |
| `secrets-leak` | GitHub code search, wayback, dorks, JS crawl |
| `quick-triage` | Primeiro passo rápido (~60s) |
| `lovable-hunt` | Caça em apps Lovable.dev |
| `lowcode-hunt` | No-code/low-code (Bubble, Glide, etc.) |

Ver `playbooks/README.md` para formato completo. Aponte `GHOSTRECON_PLAYBOOKS_DIR` para diretórios extras (suporta múltiplos paths separados por `:` POSIX ou `;` Windows).

---

## Engagements, OPSEC e Purple Team

**Engagement** = container de uma autorização: escopo, janela, contato técnico, checklist pré-run, watermark.

```bash
ghostrecon engagement --create --name acme-2026 --target acme.com \
  --scope "*.acme.com,api.acme.io" --window "2026-05-01..2026-05-31" \
  --owner "alice@acme.com"
```

**OPSEC gate** (`/api/opsec/gate` + `gateModules()`) recusa módulos intrusivos sem o profile certo:

| Profile | Módulos permitidos |
|---------|--------------------|
| `passive` | apenas leitura externa (CT, wayback, RDAP) |
| `standard` | passivo + probes leves |
| `stealth` | standard + jitter, UA rotativo, sem brute |
| `aggressive` | tudo (requer role `red` + engagement aberto) |

**Attack-narrative** (`/api/runs/:id/narrative`) traduz findings para uma narrativa de ataque encadeada (kill-chain). **Purple-team** (`/api/runs/:id/purple`) gera relatório com mitigations sugeridas + detection rules.

`POST /api/engagements/checklist` retorna o pre-run checklist (auth, escopo, OOB collaborator, Tor, etc.) — **bloqueante** se faltar item crítico.

---

## Multi-operador (team locks + audit trail)

Quando vários operadores partilham a mesma instância:

```bash
ghostrecon team --lock acme.com --owner alice --reason "scan ativo 14:00-16:00"
ghostrecon team --unlock acme.com
ghostrecon team --trail acme.com
```

- `GET /api/team/locks` — locks ativos
- `GET /api/team/trail?target=...` — audit trail
- `POST /api/team/lock | /unlock` (`team.lock` scope)
- `POST /api/team/force-unlock` (admin)

Tentativa de iniciar `recon/stream` num target com lock alheio → **409 Conflict** com mensagem clara.

---

## Evidências ricas com Playwright

O módulo `server/modules/evidence-capture.js` captura, por finding, screenshot PNG + DOM snippet + response headers + console logs via Playwright headless.

```http
POST /api/evidence/capture/:runId
{
  "minSeverity": "medium",
  "maxCaptures": 25,
  "fullPage": false
}
```

Saída persistida em `.ghostrecon-evidence/<runId>/f<idx>_<slug>.{png,html,json}`. Os findings recebem `evidence.captures = { screenshot, dom, meta }` — referenciados diretamente pelo Reporter e pelo export de Markdown/HackerOne.

Requer: `npm install playwright && npx playwright install chromium`.

---

## CVE enrichment (versão → exploit)

Cruza tech strings (de `tech-versions.js`, banners ou version-page) com:

- **OSV.dev** (sem API key)
- **NVD 2.0** (com ou sem API key)
- **ExploitDB search** (heurístico, opcional)
- **Nuclei templates** locais (se `GHOSTRECON_NUCLEI_TEMPLATES_DIR` definido)

Severidade derivada do CVSS. **Banners são degradados em 1 step** (falsos positivos comuns — servidores mentem versão). Findings têm campos `cve`, `cvss`, `exploitPublic`, `exploitSources`.

```http
POST /api/cve/enrich
{
  "techStrings": ["nginx/1.18.0", "openssl/1.1.1k"],
  "source": "banner",
  "checkExploits": true
}
```

---

## Inbound webhooks (hub)

Ferramentas externas (subfinder, amass, nuclei, dnsx, cron scripts) podem enviar eventos para o GHOSTRECON, que os armazena por target para merge no próximo recon.

```bash
# .env
GHOSTRECON_INBOUND_KEYS=subfinder:key1,nuclei:key2

# Envio
BODY='{"template-id":"cve-2021-44228","matched-at":"https://api.example.com/","info":{"severity":"critical","name":"Log4Shell"}}'
SIG=$(echo -n "$BODY" | openssl dgst -sha256 -hmac "key2" | awk '{print $2}')
curl -X POST http://127.0.0.1:3847/api/inbound/nuclei \
  -H "x-ghostrecon-signature: sha256=$SIG" \
  -H "content-type: application/json" \
  -d "$BODY"
```

Auto-detecta payloads Subfinder/Amass/Nuclei. Leitura via `GET /api/inbound/:source/:target` (Bearer token = chave da source).

---

## Projects (multi-alvo)

Agrupa runs por programa/cliente — reduz context switching quando você caça em vários programas simultaneamente.

```bash
ghostrecon projects --add --name acme --description "Acme bounty"
ghostrecon projects --name acme --scope-add "*.acme.com" --scope-add "api.acme.io"
ghostrecon projects --show acme
ghostrecon run --target api.acme.com --project acme --playbook api-first
```

Storage local em `.ghostrecon-projects/projects.json` (zero dependências extras de DB).

---

## Workflow export (Linear/Jira/GitHub/Markdown)

Exporta findings de um run como issues em:

- **GitHub Issues** — `--to github --repo owner/name --github-token $GITHUB_TOKEN`
- **Linear** — `--to linear --linear-team TEAM_ID --linear-token $LINEAR_API_KEY`
- **Jira Cloud** — `--to jira --jira-url $BASE --jira-project KEY --jira-user me@ex.com --jira-token $JIRA_TOKEN`
- **Markdown** — `--to markdown --output out.md` (HackerOne/Bugcrowd-ready)
- **Obsidian** — `ghostrecon obsidian --run X --vault ~/vault`

Cada issue carrega: título com severidade, body reprodutível (evidence, OWASP, MITRE, CVE), labels/priorities mapeadas da severidade, link para o Reporter (se `GHOSTRECON_REPORTER_BASE` definido). Use `--dry-run` para preview sem POST.

---

## Instalação por perfil

```bash
bash install.sh --profile minimal     # base Node
bash install.sh --profile passive     # + stack passiva
bash install.sh --profile full        # + Kali, IA local e extras
bash install.sh -y --skip-shannon     # CI / não-interativo
```

Flags: `--skip-docker`, `--skip-shannon`, `--skip-pentestgpt`, `--skip-playwright`, `--skip-supabase`, `--skip-ghost-local`, `-y` (assume defaults).

IAs externas opcionais (`Shannon` em `IAs/shannon/`, `PentestGPT` em `IAs/PentestGPT/`) são clonadas pelo instalador. Detalhes em `IAs/README.md`.

---

## Scripts NPM

| Script | Função |
|--------|--------|
| `npm start` | Sobe Ghost local + API Node |
| `npm run start:api` | Só API Node |
| `npm run start:ghost` | Só Ghost local FastAPI |
| `npm run dev` | API com `node --watch` |
| `npm test` | Roda todos os testes (`server/tests/*.test.js`) |
| `npm run test:cli` | Subset de testes da CLI |
| `npm run test:ai` | Smoke test das chaves IA configuradas |
| `npm run cli` | Atalho para `bin/ghostrecon.mjs` |
| `npm run mitre:extract` | Regenera bundle MITRE de `mitre-attack/cti/` |
| `npm run pentestgpt-bridge` | Sobe ponte OpenRouter→PentestGPT em `:8765` |
| `npm run db:link` | `supabase link` (project_id=gosthrecon) |
| `npm run db:push` | `supabase db push` |
| `npm run db:migration:new` | `supabase migration new` |

---

## Testes automatizados

63 ficheiros de teste em `server/tests/*.test.js`, rodados com **`node --test`** (sem framework externo).

```bash
npm test
npm run test:cli           # apenas testes da CLI (cli-args, cli-ndjson)
```

Cobertura inclui: parser CLI, NDJSON streaming, diff-engine fingerprint, playbooks loader, CVE enrichment, inbound webhooks, projects CRUD, workflow export, payload mutator, JWT lab, race harness, OOB collaborator, Tor strict tunnel, identity controller, attack-narrative, purple-team, engagement, OPSEC, team-concurrency, authz-matrix, semantic-dedupe, owasp/mitre tagging, e mais.

---

## Docker

```bash
docker build -t ghostrecon .
docker run --rm -p 3847:3847 \
  -e AUTH_API_KEYS=$KEY:admin:docker \
  -v $(pwd)/data:/app/data \
  ghostrecon
```

Imagem mínima da API (sem painéis auxiliares e ferramentas Kali externas — para isso use a stack completa via `npm start`).

---

## Variáveis de ambiente

Veja `.env.example` para a lista completa **comentada**. Categorias principais:

- **Básico**: `PORT`, `HOST`, `GHOSTRECON_DB`
- **DB**: `DATABASE_URL` ou `SUPABASE_URL` + chaves
- **Auth**: `AUTH_MODE`, `AUTH_API_KEYS`, `AUTH_API_KEYS_FILE`, `AUTH_JWT_*`, `AUTH_DISABLE`, `AUTH_AUDIT_DIR`
- **CSRF / RL**: `GHOSTRECON_RL_MAX`, `GHOSTRECON_RL_WINDOW_MS`
- **IA cloud**: `GEMINI_API_KEY`, `OPENROUTER_API_KEY`, `ANTHROPIC_API_KEY`, modelos e retries
- **IA local**: `GHOSTRECON_LMSTUDIO_*`, `GHOSTRECON_GHOST_*`, `GHOSTRECON_AI_AUTO`
- **APIs recon**: `VIRUSTOTAL_API_KEY`, `GITHUB_TOKEN`, `WPSCAN_API_TOKEN`
- **Tor**: `GHOSTRECON_TOR_REQUIRED`, `GHOSTRECON_TOR_STRICT`, `GHOSTRECON_TOR_ISOLATE`, `GHOSTRECON_TOR_*`
- **Proxy/MITM**: `GHOSTRECON_PROXY_POOL`, `GHOSTRECON_PROXY_ROTATION`, `GHOSTRECON_PROXYCHAINS_*`, `GHOSTRECON_PROXY_CAPTURE_PORT`, `GHOSTRECON_PROXY_MITM`
- **CLI / scheduler**: `GHOSTRECON_SERVER`, `GHOSTRECON_API_KEY`, `GHOSTRECON_PLAYBOOKS_DIR`, `GHOSTRECON_PROJECTS_DIR`, `GHOSTRECON_INBOUND_DIR`, `GHOSTRECON_INBOUND_KEYS`, `GHOSTRECON_NUCLEI_TEMPLATES_DIR`, `GHOSTRECON_REPORTER_BASE`
- **Kali tooling**: `GHOSTRECON_FFUF_THREADS`, `GHOSTRECON_DIRSEARCH_*`, `GHOSTRECON_FTP_*`, `GHOSTRECON_EXPLOIT_GOOGLE_MAX_QUERIES`, `GHOSTRECON_WPSCAN_*`, `GHOSTRECON_XSS_VIBES_*`
- **Webhooks**: `GHOSTRECON_WEBHOOK_URL`, `GHOSTRECON_WEBHOOK_DELTA_FULL`, `GHOSTRECON_WEBHOOK_DELTA_MAX_FINDINGS`
- **Shannon / PentestGPT**: `GHOSTRECON_SHANNON_*`, `GHOSTRECON_PENTESTGPT_*`
- **Export**: `GITHUB_TOKEN`, `LINEAR_API_KEY`, `JIRA_USER`, `JIRA_TOKEN`

---

## Proxychains-ng + rotação de IP

`proxychains-ng` é uma opção dedicada da UI via módulo `kali_proxychains` (separada da rotação de identidade/proxy pool). Quando marcado no run, os scanners do modo Kali rodam por `proxychains-ng` (chains SOCKS/HTTP/Tor).

```bash
# .env
GHOSTRECON_PROXYCHAINS=1
GHOSTRECON_PROXYCHAINS_BIN=proxychains4
GHOSTRECON_PROXYCHAINS_CONF=/etc/proxychains4.conf
GHOSTRECON_PROXYCHAINS_QUIET=1
GHOSTRECON_PROXYCHAINS_SKIP=nmap        # CSV: ferramentas a excluir do chain
```

Com isso, ferramentas como `nmap`, `nuclei`, `ffuf`, `dirsearch`, `dalfox`, `whois`, `sqlmap` e `wpscan` passam a ser executadas via `proxychains4`. O modo Tor strict (`GHOSTRECON_TOR_STRICT=1`) ativa isso automaticamente com config endurecida (`strict_chain` + `proxy_dns`).

---

## Troubleshooting rápido

| Sintoma | Ação |
|---------|------|
| Porta ocupada | Ajuste `PORT` no `.env` ou mate o processo (`lsof -i :3847`) |
| `403 CSRF` em mutações | Pegue token em `GET /api/csrf-token` e envie `X-CSRF-Token` |
| `401 Unauthorized` | Configure `AUTH_API_KEYS` ou use `Authorization: Bearer <key>` |
| Modo Kali com módulos faltando | Verifique `GET /api/capabilities` e `npm run start:api` com `PATH` correto |
| IA falhando | `npm run test:ai` e cheque cota/Retry-After do provider |
| Ghost local offline | Veja `ghost-local-v5/ghost-local/ghost.log`; `start.sh` standalone |
| Tor não valida | `GET /api/tunnel/strict-check` e `tor-validator.html` no browser |
| DB falhando | Valide `DATABASE_URL` (URL-encode da senha) ou troque para SQLite |
| Audit log não aparece | `AUTH_AUDIT_DIR` e permissão de escrita; `AUTH_AUDIT_DISABLE=1` desliga ficheiro |

---

## Limites e uso responsável

- **Use somente em ambientes com autorização explícita** (contrato, programa de bounty ou escopo formal).
- Módulos do **Kali mode** podem ser intrusivos — exigem role `red` + engagement aberto + `recon.intrusive` scope.
- A stack depende de **APIs externas** (Gemini, OpenRouter, OSV, NVD, GitHub Code Search, etc.) e respeita seus rate-limits.
- Higiene de dados locais: `.env`, `clone/`, `escopo/`, `pocs/`, `.ghostrecon-evidence/`, `data/*.db` não vão para Git (já no `.gitignore`).
- Respeite a legislação local, políticas do alvo e regras de disclosure.
- O modo `AUTH_DISABLE=1` é **só para loopback** em dev. Nunca exponha o servidor sem auth.

---

> GHOSTRECON é uma ferramenta para **profissionais autorizados**. O uso indevido é responsabilidade exclusiva do operador.
