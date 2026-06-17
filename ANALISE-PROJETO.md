# Análise geral do GHOSTRECON

Documento de referência com diagnóstico do projeto, pontos fortes, dívida técnica, roadmap de funcionalidades e recomendações priorizadas.

**Gerado em:** 2026-06-17  
**Escopo:** monorepo completo (núcleo Node, GhostTrace, GhostMap, GhostDesk, ghost-local-v5)

---

## Visão geral

O GHOSTRECON é um **monorepo maduro de OSINT/recon** voltado a bug bounty e pentest autorizado. O núcleo é **Node/Express** com ~165 módulos e 70 testes automatizados, integrado a satélites especializados:

| Componente | Stack | Porta típica |
|------------|-------|--------------|
| **Núcleo GHOSTRECON** | Node 20–26, Express 4, ESM, Playwright, SQLite/Postgres/Supabase | `:3847` |
| **GhostTrace** (anotações) | Next.js 15, React, TipTap, Zustand | UI `:3010` (proxy `/anotacao`), API `:8787` |
| **GhostMap** (mapeamento visual) | Next.js 14, FastAPI, PostgreSQL, Neo4j, Redis, mitmproxy | Docker `:3000`/`:8000`; integração `:3020` |
| **GhostDesk** (gestão de scans) | Vue 3, Vite, Pinia | `:5173` (dev) |
| **Ghost Intelligence** (`ghost-local-v5`) | FastAPI, Ollama, ChromaDB | `:8000` |
| **CLI** | `bin/ghostrecon.mjs` → 16 comandos headless | — |

### Propósito operacional

Centralizar o ciclo de investigação de superfície de ataque:

```
descobrir ativos → sinais de vulnerabilidade → validação → priorização (OWASP/MITRE)
→ evidência → relatório/IA → export para ferramentas de workflow
```

Arquitetura **localhost-first**, **single-process Node**, streaming **NDJSON**, com subprojetos integrados por proxy HTTP.

---

## Estrutura do repositório

```
GHOSTRECON/
├── server/
│   ├── index.js                     # Entrypoint Express (~5000 linhas)
│   ├── config.js                    # Limites, rate-limit, regex de paths
│   ├── modules/                     # ~165 módulos (.js/.mjs)
│   │   ├── cli/commands/            # 16 comandos CLI
│   │   └── playbooks/loader.mjs
│   ├── scripts/                     # MITRE bundle, sync DB, smoke IA
│   └── tests/                       # 70 arquivos *.test.js
├── bin/ghostrecon.mjs               # Binário CLI
├── scripts/                         # start-stack, anotacao, ghostmap, ghostdesk
├── GhostTrace/                      # Next.js + backend FastAPI
├── ghostmap/                        # Stack separada (docker-compose)
├── GhostDesk/frontend/              # Vue 3 (backend integrado no server/)
├── ghost-local-v5/ghost-local/      # IA local FastAPI
├── playbooks/                       # 11 JSON + checklists MD
├── docs/                            # AUTH-RBAC, TOR, MODULE-CONTRACT, schema VPS
├── supabase/migrations/             # 1 migration SQL
├── mitre-attack/                    # Bundle MITRE recon
├── tools/                           # Tor/proxychains, XSS, scanners auxiliares
├── IAs/                             # Placeholder para clones externos (Shannon, PentestGPT)
├── Dockerfile                       # Imagem mínima da API Node
├── install.sh                       # Instalador por perfil (minimal|passive|full)
└── .env.example                     # ~350 linhas documentadas
```

---

## O que já está muito bem feito

| Área | Situação |
|------|----------|
| **Pipeline de recon** | Ciclo completo com streaming NDJSON via `POST /api/recon/stream` |
| **Módulos** | ~165 módulos: passivo, Kali, correlação OWASP/MITRE, OPSEC/Tor, export multi-plataforma |
| **CLI** | 16 comandos headless reutilizando o mesmo pipeline da API (sem duplicação de lógica) |
| **Auth/RBAC** | API keys + JWT, scopes granulares, audit log NDJSON, CSRF, rate limit |
| **Playbooks** | 11 playbooks JSON + checklists para cenários comuns |
| **Testes (núcleo)** | 70 testes com `node --test` — auth, CLI, Tor, OPSEC, diff-engine, etc. |
| **Documentação** | README extenso (~950 linhas), contrato de módulos, Tor, RBAC, schema VPS |
| **OPSEC** | Gating de módulos intrusivos, Tor strict mode, team locks, engagement checklist |

### Camadas do pipeline

| Camada | Exemplos de módulos |
|--------|---------------------|
| **Recon passivo** | `crtsh`, `virustotal`, `wayback`, `commoncrawl`, `rdap`, `dns-enrichment`, `tls-cert`, `tech`, `openapi-harvest`, `graphql-recon` |
| **Leaks/código** | `github`, `github-clone`, `secrets`, `dorks`, `google-cse`, `js-crawler`, `js-analyzer`, `js-intel` |
| **Validação** | `verify`, `dom-xss-verify`, `browser-xss-verify`, `sqlmap-runner`, `payload-mutator`, `oob-collaborator`, `cve-enrichment` |
| **Kali (intrusivo)** | `kali-scan.js` (~1800 linhas): nmap, ffuf, dirsearch, nuclei, dalfox, wpscan, xss_vibes… |
| **Correlação** | `correlation`, `prioritization`, `semantic-dedupe`, `chaining`, `owasp-top10`, `mitre-recon`, `scoring` |
| **Red Team/OPSEC** | `engagement`, `opsec`, `team-concurrency`, `attack-narrative`, `purple-team`, `cred-spray`, `cloud-bruteforce`, `authz-matrix`, `jwt-lab`, `race-harness` |
| **Anonimato** | `tor-control`, `tor-strict`, `socks5-dispatcher`, `identity-controller`, `proxy-capture` |

### CLI headless (`bin/ghostrecon.mjs`)

Comandos: `run`, `runs`, `diff`, `schedule`, `playbooks`, `projects`, `engagement`, `narrative`, `purple`, `team`, `chains`, `obsidian`, `oob`, `phish-infra`, `replay`, `export`.

### Playbooks disponíveis

`api-first`, `wordpress`, `cloud-takeover`, `subdomain-hunt`, `secrets-leak`, `quick-triage`, `lovable-hunt`, `lowcode-hunt`, `firebase-client-auth-hunt`, `client-surface-hunt`, `full-recon`.

### Integrações

- **Persistência:** SQLite (`data/bugbounty.db`), Postgres (`DATABASE_URL`), Supabase API
- **IA cascata:** Gemini → OpenRouter → Claude → LM Studio/Ghost local (`server/modules/ai-dual-report.js`)
- **Workflow export:** GitHub Issues, Linear, Jira, Markdown, Obsidian
- **Inbound webhooks HMAC:** Subfinder/Amass/Nuclei
- **GhostDesk:** rotas `/api/ghostdesk/*` em `server/modules/ghostdesk.mjs`

---

## Dívida técnica e melhorias imediatas

### 1. Arquivos monolíticos (prioridade alta)

| Arquivo | Linhas | Problema |
|---------|--------|----------|
| `server/index.js` | ~5.027 | Rotas + `runPipeline` + imports massivos |
| `server/modules/kali-scan.js` | ~1.838 | Lógica Kali concentrada em um único módulo |

**Sugestão:** extrair rotas por domínio (`routes/recon.mjs`, `routes/ghostdesk.mjs`, etc.) e quebrar o pipeline em orquestrador + estágios. Facilita manutenção e testes.

### 2. Contrato de módulos parcialmente adotado

Apenas **10 de ~165** módulos possuem `moduleManifest` registrado em `server/modules/module-registry.mjs`. O contrato está documentado em `docs/MODULE-CONTRACT.md`, mas a maioria dos módulos legados ainda não segue.

Módulos com manifesto hoje:

- `api-contract-diff`
- `cookie-session-audit`
- `csrf-flow-audit`
- `jwt-jwks-audit`
- `service-worker-audit`
- `websocket-recon`
- `hpp-param-pollution`
- `dom-clobbering-audit`
- `email-security-deep`
- `secrets-context-ranker`

**Sugestão:** migrar módulos em lotes por categoria (`discovery` → `surface` → `validation`) e expor tudo via `/api/capabilities` para UI e playbooks dinâmicos.

### 3. Sem CI/CD

- Pasta `.github/` ausente
- Sem pre-commit, husky ou lint-staged na raiz
- Docker apenas para API Node (`Dockerfile`) e GhostMap (`ghostmap/docker-compose.yml`)

**Sugestão mínima:**

```yaml
# .github/workflows/test.yml
- node 20/22
- npm test
- (opcional) smoke do CLI: ghostrecon capabilities
```

Para GhostTrace/GhostMap: ESLint + `pytest` quando houver testes.

### 4. Conflito de portas

`ghost-local-v5`, backend GhostMap (Docker) e LM Studio usam **:8000**. O `scripts/start-stack.mjs` sobe Ghost em 8000 e GhostMap em 3020, mas a stack Docker completa do GhostMap ainda conflita.

**Sugestão:** padronizar portas no `.env.example` (ex.: Ghost `:8100`, GhostMap API `:8200`) e documentar matriz de serviços no `start-stack`.

### 5. Testes limitados ao núcleo Node

| Componente | Testes |
|------------|--------|
| `server/tests/` | 70 arquivos |
| GhostTrace | nenhum |
| GhostMap (Python) | pytest configurado, 0 arquivos de teste |
| GhostDesk | nenhum |

**Sugestão:** começar por testes de integração do proxy (`/ghostmap`, `/anotacao`) e smoke E2E do pipeline.

### 6. UIs HTML monolíticas

`index.html`, `post-exploitation.html`, `mitre-map.html` (legado) concentram CSS/JS inline. Há duplicidade com GhostMap Next.js.

**Sugestão:** migrar gradualmente para os frontends modernos ou extrair componentes compartilhados.

### 7. Anti-padrões observados

1. **Naming enganoso:** GhostTrace usa `GhostTrace/src/lib/mock/store.ts` — na prática é Zustand + localStorage real, não mock
2. **Duplicidade GhostMap:** `mitre-map.html` legado + `ghostmap/` Next.js — dois caminhos para visualização MITRE
3. **Sem lint/format na raiz:** apenas GhostTrace e ghostmap frontend têm ESLint
4. **Integrações externas não versionadas:** Shannon e PentestGPT exigem clone manual em `IAs/`
5. **Pasta `novas funções/`:** PoCs operacionais fora do escopo do framework, não integrados

---

## Segurança — controles e gaps

### Controles implementados

- API keys + JWT com RBAC (`viewer` → `admin`) e scopes granulares (`recon.intrusive`, etc.)
- `AUTH_DISABLE=1` só em loopback; aviso se `HOST` não-local
- CSRF em rotas mutantes (`GET /api/csrf-token` + `X-CSRF-Token`)
- Rate limiting em `POST /api/recon/stream` (`GHOSTRECON_RL_MAX`)
- Tor strict mode anti-leak: DNS lock, proxychains, recusa se ferramentas faltarem
- Inbound webhooks com HMAC SHA-256 (`GHOSTRECON_INBOUND_KEYS`)
- Sanitização em queries (`searchsploit` remove shell metacharacters)
- Audit log NDJSON diário (`AUTH_AUDIT_DIR`)
- Team locks evitam scans concorrentes no mesmo alvo (409 Conflict)
- Engagement + checklist pré-run bloqueante
- GhostMap AI: política de redação de JWT/cookies em prompts
- `.gitignore` exclui `.env`, `data/*.db`, `clone/`, `pocs/`, `tokens/`, evidências

### Riscos e limitações documentadas

| Risco | Detalhe |
|-------|---------|
| API keys estáticas em env | `docs/AUTH-RBAC.md` — TODO: vault/KMS |
| CSRF token público | Emitido sem auth (defesa em profundidade, não substituto) |
| MITM proxy nativo | Root CA em `GET /api/proxy/ca.crt` — risco se exposto |
| Módulos intrusivos | sqlmap, cred-spray, cloud-bruteforce — exigem role `red` mas granularidade média |
| GhostTrace API keys | Armazenadas em `localStorage` (protótipo) |
| GhostMap default secret | `GHOSTMAP_SECRET=change-me-in-production` no docker-compose |
| Execução de binários externos | nmap, sqlmap, searchsploit via `spawn`/`execFile` — superfície se PATH comprometido |

---

## Roadmap de funcionalidades — módulos futuros

Fonte: `docs/ideias-modulos-futuros.txt` — **10 de 28 implementados**, **18 pendentes**.

### Já implementados

| # | Módulo | ID no registry |
|---|--------|----------------|
| 1 | api-contract-diff | `api_contract_diff` |
| 3 | websocket-recon | `websocket_recon` |
| 4 | cookie-session-audit | `cookie_session_audit` |
| 5 | csrf-flow-audit | `csrf_flow_audit` |
| 8 | hpp-param-pollution | `hpp_param_pollution` |
| 13 | jwt-jwks-audit | `jwt_jwks_audit` |
| 18 | email-security-deep | `email_security_deep` |
| 22 | secrets-context-ranker | `secrets_context_ranker` |
| 23 | service-worker-audit | `service_worker_audit` |
| 24 | dom-clobbering-audit | `dom_clobbering_audit` |

### Pendentes — priorizados

| Prioridade | Módulo | Por quê |
|------------|--------|---------|
| **Alta** | `cache-poisoning-audit` | Vetor comum em APIs/CDN |
| **Alta** | `file-upload-audit` | Superfície crítica em bug bounty |
| **Alta** | `oauth-flow-replay` | Fluxos OAuth mal configurados são frequentes |
| **Alta** | `graphql-cost-depth` | Complementa `graphql-recon` existente |
| **Média** | `ssti-fingerprint` | Detecção passiva de template injection |
| **Média** | `cdn-origin-leak` | Bypass de WAF / origem exposta |
| **Média** | `rate-limit-behavior-audit` | Sem spray agressivo, alinhado ao OPSEC |
| **Média** | `supply-chain-lockfile-audit` | JS já analisado; lockfiles fecham o ciclo |
| **Média** | `mobile-api-fingerprint` | Firebase/Supabase/mobile backends |
| **Baixa** | `llm-prompt-surface` | Endpoints de chatbot expostos |
| **Baixa** | `business-logic-planner` | Cupom, checkout, saldo — mais IA/planejamento |

### Pendentes — lista completa

| # | Módulo | Descrição |
|---|--------|-----------|
| 2 | `openapi-authz-matrix` | Testa endpoints por persona/token |
| 6 | `cache-poisoning-audit` | Heurísticas de cache poisoning com headers seguros |
| 7 | `web-cache-deception` | Identifica rotas com risco de cachear conteúdo privado |
| 9 | `file-upload-audit` | Superfície de upload, extensão, content-type, storage público |
| 10 | `ssti-fingerprint` | Fingerprint passivo/seguro de template injection |
| 11 | `deserialization-surface` | Procura sinais de objetos serializados em params/bodies |
| 12 | `graphql-cost-depth` | Analisa depth/cost/introspection/batching |
| 14 | `oauth-flow-replay` | Valida redirect_uri, state, nonce, PKCE em fluxo controlado |
| 15 | `saml-metadata-audit` | SAML metadata, ACS, assinatura, NameID, endpoints expostos |
| 16 | `cdn-origin-leak` | Cruza DNS, headers, TLS SAN, historical IPs e WAF bypass |
| 17 | `dns-zone-transfer` | AXFR, wildcard DNS, split-horizon hints |
| 19 | `cloud-iam-exposure` | Enumeração passiva de IAM leaks em JS/configs |
| 20 | `container-manifest-audit` | Dockerfile/compose/K8s secrets e portas expostas |
| 21 | `supply-chain-lockfile-audit` | package-lock, pip, composer, go mod com risco explorável |
| 25 | `rate-limit-behavior-audit` | Mede lockout/rate-limit sem spray agressivo |
| 26 | `mobile-api-fingerprint` | Detecta padrões Firebase/Supabase/GraphQL/mobile backends |
| 27 | `llm-prompt-surface` | Acha endpoints/chatbots com risco de prompt injection/data leak |
| 28 | `business-logic-planner` | Gera planos de teste para cupom, checkout, saldo, assinatura |

---

## Maturidade dos subprojetos

```
┌─────────────────────────────────────────────────────────────┐
│  MADURO          │  FUNCIONAL / PROTÓTIPO  │  SETUP PESADO │
├──────────────────┼─────────────────────────┼───────────────┤
│  GHOSTRECON Core │  GhostDesk (Vue)        │  GhostMap     │
│  CLI (16 cmds)   │  GhostTrace (Next.js)   │  (Neo4j+PG)   │
│  Auth/RBAC       │  Ghost Local (IA)       │  Shannon/     │
│                  │                         │  PentestGPT   │
└──────────────────┴─────────────────────────┴───────────────┘
```

| Subprojeto | Estado | Próximos passos naturais |
|------------|--------|--------------------------|
| **GhostDesk** | Integrado ao core; KPIs, clientes, scans | Handoff de evidências, relatório por projeto, dashboard viewer |
| **GhostTrace** | Protótipo funcional v0.1 | OAuth2, PostgreSQL, parsers Nmap/Nuclei/LinPEAS, embeddings |
| **GhostMap** | Stack pesada (Neo4j, Redis, mitmproxy) | Clustering 10k+ nós, replay batch, unificar com `mitre-map.html` legado |
| **Ghost Local** | FastAPI + Ollama + ChromaDB | Resolver conflito de porta, integrar melhor com `ai-dual-report.js` |
| **Shannon / PentestGPT** | Pastas em `IAs/`, clone manual | Script de install no `install.sh`, bridge já existe (`pentestgpt-bridge`) |

### GhostDesk — rotas integradas

Backend em `server/modules/ghostdesk.mjs`, montado no Express principal:

| Método | Rota | Scope | Função |
|--------|------|-------|--------|
| GET | `/api/ghostdesk/overview` | recon.read | KPIs: scans, alvos, projetos, clientes, findings |
| GET | `/api/ghostdesk/scans` | recon.read | Lista/detalha runs do GHOSTRECON |
| POST | `/api/ghostdesk/scans/:id/attach` | project.write | Anexa run a projeto |
| GET/POST/DELETE | `/api/ghostdesk/clients` | read/write | CRUD de clientes |
| GET | `/api/ghostdesk/intel/:target` | recon.read | Corpus deduplicado (Supabase/bounty_intel) |

### Itens incompletos ou placeholder

| Item | Evidência | Estado |
|------|-----------|--------|
| **GhostTrace** | README — "protótipo funcional" v0.1.0 | UI completa; sync SQLite opcional; sem auth enterprise |
| **GhostMap integrado** | Proxy `:3020` vs Docker `:3000`/`:8000` | Frontend integrável; backend pesado exige docker-compose separado |
| **Shannon / PentestGPT** | `IAs/README.md` — clones não estão no repo | Pastas ignoradas no `.gitignore`; capabilities retornam `ok: false` sem install |
| **module-registry** | Só 10 manifests | Contrato novo parcialmente adotado |
| **Supabase** | 1 migration | Schema mínimo; auto-detect desligado por default (`GHOSTRECON_SUPABASE_AUTO`) |
| **CI/CD** | Sem `.github/workflows` | Nenhuma automação de test/build |
| **Testes frontend/Python** | 0 testes GhostTrace/GhostMap/GhostDesk | Lacuna de cobertura |
| **`anotacao.html`** | Redirect para GhostTrace | Legado mantido por compatibilidade |

---

## Melhorias de produto e operação

1. **Orquestração unificada** — `npm start` já sobe stack via `scripts/start-stack.mjs`; falta health dashboard e restart automático de serviços que caem
2. **Diff entre runs** — `cli diff` existe; expor na UI do cockpit e no GhostDesk
3. **Agendamento** — `cli schedule` existe; falta cron/UI para runs recorrentes
4. **Supabase** — 1 migration; `GHOSTRECON_SUPABASE_AUTO` desligado por default; ativar sync automático e multi-tenant seria salto de maturidade
5. **Obsidian / relatórios** — export existe; templates DOCX via GhostTrace podem ser padronizados por playbook
6. **Inbound webhooks** — Subfinder/Amass/Nuclei já entram; documentar receitas para CI de segurança
7. **Empacotamento** — `Dockerfile` mínimo só para API; falta imagem "full stack" ou compose raiz unificando tudo

---

## Recomendações priorizadas

### Curto prazo (1–2 sprints)

1. Adicionar **CI** com `npm test` em PRs
2. Resolver **conflito de portas** e documentar matriz de serviços
3. Extrair **rotas** de `server/index.js` (primeiro corte: GhostDesk, auth, recon/stream)
4. Implementar **2–3 módulos** do roadmap (ex.: `file-upload-audit`, `cache-poisoning-audit`, `oauth-flow-replay`)

### Médio prazo

5. Migrar **50+ módulos** para `moduleManifest` + registry
6. Testes de integração para **GhostTrace** e smoke do **GhostMap** proxy
7. Consolidar **GhostMap legado** (`mitre-map.html`) no Next.js
8. GhostDesk: **handoff evidências** Reporte → GhostTrace → projeto

### Longo prazo

9. Vault/KMS para secrets; scopes `recon.kali` / `recon.sqlmap`
10. GhostMap Docker como **opcional** no `install.sh --profile full`
11. Completar os **18 módulos** restantes do roadmap
12. UI moderna substituindo HTML monolítico do cockpit

---

## Métricas de referência

| Métrica | Valor |
|---------|-------|
| Módulos em `server/modules/` | ~165 |
| Testes em `server/tests/` | 70 |
| Linhas em `server/index.js` | ~5.027 |
| Linhas em `server/modules/kali-scan.js` | ~1.838 |
| Módulos com `moduleManifest` | 10 |
| Playbooks JSON | 11 |
| Comandos CLI | 16 |
| Migrations Supabase | 1 |
| Workflows CI/CD | 0 |

---

## Arquivos-chave para onboarding

| Arquivo | Conteúdo |
|---------|----------|
| `README.md` | Referência principal do projeto |
| `server/index.js` | Entrypoint Express + pipeline |
| `server/modules/auth.js` | Auth/RBAC |
| `bin/ghostrecon.mjs` | CLI headless |
| `.env.example` | Configuração documentada |
| `docs/MODULE-CONTRACT.md` | Contrato para novos módulos |
| `docs/AUTH-RBAC.md` | Matriz roles × scopes |
| `docs/TOR.md` | Roteamento Tor anti-leak |
| `docs/ideias-modulos-futuros.txt` | Roadmap de 28 módulos |
| `playbooks/README.md` | Formato de playbooks |

---

## Resumo executivo

O GHOSTRECON é um **framework operacional maduro no núcleo Node**, com documentação excepcional, pipeline rico (~165 módulos), auth/RBAC sério, suporte Tor/OPSEC, CLI completa e 70 testes automatizados no servidor. O monorepo agrupa **quatro produtos satélite** (GhostTrace, GhostMap, GhostDesk, ghost-local) em estágios variados de maturidade.

**Pontos fortes:** profundidade funcional de recon/validação, arquitetura localhost-first, integração ponta-a-ponta Reporte → GhostTrace → DOCX, playbooks e export multi-plataforma.

**Principais lacunas:** ausência de CI/CD; `server/index.js` monolítico; contrato de módulos aplicado a apenas 10 módulos; conflito de porta `:8000`; dependências externas (Shannon, PentestGPT, ferramentas Kali) não empacotadas; testes limitados ao núcleo Node; subprojetos frontend/Python sem suite de testes.

Os maiores ganhos agora vêm de **engenharia** (refatorar `index.js`, CI, contrato de módulos, portas) e de **fechar o ecossistema** (GhostDesk ↔ GhostTrace ↔ GhostMap), não de reinventar o core.
