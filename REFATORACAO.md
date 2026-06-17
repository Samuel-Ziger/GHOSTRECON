# Plano de refatoração — GHOSTRECON

Documento técnico focado em **como reestruturar o código** sem alterar o comportamento operacional. Complementa o [ANALISE-PROJETO.md](./ANALISE-PROJETO.md) (diagnóstico geral) com blueprint executável.

**Gerado em:** 2026-06-17  
**Princípio rector:** refatoração incremental — cada fase deve manter `npm test` verde e o pipeline `/api/recon/stream` funcional.

---

## Progresso da implementação

| Fase | Estado | Notas |
|------|--------|-------|
| **0 — CI** | ✅ Feito | `.github/workflows/test.yml` (`npm test` + `test:cli`) |
| **1 — Infra compartilhada** | ✅ Feito | CSRF, rate-limit, http-history, outbound-fetch, severity, proxy factory, `isSha256FingerprintHex` |
| **2 — Rotas HTTP** | ✅ Feito | 11 ficheiros em `server/routes/` + `server/app/register-routes.mjs` |
| **3 — runPipeline** | ✅ Feito | Orquestrador fino + 9 fases em `server/pipeline/phases/` |
| **4+** | ⏳ Próximo | Registry, kali-scan split, frontend |

**Métrica atual:** `server/index.js` ≈ **171 linhas**. `run-pipeline.mjs` ≈ **58 linhas** (orquestrador). Pipeline: `pipeline-state.mjs`, `finding-context.mjs`, `pipeline-helpers.mjs`, **9 fases** em `phases/` (~3.400 linhas total).

---

## Resumo executivo

O maior débito estrutural está concentrado em **três monólitos**:

| Arquivo | Linhas | % do problema |
|---------|--------|---------------|
| `server/index.js` | 5.027 | Orquestrador + rotas + bootstrap |
| `index.html` | 8.778 | UI cockpit (56% JS inline) |
| `server/modules/kali-scan.js` | 1.838 | Ferramentas Kali em um único módulo |

Dentro de `index.js`, **`runPipeline` ocupa ~3.060 linhas (61%)** com 124 imports estáticos, 89 guards `modules.includes()` e zero dispatcher dinâmico.

A camada `db.js` já é um bom facade. Os módulos individuais de recon (~165 arquivos, ~32.000 linhas) estão razoavelmente separados. O trabalho principal é **desmontar o orquestrador**, **extrair rotas**, **unificar duplicações** e **expandir o registry de módulos**.

---

## Diagnóstico da arquitetura atual

### Mapa de dependências (simplificado)

```
┌─────────────────────────────────────────────────────────────────────────┐
│                         server/index.js (5027 linhas)                    │
│  ┌─────────────┐  ┌──────────────────┐  ┌─────────────────────────────┐ │
│  │ 124 imports │  │ runPipeline      │  │ 42 rotas app.get/post       │ │
│  │ estáticos   │  │ (3060 linhas)    │  │ inline                      │ │
│  └──────┬──────┘  │ 89× includes()   │  └──────────────┬──────────────┘ │
│         │         │ ~100× pipe()     │                 │                │
│         ▼         └────────┬─────────┘                 ▼                │
│  server/modules/* (~165)   │              registerNewApiRoutes (22 rotas) │
│                            │              registerGhostDeskRoutes (13)   │
│                            │              registerInboundWebhooks (2)    │
│                            ▼                                            │
│                   NDJSON emit → UI / GhostMap / CLI                     │
└─────────────────────────────────────────────────────────────────────────┘
         │                    │                         │
         ▼                    ▼                         ▼
   db.js (facade)      pipeline-stages.mjs      ghosttrace/ghostmap proxy
```

### O que já funciona bem (não refatorar agora)

| Componente | Por quê preservar |
|------------|-------------------|
| `server/modules/db.js` | Facade unificado SQLite/Postgres/Supabase |
| `server/modules/auth.js` | RBAC maduro, testado |
| `server/modules/opsec.mjs` | Gating de perfis isolado |
| `server/modules/pipeline-stages.mjs` | Tracker NDJSON limpo |
| `server/modules/module-runner.mjs` | Pool, spawn, output capped |
| `server/modules/ghostdesk.mjs` | Padrão de rota `register*Routes` |
| `server/modules/api-extensions.js` | Mesmo padrão, 22 rotas extraídas |
| `server/tests/` (70 arquivos) | Cobertura unitária do núcleo |
| CLI via HTTP (`cli/commands/run.mjs`) | Não acopla ao monólito — vantagem para refatorar |

### O que está errado estruturalmente

1. **Orquestração estática** — cada módulo é importado no topo e chamado manualmente dentro de `runPipeline`
2. **Registry cosmético** — `module-registry.mjs` lista 10 manifests; não executa nada
3. **Rotas misturadas** — 42 rotas inline + 37 em módulos `register*` (ordem de registro importa)
4. **Duplicação silenciosa** — CSRF, fetch, findings, proxies, DB backends, IDs de módulos
5. **Frontend acoplado** — `index.html` reimplementa lógica do servidor (OPSEC, normalização, stream)
6. **Naming fragmentado** — `snake_case`, `kebab-case` e nomes curtos coexistem

---

## Métricas de referência (baseline)

Use estas métricas para medir progresso da refatoração:

| Métrica | Valor atual | Meta final |
|---------|-------------|------------|
| Linhas em `server/index.js` | ~171 (Fase 3 parcial) | < 150 |
| Linhas em `runPipeline` | ~58 (`run-pipeline.mjs` orquestrador) | 0 (só `phases/`) |
| Imports em `index.js` | 124 | < 15 |
| Rotas inline em `index.js` | 0 (Fase 2) | 0 |
| Módulos com `moduleManifest` | 10 / ~80+ | 100% dos ativos |
| Guards `modules.includes` em pipeline | 89 | 0 (dispatcher) |
| Linhas JS inline em `index.html` | ~4.954 | 0 |
| Linhas CSS inline em `index.html` | ~3.823 | 0 |
| Testes de integração do pipeline | 0 | ≥ 5 |
| Workflows CI | 0 | ≥ 1 |

---

## Top 15 módulos por tamanho (candidatos a subdivisão)

| # | Linhas | Arquivo | Ação sugerida |
|---|--------|---------|---------------|
| 1 | 1.838 | `kali-scan.js` | Dividir por ferramenta: `kali/nmap.mjs`, `kali/ffuf.mjs`, etc. |
| 2 | 1.195 | `ai-dual-report.js` | Separar providers: `ai/gemini.mjs`, `ai/openrouter.mjs`, `ai/claude.mjs` |
| 3 | 957 | `verify.js` | Extrair verificadores por tipo (XSS, SQLi, LFI) |
| 4 | 796 | `supabase-rls-audit.mjs` | OK como módulo único |
| 5 | 711 | `lovable-fingerprint.js` | OK |
| 6 | 664 | `supabase-audit.mjs` | OK |
| 7 | 657 | `db-sqlite.js` | Manter; extrair `mergeIntelRow` compartilhado |
| 8 | 622 | `auth.js` | Manter; unificar listas de módulos intrusivos |
| 9 | 612 | `firebase-audit.mjs` | OK |
| 10 | 520 | `client-surface-audit.mjs` | OK |
| 11 | 501 | `curl-probe.mjs` | OK |
| 12 | 484 | `tor-strict.js` | OK |
| 13 | 482 | `identity-controller.mjs` | OK |
| 14 | 428 | `db-runs-merge.mjs` | Avaliar fusão com `db.js` após unificar merge |
| 15 | 413 | `proxy-capture.mjs` | OK |

**Prioridade de subdivisão:** `kali-scan.js` > `ai-dual-report.js` > `verify.js`.

---

## Estrutura-alvo proposta

```
server/
├── index.js                      # ~100 linhas: load-env, createApp, listen
├── app/
│   ├── create-app.mjs            # Express + middleware stack
│   └── register-routes.mjs       # agrega todos register*Routes
├── pipeline/
│   ├── run-pipeline.mjs          # orquestrador fino (~200 linhas)
│   ├── finding-context.mjs       # addFinding, emit, pipe, provenance
│   ├── dispatcher.mjs            # registry.run(modules, ctx) por fase
│   └── phases/
│       ├── input.mjs
│       ├── discovery.mjs         # subdomains, dns, ct, origin
│       ├── surface.mjs           # headers, cors, jwt, openapi, audits
│       ├── content-discovery.mjs # wayback, js, dorks, github
│       ├── validation.mjs        # verify, dom-xss, sqlmap, authz
│       ├── aggressive.mjs        # kali, cred-spray, race, oob
│       └── finalize.mjs          # scoring, AI, persistência, webhooks
├── routes/
│   ├── recon-stream.mjs          # POST /api/recon/stream
│   ├── runs.mjs                  # /api/runs, /api/intel
│   ├── proxy-tunnel.mjs          # /api/proxy/*, /api/tunnel/*
│   ├── ai.mjs                    # /api/ai-reports, shannon, pentestgpt
│   ├── brain.mjs                 # /api/brain/*
│   ├── validations.mjs           # /api/manual-validations/*
│   ├── capabilities.mjs          # /api/capabilities, /api/health
│   ├── ghostdesk.mjs             # mover de modules/
│   ├── api-extensions.mjs        # mover de modules/
│   └── inbound-webhooks.mjs      # mover de modules/
├── lib/
│   ├── outbound-fetch.mjs        # strictFetch + history + Tor/SOCKS
│   ├── http-history.mjs          # redaction, recordReconHttpHistory
│   ├── create-next-proxy.mjs     # factory para GhostTrace/GhostMap
│   ├── severity.mjs              # sevToPrio, sevToScore
│   └── dns-helpers.mjs
├── middleware/
│   ├── csrf.mjs                  # issue/validate + requireCsrf factory
│   └── rate-limit.mjs            # allowReconRequest
├── env.js                        # getters tipados para process.env
├── config.js                     # mantém limits, UA, regex (sem env direto)
└── modules/                      # só lógica de recon (sem rotas HTTP)

public/                           # ou frontend/cockpit/
├── css/
│   └── ghostrecon.css            # extraído de index.html
└── js/
    ├── api-client.mjs            # auth, csrf, apiUrl
    ├── recon-stream.mjs          # parser NDJSON
    ├── state.mjs                 # findings, stats, localStorage
    └── cockpit.mjs               # entrypoint UI
```

---

## Fase 0 — Preparação (sem mudar comportamento)

**Objetivo:** criar rede de segurança antes de mover código.

### 0.1 CI mínimo

Criar `.github/workflows/test.yml`:

```yaml
name: test
on: [push, pull_request]
jobs:
  node:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-node@v4
        with: { node-version: '22' }
      - run: npm ci
      - run: npm test
      - run: npm run test:cli
```

### 0.2 Testes de fumaça do pipeline

Criar `server/tests/pipeline-smoke.test.js`:

- Importar `runPipeline` (após extração) ou chamar `POST /api/recon/stream` com supertest
- Target: `127.0.0.1` ou fixture local
- Módulos: `['rdap']` apenas (passivo, sem rede externa se mockado)
- Assert: resposta NDJSON contém `type: 'done'`

### 0.3 Snapshot de contrato NDJSON

Salvar fixture em `server/tests/fixtures/recon-stream-rdap.ndjson` para detectar regressões no formato de eventos.

### 0.4 Regra de ouro

> Nenhum PR de refatoração altera a assinatura pública de `/api/recon/stream`, `/api/runs` ou o formato NDJSON sem migration documentada.

**Critério de conclusão:** CI verde + 1 teste smoke.

---

## Fase 1 — Extrair infraestrutura compartilhada (P0)

**Risco:** baixo. **Impacto:** reduz duplicação imediata.

### 1.1 Middleware CSRF unificado

**Origem:** `index.js:276-301`, duplicado em `api-extensions.js:48` e `ghostdesk.mjs:75`

**Destino:** `server/middleware/csrf.mjs`

```js
export function createCsrfMiddleware() { /* issue, validate, cleanup */ }
export function requireCsrf(validateCsrfToken) { /* factory */ }
```

**Migração:**
1. Criar módulo
2. Substituir nos 3 arquivos
3. `npm test` — `auth.test.js` deve passar

### 1.2 Outbound fetch + HTTP history

**Origem:** `index.js:303-527` (`redactHttpHeader`, `strictFetchInit`, monkey-patch)

**Destino:**
- `server/lib/http-history.mjs`
- `server/lib/outbound-fetch.mjs`

**Exportar:** `installOutboundFetch(app)` chamado em `create-app.mjs`.

### 1.3 Proxy factory

**Origem:** `ghosttrace-proxy.mjs` (62 linhas) e `ghostmap-proxy.mjs` (60 linhas) — ~95% idênticos

**Destino:** `server/lib/create-next-proxy.mjs`

```js
export function createNextProxyMiddleware({
  prefix, defaultPort, envPrefix, offlineTitle, offlineHint
}) { /* ... */ }
```

**Wrappers finos:**
- `ghosttrace-proxy.mjs` → 5 linhas chamando factory
- `ghostmap-proxy.mjs` → 5 linhas chamando factory

### 1.4 Helpers duplicados

| Função | Origens | Destino único |
|--------|---------|---------------|
| `isSha256FingerprintHex` | `index.js:4641`, `db.js:79` | `db-common.js` (export) |
| `sevToPrio` / `sevToScore` | `index.js:204-217` | `lib/severity.mjs` |
| `buildPipelineExportPayloadForAi` | `index.js:670` | `modules/pipeline-export.mjs` |
| `requireCsrf` closure | 3 arquivos | `middleware/csrf.mjs` |

### 1.5 Env centralizado

**Destino:** `server/env.js`

Agrupar leituras frequentes:

```js
export const env = {
  port: Number(process.env.PORT || 3847),
  ghostPort: Number(process.env.GHOST_PORT || 8100),  // resolver conflito
  ghostmapPort: Number(process.env.GHOSTMAP_PORT || 3020),
  supabaseAuto: process.env.GHOSTRECON_SUPABASE_AUTO === '1',
  // ...
};
```

Migrar gradualmente: `kali-scan.js` (41 refs), `ai-dual-report.js` (45 refs), `tor-strict.js` (23 refs).

**Critério de conclusão:** `index.js` reduz ~350 linhas; proxies unificados; zero `requireCsrf` duplicado.

---

## Fase 2 — Extrair rotas HTTP (P0)

**Risco:** médio. **Padrão existente:** `registerGhostDeskRoutes`, `registerNewApiRoutes`.

### 2.1 Inventário de rotas

| Grupo | Rotas | Arquivo atual | Destino |
|-------|-------|---------------|---------|
| Recon stream | 1 | `index.js:3804` | `routes/recon-stream.mjs` |
| CSRF + history | 2 | `index.js:4132-4148` | `routes/setup.mjs` |
| Proxy + tunnel | 11 | `index.js:4152-4266` | `routes/proxy-tunnel.mjs` |
| Tools + health | 4 | `index.js:4285-4332` | `routes/capabilities.mjs` |
| Capabilities + AI | 6 | `index.js:4334-4560` | `routes/ai.mjs` |
| Runs + intel | 4 | `index.js:4562-4632` | `routes/runs.mjs` |
| Brain | 5 | `index.js:4646-4738` | `routes/brain.mjs` |
| Anotação handoff | 2 | `index.js:4749-4783` | `routes/handoff.mjs` |
| Manual validations | 4 | `index.js:4785-4984` | `routes/validations.mjs` |
| API extensions | 22 | `api-extensions.js` | `routes/api-extensions.mjs` |
| GhostDesk | 13 | `ghostdesk.mjs` | `routes/ghostdesk.mjs` |
| Inbound webhooks | 2 | `inbound-webhooks.js` | `routes/inbound-webhooks.mjs` |

**Total:** ~76 endpoints.

### 2.2 Agregador de rotas

**Destino:** `server/app/register-routes.mjs`

```js
export function registerAllRoutes(app, deps) {
  registerReconStreamRoutes(app, deps);
  registerRunsRoutes(app, deps);
  // ...
  registerGhostDeskRoutes(app, deps);
  registerInboundWebhooks(app);
  registerGhosttraceProxy(app);  // middleware, não rota
  registerGhostmapProxy(app);
}
```

### 2.3 Handler recon/stream

O handler em `index.js:3804-4130` (~327 linhas) merece módulo próprio porque concentra:

- Rate limit (`allowReconRequest`)
- OPSEC gate (`gateModules`)
- Identity controller
- Team locks
- Chamada a `runPipeline`
- Headers NDJSON

**Dependências a injetar:** `{ runPipeline, gateModules, validateCsrfToken, allowReconRequest }`

### 2.4 Ordem de registro

Manter a ordem atual documentada em `register-routes.mjs`:

1. Rotas API (antes de static)
2. `registerInboundWebhooks`
3. `registerNewApiRoutes` / demais
4. Proxy middleware (`/anotacao`, `/ghostmap`)
5. `express.static`
6. `GET /` → `index.html`

**Critério de conclusão:** `index.js` sem `app.get/post` inline; testes de rota para auth denial.

**Estado (2026-06-17):** ✅ Concluída. `registerAllRoutes` em `server/app/register-routes.mjs`; 11 módulos em `server/routes/`; testes em `server/tests/refactor-phase2.test.js`. API extensions / GhostDesk / inbound mantidos nos módulos originais (registados pelo agregador).

---

## Fase 3 — Desmontar `runPipeline` (P0 — maior impacto)

**Risco:** alto. **Estratégia:** extração mecânica por fases, uma PR por fase.

### 3.1 Contexto do pipeline

**Destino:** `server/pipeline/finding-context.mjs`

Extrair closure `addFinding` (linha ~788) e helpers:

```js
export function createPipelineContext({ emit, log, target, modules, auth, ... }) {
  const findings = [];
  const addFinding = (f) => { /* fingerprint + provenance + emit */ };
  const stages = createPipelineStageTracker(emit);
  return { findings, addFinding, pipe: stages.pipe, ... };
}
```

### 3.2 Mapa de fases (extração de `runPipeline`)

| Fase | Linhas aprox. em `index.js` | Arquivo destino | Módulos principais |
|------|----------------------------|-----------------|-------------------|
| Input | 845-849 | `phases/input.mjs` | out_of_scope, normalização target |
| Fingerprint | 850-961 | `phases/fingerprint.mjs` | lovable, supabase, firebase |
| Discovery | 962-1215 | `phases/discovery.mjs` | virustotal, subdomains, ct, origin, dns, rdap |
| Probe / alive | 1216-1349 | `phases/probe.mjs` | probe, wafw00f |
| Surface | 1350-1807 | `phases/surface.mjs` | cookie, csrf, cors, jwt, openapi, shodan |
| Content | 1808-2358 | `phases/content-discovery.mjs` | wayback, params, js, dorks, github |
| Validation | 2585-2973 | `phases/validation.mjs` | verify, sqlmap, authz, dom-xss, race, oob |
| Kali | 2974-3070 | `phases/aggressive.mjs` | kali-scan (delegar) |
| Asset discovery | 3071-3196 | `phases/asset-discovery.mjs` | asset discovery pós-kali |
| Finalize | 3197-3801 | `phases/finalize.mjs` | prioritization, correlation, AI, persist, webhooks |

### 3.3 Orquestrador fino

**Destino:** `server/pipeline/run-pipeline.mjs`

```js
import { runInputPhase } from './phases/input.mjs';
import { runDiscoveryPhase } from './phases/discovery.mjs';
// ...

export async function runPipeline(ctx) {
  const pctx = createPipelineContext(ctx);
  await runInputPhase(pctx);
  await runDiscoveryPhase(pctx);
  // ... sequência fixa inicialmente
  return pctx.getResult();
}
```

**Importante:** na primeira iteração, **não** criar dispatcher dinâmico. Apenas mover código para arquivos separados mantendo a mesma ordem e os mesmos `modules.includes()`.

### 3.4 Ordem de PRs sugerida

1. `finding-context.mjs` + `run-pipeline.mjs` (move corpo inteiro, re-export)
2. `phases/finalize.mjs` (menos dependências upstream)
3. `phases/input.mjs` + `phases/fingerprint.mjs`
4. `phases/discovery.mjs`
5. `phases/surface.mjs`
6. `phases/content-discovery.mjs`
7. `phases/validation.mjs` + `phases/aggressive.mjs`

Após cada PR: `npm test` + smoke manual `ghostrecon run -t example.com --modules rdap`.

**Critério de conclusão:** `runPipeline` fora de `index.js`; `index.js` < 500 linhas.

**Estado (2026-06-17):** ✅ Concluída. `run-pipeline.mjs` orquestra `input`, `fingerprint`, `discovery`, `probe`, `content-discovery`, `validation`, `aggressive`, `asset-discovery`, `finalize`. Estado partilhado em `pipeline-state.mjs`.

---

## Fase 4 — Registry unificado e dispatcher (P1)

**Risco:** médio-alto. **Pré-requisito:** Fase 3 concluída.

### 4.1 Contrato canônico (já documentado)

Referência: `docs/MODULE-CONTRACT.md`

Cada módulo deve exportar:

```js
export const moduleManifest = { id, name, category, intrusive, ... };
export async function run(ctx) { return { findings, metrics, artifacts }; }
```

### 4.2 Registry expandido

**Destino:** `server/modules/module-registry.mjs`

```js
export const moduleRegistry = new Map([
  ['cookie_session_audit', { manifest, run: runCookieSessionAudit }],
  // ...
]);

export function getModulesForPhase(phase) { /* filtra por category */ }
export async function runModule(id, ctx) { /* timeout, concurrency do manifest */ }
```

### 4.3 Migração por lotes

| Lote | Categoria | Qtd estimada | Prioridade |
|------|-----------|--------------|------------|
| 1 | Audits com manifest (já feitos) | 10 | Conectar `run()` ao registry |
| 2 | Surface passivos | ~15 | security_headers, cors_audit, etc. |
| 3 | Discovery | ~12 | crtsh, wayback, virustotal, etc. |
| 4 | Validation | ~10 | verify, dom-xss, sqlmap |
| 5 | Kali sub-módulos | ~15 | após split de kali-scan.js |
| 6 | Legado / raro | restante | avaliar deprecação |

### 4.4 Unificar IDs de módulos

**Problema atual:** três convenções coexistem.

| Onde | Convenção | Exemplo |
|------|-----------|---------|
| Pipeline `modules.includes` | `snake_case` | `kali_nuclei`, `cookie_session_audit` |
| `opsec.mjs INTRUSIVE_MODULES` | `kebab-case` | `nuclei-aggressive`, `browser-xss` |
| `auth.js` prefixos | ambos | `cloud_bruteforce` e `cloud-bruteforce` |

**Decisão:** padronizar em **`snake_case`** como ID canônico.

**Plano:**
1. Criar `server/modules/module-ids.mjs` com mapa de aliases legados
2. `normalizeModuleId(id)` converte kebab → snake
3. Atualizar `opsec.mjs` para usar IDs canônicos
4. UI (`index.html`) gera checkboxes a partir de `listModuleManifests()` — elimina lista hardcoded

### 4.5 Dispatcher por fase

**Destino:** `server/pipeline/dispatcher.mjs`

```js
export async function runPhase(phaseName, moduleIds, ctx) {
  const phaseModules = moduleIds.filter(id => registry.get(id)?.manifest.category === phaseName);
  await mapPool(phaseModules, async (id) => registry.run(id, ctx), { concurrency: ctx.limits.concurrency });
}
```

Substituir gradualmente `if (modules.includes('foo'))` por `await runPhase('surface', modules, ctx)`.

**Critério de conclusão:** 0 `modules.includes` em `run-pipeline.mjs`; UI e playbooks usam registry como fonte única.

---

## Fase 5 — Refatorar módulos gigantes (P1)

### 5.1 `kali-scan.js` (1.838 linhas)

**Dividir em:**

```
server/modules/kali/
├── index.mjs           # orquestrador fino, export runKaliScan(ctx)
├── spawn-tool.mjs      # wrapper spawn + output cap (usa module-runner)
├── nmap.mjs
├── ffuf.mjs
├── dirsearch.mjs
├── nuclei.mjs
├── wpscan.mjs          # delega para wpscan.js existente
├── dalfox.mjs
├── xss-vibes.mjs
├── subfinder.mjs
├── amass.mjs
└── wordlists.mjs       # WORDLISTS constantes
```

**Manter:** `kali-scan.js` como re-export deprecado por 1 release:

```js
export { runKaliScan as default } from './kali/index.mjs';
```

### 5.2 `ai-dual-report.js` (1.195 linhas)

```
server/modules/ai/
├── index.mjs           # cascata Gemini → OpenRouter → Claude → local
├── gemini.mjs
├── openrouter.mjs
├── claude.mjs
├── lmstudio.mjs
├── prompt-templates.mjs
└── report-format.mjs
```

### 5.3 `verify.js` (957 linhas)

```
server/modules/verify/
├── index.mjs
├── xss.mjs
├── sqli.mjs
├── lfi.mjs
├── redirect.mjs
└── cors-reflect.mjs
```

**Critério de conclusão:** nenhum arquivo em `server/modules/` > 600 linhas (exceto gerados).

---

## Fase 6 — Camada de dados (P2)

### 6.1 Unificar merge de intel

**Problema:** `db-pg.js` e `db-supabase.js` duplicam `parseJsonField`, `mergeIntelRow`, `newPendingIntelRow`.

**Destino:** `server/modules/db-intel-merge.mjs`

```js
export function mergeIntelRow(existing, incoming) { /* única implementação */ }
export function parseJsonField(val) { /* única implementação */ }
```

Ambos backends importam de lá.

### 6.2 `db-runs-merge.mjs`

Avaliar se a lógica GhostDesk-specific pode virar método do facade:

```js
// db.js
export async function listRunsWithProjectMeta(opts) { /* ... */ }
```

### 6.3 Validações manuais

Hoje: SQLite + espelho `Validate/*.json` (híbrido intencional).

**Manter** o híbrido, mas extrair para `server/modules/manual-validations.mjs` — já usado implicitamente em rotas.

**Critério de conclusão:** zero funções duplicadas entre `db-pg.js` e `db-supabase.js`.

---

## Fase 7 — Frontend cockpit (P2)

### 7.1 Diagnóstico do `index.html`

| Parte | Linhas | % |
|-------|--------|---|
| CSS inline | ~3.823 | 44% |
| JS inline | ~4.954 | 56% |
| Chamadas `fetch('/api/...')` | 18 | — |
| Keys `localStorage` ghostrecon_* | 80+ | — |

### 7.2 Extração sem bundler (mínimo viável)

```
public/
├── css/ghostrecon.css
└── js/
    ├── api-client.js      # apiUrl, auth, csrf, auto-auth
    ├── recon-stream.js    # NDJSON parser + UI update hooks
    ├── state.js           # localStorage wrapper
    ├── modules-ui.js      # checkboxes de módulos (futuro: fetch /api/capabilities)
    └── cockpit.js         # init, event listeners
```

`index.html` fica com estrutura HTML + `<link>` + `<script type="module">`.

### 7.3 Eliminar duplicação com servidor

| Lógica duplicada na UI | Substituir por |
|------------------------|----------------|
| Lista de módulos hardcoded | `GET /api/capabilities` |
| Modo Kali / OPSEC manual | Mesmos campos do body de `/api/recon/stream` documentados; opcional `GET /api/opsec/profiles` |
| Normalização de target | `POST /api/recon/normalize-target` (nova rota leve) ou importar de `recon-target.js` via API |
| Export de findings | `GET /api/runs/:id/export` reutilizando `pipeline-export.mjs` |

### 7.4 HTML legados

| Arquivo | Linhas | Ação |
|---------|--------|------|
| `mitre-map.html` | 2.964 | Deprecar após GhostMap Next.js cobrir 100% |
| `post-exploitation.html` | 2.071 | Extrair JS/CSS ou migrar para GhostTrace |
| `reporte.html` | 2.157 | Manter; integrar handoff via API |
| `cortex.html` | 2.098 | Extrair JS/CSS |

**Critério de conclusão:** `index.html` < 500 linhas; CSS/JS em arquivos separados.

---

## Fase 8 — Subprojetos e integração (P3)

### 8.1 Portas padronizadas

| Serviço | Porta atual | Porta proposta | Env |
|---------|-------------|----------------|-----|
| GHOSTRECON API | 3847 | 3847 | `PORT` |
| GhostTrace | 3010 | 3010 | `GHOSTTRACE_PORT` |
| GhostMap UI | 3020 | 3020 | `GHOSTMAP_PORT` |
| GhostDesk | 5173 | 5173 | `GHOSTDESK_PORT` |
| Ghost Local | **8000** | **8100** | `GHOST_PORT` |
| GhostMap API (Docker) | **8000** | **8200** | `GHOSTMAP_API_PORT` |
| LM Studio fallback | 8000 | 1234 | `LMSTUDIO_PORT` |

Atualizar: `scripts/start-stack.mjs`, `.env.example`, `ghostmap/docker-compose.yml`.

### 8.2 GhostDesk

Backend já integrado (`ghostdesk.mjs`). Refatoração = **mover para `routes/`** (Fase 2).

Frontend Vue: criar `GhostDesk/frontend/src/api/client.ts` espelhando `public/js/api-client.js` do cockpit.

### 8.3 GhostTrace

- Renomear `GhostTrace/src/lib/mock/store.ts` → `store.ts` (não é mock)
- Auth: migrar de `localStorage` para cookies httpOnly via proxy GHOSTRECON

### 8.4 GhostMap

- Backend Docker permanece separado
- Proxy Next.js unificado via `create-next-proxy.mjs`
- NDJSON `pipe` events: documentar contrato em `docs/GHOSTMAP-NDJSON.md`

---

## Estratégia de testes durante refatoração

### Pirâmide alvo

```
        ┌─────────────┐
        │  E2E smoke  │  1-3 testes (pipeline, CLI run)
        ├─────────────┤
        │  Integração │  rotas HTTP, proxy, NDJSON format
        ├─────────────┤
        │  Unitário   │  70+ existentes + novos por fase
        └─────────────┘
```

### Novos testes prioritários

| Teste | Arquivo | O quê valida |
|-------|---------|--------------|
| Pipeline smoke | `pipeline-smoke.test.js` | `runPipeline` retorna findings |
| NDJSON contract | `recon-stream-contract.test.js` | Eventos `pipe`, `finding`, `done` |
| Route auth | `routes-auth.test.js` | 401/403 sem scope |
| CSRF middleware | `csrf.test.js` | Token issue/validate |
| Module registry | `module-registry.test.js` | Manifests válidos, IDs únicos |
| Proxy factory | `create-next-proxy.test.js` | Path rewrite, offline HTML |
| ID normalization | `module-ids.test.js` | kebab → snake aliases |

### Ferramentas

Manter `node --test` nativo (sem Jest). Para rotas HTTP: `supertest` ou `node:http` manual (padrão já usado em `auth.test.js`).

---

## Riscos e mitigações

| Risco | Probabilidade | Impacto | Mitigação |
|-------|---------------|---------|-----------|
| Regressão no pipeline | Alta | Crítico | Fase 3 em PRs pequenos; smoke test; diff NDJSON |
| Ordem de middleware quebrada | Média | Alto | Documentar ordem em `register-routes.mjs`; teste de integração |
| IDs de módulo quebram UI/playbooks | Média | Alto | `module-ids.mjs` com aliases; período de deprecação |
| CLI para de funcionar | Baixa | Alto | CLI usa HTTP, não importa pipeline — monitorar contrato API |
| GhostMap/GhostTrace proxy | Baixa | Médio | Teste factory com mock HTTP server |
| Refatoração infinita | Média | Médio | Métricas de baseline; Definition of Done por fase |

---

## Definition of Done (por fase)

| Fase | DoD |
|------|-----|
| 0 | CI verde; 1 smoke test |
| 1 | Duplicações CSRF/fetch/proxy eliminadas; `npm test` verde |
| 2 | 0 rotas inline em `index.js`; `register-routes.mjs` documentado |
| 3 | `runPipeline` em `pipeline/`; fases separadas; smoke manual OK |
| 4 | Registry com ≥ 50 módulos; UI usa `/api/capabilities` |
| 5 | `kali-scan.js` split; nenhum módulo > 600 linhas |
| 6 | `db-intel-merge.mjs` único; pg/supabase sem duplicação |
| 7 | `index.html` < 500 linhas; assets em `public/` |
| 8 | Portas sem conflito; docs atualizados |

---

## Cronograma sugerido

| Sprint | Fases | Entregável |
|--------|-------|------------|
| 1 | 0 + 1 | CI + infra compartilhada extraída |
| 2 | 2 | Todas as rotas em `server/routes/` |
| 3-4 | 3 | `runPipeline` desmontado em fases |
| 5 | 4 (lote 1-2) | Registry com ~25 módulos |
| 6 | 5 | `kali-scan.js` dividido |
| 7 | 6 + 7 | DB unificado + cockpit extraído |
| 8 | 4 (lotes 3-6) + 8 | Registry completo + portas + integração |

---

## Checklist rápido para cada PR de refatoração

- [ ] `npm test` passa
- [ ] `npm run test:cli` passa (se tocou em rotas/API)
- [ ] Nenhuma mudança de comportamento não documentada
- [ ] Imports mortos removidos
- [ ] Arquivo novo segue convenção `.mjs` para código novo
- [ ] Se moveu rota: path e método idênticos ao anterior
- [ ] Se moveu fase do pipeline: mesma ordem de execução
- [ ] README ou este doc atualizado se mudou estrutura de pastas

---

## Referências internas

| Documento | Conteúdo |
|-----------|----------|
| [ANALISE-PROJETO.md](./ANALISE-PROJETO.md) | Diagnóstico geral e roadmap de features |
| [docs/MODULE-CONTRACT.md](./docs/MODULE-CONTRACT.md) | Contrato para novos módulos |
| [docs/AUTH-RBAC.md](./docs/AUTH-RBAC.md) | Scopes e limitações de auth |
| [docs/ideias-modulos-futuros.txt](./docs/ideias-modulos-futuros.txt) | Módulos a implementar (pós-refatoração) |
| `server/modules/ghostdesk.mjs` | Padrão canônico `register*Routes` |
| `server/modules/pipeline-stages.mjs` | Ordem de estágios NDJSON |
| `server/modules/module-runner.mjs` | Utilitários de execução (reutilizar) |

---

## Resumo

A refatoração do GHOSTRECON não exige reescrever os 165 módulos de recon. O caminho crítico é:

1. **Extrair** infra, rotas e fases do monólito `server/index.js`
2. **Unificar** duplicações (CSRF, fetch, findings, DB, proxies, IDs)
3. **Expandir** o registry para substituir os 89 `modules.includes`
4. **Dividir** `kali-scan.js` e `ai-dual-report.js`
5. **Desacoplar** o cockpit `index.html` em assets estáticos

Com CI e smoke tests desde a Fase 0, cada etapa é reversível e mensurável contra o baseline deste documento.
