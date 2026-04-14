# Plano de Integracao de IAs Locais no GHOSTRECON

## Objetivo

Elevar o nivel tecnico do pipeline adicionando duas IAs locais:

1. **Shannon (white-box)**: analisa codigo-fonte de repositorios encontrados durante o recon e (no produto original) valida dinamicamente contra a aplicacao em execucao.
2. **PentestGPT (validacao pos-recon)**: revisa achados finais para aumentar precisao e reduzir ruido.

**Estado do documento:** a maior parte do fluxo Shannon + PentestGPT esta **implementada**; restam melhorias opcionais (TTL workspaces Shannon, testes extra, refinamento do contrato HTTP PentestGPT). A secao [Estado actual da implementacao](#estado-actual-da-implementacao-no-ghostrecon) resume o codigo actual.

**Congelamento para testes:** o codigo Shannon upstream **nao** vai no Git do GHOSTRECON (`IAs/shannon/` no `.gitignore`); clona o Keygraph Shannon em `IAs/shannon/` conforme `IAs/README.md`, depois corre recon com modulo `shannon_whitebox` e clone activo.

---

## Estado actual da implementacao no GHOSTRECON

### Fase 1 — GitHub + clone (feito)

- `server/modules/github.js`: `githubCodeSearch` + `githubRepoSearch` (repos candidatos).
- `server/modules/github-clone.js`: clone para `clone/`, limites, retencao **30 dias** (`GHOSTRECON_CLONE_RETENTION_DAYS`), limpeza ao iniciar clone.
- `server/index.js`: fase GitHub integra clone e emite findings `intel` com path local.
- Raiz: pasta `clone/` no `.gitignore`.

### Shannon — dependencias, UI e runner (feito)

- **`server/modules/shannon-capabilities.js`**: `getShannonCapabilities()` (Docker, pasta Shannon, `./shannon`, `apps/cli/dist/index.mjs`, imagem `shannon-worker`); `shannonPullUpstreamWorkerImage()` com captura de **stdout/stderr** do `docker pull`.
- **`GET /api/capabilities`**: inclui objeto `shannon: { ok, home, checks, message, prepHints }`.
- **`POST /api/shannon/prep`** (CSRF): corpo `{ "pullUpstream": true }` executa `docker pull keygraph/shannon:latest`; resposta inclui `dockerPullLog` (texto completo) + `shannon` actualizado apos pull; em erro HTTP 500 tambem pode vir `dockerPullLog`.
- **`POST /api/recon/stream`**: se `modules` contiver `shannon_whitebox` e `shannonPrecheck !== false` e **nao** `shannonSkipDepsVerify`, o servidor **recusa** o recon com NDJSON `error` se as dependencias Shannon falharem.
- **`server/modules/shannon-runner.js`**: fila global; `spawn` `node …/shannon start -u … -r … -w …`; poll de `workflow.log` (`Workflow COMPLETED|FAILED`); leitura de `comprehensive_security_assessment_report.md` com retries; findings `intel`; `GHOSTRECON_SHANNON_AUTO_RUN=0` desliga execucao automatica.
- **`server/index.js`**: apos fase `secrets` e clones GitHub, chama `runShannonOnClone` quando o modulo esta activo e `GHOSTRECON_SHANNON_AUTO_RUN` nao desactiva o runner.
- **`index.html`**: grupo Shannon + no **pipeline bar** no `pipe-shannon`; checkboxes e `shannonPrecheck` / `shannonSkipDepsVerify` no body do stream; textarea **Repos GitHub (manual)** → campo `shannonGithubRepos` (URLs ou `owner/repo`, varias linhas).
- **`server/tests/shannon-runner.test.js`**: testes de paths e `waitForShannonWorkflowEnd`.
- **`.gitignore`**: `IAs/shannon/workspaces/`, `IAs/shannon/credentials/`.
- **`.env.example`**: `GHOSTRECON_SHANNON_*` (home, timeouts, max clones, report max chars, pipeline testing, auto run).

### PentestGPT — validacao HTTP pos-recon (feito)

- **`server/modules/pentestgpt-local.js`**: `runPentestGptValidation(payload)` — POST JSON para `GHOSTRECON_PENTESTGPT_URL` com `ghostPayload` (mesmo shape que export IA); interpreta `summary`, `validatedFindings`, `falsePositives` de forma tolerante.
- **`server/index.js`**: se `modules` incluir `pentestgpt_validate`, apos `pipe('score','done')` corre validacao, injecta findings e actualiza `stats.high`; evento `pipe('pentestgpt', …)`.
- **`index.html`**: modulo `pentestgpt_validate` e no `pipe-pentestgpt`.
- **`server/modules/webhook-notify.js`**: Discord inclui linhas opcionais **Shannon** e **PentestGPT** quando ha resumo; JSON generico inclui `shannonSummary` / `pentestgptSummary` no payload.

### O que falta (opcional / hardening)

1. **Workspaces Shannon**: politica de retencao / prune alinhada ao clone (30 dias) se acumularem em disco.
2. **PentestGPT**: documentar ou codificar um **schema** fixo do teu servico HTTP (o Ghost aceita JSON flexivel).
3. **Testes**: mais cobertura em `pentestgpt-local` (mock fetch) e integracao e2e opcional.

---

## Shannon no repositorio (`IAs/shannon/`)

O codigo em `IAs/shannon/` corresponde ao **Shannon Lite** (Keygraph, AGPL-3.0): pentest autonomo **white-box** que combina analise de codigo com pipeline orquestrado por **Temporal**, worker em **Docker** e uso de **Claude** (SDK / API).

### Arquitetura relevante para integracao

| Componente | Papel |
|------------|--------|
| **CLI** (`apps/cli/`, entry `./shannon` ou `npx @keygraph/shannon`) | Sobe infra Docker (Temporal + opcional router), dispara worker efemero por scan, cria workspace. |
| **Worker** (`apps/worker/`) | Pipeline em fases: pre-recon, recon, analise de vulnerabilidades (agentes paralelos), exploracao, relatorio. |
| **Workspaces** | Estado por execucao: logs, `session.json`, diretorios de auditoria; em **modo local** ficam em `IAs/shannon/workspaces/<nome>/`. |
| **Deliverables no repo alvo** | Relatorios e evidencias sob `<repo>/.shannon/deliverables/` (ex.: `comprehensive_security_assessment_report.md` montado a partir dos MD por categoria). |

### Modos de execucao

- **Modo local** (recomendado para integrar com GHOSTRECON no mesmo disco): `SHANNON_LOCAL=1` (definido pelo `./shannon` em clone local), `pnpm install` + `pnpm build`, imagem `shannon-worker`, workspaces em `./workspaces/` **relativo ao root do Shannon** (`IAs/shannon/workspaces/`).
- **Modo npx**: imagem `keygraph/shannon` do Docker Hub, estado em `~/.shannon/workspaces/`.

Para o Ghost, o caminho mais previsivel e **invocar o CLI no clone local** `IAs/shannon/` com `cwd` = `IAs/shannon` e `-r` apontando para o caminho absoluto do clone feito pelo Ghost em `clone/`.

### Comando minimo (contrato real)

```text
# A partir do diretorio IAs/shannon (apos build + credenciais):
./shannon start -u <URL_ALVO> -r <CAMINHO_ABSOLUTO_DO_CLONE>

# Workspace nomeado (recomendado para correlacao Ghost <-> Shannon):
./shannon start -u <URL_ALVO> -r <CAMINHO_ABSOLUTO_DO_CLONE> -w ghostrecon-<dominio>-<runId>-<repoSlug>

# Opcoes uteis:
#   -c <config.yaml>     — auth, MFA/TOTP, parametros por app (schemas em apps/worker/configs/)
#   -o <dir>             — saida adicional de relatorios (README Shannon)
#   --pipeline-testing   — prompts minimos / iteracao rapida (README + CLAUDE.md)
```

**URL (`-u`)**: deve ser a base da aplicacao a testar (ex.: `https://example.com`). O Ghost deve derivar isso do alvo do recon (apex HTTPS preferido) ou permitir override por env/config — **nao** confundir com URL do repositorio GitHub.

**Repositorio (`-r`)**: path absoluto da pasta clonada pelo Ghost (`clone/<dominio>__owner_repo__<timestamp>/`).

### Monitoramento de progresso (substitui “API REST generica”)

Nao ha um unico `POST /v1/chat/completions` para o Shannon; o fluxo oficial e:

1. **`workflow.log`** em `IAs/shannon/workspaces/<workspace>/workflow.log` — append-only; o comando `./shannon logs <workspace>` faz tail e detecta fim quando aparece linha `Workflow COMPLETED` ou `Workflow FAILED` (regex em `apps/cli/src/commands/logs.ts`).
2. **Temporal Web UI** em `http://localhost:8233` (workflow ID tambem e impresso apos o start).

**Integracao Ghost (implementada)**: o `shannon-runner` faz **polling** de `workflow.log` no workspace; o processo `shannon start` pode terminar cedo apos arrancar o worker — o fim do trabalho e determinado pelo log, nao pelo exit do processo filho.

### Onde esta o relatorio final (para webhook / IA downstream)

Definido em `apps/worker/src/services/reporting.ts` e `apps/worker/src/paths.ts`:

- Diretorio de entregas no **repositorio montado**: `<clonePath>/.shannon/deliverables/`
- Relatorio consolidado: **`comprehensive_security_assessment_report.md`**
- Evidencias por dominio (quando existirem): `injection_exploitation_evidence.md`, `xss_exploitation_evidence.md`, `auth_exploitation_evidence.md`, `ssrf_exploitation_evidence.md`, `authz_exploitation_evidence.md`

O Ghost deve, apos `COMPLETED`, ler esse Markdown (e opcionalmente os parciais), mapear para `finding`/`intel` ou anexar ao payload de IA/webhook.

### Pre-requisitos operacionais (Shannon)

- **Docker** obrigatorio (infra Temporal + worker por scan).
- **Node.js 18+**; no clone local, **pnpm** + `pnpm build` (ou fluxo npx com imagem pre-buildada).
- **Imagem local**: `shannon-worker` apos `./shannon build` em `IAs/shannon` (o `docker pull keygraph/shannon:latest` via Ghost ajuda sobretudo o fluxo **npx**, nao substitui o build local).
- **Credencial de IA** (tipico: `ANTHROPIC_API_KEY` no `.env` dentro de `IAs/shannon/` ou env exportado no processo filho).
- Em Linux: permissao ao Docker; possivel necessidade de `host.docker.internal` se o alvo for `localhost` (documentado no Shannon).

### Riscos e decisoes de desenho

- **Dois roots de disco**: clone do alvo em `GHOSTRECON/clone/` vs workspace Shannon em `IAs/shannon/workspaces/` — ambos precisam de TTL/retencao alinhada (ja ha 30 dias no clone; replicar politica para workspaces Shannon se acumularem).
- **Duracao longa**: pentest completo pode exceder timeout de um request HTTP do Ghost; integracao deve ser **assincrona** (subprocess + polling de log ou job em fila), nao bloquear indefinidamente o stream sem configuracao.
- **Concorrencia**: varios `shannon start` disputam Docker/Temporal; limitar 1 scan Shannon por vez por host ou por `runId`.
- **Escopo legal**: Shannon executa recon dinamico e exploits — so ativar com programa/autorizacao explicitos (mesma regra do modo Kali do Ghost).

---

## Fluxo proposto (alto nivel) — actual

1. O Ghost executa recon normal.
2. Quando houver sinal em GitHub, identifica repos e clona para `clone/`.
3. Com modulo `shannon_whitebox` e `GHOSTRECON_SHANNON_AUTO_RUN` activo: apos `secrets`, **Shannon** corre por clone (fila serial), poll de `workflow.log`, leitura do relatorio em `.shannon/deliverables/`, findings na stream.
4. (**Feito — gate**) Pre-recon: capabilities + opcional bloqueio se deps Shannon falharem; UI com `docker pull` e log.
5. Apos priorizacao (`score`), se modulo **`pentestgpt_validate`**: POST para URL configurada com payload consolidado; findings / resumo na stream e no webhook.
6. Gravacao do run, webhook Discord (resumo + Shannon/PentestGPT quando aplicavel), IA opcional.

---

## Onde esta o codigo (referencia)

- `server/index.js` — pipeline, Shannon gate, `runShannonOnClone`, PentestGPT pos-`score`, webhook.
- `server/modules/shannon-capabilities.js`, `shannon-runner.js`, `pentestgpt-local.js`
- `server/modules/github.js`, `github-clone.js`, `webhook-notify.js`, `ai-dual-report.js`
- `index.html` — modulos, pipeline bar, pre-check Shannon
- `IAs/shannon/` — Shannon Lite (upstream)

---

## Requisitos tecnicos obrigatorios

### 1) Armazenamento local de clones

- Pasta `clone/` + `.gitignore` + retencao e limites (**feito**).

### 2) Shannon: codigo + workspaces

- Manter `IAs/shannon/` buildavel.
- **Feito:** `.gitignore` em `IAs/shannon/workspaces/` e `IAs/shannon/credentials/`.

### 3) Execucao de processos

- `git` + **Docker** + timeouts Shannon (runner).

### 4) Contrato Ghost <-> Shannon (CLI + ficheiros)

| Parametro Shannon | Origem no Ghost |
|-------------------|-----------------|
| `-u` | `https://{domain}/` ou URL viva preferida do probe |
| `-r` | path absoluto do clone |
| `-w` | `ghostrecon-{domain}-{runId}-{repoSlug}` |
| `-c` | opcional: `GHOSTRECON_SHANNON_CONFIG_PATH` |

| Artefato | Caminho |
|----------|---------|
| Log de orquestracao | `IAs/shannon/workspaces/<w>/workflow.log` |
| Relatorio final | `<clonePath>/.shannon/deliverables/comprehensive_security_assessment_report.md` |

---

## UI e API (Shannon + PentestGPT)

| Elemento | Descricao |
|----------|-----------|
| Modulo `shannon_whitebox` | Incluido em `modules[]`; no `pipeline-bar`, no `pipe-shannon`. |
| `shannonPrecheck` / `shannonSkipDepsVerify` | Corpo do `POST /api/recon/stream`. |
| `GET /api/capabilities` → `shannon` | Estado Docker / build / imagem. |
| `POST /api/shannon/prep` | `{ pullUpstream: true }` + `dockerPullLog`. |
| Modulo `pentestgpt_validate` | Pos-`score`; requer `GHOSTRECON_PENTESTGPT_URL`; `pipe-pentestgpt`. |

**Opcional na UI:** link directo Temporal (`8233`), estado detalhado “a correr” além do `pipe` NDJSON.

---

## MCP Hexstrike vs PentestGPT

Recomendacao: PentestGPT primeiro; Hexstrike como segunda opiniao opcional.

---

## Plano de implementacao por fases

### Fase 1 — GitHub + clone

**Feito.**

### Fase 2 — Shannon

| Sub-fase | Estado |
|----------|--------|
| 2a Dependencias (capabilities, UI, gate no stream, prep + log pull) | **Feito** |
| 2b Runner (`shannon-runner.js`, workflow, deliverables → findings) | **Feito** |
| 2c Webhook com resumo Shannon (+ PentestGPT no Discord) | **Feito** (resumo textual; payload JSON completo inclui campos extra) |

### Fase 3 — PentestGPT

**Feito** (`pentestgpt-local.js`, modulo UI, integracao pos-`score`, envs).

### Fase 4 — Persistencia e hardening

**Parcial**: fila Shannon global e testes do runner existem; **opcional**: TTL workspaces, mais testes PentestGPT, mutex documentado por host.

---

## Checklist objetivo

- [x] Pasta `clone/` + gitignore + limite/retencao (Fase 1).
- [x] Forma real de execucao Shannon documentada (CLI + Docker + Temporal).
- [x] `getShannonCapabilities` + `GHOSTRECON_SHANNON_HOME` em `.env.example`.
- [x] UI modulo `shannon_whitebox` + pre-check + omitir verificacao + log `dockerPullLog`.
- [x] `POST /api/shannon/prep` + CSRF.
- [x] `.gitignore`: `IAs/shannon/workspaces/`, `IAs/shannon/credentials/`.
- [x] `server/modules/shannon-runner.js` + testes basicos.
- [x] PentestGPT: modulo + POST + findings + webhook Discord.
- [ ] Opcional: TTL workspaces Shannon; testes mock `pentestgpt-local`; schema HTTP documentado lado servidor receptor.

---

## Variaveis de ambiente (revisao)

**Clone**

- `GHOSTRECON_GITHUB_CLONE_ENABLED`, `GHOSTRECON_CLONE_DIR`, `GHOSTRECON_CLONE_MAX_REPOS`, `GHOSTRECON_CLONE_MAX_SIZE_MB`, `GHOSTRECON_CLONE_TIMEOUT_MS`, `GHOSTRECON_CLONE_RETENTION_DAYS`

**Shannon (diagnostico + runner)**

- `GHOSTRECON_SHANNON_HOME`, `GHOSTRECON_SHANNON_AUTO_RUN`, `GHOSTRECON_SHANNON_MAX_CLONES_PER_RUN`, `GHOSTRECON_SHANNON_START_TIMEOUT_MS`, `GHOSTRECON_SHANNON_WORKFLOW_TIMEOUT_MS`, `GHOSTRECON_SHANNON_PIPELINE_TESTING`, `GHOSTRECON_SHANNON_REPORT_MAX_CHARS`, etc. (ver `.env.example`).

**PentestGPT**

- `GHOSTRECON_PENTESTGPT_URL` — URL completa do POST (obrigatorio para correr).
- `GHOSTRECON_PENTESTGPT_ENABLED` — default activo; `0` desliga.
- `GHOSTRECON_PENTESTGPT_TIMEOUT_MS` — default 120000 (max 600000).

**Credenciais Shannon**

- Preferencia: `IAs/shannon/.env` com `ANTHROPIC_API_KEY` ou env no processo do `spawn`.

---

## Resultado esperado

- **Shannon**: gate + prep + UI + **runner** com poll de `workflow.log` e ingestao do relatorio em `.shannon/deliverables/`.
- **PentestGPT**: camada final via **HTTP configuravel**; o operador expoe um endpoint que consome `ghostPayload` e devolve JSON interpretado pelo Ghost.
