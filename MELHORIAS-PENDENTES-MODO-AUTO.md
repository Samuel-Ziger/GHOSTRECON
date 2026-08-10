# Melhorias pendentes do Modo Auto

Atualizado em: 2026-08-10

Este arquivo é o backlog executável e contém somente trabalho aberto. O estado
de liberação e a Definition of Done estão em
`STATUS-FINALIZACAO-MODO-AUTO.md`; o comportamento operacional atual está em
`MODO-AUTO-GHOSTRECON.md`.

## Regras do backlog

- Um item só pode ser removido depois de código, teste e documentação
  demonstrarem o comportamento.
- Testes de segurança devem cobrir sucesso, negação, timeout, cancelamento,
  restart e ausência de efeitos posteriores.
- Nenhum teste deste backlog autoriza rede externa. Use fixtures, executores
  injetados e laboratório explicitamente autorizado.
- `authorized`, `authorized_opsec`, Vigolium Auto e FrameSeven
  ofensivo/autenticado não estão liberados e devem permanecer desabilitados por
  política enquanto houver P0 aberto.

## P0.1 — plano efetivo completo do Vigolium

### Implementação

- [x] Criar introspecção determinística dos módulos internos do Vigolium antes
      do popup (`bridge/vigolium-plan-expand.mjs` + `listVigoliumModules`).
- [x] Resolver `-m`/tags/`--only` para IDs exatos (fail-closed); expansão de
      fases `--only` internas do CLI ainda depende da fonte `vigolium/` presente.
- [x] Falhar fechado quando a resolução resultar em zero, `all` implícito,
      ambiguidade ou módulo não catalogado.
- [x] Incluir a resolução concreta no plano público e no hash
      (`resolvedModules`, `catalogHash` no runtime plan).
- [x] Aplicar a classificação de maior risco a cada módulo interno.
- [x] Separar capabilities de leitura, escrita, upload, stored payload e
      tentativa de credencial (classes + tags/padrões).
- [x] Bloquear writes e credential attempts no Auto atual.
- [ ] Vincular timeout, concorrência, requisitos e identidade do engine à
      resolução aprovada (parcial: IDs/risco/hash; timeouts por módulo interno
      ainda amplos).

### Evidência exigida

- [x] Fixture sem filtro deve falhar fechado, nunca selecionar `all`.
- [x] Tag inexistente deve falhar fechado.
- [ ] Filtro fuzzy deve exibir todos os IDs concretos antes da aprovação
      (fuzzy ambíguo já falha fechado).
- [x] Upload/credential na fixture Auto são bloqueados antes do spawn.
- [ ] Extensão adicionada depois do hash deve ser recusada.

Arquivos-alvo:

- `server/auto-agent/effective-plan.mjs`;
- `server/auto-agent/orchestrator.mjs`;
- `bridge/vigolium-config.mjs`;
- `bridge/vigolium-runner.mjs`;
- `vigolium/pkg/cli/`;
- `vigolium/internal/runner/`.

## P0.2 — contenção de escopo ponta a ponta

### Implementação

- [x] Definir um formato selado de `scopePolicy` consumível por subprocessos
      (`server/modules/engine-scope-policy.mjs`).
- [x] Transportar hash/JSON (sem binding) via env para FrameSeven/Vigolium no
      Auto; binding permanece no plano GHOSTRECON.
- [x] Impedir execução do engine no Auto quando não declarar suporte
      (`ENGINE_SCOPE_UNSUPPORTED`; lab override
      `GHOSTRECON_ENGINE_SCOPE_SUPPORT=1`).
- [x] Usar redirect manual e validar cada novo destino antes da segunda
      request nos módulos Node P0 (`scoped-fetch.mjs` + wellknown, panel,
      service-worker, jwt-jwks).
- [x] Validar `jwks_uri`/OIDC endpoints, well-known, painel e service worker
      contra `urlInScope`/same-origin antes da rede.
- [x] Sitemap/robots via `scoped-fetch` + filtro de URLs fora do escopo.
- [x] Validar DNS→IP contra allowlist formal nos módulos Node
      (`dnsResolvedAddressesEligibleForProbe` + discovery); subdomínio/crawler
      já passam por `hostInScope`/`scoped-fetch` (CLI engines nativo ainda
      pendente).
- [ ] Repetir os gates depois de qualquer mudança de política ou expansão.
- [x] Transportar política selada ao FrameSeven via env/arquivo 0600
      (`GHOSTRECON_SCOPE_POLICY_*`); Vigolium já recebia bindings.
- [ ] CLI FrameSeven/Vigolium impor a política selada nativamente
      (`supportsSealedScopePolicy` no binário).

### Evidência exigida

- [x] Redirect de alvo permitido para origem externa deve realizar somente a
      primeira request (`scoped-fetch.test.js`).
- [x] `jwks_uri` externo não deve receber request (filtro em jwt-jwks + OIDC).
- [x] IP fora do CIDR bloqueado antes de virar probe
      (`dnsResolvedAddressesEligibleForProbe` + `scope.test.js`); subdomínio
      excluído/`scoped-fetch` já cobertos; crawler amplo nativo nos engines
      ainda aberto.
- [x] Fake FrameSeven recebe política selada via env/arquivo
      (`engine-scope-transport.test.js`); contenção nativa no CLI ainda
      aberta.
- [x] Mudança no engagement depois da aprovação invalida o plano
      (status/checklist e `scopeIps`/`scopeDomains` via binding;
      `AUTO_ENGAGEMENT_CHANGED`).

Arquivos-alvo:

- `server/modules/scope.js`;
- `server/modules/module-registry-runners.mjs`;
- `server/auto-agent/orchestrator.mjs`;
- `server/integrations/frameseven-*.mjs`;
- `bridge/vigolium-*.mjs`;
- módulos que ainda usam redirect automático.

## P0.3 — cancelamento, timeout e falhas fatais

### Implementação

- [x] Repropagar aborts no conselho em vez de convertê-los em turno
      `ok:false` (council-runner + openai-compatible não mascara cancel como timeout).
- [x] Repropagar abort no dispatcher (não emite `done` após AbortError;
      emite `cancelled`/`failed`).
- [x] Não emitir `done` depois de exceção no dispatcher de registry.
- [x] Verificar a sessão (`assertActive`) após providers, conselho, aprovação,
      pipeline e antes do terminal.
- [x] Impedir fallback determinístico e nova iteração depois de cancelamento
      no conselho (AbortError repropagado; sem turno `ok:false`).
- [x] Passar o `AbortSignal` também à detecção de providers.
- [x] Watchdog por turno: `activeAgentTurns` + idle no turno mais antigo;
      deadline por provider via `combineTurnSignal` /
      `AUTO_PROVIDER_TURN_TIMEOUT` (council-runner).
- [x] Limpar `currentStage` ao final de step/turno/close.

### Evidência exigida

- [x] Cancelamento durante proposal do conselho termina com AbortError
      repropagado, sem turno `ok:false` (teste em auto-planner-contract).
- [x] Cancelamento durante review repropaga AbortError sem fallback
      (`auto-planner-contract`).
- [x] Abort no conselho pós-pipeline sem `heuristic_evaluation`
      (`auto-post-pipeline-council-abort`).
- [x] Timeout isolado por turno de provider (`auto-provider-turn-timeout`;
      stall paralelo em `auto-agent-turn-stall`).
- [x] Módulo registry com `PROCESS_UNTERMINATED` não emite `done`
      (`dispatcher-unterminated`); AbortError/timeout do dispatcher já cobertos.
- [x] Desconexão HTTP: `captureEmit`/NDJSON gate pós-abort; teste
      `auto-http-disconnect` (efeito residual de engines externos ainda aberto).
- [x] Provider que ignora abort: App Server `close` await exit
      (`CODEX_APP_SERVER_UNTERMINATED`); `execFileClosedStdin` →
      `PROCESS_UNTERMINATED`; `session.close` fail-closed em cleanup.

Arquivos-alvo:

- `server/auto-agent/council/council-runner.mjs`;
- `server/auto-agent/orchestrator.mjs`;
- `server/auto-agent/session-store.mjs`;
- `server/auto-agent/provider-detector.mjs`;
- `server/pipeline/dispatcher.mjs`.

## P0.4 — terminal, outcomes e UI

### Implementação

- [x] Definir terminal de sessão com `completed`, `partial`, `failed`,
      `cancelled`, `timed_out`, `stalled` e `budget_exceeded`
      (`partial` em AUTO_SESSION_STATUSES).
- [x] Propagar `evaluation.status` ao terminal da sessão
      (`sessionTerminalFromEvaluation` no orquestrador).
- [x] Emitir outcome por módulo com base no runner real
      (`module_outcome` no dispatcher registry; timeout ≠ cancelled).
- [x] Remover inferência de fase para IDs de módulo no collect
      (`module_outcome`/`pipe` primeiro; `evaluateAutoRun` usa moduleOutcomes).
- [x] Fazer a UI continuar lendo após `error` com `recoverable:true`.
- [x] UI: `waitForAutoSessionTerminal` + `markAutoAwaitingTerminal`; cancel
      permanece até snapshot confirmar fase terminal.
- [x] Exibir falhas parciais na UI (`AUTO PARCIAL` vs `AUTO COMPLETO`).

### Evidência exigida

- [x] Falha recuperável de fase seguida de conclusão termina como `partial`
      (auto-agent.test.js + auto_session.phase).
- [x] Falha na avaliação nunca vira `completed`
      (`sessionTerminalFromEvaluation` + auto-persist-failed.test.js).
- [x] Erro recuperável não interrompe o leitor NDJSON do cockpit
      (contrato em ui-consent-contract.test.js).
- [x] Cada terminal deve corresponder à matriz de outcomes dos módulos
      (`classifyModuleOutcomeStatus` + teste de matriz em auto-agent.test.js).
- [x] Teste de UI executa o mapeamento de estado (`autoUiTerminalStatusText`
      via Function no ui-consent-contract.test.js), não só regex de rótulo.

Arquivos-alvo:

- `server/auto-agent/planner.mjs`;
- `server/auto-agent/orchestrator.mjs`;
- `server/pipeline/dispatcher.mjs`;
- `public/index.html`.

## P0.5 — retomada, orçamento e cleanup

### Implementação

- [x] Persistir `deadlineAt` absoluto na sessão (retomada usa saldo restante).
- [x] Preservar saldo de chamadas, custo e iterações na retomada
      (`assertActive` via `deadlineAt`; limits intersectados com env).
- [x] Incluir limits de sessão (calls/cost/timeouts/iterações) na
      `resumePolicy` hashada; drift falha fechado.
- [x] Incluir timeouts pipeline/FrameSeven/settle na `engineTimeouts` da policy.
- [x] Recusar renovação silenciosa de limits (intersect mais restritivo;
      counters do snapshot preservados).
- [x] Persistir aprovação pendente antes de aguardar o operador
      (snapshot antes do NDJSON `auto_approval_required`).
- [x] Tornar `session.close()` assíncrono e aguardar resources
      (`auto-session-close.test.js`).
- [x] Exit/close comprovado para App Server e filhos Codex exec (Node);
      browser/FrameSeven/Vigolium workers ainda abertos.
- [x] Falha de snapshot terminal emite `auto_persist_failed` (não engole
      silenciosamente no catch).
- [x] Reconciliação de startup aguardada antes do listen
      (`prepareAutoReconStartup` / `runAutoStartupReconciliation`) + audit.

### Evidência exigida

- [x] Retomada próxima do deadline deve receber apenas o saldo restante
      (`auto-resume-budgets.test.js`).
- [x] Restart não pode renovar orçamento de calls/cost/limits.
- [x] Crash com aprovação pendente: reconcile → `interrupted` + approval
      `expired` (`auto-startup-reconcile`); sem reexecução.
- [x] Terminal de sucesso exige cleanup sem erro + snapshot terminal
      (`persistTerminalSession`); browser/temps de engine ainda abertos.
- [x] Falha de persistência obrigatória impede `completed`
      (`auto-terminal-persist`).

Arquivos-alvo:

- `server/auto-agent/session-store.mjs`;
- `server/auto-agent/orchestrator.mjs`;
- `server/auto-agent/providers/codex-app-server.mjs`;
- `server/routes/auto-recon.mjs`.

## P0.6 — isolamento de dados e providers

### Implementação

- [x] Particionar RAG por principal, engagement e alvo
      (`data/auto-rag/tenants/...`; `GHOSTRECON_AUTO_RAG_PARTITION`).
- [x] Aplicar o mesmo isolamento às APIs `/api/auto-rag/status|search|note`
      (principal obrigatório; partição por engagement/alvo).
- [x] Snapshots particionados em `tenants/p-…/e-…/t-…/sessions/{id}`
      (`GHOSTRECON_AUTO_SESSION_PARTITION`; legado `sessions/` compatível).
- [x] Definir TTL de listagem RAG (`GHOSTRECON_AUTO_RAG_TTL_DAYS`, default 30).
- [x] Prune físico `pruneExpiredAutoRagMarkdown`; leitura/listagem/contexto
      falham fechado para memória expirada.
- [x] Exigir confirmação explícita para provider cloud
      (`cloudEvidenceConsent` + `assertCloudEvidenceConsent`; openrouter
      `dataPlane:cloud`).
- [x] Política de redação configurável `GHOSTRECON_AUTO_REDACT_EXTRA`
      consumida em `redactAutoText` + anunciada no `auto_session.started`.
- [x] Orçamento: `budgetVerifiable=false` quando usage sem `cost` reportado.
- [x] Substituir fallback silencioso por estado `degraded`/`ask_operator`
      quando commanders foram selecionados e o conselho não decide
      (`auto_council_degraded`; baseline só com commanders vazio).
- [x] Binding persistente exigível via
      `GHOSTRECON_AUTO_REQUIRE_PERSISTENT_BINDING=1`.

### Evidência exigida

- [x] Principal A não pode pesquisar ou carregar memória do principal B
      (`auto-rag-partition-routes.test.js`).
- [x] Engagement/alvo entram na chave de partição das APIs RAG.
- [x] Memória expirada não é listada/lida/carregada (`auto-rag-ttl.test.js`).
- [x] Provider selecionado indisponível não inicia pipeline fingindo decisão
      de IA (teste degradado em auto-agent.test.js).
- [x] Prompt cloud sem consentimento falha fechado / redige evidência
      (`auto-cloud-consent.test.js`); registro de versão de política ainda
      aberto.

Arquivos-alvo:

- `server/auto-agent/rag-memory.mjs`;
- `server/auto-agent/providers/`;
- `server/auto-agent/provider-detector.mjs`;
- `server/auto-agent/planner.mjs`;
- `server/modules/auth.js`;
- `server/routes/auto-recon.mjs`.

## P0.7 — regressão e E2E

- [x] Corrigir a referência inexistente `pipelineState` em
      `server/tests/auto-agent.test.js`.
- [x] `auth-principal-restart.test.js` estável no Node 22 (incluso no hermético).
- [x] Criar `npm run test:auto:hermetic` (Auto A–G + module-runner /
      process-cancellation; sem `pipeline-smoke`/rede).
- [x] Gate hermético verde localmente (Windows + Node 22; 179 pass / 0 fail).
- [x] CI: job `auto-hermetic` + `npm test` hermético via
      `scripts/run-server-tests.mjs`.
- [x] Smoke `example.com` em `npm run test:network` / job opt-in
      (`workflow_dispatch`).
- [ ] Executar E2E controlado de `observation`.
- [ ] Executar `assisted` aprovado e recusado.
- [ ] Exercitar todos os pontos de cancelamento e timeout.
- [ ] Exercitar restart/resume perto do deadline.
- [ ] Exercitar redirect, subdomínio e IP fora da allowlist.
- [ ] Exercitar contexto autenticado single-use e cleanup.
- [ ] Inspecionar NDJSON, RAG, snapshot, SQLite e relatórios.
- [ ] Confirmar zero processo, browser e temporário residual.

## P1 — operação real

- [x] Exigir engagement/ROE para qualquer plano ativo (`active` + `intrusive`).
- [x] Mapear pipe terminal legado → `auto_module_outcome` (`source: pipe`) no
      caminho Auto; migração integral de deadline/progresso por módulo legado
      permanece parcial fora do registry.
- [x] Criar `runId` e relatório Auto consolidado (`reports/auto/{runId}/`,
      evento `auto_report_ready`, rota dedicada).
- [x] Informar readiness real por item do catálogo (`readiness.{ok,reason,checks}`).
- [x] Aplicar limites de concorrência por principal/global/engine
      (`GHOSTRECON_AUTO_MAX_SESSIONS_*`, código `AUTO_CONCURRENCY_LIMIT`).
- [x] Definir retenção comum para artefatos Auto
      (`GHOSTRECON_AUTO_ARTIFACT_TTL_DAYS` + prune no startup).
- [x] Persistir trilha `approvalTransitions` na sessão/snapshot (auditoria
      formal de evento ainda pode evoluir).
- [x] Endurecer Forge store (0700/0600 + path containment); Bubblewrap E2E
      real permanece Linux-only / não alegado no Windows.

## P2 — paridade e operação do produto

- [x] Unificar a classificação de risco e adicionar teste de paridade.
- [x] Tor/proxy estrito → FrameSeven fail-closed Node (`FRAMESEVEN_TOR_UNSUPPORTED`);
      enforcement inicial de `scopePolicy` no CLI Go; SOCKS completo ainda
      não implementado (documentado).
- [x] Listagem/seleção de sessões retomáveis na UI (`?resumable=1`).
- [x] Expor claramente fallback/degradado (`auto_council_degraded` na UI).
- [x] Comando `ghostrecon auto` na CLI.
- [x] Aprovação interativa Auto no MCP (`ghostrecon_auto_approve` /
      `ghostrecon_auto_deny`; `run_auto` default deny).
- [x] `stack:status` / `stack:stop` via `.runtime/stack-pids.json`.
- [x] Auditar/wire `GHOSTRECON_AUTO_*` mortas (`CLOUD_REDACTION` ligada;
      concurrency/TTL/report documentadas em `.env.example`).

## Bloqueados (não marcar como feito)

| Item | Motivo |
| --- | --- |
| CLI Vigolium impondo `scopePolicy` nativo | sem fonte `vigolium/` |
| E2E lab com rede / browser real / zero residual físico | precisa alvo + autorização |
| Bubblewrap E2E no Windows | plataforma |
| Liberação operacional `authorized` | política de produto |
| Tor SOCKS completo no FrameSeven | só fail-closed + scopePolicy inicial |

## Matriz de regressões que ainda faltam

| Cenário | Evidência esperada |
| --- | --- |
| `vigolium_dast` sem filtro | bloqueio antes do popup; nunca `all` |
| filtro/tag Vigolium inválido | falha fechada |
| módulo interno de escrita/credencial | ausente do plano e zero execução |
| redirect/JWKS fora do escopo | nenhuma segunda request |
| engine sem suporte à `scopePolicy` | bloqueado antes do spawn |
| cancelamento durante conselho | terminal `cancelled`, zero fallback |
| erro fatal no dispatcher | `failed`, nunca `done` |
| erro recuperável | stream continua e terminal `partial` |
| resume perto do deadline | somente saldo restante |
| crash com aprovação pendente | reconciliação sem execução |
| principal/engagement diferente | RAG e snapshot invisíveis |
| provider selecionado indisponível | erro/degradação explícita |
| finalização | relatório consolidado e zero resíduos |

## Checks locais pendentes

O gate final deve incluir:

```bash
node --check server/routes/auto-recon.mjs
node --check server/auto-agent/orchestrator.mjs
node --check server/auto-agent/effective-plan.mjs
node --check server/auto-agent/session-store.mjs

node --test server/tests/auto-agent.test.js
node --test server/tests/auto-effective-plan.test.js
node --test server/tests/auto-session-security.test.js
node --test server/tests/auto-resume-checkpoint.test.js
node --test server/tests/auto-strict-phase-gates.test.js
node --test server/tests/auto-content-network-gates.test.js
node --test server/tests/auto-event-redaction.test.js
node --test server/tests/auto-rag-runtime-security.test.js
node --test server/tests/pipeline-resilience.test.js
node --test server/tests/process-cancellation.test.js
node --test server/tests/frameseven-integration.test.js
node --test server/tests/vigolium-bridge.test.js
node --test server/tests/vigolium-agent.test.js
node --test server/tests/auth.test.js
node --test server/tests/auth-principal-restart.test.js
node --test server/tests/opsec.test.js
node --test server/tests/scope.test.js
node --test server/tests/engagement.test.js

GHOSTRECON_NO_HTTP_LISTEN=1 node -e "import('./server/index.js')"
npm run test:cli
npm run test:mcp
```

O smoke com rede e o E2E autenticado permanecem separados e exigem alvo de
laboratório autorizado.
