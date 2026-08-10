# Status de finalização do Modo Auto

Atualizado em: 2026-08-10

## Finalidade

Este documento registra **somente o que ainda falta** para considerar o Modo
Auto concluído. Histórico de entregas, itens marcados como concluídos e
contagens antigas de testes foram removidos.

Código, schemas e testes continuam sendo a fonte de verdade. O contrato
operacional está em `MODO-AUTO-GHOSTRECON.md` e o backlog executável em
`MELHORIAS-PENDENTES-MODO-AUTO.md`.

## Veredito atual

O Modo Auto permanece **beta supervisionado**. Nenhuma autonomia deve ser
tratada como finalizada:

| Caminho | Estado de liberação |
| --- | --- |
| Testes com fixtures | `npm test` + `test:auto:hermetic` herméticos; CI acoplada; E2E ainda aberto |
| `observation` | somente piloto passivo, em alvo próprio/laboratório e com operador acompanhando |
| `assisted` | somente laboratório controlado; não liberar operacionalmente |
| `authorized` | implementado experimentalmente; não liberado e deve permanecer desabilitado por política |
| `authorized_opsec` | implementado experimentalmente; não liberado e deve permanecer desabilitado por política |
| Vigolium no Auto | não liberado; deve permanecer desabilitado até expansão interna, gates e contenção de escopo |
| FrameSeven ofensivo/autenticado | não liberado; deve permanecer desabilitado até contenção de escopo, cleanup e E2E |
| Provider externo com evidência autenticada | não liberado; deve permanecer desabilitado até consentimento, isolamento, redação e custo verificáveis |
| Writes, credential attempts e `-active-scan` | fora do Auto atual |

O evento `completed` agora exige ausência de falha recuperável na avaliação
(`partial` é terminal distinto). Ainda não comprova cobertura integral de
todos os módulos desejados, persistência consolidada nem limpeza de todos os
recursos.

## P0 — bloqueadores de segurança e correção

### 1. Expandir integralmente o Vigolium antes dos gates

- [x] Expansão fail-closed via `bridge/vigolium-plan-expand.mjs` + fixture
      catalogável; tag/filtro inválido não vira `all`.
- [x] Bloquear write/credential attempts no plano Auto expandido.
- [ ] Incluir no plano/hash cada módulo interno, classe de risco, timeout,
      concorrência e requisito operacional com paridade total do CLI nativo.
- [ ] Instrumentar o wrapper para provar que nenhum módulo não aprovado foi
      carregado, inclusive extensões (requer fonte `vigolium/` / binário).

### 2. Aplicar a mesma política de escopo a toda operação de rede

- [x] Selagem + transporte `GHOSTRECON_SCOPE_POLICY_*` / arquivo 0600 para
      FrameSeven; Vigolium recebe bindings no bridge.
- [x] `scoped-fetch` + redirects manuais nos módulos Node P0 (wellknown,
      panel, SW, jwt-jwks, robots/sitemap).
- [ ] CLI FrameSeven/Vigolium impondo `scopePolicy` nativamente (bloqueado
      sem `vigolium/` / mudança CLI).
- [x] DNS→IP fora do CIDR bloqueado nos módulos Node (discovery + helper
      de escopo); crawler amplo nativo nos engines e URLs restantes ainda
      abertos.
- [x] Falhar fechado quando suporte de escopo do engine não estiver habilitado
      (`GHOSTRECON_ENGINE_SCOPE_SUPPORT`).

### 3. Tornar cancelamento, timeout e falha fatal incontornáveis

- [x] Repropagar `AbortError` no conselho (sem turno `ok:false`); providers
      OpenAI-compatible não mascaram cancel externo como timeout.
- [x] Dispatcher: AbortError/`PROCESS_UNTERMINATED` sem `done`
      (`dispatcher-abort`, `dispatcher-unterminated`); adapters/pipeline
      restantes ainda abertos.
- [x] Impedir fallback determinístico depois de cancelamento no conselho.
- [x] Remover o caminho em que o dispatcher captura erro e ainda emite `done`.
- [x] `assertActive` nas fronteiras principais do orquestrador Auto; cobertura
      E2E de desconexão HTTP ainda aberta.
- [x] Deadline por turno (`combineTurnSignal`) + watchdog ancorado no turno
      mais antigo (`activeAgentTurns` / `getAgentIdleMs`).
- [x] Abort durante review do conselho repropaga sem fallback; `recordUsage`
      tolera `usage: null`.

### 4. Emitir outcomes e terminais verdadeiros

- [x] Derivar `done`, `skipped`, `failed`, `timeout` e `cancelled` da execução
      real de cada módulo registry (`module_outcome`); sem inferência de fase
      para IDs de módulo no Auto.
- [x] Tornar `completed`, `partial`, `failed`, `cancelled`, `timed_out`,
      `stalled` e `budget_exceeded` estados terminais distintos na sessão.
- [x] Nunca converter `evaluation.status=partial` em `completed`.
- [x] Fazer a UI continuar consumindo o stream após `error` recuperável.
- [x] Remover “AUTO COMPLETO” quando o terminal for `partial` (`AUTO PARCIAL`).
- [x] Matriz `moduleOutcomes` → avaliação → terminal (`unterminated`/`fatal`
      → `failed`; timeout/cancelled/failed → `partial`); UI testa estado via
      `autoUiTerminalStatusText`.

### 5. Preservar orçamento e comprovar cleanup

- [x] Persistir um `deadlineAt` absoluto e usar somente o tempo restante após
      restart/resume.
- [x] Preservar na retomada calls/cost/iterações e limits (intersect restritivo).
- [x] Congelar limits na `resumePolicy` hashada; drift de orçamento falha.
- [x] Vincular timeouts pipeline/FrameSeven/settle ao hash (`engineTimeouts`).
- [x] Impedir que a retomada renove tetos via env mais permissivo.
- [x] Persistir aprovação pendente antes da espera do operador
      (`auto-approval-persist`) + trilha `approvalTransitions`.
- [x] FrameSeven await cleanup auth temp antes do resolve/reject
      (`frameseven-cleanup-settle`); residual eleva falha.
- [x] `session.close()` assíncrono aguarda resources antes do terminal.
- [x] Reconciliação de startup aguardada antes do listen + aprovação órfã
      expirada sem reexecução.
- [x] Snapshots particionados por principal/engagement/alvo (legado compatível).
- [x] App Server e process groups Codex Node aguardam exit antes do close;
      browser/workers de engine ainda abertos.
- [ ] Aguardar browser FrameSeven e workers Vigolium antes do terminal.
- [x] Snapshot e terminal já fail-closed (`auto_persist_failed`,
      `AUTO_TERMINAL_PERSIST_FAILED`); RAG agora fail-closed sob
      `GHOSTRECON_AUTO_RAG_REQUIRED=1` via `rag-persist-guard.mjs`
      (`auto_persist_failed` stage `rag_plan`/`rag_evaluation` +
      `AUTO_RAG_PERSIST_FAILED`); default off preserva comportamento.

### 6. Fechar isolamento de dados e comportamento degradado

- [x] Particionar RAG por principal, engagement e alvo
      (`data/auto-rag/tenants/...`); snapshots/artefatos ainda abertos.
- [x] TTL de listagem RAG (`GHOSTRECON_AUTO_RAG_TTL_DAYS`) + prune físico;
      memória expirada não é recuperada.
- [x] APIs `/api/auto-rag/*` isoladas por principal/engagement/alvo.
- [x] Snapshot terminal com falha emite `auto_persist_failed`.
- [x] Exigir `cloudEvidenceConsent` antes de openrouter/cloud receber evidência.
- [ ] Tornar redação, política de dados e contabilização de custo verificáveis
      para todos os providers.
- [x] Quando nenhum provider selecionado estiver utilizável, entrar em estado
      `degraded`/`ask_operator` explícito (`auto_council_degraded`).
- [x] Proibir fallback determinístico silencioso apresentado como decisão das
      IAs selecionadas (baseline só com commanders vazio).

### 7. Renovar a evidência de teste

- [x] Corrigir `pipelineState is not defined` em
      `server/tests/auto-agent.test.js`.
- [x] Binding de principal entre processos estável (`auth-principal-restart`).
- [x] `npm run test:auto:hermetic` + job CI `auto-hermetic` (179 pass local).
- [x] `pipeline-smoke` fora de `npm test`; job `network-smoke` opt-in.
- [x] Startup reconcile await + audit; snapshots particionados; disconnect gate;
      UI poll até terminal; abort pós-pipeline sem heuristic.
- [x] App Server/exec settle fail-closed; persist terminal obrigatória;
      `budgetVerifiable`; redação extra; binding persistente opt-in.
- [x] Gate local consolidado `npm run test:auto:gate`
      (`scripts/run-auto-gate.mjs`): preflight de smoke de import + Auto
      hermético + CLI (`cli-*.test.js`) + MCP (`ghostrecon-mcp.test.js`).
      `test:auto:hermetic` reusa o mesmo runner (`--hermetic-only`).
- [ ] Executar E2E controlado cobrindo todas as autonomias, aprovação, recusa,
      cancelamento em cada estágio, timeout, restart/resume, redirect fora do
      escopo, autenticação, redação e ausência de resíduos.

## P1 — necessário para operação real

- [x] Exigir engagement/ROE formal para planos `active` + `intrusive` (passivo
      puro continua sem formal).
- [x] Pipe legado → `auto_module_outcome` com `source: pipe` no caminho Auto;
      deadline/progresso integral por módulo legado permanece parcial.
- [x] `runId` canônico + relatório consolidado (`reports/auto/{runId}/`,
      `auto_report_ready`).
- [x] Catálogo com `readiness` tipada e `available` derivado.
- [x] Binding persistente do principal já coberto nos testes de restart/owner
      quando habilitado.
- [x] Reconciliação de startup aguardada + prune TTL de artefatos Auto.
- [x] Limites de concorrência por principal/global/engine.
- [x] Retenção/TTL comum para snapshots e `reports/auto` (RAG já tinha TTL).
- [x] Forge store endurecido (path + permissões); Bubblewrap E2E real só
      Linux-gated — não alegado no Windows.

> O runtime Forge atual já usa Bubblewrap. “Isolar o runtime final do Forge”
> não é pendência vigente; falta provar E2E real fora do Windows.

## P2 — paridade e produto

- [x] Paridade de classificação de risco (`risk-classification-parity.test.js`).
- [x] Tor estrito → FrameSeven fail-closed Node; `scopePolicy` inicial no CLI
      Go; SOCKS completo ainda aberto.
- [x] Sessões retomáveis na API/UI + `auto_council_degraded` / relatório na UI.
- [x] Comando `ghostrecon auto` na CLI.
- [x] Tools MCP `ghostrecon_auto_approve` / `ghostrecon_auto_deny`.
- [x] `npm run stack:status` / `stack:stop` via PID file.
- [x] `GHOSTRECON_AUTO_CLOUD_REDACTION` wired; vars de concurrency/TTL/report
      em `.env.example`.
- [x] Docs/backlog atualizados; E2E hermético fixture
      (`auto-e2e-hermetic.test.js`).

## Ainda bloqueado (fora do DoD desta rodada)

- fonte `vigolium/` + enforcement nativo de scope no CLI Vigolium;
- E2E lab com rede/browser real e zero residual físico;
- Bubblewrap E2E no Windows;
- liberação operacional de `authorized` / FS ofensivo autenticado;
- Tor SOCKS completo no FrameSeven.

## Definition of Done

O Modo Auto só pode ser declarado concluído quando todos os itens abaixo forem
verdadeiros:

- [ ] o plano mostrado e hashado é exatamente o executado, incluindo módulos
      internos, engines, limites, escopo e identidades;
- [ ] RBAC, scope, engagement, OPSEC e aprovação passam antes de qualquer
      preparação ou `spawn`;
- [ ] nenhum redirect, subdomínio, IP, crawler ou origem autenticada sai da
      allowlist;
- [ ] cancelamento, timeout e falha fatal impedem qualquer continuação e geram
      o terminal correto;
- [ ] o terminal só é publicado após cleanup e assentamento comprovados;
- [ ] retomada preserva deadline/orçamentos e recusa drift, replay e snapshot
      incompatível;
- [ ] relatório consolidado representa resultado integral, parcial, falhas e
      proveniência real;
- [ ] RAG, snapshots, SQLite, NDJSON e relatórios não vazam segredos nem dados
      entre principals/engagements;
- [ ] providers externos possuem consentimento, redação, política de dados e
      custo verificáveis;
- [ ] regressão hermética, CLI, MCP e smoke de import passam no estado final;
- [ ] E2E controlado repetido deixa zero browser, processo ou temporário
      residual;
- [ ] README, contrato operacional, status e backlog descrevem o código final
      sem garantias aspiracionais.

## Ordem recomendada

1. bloquear temporariamente os caminhos P0 no produto;
2. corrigir expansão interna do Vigolium e contenção de escopo;
3. corrigir propagação de falhas e verdade terminal;
4. corrigir retomada, orçamento e cleanup;
5. isolar dados e comportamento de providers;
6. consolidar relatório, progresso e executabilidade;
7. passar a regressão hermética;
8. executar os E2E controlados;
9. revisar a liberação de cada autonomia separadamente.
