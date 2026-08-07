# Status de finalização do Modo Auto

Atualizado em: 2026-08-07

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
- [ ] Tornar falhas de checkpoint, snapshot, RAG e terminal observáveis e
      fail-closed quando a trilha durável for obrigatória.

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
- [ ] Manter CLI, MCP e smoke de import no gate local.
- [ ] Executar E2E controlado cobrindo todas as autonomias, aprovação, recusa,
      cancelamento em cada estágio, timeout, restart/resume, redirect fora do
      escopo, autenticação, redação e ausência de resíduos.

## P1 — necessário para operação real

- [ ] Exigir engagement/ROE formal para qualquer plano ativo operacional, não
      apenas para módulos classificados como intrusivos.
- [ ] Aplicar timeout, cancelamento, outcome e progresso por módulo.
- [ ] Criar um `runId` Auto único e relatório consolidado de todas as
      iterações, engines, aprovações, outcomes, findings e proveniência.
- [ ] Fazer o catálogo refletir executabilidade real, dependências, binários,
      credenciais necessárias e motivo de indisponibilidade.
- [ ] Exigir binding persistente do principal quando autenticação e retomada
      owner-bound forem habilitadas.
- [ ] Tornar reconciliação de startup aguardada, auditável e configurável pelo
      mesmo ambiente injetado.
- [ ] Adicionar limites de concorrência por principal, sessão e engine.
- [ ] Definir retenção/TTL comum para RAG, snapshots, relatórios, SQLite e
      evidência autenticada.
- [ ] Validar o runtime Forge real em Bubblewrap, permissões do store, escrita
      atômica, timeout e ausência de processo residual.

> O runtime Forge atual já usa Bubblewrap. “Isolar o runtime final do Forge”
> não é pendência vigente; falta provar e endurecer seu comportamento real.

## P2 — paridade e produto

- [ ] Unificar a classificação de risco entre manifests, catálogo, OPSEC, RBAC
      e engagement, com teste exaustivo de paridade.
- [ ] Implementar Tor/proxy estrito para FrameSeven ou bloquear explicitamente
      o engine quando esse perfil for exigido.
- [ ] Listar snapshots retomáveis na API/UI e exibir motivo de bloqueio,
      degradação ou incompatibilidade.
- [ ] Adicionar comando Auto à CLI ou documentar formalmente sua ausência.
- [ ] Definir o fluxo de aprovação do Auto no MCP; hoje a execução interativa
      não possui paridade com o cockpit.
- [ ] Implementar `stop/status` confiáveis para sidecars iniciados pela stack.
- [ ] Remover configurações mortas/enganosas ou implementá-las com testes.
- [ ] Atualizar schemas e documentação depois da estabilização.

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
