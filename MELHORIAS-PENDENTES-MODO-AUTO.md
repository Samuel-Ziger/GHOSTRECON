# Melhorias pendentes do Modo Auto

Atualizado em: 2026-07-30

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

- [ ] Criar introspecção determinística dos módulos internos do Vigolium antes
      do popup.
- [ ] Resolver estratégia, `-m` e tags para IDs exatos; expandir `--only` para
      as fases/capabilities concretas e resolver também as extensões.
- [ ] Falhar fechado quando a resolução resultar em zero, `all` implícito,
      ambiguidade ou módulo não catalogado.
- [ ] Incluir a resolução concreta no plano público e no hash.
- [ ] Aplicar a classificação de maior risco a cada módulo interno.
- [ ] Separar capabilities de leitura, escrita, upload, stored payload e
      tentativa de credencial.
- [ ] Bloquear writes e credential attempts no Auto atual.
- [ ] Vincular timeout, concorrência, requisitos e identidade do engine à
      resolução aprovada.

### Evidência exigida

- [ ] Fixture sem filtro deve falhar fechado, nunca selecionar `all`.
- [ ] Tag inexistente deve falhar fechado.
- [ ] Filtro fuzzy deve exibir todos os IDs concretos antes da aprovação.
- [ ] Upload, stored XSS, verbos mutáveis e tentativas de login devem produzir
      zero chamadas sob `vigolium_dast` genérico.
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

- [ ] Definir um formato selado de `scopePolicy` consumível por subprocessos.
- [ ] Transportar domínios, wildcards, IPs, CIDRs, exclusões e binding do
      engagement para FrameSeven e Vigolium.
- [ ] Impedir execução do engine quando ele não conseguir impor a política.
- [ ] Usar redirect manual e validar cada novo destino antes da segunda
      request.
- [ ] Validar `jwks_uri`, endpoints OIDC, sitemap, service worker, well-known,
      painel e qualquer URL descoberta.
- [ ] Validar DNS→IP e cada subdomínio/crawler contra a allowlist formal.
- [ ] Repetir os gates depois de qualquer mudança de política ou expansão.

### Evidência exigida

- [ ] Redirect de alvo permitido para origem externa deve realizar somente a
      primeira request.
- [ ] `jwks_uri` externo não deve receber request.
- [ ] Subdomínio excluído, IP fora do CIDR e crawler fora da allowlist devem
      ser bloqueados antes da rede.
- [ ] Fake FrameSeven/Vigolium deve receber a política selada e provar a
      contenção.
- [ ] Mudança no engagement depois da aprovação deve invalidar o plano.

Arquivos-alvo:

- `server/modules/scope.js`;
- `server/modules/module-registry-runners.mjs`;
- `server/auto-agent/orchestrator.mjs`;
- `server/integrations/frameseven-*.mjs`;
- `bridge/vigolium-*.mjs`;
- módulos que ainda usam redirect automático.

## P0.3 — cancelamento, timeout e falhas fatais

### Implementação

- [ ] Repropagar aborts no conselho em vez de convertê-los em turno
      `ok:false`.
- [ ] Repropagar abort, timeout e `PROCESS_UNTERMINATED` no dispatcher.
- [ ] Não emitir `done` depois de exceção.
- [ ] Verificar a sessão depois de proposal, review, arbitragem, avaliação,
      aprovação, pipeline, merge e persistência.
- [ ] Impedir fallback determinístico e nova iteração depois de cancelamento.
- [ ] Passar o `AbortSignal` também à detecção de providers.
- [ ] Corrigir o watchdog compartilhado entre providers concorrentes.
- [ ] Limpar `currentStage` ao final de cada etapa.

### Evidência exigida

- [ ] Cancelamento durante proposal, review e conselho pós-pipeline deve
      terminar como `cancelled`, sem fallback.
- [ ] Timeout do planner deve terminar como `timed_out`.
- [ ] Módulo registry que lança `AbortError`, timeout ou
      `PROCESS_UNTERMINATED` não pode emitir `done`.
- [ ] Desconexão HTTP durante provider, aprovação e pipeline deve deixar zero
      evento/efeito posterior.
- [ ] Provider que ignora abort deve ser encerrado e assentado antes da sessão
      terminar.

Arquivos-alvo:

- `server/auto-agent/council/council-runner.mjs`;
- `server/auto-agent/orchestrator.mjs`;
- `server/auto-agent/session-store.mjs`;
- `server/auto-agent/provider-detector.mjs`;
- `server/pipeline/dispatcher.mjs`.

## P0.4 — terminal, outcomes e UI

### Implementação

- [ ] Definir terminal único de sessão com `completed`, `partial`, `failed`,
      `cancelled`, `timed_out`, `stalled` e `budget_exceeded`.
- [ ] Propagar `evaluation.status` ao terminal.
- [ ] Emitir outcome por módulo com base no runner real.
- [ ] Remover inferência de módulo baseada somente em pipe/fase.
- [ ] Fazer a UI continuar lendo após `error` com `recoverable:true`.
- [ ] Manter cancelamento e acompanhamento disponíveis até terminal
      confirmado.
- [ ] Exibir falhas parciais, engines incompletos e motivo do terminal.

### Evidência exigida

- [ ] Falha recuperável seguida de conclusão deve terminar como `partial`.
- [ ] Falha fatal nunca deve produzir `completed`.
- [ ] Erro recuperável do FrameSeven não deve interromper o leitor NDJSON.
- [ ] Cada terminal deve corresponder à matriz de outcomes dos módulos.
- [ ] Teste de UI deve executar o parser/estado, não apenas procurar regex.

Arquivos-alvo:

- `server/auto-agent/planner.mjs`;
- `server/auto-agent/orchestrator.mjs`;
- `server/pipeline/dispatcher.mjs`;
- `public/index.html`.

## P0.5 — retomada, orçamento e cleanup

### Implementação

- [ ] Persistir `deadlineAt` absoluto.
- [ ] Preservar saldo de tempo, chamadas, custo e iterações na retomada.
- [ ] Incluir limites de providers, pipeline, FrameSeven e settle na política
      e no hash compatível.
- [ ] Recusar qualquer drift de limites.
- [ ] Persistir aprovação pendente antes de aguardar o operador.
- [ ] Tornar `session.close()` assíncrono e aguardar todos os recursos.
- [ ] Comprovar `exit/close` de App Server, browser, workers e process groups.
- [ ] Tornar falhas de checkpoint/snapshot/terminal visíveis.
- [ ] Fazer a reconciliação de startup ser aguardada e auditável.

### Evidência exigida

- [ ] Retomada próxima do deadline deve receber apenas o saldo restante.
- [ ] Restart não pode renovar orçamento.
- [ ] Crash real com aprovação pendente deve ser reconciliado sem execução.
- [ ] Terminal só pode aparecer depois de zero processo/browser/temporário.
- [ ] Falha de persistência obrigatória deve impedir sucesso.

Arquivos-alvo:

- `server/auto-agent/session-store.mjs`;
- `server/auto-agent/orchestrator.mjs`;
- `server/auto-agent/providers/codex-app-server.mjs`;
- `server/routes/auto-recon.mjs`.

## P0.6 — isolamento de dados e providers

### Implementação

- [ ] Particionar RAG por principal, engagement e alvo.
- [ ] Aplicar o mesmo isolamento às APIs de status/search e aos snapshots.
- [ ] Definir TTL e retenção mínima.
- [ ] Exigir confirmação explícita para provider cloud quando houver alvo ou
      evidência privada/autenticada.
- [ ] Implementar política de redação configurável e realmente consumida.
- [ ] Obter uso/custo confiável ou declarar orçamento não verificável.
- [ ] Substituir fallback silencioso por falha ou estado `degraded` aprovado
      pelo operador.
- [ ] Exigir segredo estável de binding do principal em operação persistente.

### Evidência exigida

- [ ] Principal A não pode pesquisar ou carregar memória do principal B.
- [ ] Engagement A não pode contaminar o contexto do engagement B.
- [ ] Memória expirada não deve ser recuperada.
- [ ] Provider indisponível não pode iniciar pipeline fingindo decisão de IA.
- [ ] Prompt enviado a cloud deve registrar consentimento e versão da política,
      sem segredo.

Arquivos-alvo:

- `server/auto-agent/rag-memory.mjs`;
- `server/auto-agent/providers/`;
- `server/auto-agent/provider-detector.mjs`;
- `server/auto-agent/planner.mjs`;
- `server/modules/auth.js`;
- `server/routes/auto-recon.mjs`.

## P0.7 — regressão e E2E

- [ ] Corrigir a referência inexistente `pipelineState` em
      `server/tests/auto-agent.test.js`.
- [ ] Corrigir `auth-principal-restart.test.js` para capturar o resultado do
      subprocesso de forma compatível com Node 22.
- [ ] Criar `test:hermetic` ou comando equivalente.
- [ ] Executar o gate hermético em CI sem rede.
- [ ] Mover o smoke de `example.com` para job opt-in.
- [ ] Executar E2E controlado de `observation`.
- [ ] Executar `assisted` aprovado e recusado.
- [ ] Exercitar todos os pontos de cancelamento e timeout.
- [ ] Exercitar restart/resume perto do deadline.
- [ ] Exercitar redirect, subdomínio e IP fora da allowlist.
- [ ] Exercitar contexto autenticado single-use e cleanup.
- [ ] Inspecionar NDJSON, RAG, snapshot, SQLite e relatórios.
- [ ] Confirmar zero processo, browser e temporário residual.

## P1 — operação real

- [ ] Exigir engagement/ROE para qualquer plano ativo.
- [ ] Migrar módulos legados para deadline, cancelamento, outcome e progresso
      individuais.
- [ ] Criar `runId` e relatório Auto consolidado.
- [ ] Informar readiness real por item do catálogo.
- [ ] Aplicar limites de concorrência por principal, sessão e engine.
- [ ] Definir retenção comum para todos os artefatos.
- [ ] Persistir e auditar cada transição de aprovação.
- [ ] Testar Bubblewrap real e endurecer permissões/escritas do Forge store.

## P2 — paridade e operação do produto

- [ ] Unificar a classificação de risco e adicionar teste de paridade.
- [ ] Integrar Tor/proxy estrito ao FrameSeven.
- [ ] Criar listagem/seleção de sessões retomáveis na UI.
- [ ] Expor claramente fallback, bloqueio e estado degradado.
- [ ] Adicionar comando Auto à CLI ou documentar a decisão de não suportá-lo.
- [ ] Definir aprovação interativa do Auto no MCP.
- [ ] Implementar `stop/status` confiáveis para sidecars.
- [ ] Remover ou implementar configurações Auto sem consumidor real.

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
