# Plano de melhorias do Modo AUTO e integração das IAs

Documento de investigação, arquitetura alvo e roteiro de implementação para transformar o Modo AUTO em um orquestrador no qual somente as IAs selecionadas tomam decisões reais, justificam essas decisões, persistem a trilha no RAG e podem propor novos módulos com validação segura.

Criado em: 2026-07-14

## Estado de implementação em 2026-07-14

Implementado nesta primeira evolução:

- correção de papéis para considerar somente IAs selecionadas;
- JSON Schema e validação local de decisões;
- adaptador Codex via `codex exec`, efêmero e read-only;
- redução do ambiente herdado pelo processo Codex para evitar vazamento cruzado de chaves;
- adaptador OpenRouter real via Chat Completions;
- adaptador Skynet/GHOST via endpoint OpenAI-compatible local;
- redação de segredos antes de montar contexto de agente;
- conselho em dois turnos: propostas independentes e revisão cruzada;
- veredito determinístico por quórum sobre módulos;
- persistência de cada turno no Auto RAG;
- busca RAG priorizando memórias do mesmo alvo;
- pasta RAG exclusiva para solicitações de Module Forge;
- storage `dynamic/by-model/<autor>/<modelo>/pending/<forgeId>`;
- preservação de request, proveniência, transcript e veredito;
- eventos de conselho e Module Forge na UI;
- testes offline dos adaptadores, conselho, redação e storage.
- provider Claude Code não interativo com JSON Schema, `permission-mode=plan` e tools desabilitadas;
- observation bundle redigido com findings, warnings, erros e módulos executados;
- segunda rodada do conselho após o pipeline;
- decisão pós-pipeline persistida por agente no RAG;
- geração estruturada de `module.mjs`, `module.test.js`, `manifest.json` e notas em `pending`;
- geração de código sem permitir que Codex/Claude escrevam diretamente no projeto;
- validação estática conservadora de imports, rede, filesystem, subprocessos e código dinâmico;
- syntax check do módulo e do teste;
- execução de testes com Node permission model sem rede, escrita ou subprocessos;
- review formal `approve/request_changes/reject/abstain` pelas IAs selecionadas;
- quórum para liberar um pacote à aprovação humana;
- API para listar pacotes Forge e aprovar/rejeitar um pacote;
- movimentação auditável de `pending` para `active` ou `rejected`;
- loader dinâmico restrito a módulos ativos, por `forgeId` e alvo original;
- aprovação humana ativa o módulo e dispara a primeira execução imediatamente no alvo registrado;
- falha na primeira execução desabilita o módulo e registra `activation_failed`;
- correção automática de módulos após `request_changes`, devolvendo ao autor os pareceres completos;
- snapshots imutáveis em `revisions/revision-NN` antes de cada correção;
- nova validação, novos testes e nova votação após cada correção;
- limite configurável de correções e estado auditável `correction_attempts_exhausted`;
- rota autenticada de detalhe do pacote, limitada aos artefatos conhecidos do Forge;
- painel visual no Modo AUTO para consultar código, testes, gates e votos;
- aprovação/rejeição humana com justificativa e CSRF diretamente no painel;

Ainda pendente:

- teste real de credenciais e conectividade com os provedores configurados pelo operador;

## Estado de implementação em 2026-07-16

Concluído na segunda evolução:

- probes separados para instalação, configuração, autenticação, alcance e usabilidade;
- verificação de sessão do Codex e Claude Code, `/health` + `/v1/models` do GHOST e `/models` autenticado do OpenRouter;
- adaptador OpenAI-compatible para LM Studio/Ollama;
- rejeição de referências de evidência inexistentes e requisitos completos para Forge;
- sessão persistente com limites de iteração, tempo, chamadas, contexto e custo;
- cancelamento do stream propagado para conselho, CLIs, HTTP e pipeline;
- loop iterativo real, sem repetir módulos já executados;
- consenso ponderado por confiança e evidência, com pergunta ao operador em conflito entre concluir e continuar;
- snapshot reproduzível com `sessionId`, `promptVersion`, hash do catálogo, memórias e usage;
- recuperação RAG isolada pelo alvo, sem injeção indiscriminada de memórias recentes globais;
- versionamento de pacotes ativos, canary percentual, promoção, desativação e rollback auditável;
- API e painel para administrar todo o lifecycle do Module Forge;
- Codex App Server persistente por sessão, com uma thread reutilizada entre turnos e fallback para `codex exec`;
- Cursor Agent executável quando habilitado e autenticado, mantendo handoff como fallback;
- checkpoints retomáveis, heartbeat e cancelamento cooperativo entre fases;
- reparo de JSON limitado a uma tentativa;
- ranking RAG híbrido por alvo, tecnologia, módulo, decisão, resultado, recência e embedding local;
- estimativa configurável de custo para providers sem custo reportado;
- comparação automática de versões e canary determinístico por execução;

## Resumo executivo

O Modo AUTO atual ainda é uma fase inicial. Ele detecta provedores, monta uma lista fixa de módulos, executa o pipeline e grava snapshots Markdown. As IAs Codex, Claude Code, Skynet/GHOST, modelo local e OpenRouter não são consultadas pelo orquestrador para criar o plano ou avaliar a execução. Cursor recebe somente um handoff Markdown por padrão.

O próximo objetivo do projeto é:

> As IAs escolhidas pelo operador devem participar de uma sessão real de decisão, produzir respostas estruturadas e auditáveis, selecionar módulos com base nas evidências, avaliar os resultados de cada iteração, salvar suas decisões no Auto RAG e abrir uma solicitação de Module Forge quando detectarem uma lacuna de cobertura.

O GHOSTRECON continua sendo a autoridade de execução. Nenhuma IA pode ignorar escopo, OPSEC, timeouts, permissões, testes ou aprovação.

## Diagnóstico confirmado do estado atual

### O que já funciona

- Endpoint NDJSON `POST /api/recon/auto/stream`.
- Detecção de CLIs e serviços configurados.
- Catálogo inicial de módulos AUTO.
- Gate de OPSEC antes de executar o pipeline.
- Execução do pipeline normal com os módulos planejados.
- Persistência Markdown em `data/auto-rag/`.
- Busca textual, listagem e leitura das memórias.
- Handoff Markdown para Cursor.
- Cliente OpenRouter, cliente Anthropic e cliente OpenAI-compatible/LM Studio no subsistema de relatórios.
- Endpoint OpenAI-compatible do GHOST em `POST /v1/chat/completions`.
- Contrato de módulos, registry e dispatcher para parte dos módulos modernos.
- Testes unitários do esqueleto AUTO e de módulos.

### O que ainda não funciona

- Codex não é chamado pelo AUTO.
- Claude Code não é chamado pelo AUTO.
- OpenRouter não é chamado pelo AUTO.
- Skynet/GHOST tem apenas o `/health` consultado.
- Modelo local é apenas detectado.
- Cursor, por padrão, apenas recebe um arquivo de tarefa.
- A lista de módulos é fixa e não é resultado de raciocínio de uma IA.
- A avaliação final somente conta eventos, warnings e findings.
- Provedores não selecionados podem receber papéis.
- Não existe protocolo de conselho multi-IA.
- Não existe schema validado para decisões.
- O Forge usa `dynamic/by-model/<autor>/<modelo>/pending`; após aprovação, o pacote vai para `active/<moduleId>/<forgeId>` e é carregado somente quando seu ID estiver nos módulos da execução e o alvo coincidir.
- O RAG atual recupera arquivos recentes ou usa busca textual; não há recuperação direcionada por alvo, tecnologia, módulo e tipo de decisão.
- Não existe controle de budget por provedor, quantidade de turnos ou custo.
- Não existe cancelamento compartilhado entre stream, chamadas de IA e pipeline.

## Princípios obrigatórios

1. Somente provedores explicitamente selecionados podem receber papéis.
2. `instalado`, `configurado`, `autenticado`, `alcançável` e `selecionado` são estados diferentes.
3. Uma IA indisponível deve produzir degradação explícita; nunca ser apresentada como participante real.
4. Toda decisão deve possuir autor, entrada resumida, justificativa, confiança e saída estruturada.
5. Toda ação proposta deve ser validada pelo GHOSTRECON antes da execução.
6. Respostas de modelo são dados não confiáveis, mesmo quando produzidas por uma CLI local.
7. Conteúdo encontrado no alvo não pode virar instrução para a IA; deve ser marcado como evidência não confiável para reduzir prompt injection.
8. Segredos, cookies, tokens e corpos sensíveis devem ser redigidos antes de qualquer provedor cloud.
9. Uma IA pode propor código. O GHOSTRECON decide se grava, testa, aprova e ativa.
10. Módulo gerado nunca entra automaticamente no registry principal na primeira versão.
11. Todas as decisões precisam ser reproduzíveis a partir de `runId`, modelo, promptVersion, catálogo e memórias utilizadas.

## Arquitetura alvo

```text
Operador
  -> cria Auto Session e escolhe provedores
  -> Provider Registry valida capacidade real
  -> Role Resolver usa somente selecionados e saudáveis
  -> Context Builder redige e limita o contexto
  -> RAG Retriever busca memórias relevantes
  -> Agent Council executa turnos estruturados
       planner -> critic/reviewer -> arbiter
  -> Decision Validator valida schema, escopo e OPSEC
  -> Pipeline Executor executa módulos aprovados
  -> Observation Builder resume resultados
  -> Agent Council avalia lacunas e próxima iteração
       continuar | concluir | pedir operador | forge_module
  -> Memory Writer persiste decisões e resultados
  -> Module Forge, quando necessário
       request -> draft -> static checks -> tests -> review -> pending approval
```

### Componentes novos propostos

```text
server/auto-agent/
  schemas/
    decision-schema.mjs
    council-schema.mjs
    forge-schema.mjs
  providers/
    base-provider.mjs
    openrouter.mjs
    ghost-openai.mjs
    lmstudio.mjs
    codex.mjs
    claude-code.mjs
    cursor.mjs
  council/
    role-resolver.mjs
    context-builder.mjs
    prompt-templates.mjs
    council-runner.mjs
    consensus.mjs
  forge/
    forge-manager.mjs
    policy-validator.mjs
    static-validator.mjs
    test-runner.mjs
    pending-registry.mjs
  session-store.mjs
  orchestrator.mjs
```

Essa estrutura deve ser introduzida incrementalmente. O pipeline atual não precisa ser reescrito para iniciar a integração das IAs.

## Contrato unificado de provedor

Todos os provedores devem implementar a mesma interface conceitual:

```js
{
  id,
  kind,                  // cli | openai-compatible | anthropic | handoff
  capabilities: {
    plan: true,
    review: true,
    evaluate: true,
    generateCode: false,
    applyPatch: false,
    structuredOutput: true
  },
  async probe(ctx),
  async decide(request, ctx),
  async cancel(reason)
}
```

O resultado de `probe()` deve separar:

```json
{
  "installed": true,
  "configured": true,
  "authenticated": true,
  "reachable": true,
  "usable": true,
  "mode": "exec",
  "reason": null
}
```

Encontrar um binário com `which` não comprova autenticação nem capacidade de executar uma tarefa.

## Adaptação por IA

### OpenRouter

- Reaproveitar a lógica HTTP existente em `ai-dual-report.js`, extraindo um cliente compartilhado.
- Aceitar `baseUrl`, modelo, timeout, retries e `AbortSignal`.
- Exigir JSON estruturado e validar localmente.
- Consultar modelos dinamicamente, mantendo fallback configurável.
- Registrar modelo real, latência, tentativas e usage retornado.

### Skynet/GHOST local

- Usar `POST /v1/chat/completions`, já disponível no GHOST.
- Antes de marcar como utilizável, consultar `/health` e `/v1/models`.
- Configurar modelo explicitamente; não assumir que `ghost` está carregado no Ollama.
- Evitar duplicar o Auto RAG dentro do RAG interno do GHOST sem registrar quais contextos foram usados.

### LM Studio/modelo local

- Usar endpoint OpenAI-compatible configurado.
- Detectar modelo real por `/models`.
- Aplicar budget de contexto menor e resumo hierárquico quando necessário.
- Degradar para planner simples quando o modelo não seguir o schema após reparo controlado.

### Codex

- Primeira integração: modo não interativo com saída JSON/JSONL e schema.
- Executar com cwd controlado e prompt versionado.
- Para planejamento, preferir modo somente leitura.
- Edição deve existir apenas dentro do Module Forge e em diretório pending.
- Nunca entregar ao processo uma chave, cookie ou arquivo fora do conjunto explicitamente permitido.
- Capturar eventos, exit code, stderr redigido, timeout e cancelamento.

### Claude Code

- Mesmo contrato do Codex, com adaptador CLI separado.
- Planejamento deve ser read-only.
- Geração de módulo deve usar workspace pending isolado.
- Uma segunda chamada de review não pode reutilizar instruções ocultas do turno de implementação sem registro.

### Cursor

- Manter handoff como fallback oficial.
- Só declarar participação em tempo real quando existir Agent CLI utilizável e autenticado.
- Handoff não conta como decisão concluída; conta como `awaiting_human`.

## Contrato de decisão

Cada turno de IA deve devolver um envelope equivalente a:

```json
{
  "schemaVersion": 1,
  "decisionId": "dec_...",
  "sessionId": "auto_...",
  "iteration": 1,
  "provider": "codex",
  "model": "provider-specific-model",
  "role": "planner",
  "action": "run_modules",
  "objective": "Mapear a superfície HTTP autorizada",
  "reasoningSummary": [
    "O alvo respondeu em HTTPS.",
    "Foram encontrados artefatos JavaScript ainda não analisados."
  ],
  "evidenceRefs": ["event:42", "finding:17", "memory:lessons/example.md"],
  "requestedModules": ["js_intel", "api_contract_diff"],
  "rejectedModules": [
    {"id": "sqlmap", "reason": "intrusivo e fora da política desta sessão"}
  ],
  "confidence": 0.82,
  "assumptions": [],
  "operatorQuestion": null,
  "forgeRequest": null
}
```

Ações permitidas inicialmente:

- `run_modules`
- `continue_with_context`
- `finish`
- `ask_operator`
- `forge_module`
- `abstain`

O schema deve rejeitar módulo inexistente, módulo fora do catálogo, ação desconhecida, confiança inválida e referência de evidência inexistente.

## Conselho multi-IA

### Regra de papéis

- Resolver papéis somente entre selecionados com `usable=true`.
- Respeitar líder escolhido manualmente.
- Sem líder manual, escolher pelo conjunto de capacidades da tarefa, não apenas por uma prioridade fixa.
- Um provedor em handoff não bloqueia o conselho; registra `awaiting_human`.
- Um provedor indisponível não é substituído silenciosamente por um não selecionado.

### Protocolo inicial recomendado

1. Planner produz proposta independente.
2. Reviewer recebe proposta, catálogo, política e evidências, mas não recebe raciocínio privado irrestrito.
3. Reviewer aprova, rejeita ou solicita mudanças em JSON.
4. Arbiter determinístico do GHOSTRECON combina apenas itens válidos.
5. Em conflito de alto impacto, o sistema pergunta ao operador.

Não usar votação cega. Duas IAs podem repetir o mesmo erro. Evidência, policy e capacidade têm precedência sobre quantidade de votos.

## RAG de decisões

### Estrutura proposta

```text
data/auto-rag/
  sessions/<sessionId>/session.json
  decisions/<timestamp>-<decisionId>.md
  observations/<timestamp>-<iteration>.md
  lessons/<timestamp>-<lesson>.md
  forge-requests/<forgeId>.md
  provider-events/<sessionId>.ndjson
  cursor-tasks/
```

### Campos obrigatórios da memória

- `sessionId`, `decisionId`, `iteration` e `target`.
- Provedor, modelo, papel e versão do prompt.
- Hash ou identificador do catálogo usado.
- Memórias lidas para tomar a decisão.
- Evidências referenciadas.
- Proposta original validada e decisão efetivamente executada.
- Resultado: concluído, rejeitado, timeout, cancelado ou aguardando aprovação.
- Lição posterior vinculada à decisão.
- Usage/custo quando o provedor fornecer esses dados.

### Recuperação

A primeira versão pode continuar sem banco vetorial, mas deve pontuar por:

- mesmo alvo ou domínio raiz;
- mesmas tecnologias;
- mesmos módulos;
- mesmo tipo de decisão;
- lessons com resultado conhecido;
- recência.

Memórias globais não devem ser injetadas indiscriminadamente em todos os alvos. Isso reduz contaminação de contexto e decisões irrelevantes.

## Module Forge

### Objetivo

Module Forge cobre uma lacuna comprovada. Ele não deve ser acionado apenas porque uma IA imaginou um módulo interessante.

### Requisitos para abrir uma solicitação

- Evidência observada na sessão.
- Declaração da lacuna no catálogo atual.
- Benefício esperado.
- Classificação passiva/intrusiva.
- Entradas e saídas propostas.
- Estratégia de teste sem rede real.
- Riscos e limites.

### Estados

```text
proposed
  -> approved_for_draft
  -> generated
  -> static_validation_failed | test_failed | review_failed
  -> pending_operator_approval
  -> approved
  -> enabled_for_canary
  -> promoted | rolled_back
```

### Diretórios propostos

```text
dynamic/
  by-model/
    codex/
      approved/<moduleId>/<version>/
      rejected/<moduleId>/<version>/
      pending/<forgeId>/
    claude-code/
      approved/<moduleId>/<version>/
      rejected/<moduleId>/<version>/
      pending/<forgeId>/
    openrouter/<modelSlug>/
      approved/<moduleId>/<version>/
      rejected/<moduleId>/<version>/
      pending/<forgeId>/
    skynet/<modelSlug>/
      approved/<moduleId>/<version>/
      rejected/<moduleId>/<version>/
      pending/<forgeId>/
    cursor/<modelSlug>/
      approved/<moduleId>/<version>/
      rejected/<moduleId>/<version>/
      pending/<forgeId>/
```

Cada diretório de versão deve conter `module.mjs`, `module.test.js`, `manifest.json`, `provenance.json`, `council-transcript.ndjson`, `verdict.json` e `test-results.json`. A autoria é sempre preservada, mesmo quando outra IA melhora o código: `provenance.json` registra autor original, contribuidores e revisor.

Módulo rejeitado nunca é apagado. Ele é movido para a pasta `rejected` do modelo autor com o código integral, testes, veredito, votos, justificativas e possibilidade de nova versão futura. Somente artefatos em `active` com `pipelineEnabled=true` podem ser considerados pelo loader do pipeline.

### Veredito entre modelos

Quando mais de uma IA estiver selecionada, o Module Forge deve executar uma conversa registrada:

1. A IA autora apresenta lacuna, evidência, desenho, código e testes.
2. Cada outra IA faz uma revisão independente.
3. A autora recebe as críticas e pode gerar uma nova versão.
4. Os revisores emitem veredito final estruturado: `approve`, `request_changes`, `reject` ou `abstain`.
5. O GHOSTRECON valida policy e testes, que possuem poder de veto mesmo com unanimidade das IAs.
6. A aprovação técnica do conselho ainda exige confirmação humana para entrar em `active`.

O quórum padrão proposto é maioria simples dos revisores aptos, sem contar a IA autora. Um único modelo selecionado deve fazer dois turnos separados, autor e revisor, mas o resultado permanece `pending_operator_approval` por não existir revisão independente.

### Política da primeira versão

- Somente módulos `intrusive: false` podem chegar a canary.
- Sem `child_process`, `eval`, `Function`, imports dinâmicos arbitrários ou escrita fora do diretório de artifacts.
- Rede somente via `fetchImpl` injetado.
- Processos externos somente via executor permitido, inicialmente desabilitado para módulo gerado.
- Testes obrigatoriamente offline.
- Manifesto deve seguir `docs/MODULE-CONTRACT.md`.
- Ativação exige aprovação humana na primeira fase.
- Canary executa com timeout curto e alvo de teste controlado.
- Promoção ao registry principal é uma etapa separada.

## Fluxo da sessão AUTO

```text
1. Validar alvo, escopo e seleção.
2. Criar sessionId persistente.
3. Probar somente os provedores selecionados.
4. Mostrar ao operador quais selecionados estão realmente utilizáveis.
5. Criar snapshot do catálogo e da policy.
6. Recuperar RAG relevante.
7. Solicitar plano estruturado ao planner.
8. Revisar plano quando houver outro participante apto.
9. Validar deterministicamente o plano.
10. Persistir proposta, revisão e plano efetivo.
11. Executar uma iteração limitada do pipeline.
12. Resumir observações sem expor segredos.
13. Solicitar avaliação estruturada.
14. Persistir avaliação e resultado.
15. Continuar, concluir, perguntar ao operador ou abrir Module Forge.
16. Aplicar limites de iteração, tempo e custo.
17. Encerrar sessão com resumo reproduzível.
```

## Observabilidade e interface

Eventos novos sugeridos:

- `auto_session`
- `auto_provider_probe`
- `auto_agent_turn_started`
- `auto_agent_turn_completed`
- `auto_agent_turn_failed`
- `auto_decision_validated`
- `auto_decision_rejected`
- `auto_council_review`
- `auto_iteration_started`
- `auto_iteration_completed`
- `auto_memory_written`
- `auto_forge_requested`
- `auto_forge_status`
- `auto_heartbeat`

A interface deve diferenciar:

- selecionado;
- online e autenticado;
- participando agora;
- handoff pendente;
- falhou e foi removido da sessão;
- decisão proposta versus decisão executada.

## Limites de segurança e operação

Configurações sugeridas:

```env
GHOSTRECON_AUTO_MAX_ITERATIONS=3
GHOSTRECON_AUTO_SESSION_TIMEOUT_MS=1800000
GHOSTRECON_AUTO_AGENT_TIMEOUT_MS=180000
GHOSTRECON_AUTO_MAX_AGENT_CALLS=12
GHOSTRECON_AUTO_MAX_CONTEXT_CHARS=120000
GHOSTRECON_AUTO_CLOUD_REDACTION=1
GHOSTRECON_AUTO_FORGE_ENABLED=0
GHOSTRECON_AUTO_FORGE_REQUIRE_APPROVAL=1
GHOSTRECON_AUTO_FORGE_CANARY=0
```

Cada limite deve aparecer no snapshot da sessão e no documento de decisão.

## Plano de implementação por etapas

### Etapa 1 — Base confiável de provedores

- Corrigir a seleção de papéis.
- Criar contrato comum de provider.
- Separar disponibilidade de usabilidade/autenticação.
- Implementar adaptadores OpenRouter e GHOST/OpenAI-compatible.
- Adicionar timeouts, retries, cancelamento e redação.
- Testar com clientes injetáveis, sem rede real.

Critério de aceite: selecionar `codex,cursor` nunca inclui Skynet/OpenRouter; selecionar OpenRouter faz uma chamada real mockável e salva a resposta validada.

### Etapa 2 — Decisão real e RAG auditável

- Criar schema de decisão.
- Criar prompts versionados.
- Criar context builder e recuperação RAG direcionada.
- Persistir cada turno, revisão e decisão efetiva.
- Usar o plano validado para escolher módulos.

Critério de aceite: o plano deixa de ser lista fixa; existe fallback determinístico explicitamente marcado quando nenhum agente responde.

### Etapa 3 — Conselho multi-IA

- Implementar planner, reviewer e arbiter.
- Resolver capacidades por tarefa.
- Implementar conflito, abstention e pergunta ao operador.
- Medir latência, chamadas e custo.

Critério de aceite: cada IA selecionada tem participação rastreável ou estado de falha/handoff; nenhuma IA não selecionada participa.

### Etapa 4 — Loop iterativo

- Executar plano por iterações limitadas.
- Construir observation bundles compactos.
- Permitir continuar/concluir/perguntar/forge.
- Implementar cancelamento e heartbeat da sessão.

Critério de aceite: uma IA pode adaptar a segunda iteração aos findings da primeira sem repetir módulos inutilmente.

### Etapa 5 — Module Forge pending

- Criar schema e lifecycle do forge.
- Criar diretórios isolados.
- Implementar validação estática e testes offline.
- Implementar revisão por outra IA quando disponível.
- Exigir aprovação humana.

Critério de aceite: uma lacuna comprovada gera pacote completo em pending, mas não altera automaticamente o registry principal.

### Etapa 6 — Canary e promoção

- Loader dinâmico limitado.
- Canary controlado.
- Rollback e quarentena.
- Promoção auditável ao arsenal.

Critério de aceite: falha no canary desabilita o módulo e preserva evidências; promoção exige todos os gates.

### Etapa 7 — Robustez geral do AUTO

- Corrigir progresso do CORS e separar ALIVE/SURFACE.
- Concorrência e budget global por módulo.
- Watchdog e cancelamento do recon.
- Checkpoints e retomada.
- Corrigir supervisão do GHOST/GhostTrace.

## Testes obrigatórios

- Papéis usam somente selecionados.
- Provedor instalado mas não autenticado não é `usable`.
- Timeout e cancelamento de cada adaptador.
- Resposta inválida da IA não chega ao pipeline.
- Reparo de JSON limitado a uma tentativa.
- Módulo inexistente é rejeitado.
- Módulo intrusivo é bloqueado pela policy.
- Prompt injection presente em HTML permanece como dado citado.
- Redação remove tokens antes de provedor cloud.
- Toda decisão executada gera memória.
- Falha ao gravar RAG aparece na sessão e não é silenciosa.
- Conselho trata aprovação, rejeição, conflito e abstention.
- Forge não escreve fora de `dynamic/pending/<forgeId>`.
- Forge não ativa módulo sem aprovação.
- Limites de iteração, chamadas, tempo e custo encerram a sessão corretamente.

## Definição de pronto do objetivo principal

O objetivo "IAs selecionadas tomam decisões e salvam no RAG" estará concluído somente quando:

1. Cada provedor selecionado for comprovadamente utilizável ou marcado com falha clara.
2. Pelo menos OpenRouter e GHOST local produzirem planos reais pelo contrato comum.
3. Codex e Claude Code tiverem adaptadores CLI testáveis e com timeout.
4. O plano efetivamente executado vier de uma decisão validada.
5. Cada turno e decisão efetiva estiver persistido no RAG com proveniência.
6. O conselho multi-IA não incluir provedores não selecionados.
7. Resultados da primeira iteração puderem alterar a seguinte.
8. Uma lacuna puder gerar um `forge_request` persistido.
9. Código gerado permanecer em pending até passar por policy, testes, review e aprovação.
10. Os testes de integração cobrirem sucesso, timeout, resposta inválida, cancelamento e fallback.

## Decisões tomadas nesta investigação

- Reutilizar os clientes de IA existentes, mas extraí-los do módulo de relatórios para evitar acoplamento.
- Usar o endpoint OpenAI-compatible existente do GHOST como adaptador Skynet inicial.
- Preservar o pipeline atual como executor; o conselho decide e o pipeline executa.
- Evoluir o RAG Markdown antes de introduzir obrigatoriamente embeddings.
- Implementar Module Forge em pending, com ativação somente após revisão, aprovação humana e primeira execução controlada.
- Tratar Cursor handoff como participação humana pendente, não como decisão da IA.
- Fazer OpenRouter e GHOST local primeiro, pois já existem protocolos HTTP utilizáveis e testáveis.
- Implementar Codex e Claude Code depois sobre o mesmo contrato, sem colocar comandos específicos dentro do orquestrador.

## Próxima entrega recomendada

Próxima evolução é robustecer o ciclo de módulos já ativos:

1. rollback manual e versionamento de módulos ativos;
2. promoção gradual por percentual de execuções;
3. cancelamento real de módulos com timeout cooperativo;
4. comparação de resultados entre versões;
5. correção dos travamentos e progresso por módulo;
6. testes de integração HTTP da aprovação com execução no alvo.
