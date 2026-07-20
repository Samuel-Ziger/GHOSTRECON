# Modo Auto GHOSTRECON

> Estado em 2026-07-20: desenvolvimento pausado temporariamente. O fluxo passivo está validado; autonomia intrusiva 3/4 ainda aguarda teste completo de aprovação humana.

Blueprint para integrar GHOSTRECON, HexStrike, MCP, Codex, Claude Code, Cursor, Skynet, modelos locais e OpenRouter em um modo autonomo de bug bounty autorizado.

Gerado em: 2026-07-05

## Objetivo

Criar um modo `auto` onde o operador escolhe uma ou mais IAs comandantes. A IA escolhida assume a frente da operacao: decide quais modulos do GHOSTRECON usar, quais ferramentas do HexStrike chamar, quando usar MCP, quando consultar memoria, quando acionar outra IA e quando criar um modulo novo para cobrir uma lacuna encontrada durante o recon.

O GHOSTRECON continua sendo o orquestrador local, dono de OPSEC, escopo, logs, pipeline, findings, persistencia e validacao. As IAs sao os comandantes/analistas. HexStrike, Kali, Vigolium e os modulos GHOSTRECON sao as ferramentas operacionais.

## Memoria RAG em Markdown

O Modo Auto deve manter uma memoria local em Markdown para reduzir repeticao de contexto entre IAs e permitir leitura humana no Obsidian.

Local padrao:

```text
data/auto-rag/
  README.md
  decisions/
    2026-...-target-plan-auto-....md
    2026-...-target-evaluation-auto-....md
  lessons/
    2026-...-lesson-....md
  notes/
  cursor-tasks/
```

Cada decisao relevante gera um novo `.md` com frontmatter, target, requestRunId, comandantes, modulos, plano, avaliacao e estatisticas de eventos. Lessons registram problema, decisao e resultado para o agente nao repetir o mesmo raciocinio. O planner carrega memorias recentes e injeta resumo em `plan.memory`.

Variaveis:

```bash
GHOSTRECON_AUTO_RAG_ENABLED=1
GHOSTRECON_AUTO_RAG_DIR=data/auto-rag
```

MCP relacionado:

- `ghostrecon_auto_rag_list`
- `ghostrecon_auto_rag_read`
- `ghostrecon_auto_rag_search`
- `ghostrecon_auto_rag_write_note`
- `ghostrecon_auto_rag_write_lesson`
- `ghostrecon://auto-rag/index`
- `ghostrecon://auto-rag/{folder}/{file.md}`

API local relacionada:

- `GET /api/auto-rag/status`
- `GET /api/auto-rag/search?q=termo`
- `POST /api/auto-rag/note`

Quando Cursor for selecionado, o Auto Orchestrator grava uma tarefa em `data/auto-rag/cursor-tasks/`. Essa tarefa e um handoff seguro para o IDE/Agent com plano, modulos, papeis e contexto RAG. Execucao headless deve ficar atras de variavel de ambiente; o padrao e human-in-loop.

## Principio central

Separar claramente:

1. **Comandantes**: IAs que tomam decisoes.
2. **Ferramentas**: sistemas que executam acoes.
3. **Orquestrador**: GHOSTRECON, que valida, executa, registra e limita tudo.

```text
Usuario
  -> escolhe IA(s) comandante(s)
     -> Auto Orchestrator
        -> Tool Catalog
        -> Provider Router / Agent Council
        -> Planner
        -> Executor
        -> Evaluator
        -> Module Forge
        -> Memory / Cortex

Ferramentas disponiveis:
  - GHOSTRECON modules
  - HexStrike HTTP
  - HexStrike MCP
  - Vigolium
  - Kali tools
  - Playbooks
  - Cortex / memoria
```

## Quando o usuario escolhe uma IA

Se o operador marcar apenas uma IA, ela vira a comandante principal e executa todas as funcoes possiveis:

| IA | Papel quando selecionada sozinha |
| --- | --- |
| Codex | Planeja, cria modulos, edita codigo, roda testes e integra patches. |
| Claude Code | Planeja, analisa profundamente, cria/refatora codigo, usa subagents e revisa estrategia. |
| Cursor | Atua como agente IDE/headless quando disponivel; bom para revisao contextual e fluxo human-in-loop. |
| Skynet | Comandante local privado, usa memoria, decide plano e interpreta findings. |
| Modelo local GLM/Outro | Backend local OpenAI-compatible para Skynet ou planner offline. |
| OpenRouter | Comandante cloud/fallback com acesso a varios modelos por uma API OpenAI-compatible. |

Regra obrigatoria: qualquer comandante selecionado sozinho deve conseguir operar em **solo full-stack**. Isso significa assumir, dentro das suas capacidades, todas as etapas:

```text
planejar -> executar plano via GHOSTRECON/HexStrike -> avaliar findings -> detectar lacunas -> criar ou propor modulo -> revisar -> pedir testes -> integrar ou deixar pending
```

Se a IA solo nao tiver capacidade segura de editar arquivos diretamente, ela deve gerar plano/patch/modulo em formato estruturado e o GHOSTRECON coloca em `dynamic/pending` para teste e aprovacao.

### Papel solo por comandante

| Comandante solo | Como faz tudo |
| --- | --- |
| Codex | Planeja, edita arquivos, cria modulo/teste, roda testes e integra no arsenal. |
| Claude Code | Planeja, cria modulo/teste, revisa em turno separado, roda comandos e integra se permitido. |
| Cursor Agent | Planeja e cria via CLI/headless se disponivel; se for apenas IDE, opera com human-in-loop e pending. |
| Skynet | Planeja e avalia localmente; gera rascunho de modulo/patch e deixa GHOSTRECON testar/aprovar. |
| GLM/local model | Igual Skynet quando servido via API local; gera JSON/patch, GHOSTRECON aplica com policy. |
| OpenRouter | Planeja, avalia, gera modulo/patch em JSON; GHOSTRECON aplica em pending, testa e so ativa apos policy/aprovacao. |

### Contrato minimo para modo solo

Toda IA solo deve responder com este tipo de pacote quando quiser criar capacidade nova:

```json
{
  "action": "forge_module",
  "reason": "Classe de tecnologia/vulnerabilidade sem cobertura nativa.",
  "module": {
    "id": "forge_example_module",
    "filename": "forge-example-module.mjs",
    "code": "...",
    "manifest": {
      "id": "forge_example_module",
      "category": "validation",
      "intrusive": false,
      "outputs": ["finding"]
    }
  },
  "test": {
    "filename": "forge-example-module.test.js",
    "code": "..."
  },
  "activation": {
    "requested": true,
    "requiresApproval": true
  }
}
```

O GHOSTRECON, nao a IA, decide se o pacote sera escrito, testado, aprovado e ativado.

## Quando o usuario escolhe varias IAs

Se o operador marcar varias IAs, o GHOSTRECON monta um conselho de agentes. Um lider e escolhido por disponibilidade e tipo de tarefa; os outros recebem funcoes especializadas.

### Ordem sugerida para lider tatico

1. Skynet local, se estiver online e o operador quiser privacidade/offline.
2. Claude Code, se disponivel e a tarefa exigir planejamento profundo.
3. Codex, se a tarefa envolver forte criacao de codigo/modulos.
4. OpenRouter, se modelos cloud estiverem permitidos ou como fallback.
5. Cursor, se o fluxo for IDE/human-in-loop ou se o Cursor Agent CLI estiver disponivel.

### Divisao ideal de funcoes

| Agente | Melhor uso |
| --- | --- |
| Skynet | Planejamento privado, memoria operacional, interpretacao de findings, decisao rapida. |
| GLM local | Motor local para Skynet; bom para reasoning/coding/tool calling se servido via endpoint OpenAI-compatible. |
| Claude Code | Estrategista, revisor profundo, subagents, validacao de planos e analise de arquitetura. |
| Codex | Module Forge, edicao do repo, testes, patches, integracao no registry. |
| Cursor | Revisao no IDE, execucao assistida, MCP do HexStrike no ambiente do editor, human-in-loop. |
| OpenRouter | Fallback cloud, acesso a modelos diferentes, roteamento de modelo por custo/capacidade. |

## Matriz fixa de papeis por combinacao

O Modo Auto deve ter papeis predefinidos para cada combinacao de comandantes. Isso evita que as IAs fiquem competindo sem regra clara.

Importante: OpenRouter nao deve entrar na matriz apenas como `openrouter`. O modelo escolhido muda o papel dele na equipe. Portanto o comandante real deve ser tratado como:

```text
openrouter:<model_id>
```

Exemplos:

```text
openrouter:openai/gpt-5.5-pro
openrouter:z-ai/glm-5.2
openrouter:moonshotai/kimi-k2.7-code
openrouter:anthropic/claude-opus-4.8
```

Isso permite que modelos mais fortes assumam funcoes mais importantes do que outros agentes em determinadas etapas.

Regra geral:

1. Um agente lidera a decisao tatica.
2. Um agente implementa quando houver codigo novo.
3. Um agente revisa o plano ou o modulo.
4. O GHOSTRECON executa, testa e registra.
5. Se os testes passarem, o modulo entra no arsenal.

### Fluxo canonico Codex + Claude Code + OpenRouter

Este e o fluxo principal desejado para auto-melhoria:

```text
1. Codex analisa a run e decide se existe lacuna.
2. Se precisar de modulo novo, Codex abre uma "module-forge request".
3. Claude Code cria o modulo e o teste correspondente.
4. OpenRouter revisa o modulo, o teste e a justificativa.
5. GHOSTRECON roda os testes em sandbox/local.
6. Se passar, Codex integra no dynamic registry / arsenal.
7. GHOSTRECON salva aprendizado em Cortex/playbook auto-learned.
```

Responsabilidades:

| Etapa | Responsavel | Saida esperada |
| --- | --- | --- |
| Detectar lacuna | Codex | `forge_request` com motivo, padrao observado e modulo sugerido. |
| Criar modulo | Claude Code | Arquivo `.mjs` + teste `.test.js` em `dynamic/pending`. |
| Revisar modulo | OpenRouter | Parecer JSON: aprovado, riscos, alteracoes exigidas. |
| Testar | GHOSTRECON | Resultado de `node --test` e validacao de manifest. |
| Integrar arsenal | Codex | Move para `dynamic/approved`, atualiza catalogo e playbook. |
| Aprender | GHOSTRECON/Skynet | Registro em memoria/Cortex. |

### Combinacoes principais

| Selecionados | Lider | Implementador | Revisor | Uso ideal |
| --- | --- | --- | --- | --- |
| Codex | Codex | Codex | Codex em modo review | Tudo em um: planeja, cria, testa e integra. |
| Claude Code | Claude Code | Claude Code | Claude Code em etapa separada | Planejamento profundo e criacao direta. |
| OpenRouter | OpenRouter modelo escolhido | Nenhum direto; gera patch/plano | OpenRouter segundo modelo/preset | Quando so ha cloud LLM disponivel; GHOSTRECON executa plano. |
| Skynet | Skynet | Nenhum direto | Skynet/evaluator | Operacao local privada sem criacao automatica pesada. |
| Codex + Claude Code | Codex | Claude Code | Codex | Codex decide lacuna; Claude implementa; Codex testa/integra. |
| Codex + OpenRouter | Codex | Codex | OpenRouter | Codex implementa; OpenRouter revisa qualidade/risco. |
| Claude Code + OpenRouter | Claude Code | Claude Code | OpenRouter | Claude planeja/cria; OpenRouter revisa com modelo escolhido. |
| Skynet + Codex | Skynet | Codex | Skynet | Skynet decide com memoria local; Codex cria modulo. |
| Skynet + OpenRouter | Skynet | Nenhum direto | OpenRouter | Skynet lidera; OpenRouter da segunda opiniao/fallback. |
| Cursor + Codex | Codex | Codex | Cursor/human-in-loop | Codex trabalha; Cursor ajuda revisao no IDE. |
| Cursor + Claude Code | Claude Code | Claude Code | Cursor/human-in-loop | Claude cria; Cursor revisa no IDE. |
| Codex + Claude Code + OpenRouter | Codex | Claude Code | OpenRouter | Fluxo canonico de Module Forge. |
| Skynet + Codex + OpenRouter | Skynet | Codex | OpenRouter | Operacao privada com revisao cloud opcional. |
| Skynet + Codex + Claude Code | Skynet | Codex ou Claude Code | Claude Code ou Codex | Skynet decide; Codex/Claude dividem engenharia. |
| Todos | Skynet ou Codex, conforme modo escolhido | Claude Code para modulo novo; Codex para integracao | OpenRouter + Cursor | Conselho completo: decisao, implementacao, revisao e arsenal. |

### Peso do modelo OpenRouter na equipe

Quando OpenRouter estiver selecionado junto com Codex, Claude Code, Cursor ou Skynet, o papel dele depende do modelo escolhido.

| Modelo/Preset OpenRouter | Peso na equipe | Pode liderar? | Melhor funcao |
| --- | --- | --- | --- |
| `openai/gpt-5.5-pro` | muito alto | sim | Lider premium, reasoning profundo, revisao final. |
| `openai/gpt-5.5` | alto | sim | Lider geral, planner, evaluator. |
| `anthropic/claude-opus-4.8` | muito alto | sim | Revisor profundo, estrategia, risco. |
| `anthropic/claude-sonnet-5` | alto | sim | Planner, analise, revisao equilibrada. |
| `moonshotai/kimi-k2.7-code` | alto em codigo | sim para Forge | Module design, revisao de codigo, patches. |
| `z-ai/glm-5.2` | medio/alto | sim em custo-beneficio/local-like | Planner barato, evaluator frequente, coding assistido. |
| `qwen/qwen3.7-max` | medio/alto | sim em coding/custo | Coding, analise tecnica, plano alternativo. |
| `qwen/qwen-plus` | medio | nao por padrao | Iteracoes baratas e triagem. |
| `deepseek/deepseek-r1` | alto reasoning | sim para revisao | Raciocinio, validacao de hipoteses. |
| `deepseek/deepseek-chat` | medio | nao por padrao | Custo-beneficio, triagem. |
| `google/gemini-3.5-flash` | medio/alto contexto | sim para contexto grande | Logs/runs grandes, triagem com contexto. |
| `google/gemini-3.1-flash-lite` | medio baixo custo | nao por padrao | Avaliacao barata e repetida. |
| `openrouter/auto` | variavel | sim se operador permitir | Deixar OpenRouter escolher o melhor disponivel. |
| `openrouter/fusion` | variavel | sim se operador permitir | Combinacao/roteamento avancado. |

Regra pratica:

```text
Se OpenRouter usa modelo premium reasoning:
  ele pode liderar ou revisar acima dos outros.

Se OpenRouter usa modelo coding:
  ele deve participar do Module Forge e revisar/criar codigo.

Se OpenRouter usa modelo custo-beneficio:
  ele nao deve liderar quando Codex/Claude/Skynet estiverem disponiveis;
  deve atuar como evaluator barato/fallback.

Se OpenRouter usa auto/fusion:
  ele pode liderar apenas se o operador aceitar roteamento automatico.
```

### Exemplo: Claude Code + Codex + OpenRouter GLM + Cursor

Selecao:

```text
claude-code
codex
cursor
openrouter:z-ai/glm-5.2
```

Papeis recomendados:

```text
Claude Code: lider estrategico e criador principal de modulo.
Codex: detector de lacuna, executor de integracao e testes do arsenal.
OpenRouter GLM 5.2: evaluator barato/segunda opiniao/cross-check.
Cursor: revisao human-in-loop no IDE.
GHOSTRECON: policy, execucao, testes e registry.
```

Se em vez de GLM 5.2 fosse `openai/gpt-5.5-pro`:

```text
OpenRouter GPT-5.5 Pro: pode virar lider premium ou revisor final.
Claude Code: cria modulo.
Codex: integra/testa.
Cursor: human-in-loop.
```

Se fosse `moonshotai/kimi-k2.7-code`:

```text
OpenRouter Kimi Code: participa diretamente do design/revisao do modulo.
Claude Code: implementa.
Codex: integra/testa.
Cursor: human-in-loop.
```

### Regra de escolha do lider

O operador pode escolher manualmente o lider. Se usar `leaderMode: auto`, aplicar:

```text
Se Skynet selecionada e online:
  Skynet lidera operacao de bug bounty.
Se OpenRouter premium reasoning selecionado e operador permitir cloud leader:
  OpenRouter pode liderar acima de Skynet/Codex/Claude para planejamento.
Senao se Codex selecionado:
  Codex lidera quando Module Forge estiver ativo.
Senao se Claude Code selecionado:
  Claude Code lidera planejamento profundo.
Senao se OpenRouter selecionado:
  OpenRouter lidera com o modelo escolhido.
Senao se Cursor Agent selecionado:
  Cursor lidera em modo human-in-loop.
```

Configuracao sugerida para controlar isso:

```env
GHOSTRECON_OPENROUTER_CAN_LEAD=1
GHOSTRECON_OPENROUTER_PREMIUM_CAN_OVERRIDE=1
GHOSTRECON_OPENROUTER_CHEAP_CAN_LEAD=0
```

### Regra de Module Forge

Quando Module Forge estiver ativo, a divisao deve ser:

```text
Detectar necessidade:
  Preferir Codex.
  Fallback: Skynet, Claude Code, OpenRouter.

Criar modulo:
  Preferir Claude Code se selecionado.
  Fallback: Codex.
  Fallback cloud: OpenRouter gera patch/plano, mas GHOSTRECON aplica com cuidado.

Revisar:
  Preferir OpenRouter com preset "reasoning" ou "coding".
  Fallback: Claude Code.
  Fallback: Codex review.

Testar:
  Sempre GHOSTRECON local.

Adicionar ao arsenal:
  Preferir Codex.
  Fallback: GHOSTRECON dynamic loader apos aprovacao.
```

### Fallbacks quando Codex nao foi selecionado

Codex e o melhor candidato para integrar codigo ao arsenal, mas o Modo Auto nao pode depender dele. Se Codex nao estiver selecionado ou nao estiver disponivel, aplicar esta cadeia:

```text
Detectar lacuna:
  1. Skynet
  2. Claude Code
  3. OpenRouter Reasoning
  4. Cursor Agent
  5. GHOSTRECON evaluator heuristico

Criar modulo:
  1. Claude Code
  2. Cursor Agent
  3. OpenRouter Coding gera patch estruturado
  4. Skynet/local model gera rascunho
  5. GHOSTRECON cria stub/template pendente

Revisar:
  1. OpenRouter Reasoning/Coding
  2. Claude Code
  3. Skynet
  4. Cursor/human-in-loop
  5. GHOSTRECON lint/test-only

Testar:
  Sempre GHOSTRECON local.

Adicionar ao arsenal:
  1. Claude Code aplica integracao se selecionado.
  2. Cursor Agent aplica integracao se disponivel.
  3. GHOSTRECON dynamic loader move para approved apos testes + policy.
  4. Se nenhum integrador existir, manter em pending aguardando aprovacao humana.
```

Regra importante: sem Codex, a integracao final deve ser mais conservadora. O modulo pode ser gerado e testado, mas deve ficar em `dynamic/pending` ate:

- passar testes;
- passar validacao de manifest;
- passar policy de imports/execucao;
- ter revisao por OpenRouter/Claude/Skynet ou aprovacao humana.

### Probabilidades de selecao e papeis

As combinacoes abaixo cobrem os cenarios principais sem Codex. Para combinacoes com Codex, usar a tabela anterior.

| Selecionados sem Codex | Lider | Criador de modulo | Revisor | Integracao ao arsenal |
| --- | --- | --- | --- | --- |
| Claude Code | Claude Code | Claude Code | Claude Code em turno separado | Claude Code ou dynamic loader apos teste. |
| OpenRouter | OpenRouter escolhido | OpenRouter Coding gera patch | OpenRouter Reasoning ou segundo modelo | Dynamic loader em pending; aprovacao recomendada. |
| Skynet | Skynet | Skynet gera rascunho | Skynet/evaluator | Pending ate revisao/teste. |
| Cursor | Cursor Agent se disponivel | Cursor Agent | Cursor/human-in-loop | Cursor ou pending. |
| Claude Code + OpenRouter | Claude Code | Claude Code | OpenRouter | Claude Code integra; GHOSTRECON testa. |
| Claude Code + Skynet | Skynet | Claude Code | Skynet | Claude Code integra; Skynet registra aprendizado. |
| Claude Code + Cursor | Claude Code | Claude Code | Cursor/human-in-loop | Claude Code ou Cursor integra. |
| OpenRouter + Skynet | Skynet | OpenRouter Coding ou Skynet rascunho | OpenRouter Reasoning | Pending/dynamic loader apos policy. |
| OpenRouter + Cursor | OpenRouter | Cursor Agent se disponivel; senao OpenRouter patch | OpenRouter + Cursor | Cursor integra ou pending. |
| Skynet + Cursor | Skynet | Cursor Agent; fallback Skynet rascunho | Cursor/human-in-loop | Cursor integra ou pending. |
| Claude Code + OpenRouter + Skynet | Skynet | Claude Code | OpenRouter | Claude Code integra; GHOSTRECON testa. |
| Claude Code + OpenRouter + Cursor | Claude Code | Claude Code | OpenRouter + Cursor | Claude Code/Cursor integra. |
| Claude Code + Skynet + Cursor | Skynet | Claude Code | Cursor + Skynet | Claude Code integra. |
| OpenRouter + Skynet + Cursor | Skynet | Cursor Agent ou OpenRouter Coding | OpenRouter | Cursor integra ou pending. |
| Claude Code + OpenRouter + Skynet + Cursor | Skynet | Claude Code | OpenRouter + Cursor | Claude Code integra; GHOSTRECON aprova. |

### Todas as probabilidades por funcao

Em vez de tentar decorar todas as combinacoes, o codigo deve resolver por funcao:

```text
Lider:
  userSelectedLeader
  -> Skynet
  -> Claude Code
  -> Codex
  -> OpenRouter
  -> Cursor Agent
  -> modo manual

Detector de lacuna:
  Codex
  -> Skynet
  -> Claude Code
  -> OpenRouter Reasoning
  -> Cursor Agent
  -> GHOSTRECON evaluator

Criador de modulo:
  Claude Code
  -> Codex
  -> Cursor Agent
  -> OpenRouter Coding
  -> Skynet/local model
  -> template pending

Revisor:
  OpenRouter Reasoning/Coding
  -> Claude Code
  -> Codex
  -> Skynet
  -> Cursor/human-in-loop
  -> test-only

Integrador:
  Codex
  -> Claude Code
  -> Cursor Agent
  -> dynamic loader approved
  -> pending/human approval
```

Assim, qualquer selecao vira uma equipe valida. Se a selecao nao tiver um papel forte para alguma etapa, o GHOSTRECON degrada com seguranca para `pending` e nao ativa o modulo automaticamente.

### Papel dos modelos OpenRouter dentro do conselho

Cada preset OpenRouter deve ser tratado como um comandante/revisor diferente:

| Preset OpenRouter | Papel quando selecionado junto com agentes |
| --- | --- |
| Melhor geral | Pode liderar se nenhum agente local forte estiver selecionado. |
| Reasoning profundo | Revisor de planos, riscos e cadeias de ataque. |
| Coding / Module Forge | Revisor tecnico de modulo novo e sugestor de implementacao. |
| Custo-beneficio | Avaliador barato para iteracoes frequentes. |
| Maior contexto | Analisa runs grandes, logs extensos e historico do alvo. |
| Auto Router | Fallback generico quando o operador nao quer escolher modelo. |

Exemplo com todos selecionados:

```text
Skynet: memoria e contexto operacional.
Codex: decide se precisa criar modulo e integra ao arsenal.
Claude Code: cria o modulo novo.
OpenRouter Reasoning: revisa plano e risco.
OpenRouter Coding: revisa modulo e teste.
Cursor: revisao human-in-loop no IDE.
GHOSTRECON: executa, testa, normaliza e registra.
```

### Exemplos de composicao

```text
Codex somente
  Codex planeja, executa module forge, testa e avalia.

Codex + Cursor
  Codex cria modulos e roda testes.
  Cursor revisa no IDE e pode usar MCP/human-in-loop.

Codex + Claude Code
  Claude lidera planejamento e revisao profunda.
  Codex implementa modulos, testes e patches.

Skynet + Codex
  Skynet decide estrategia e interpreta findings.
  Codex cria ou melhora modulos quando houver lacuna.

Todas disponiveis
  Skynet lidera operacao local.
  Claude revisa plano e hipoteses.
  Codex implementa lacunas.
  Cursor revisa no IDE quando necessario.
  OpenRouter entra como fallback ou consulta especializada.
```

## OpenRouter no Modo Auto

OpenRouter entra como um comandante cloud e tambem como roteador de modelos. Ele e util quando:

- Skynet/modelo local estiver offline ou fraco para a tarefa.
- O operador quiser usar modelos especificos sem integrar cada provider separado.
- O Auto Mode precisar de fallback automatico.
- O planejamento exigir modelos com contexto maior, tool calling ou melhor raciocinio.

Quando o operador selecionar OpenRouter como comandante, o GHOSTRECON deve perguntar qual modelo usar. Se o operador selecionar OpenRouter junto com outras IAs, o OpenRouter pode ser configurado como lider, revisor, fallback ou especialista por tipo de tarefa.

Fluxo desejado:

```text
Usuario marca OpenRouter
  -> GHOSTRECON consulta /api/v1/models
  -> mostra presets recomendados + lista completa pesquisavel
  -> usuario escolhe:
      1. Melhor geral
      2. Melhor reasoning profundo
      3. Melhor coding/module forge
      4. Melhor custo-beneficio
      5. Maior contexto
      6. Auto Router
      7. Ver todos os modelos OpenRouter
      8. Informar model id manualmente
  -> Auto Mode usa esse model id no planner/evaluator
```

### Como a API funciona

OpenRouter oferece endpoint OpenAI-compatible:

```text
POST https://openrouter.ai/api/v1/chat/completions
Authorization: Bearer <OPENROUTER_API_KEY>
Content-Type: application/json
HTTP-Referer: <opcional>
X-OpenRouter-Title: <opcional>
```

Exemplo de payload:

```json
{
  "model": "anthropic/claude-sonnet-4.6",
  "messages": [
    {
      "role": "system",
      "content": "Voce e o comandante do modo auto GHOSTRECON. Responda apenas JSON valido."
    },
    {
      "role": "user",
      "content": "Planeje a iteracao 1 para o alvo autorizado."
    }
  ],
  "stream": false
}
```

Tambem deve ser usado:

```text
GET https://openrouter.ai/api/v1/models
GET https://openrouter.ai/api/v1/model/{author}/{slug}
```

Esses endpoints permitem descobrir modelos, contexto, preco, parametros suportados e disponibilidade.

### Seletor de modelos OpenRouter

O seletor nao deve ser hardcoded para sempre. Ele deve:

1. Buscar `GET /api/v1/models` no inicio da sessao.
2. Cruzar modelos disponiveis com uma lista de preferencias do GHOSTRECON.
3. Mostrar os modelos recomendados como botoes/presets rapidos.
4. Mostrar tambem **todos os modelos retornados pelo OpenRouter** em lista pesquisavel/filtravel.
5. Mostrar apenas modelos realmente disponiveis na conta/API no momento.
6. Permitir model id manual.
7. Salvar a escolha na run auto para reproducibilidade.

Snapshot de recomendacoes iniciais consultadas na API do OpenRouter em 2026-07-05:

| Preset | Modelos candidatos | Uso |
| --- | --- | --- |
| Melhor geral | `openai/gpt-5.5-pro`, `anthropic/claude-sonnet-5`, `~openai/gpt-latest`, `~anthropic/claude-sonnet-latest` | Lider do modo auto quando custo nao for a principal restricao. |
| Reasoning profundo | `openai/gpt-5.5-pro`, `anthropic/claude-opus-4.8`, `anthropic/claude-opus-4.8-fast`, `~openai/gpt-latest` | Planejamento complexo, analise de cadeia de ataque, avaliacao de lacunas. |
| Coding / Module Forge | `moonshotai/kimi-k2.7-code`, `openai/gpt-5.5-pro`, `anthropic/claude-sonnet-5`, `z-ai/glm-5.2`, `qwen/qwen3.7-max` | Criar modulos, testes, parsers, normalizadores e refatoracoes. |
| Custo-beneficio | `z-ai/glm-5.2`, `qwen/qwen3.7-plus`, `qwen/qwen-plus`, `google/gemini-3.1-flash-lite`, `~openai/gpt-mini-latest` | Iteracoes frequentes, avaliacao barata, triagem inicial. |
| Maior contexto | `openrouter/auto`, `~openai/gpt-latest`, `z-ai/glm-5.2`, `~google/gemini-pro-latest`, `anthropic/claude-sonnet-5` | Ler runs grandes, logs, muitos findings e historico longo. |
| Gratuito/teste | modelos com sufixo `:free`, quando retornados por `/api/v1/models` | Testes de integracao, smoke tests e desenvolvimento. |
| Auto Router | `openrouter/auto` ou `openrouter/fusion` | Deixar o OpenRouter escolher/combinar modelos conforme disponibilidade. |

Regra: se um modelo recomendado nao existir na resposta de `/api/v1/models`, esconder da UI e usar o proximo candidato do preset.

Exemplo de prompt no CLI:

```text
OpenRouter selecionado.

Escolha o modelo:
1. Melhor geral: openai/gpt-5.5
2. Premium reasoning: openai/gpt-5.5-pro
3. Coding / Module Forge: moonshotai/kimi-k2.7-code
4. Custo-beneficio: z-ai/glm-5.2
5. Maior contexto: openrouter/auto
6. Claude reasoning: anthropic/claude-opus-4.8
7. Ver todos os modelos
8. Manual: informar model id
```

### Modelos que devem aparecer como opcoes rapidas

Quando estes modelos estiverem presentes na resposta da API, eles devem aparecer como botoes/opcoes rapidas no seletor OpenRouter:

```text
openai/gpt-5.5-pro
openai/gpt-5.5
~openai/gpt-latest
openai/gpt-chat-latest
anthropic/claude-sonnet-5
~anthropic/claude-sonnet-latest
anthropic/claude-opus-4.8
anthropic/claude-opus-4.8-fast
moonshotai/kimi-k2.7-code
z-ai/glm-5.2
qwen/qwen3.7-max
qwen/qwen3.7-plus
qwen/qwen-plus
~google/gemini-pro-latest
google/gemini-3.5-flash
google/gemini-3.1-flash-lite
x-ai/grok-4.3
deepseek/deepseek-r1
deepseek/deepseek-chat
openrouter/auto
openrouter/fusion
```

Mas o operador deve poder abrir "todos os modelos" e escolher qualquer um dos modelos retornados por `/api/v1/models`.

Exemplo de configuracao gravada na run:

```json
{
  "commander": "openrouter",
  "openrouter": {
    "preset": "coding",
    "model": "moonshotai/kimi-k2.7-code",
    "fallbackModels": [
      "anthropic/claude-sonnet-5",
      "z-ai/glm-5.2",
      "openrouter/auto"
    ]
  }
}
```

### Variaveis sugeridas

```env
OPENROUTER_API_KEY=
GHOSTRECON_OPENROUTER_ENABLED=1
GHOSTRECON_OPENROUTER_BASE_URL=https://openrouter.ai/api/v1
GHOSTRECON_OPENROUTER_DEFAULT_MODEL=anthropic/claude-sonnet-4.6
GHOSTRECON_OPENROUTER_FALLBACK_MODEL=openai/gpt-5.2
GHOSTRECON_OPENROUTER_LOW_COST_MODEL=openrouter/auto
GHOSTRECON_OPENROUTER_MODEL_PRESET=best-general
GHOSTRECON_OPENROUTER_ALLOWED_MODELS=
GHOSTRECON_OPENROUTER_APP_TITLE=GHOSTRECON Auto Mode
GHOSTRECON_OPENROUTER_HTTP_REFERER=http://127.0.0.1:3847
```

### Papel do OpenRouter

| Tarefa | Uso recomendado |
| --- | --- |
| Planner cloud | Gerar plano JSON quando Skynet/Claude/Codex local nao estiverem disponiveis. |
| Fallback | Repetir plano com outro modelo se o comandante falhar. |
| Model router | Escolher modelo por custo, contexto, tool calling ou reasoning. |
| Evaluator | Revisar findings e decidir proxima iteracao. |
| Code reviewer | Revisar modulo gerado, mas nao editar arquivos diretamente. |

No modo multi-IA, OpenRouter pode ter papeis diferentes por modelo:

```text
OpenRouter + Codex
  OpenRouter: planner/evaluator cloud
  Codex: implementa modulos e roda testes

OpenRouter + Skynet
  Skynet: lider local e memoria
  OpenRouter: segunda opiniao ou fallback quando Skynet falhar

OpenRouter + Claude Code + Codex
  Claude Code: estrategia profunda local/CLI
  OpenRouter: consulta externa/modelo alternativo
  Codex: module forge
```

## Integracoes pesquisadas

### Codex

Fontes oficiais indicam que Codex pode ser usado via:

- `codex exec` para automacao nao interativa.
- `codex exec --json` para eventos JSONL.
- `--output-schema` para respostas estruturadas.
- SDK TypeScript `@openai/codex-sdk`.
- SDK Python `openai-codex`.
- `codex app-server` via JSON-RPC.
- MCP servers configurados no `config.toml`.

Uso recomendado no GHOSTRECON:

- Module Forge.
- Edicao de codigo.
- Criacao de testes.
- Refatoracao do core.
- Revisao de diffs.
- Saida estruturada para planos quando usado como comandante.

### Claude Code

Fontes oficiais indicam que Claude Code:

- Le o codebase, edita arquivos, roda comandos e integra ferramentas.
- Possui CLI `claude`, `claude -p`, continuidade de sessoes e background agents.
- Tem Agent SDK para workflows customizados.
- Suporta MCP, memorias, hooks, skills e subagents.

Uso recomendado no GHOSTRECON:

- Lider tatico de planejamento profundo.
- Revisor de planos.
- Analise de arquitetura.
- Revisao de modulos criados pelo Codex.
- Subagents para investigar areas diferentes em paralelo.

### Cursor

Fontes oficiais indicam que Cursor possui:

- Cursor CLI.
- Headless CLI para automacao.
- MCP no CLI.
- ACP, Agent Client Protocol, para clientes customizados.
- Configuracao de MCP por `.cursor/mcp.json`.

Uso recomendado no GHOSTRECON:

- Provider opcional.
- Human-in-loop no IDE.
- Revisao visual.
- Uso de MCP HexStrike no ambiente Cursor.
- Automacao via CLI/headless quando o binario `agent` estiver disponivel.

Observacao: nesta maquina foi encontrado `cursor.cmd`, mas nao foi encontrado `agent` no PATH. O detector deve separar "Cursor IDE instalado" de "Cursor Agent CLI disponivel".

### Skynet

Skynet ainda sera definida como IA propria/futura. No Modo Auto ela deve ser uma interface local padronizada, nao um acoplamento direto a um modelo especifico.

Contrato sugerido:

```text
POST http://127.0.0.1:8000/v1/chat/completions
OpenAI-compatible
```

Funcoes:

- Comandante local.
- Memoria privada.
- Planner padrao.
- Evaluator.
- Consulta ao Cortex/Ghost KB.

### GLM local ou outro modelo local

Nao amarrar o projeto a um nome fixo. Criar provider generico `local-openai-compatible`.

Variaveis:

```env
GHOSTRECON_LOCAL_MODEL_ENABLED=1
GHOSTRECON_LOCAL_MODEL_BASE_URL=http://127.0.0.1:8001/v1
GHOSTRECON_LOCAL_MODEL_NAME=glm-4.5-air
GHOSTRECON_LOCAL_MODEL_ROLE=planner,evaluator
```

Se futuramente existir GLM 5.5 local, basta trocar o `MODEL_NAME`.

## Componentes novos no repositorio

Estrutura sugerida:

```text
server/
  auto-agent/
    orchestrator.mjs
    provider-detector.mjs
    provider-router.mjs
    council.mjs
    tool-catalog.mjs
    planner.mjs
    executor.mjs
    evaluator.mjs
    run-memory.mjs
    module-forge.mjs
    schemas.mjs
    policy.mjs
    providers/
      codex.mjs
      claude-code.mjs
      cursor.mjs
      skynet.mjs
      local-openai.mjs
      openrouter.mjs
  integrations/
    hexstrike-client.mjs
    hexstrike-mcp.mjs
  modules/
    dynamic/
      pending/
      approved/
    hexstrike-orchestrator.mjs
  routes/
    auto.mjs
```

## Provider Detector

Detecta quais comandantes existem:

```text
codex --version
claude --version
cursor --version
agent --version
GET Skynet /health
GET local model /models
GET OpenRouter /api/v1/models com OPENROUTER_API_KEY
```

Saida esperada:

```json
{
  "codex": {
    "available": true,
    "roles": ["planner", "codegen", "module_forge", "review"]
  },
  "claudeCode": {
    "available": false,
    "roles": ["planner", "deep_review", "subagents"]
  },
  "cursor": {
    "available": true,
    "agentCli": false,
    "roles": ["ide_review", "human_in_loop"]
  },
  "skynet": {
    "available": false,
    "roles": ["local_planner", "memory", "private_reasoning"]
  },
  "openrouter": {
    "available": true,
    "roles": ["cloud_planner", "fallback", "model_router"]
  }
}
```

## Tool Catalog

O planner deve receber um catalogo unificado:

```json
{
  "ghostModules": [],
  "kaliTools": {},
  "hexstrike": {},
  "hexstrikeMcp": {},
  "vigolium": {},
  "externalPacks": [],
  "playbooks": [],
  "pastRuns": [],
  "forgedModules": [],
  "opsec": {},
  "scope": {}
}
```

Fontes:

- `listModuleManifests()`
- `getKaliCapabilities()`
- `getVigoliumCapabilities()`
- `listExternalToolPacks()`
- `listPlaybooks()`
- `listRuns()`
- `hexstrike /health`
- `server/modules/dynamic/approved`

## Plano JSON do comandante

Toda IA comandante deve responder em JSON validado por schema:

```json
{
  "iteration": 1,
  "leader": "skynet",
  "assistants": ["codex", "openrouter"],
  "hypothesis": "O alvo parece expor API GraphQL com possivel IDOR.",
  "ghostrecon": {
    "modules": ["graphql_recon", "openapi_harvest", "authz_matrix"],
    "profile": "stealth",
    "kaliMode": false
  },
  "hexstrike": {
    "enabled": true,
    "calls": [
      {
        "path": "/api/intelligence/analyze-target",
        "payload": {
          "target": "api.example.com",
          "analysis_type": "comprehensive"
        }
      }
    ]
  },
  "forge": {
    "enabled": false,
    "reason": ""
  },
  "stop": {
    "maxMinutes": 45,
    "stopIfNoNewFindingsForIterations": 2
  }
}
```

## Endpoint do Modo Auto

```text
POST /api/recon/auto/stream
```

Payload:

```json
{
  "domain": "alvo-autorizado.com",
  "engagementId": "eng_123",
  "maxIterations": 8,
  "selectedCommanders": ["skynet", "codex", "openrouter"],
  "leaderMode": "auto",
  "hexstrike": true,
  "hexstrikeMcp": false,
  "forgeModules": true,
  "forgeRequireApproval": true,
  "opsecProfile": "stealth"
}
```

Eventos NDJSON:

```text
agent_detected
agent_team
agent_plan
agent_tool
hexstrike_call
pipeline_run
finding
evaluation
module_forge_requested
module_forged
module_test
done
```

## HexStrike no Node

Criar `server/integrations/hexstrike-client.mjs` para o Node falar diretamente com HexStrike:

```text
GET  /health
GET  /api/telemetry
POST /api/intelligence/analyze-target
POST /api/intelligence/select-tools
POST /api/intelligence/technology-detection
POST /api/bugbounty/reconnaissance-workflow
POST /api/tools/<tool>
```

Evitar liberar `/api/command` como primeira versao. Quando necessario, criar wrappers explicitamente aprovados.

## Module Forge

Module Forge e o mecanismo de auto-melhoria.

Quando ativar:

- Ferramenta falhou repetidamente no mesmo padrao.
- IA detectou classe de vulnerabilidade sem modulo.
- Reporter marcou finding como "sem cobertura automatica".
- HexStrike encontrou algo recorrente que o GHOSTRECON nao normaliza.

Fluxo:

1. Criar modulo em `server/modules/dynamic/pending/<slug>.mjs`.
2. Criar teste em `server/tests/dynamic/<slug>.test.js`.
3. Rodar apenas o teste novo.
4. Se passar, mover para `approved`.
5. Dynamic loader carrega no proximo refresh/boot.
6. Modulo aparece em `/api/capabilities`.
7. Planner pode selecionar nas proximas runs.

## Dynamic Registry

Hoje o registry e estatico. Para o Forge funcionar, criar:

```text
server/modules/module-registry-dynamic.mjs
```

Responsabilidades:

- Ler `server/modules/dynamic/approved/*.mjs`.
- Importar dinamicamente.
- Validar `moduleManifest`.
- Expor manifestos em `/api/capabilities`.
- Bloquear modulo sem teste aprovado.
- Bloquear modulo com imports proibidos ou execucao direta fora do runner.

## Politicas de seguranca e controle

Mesmo rodando somente local:

- Respeitar escopo e engagement.
- Evitar duplicar scans pesados em paralelo.
- Usar mutex por alvo.
- Separar modo passivo, standard e agressivo.
- Todo plano da IA deve passar por schema e policy.
- HexStrike `/api/command` deve ficar bloqueado por padrao.
- Module Forge deve comecar com aprovacao humana.
- Logs nao devem salvar segredos em claro.
- OpenRouter deve ser opt-in porque envia dados para cloud.

## Roadmap de implementacao

### Fase 0 - Documento e fundacao

- [x] Criar este documento.
- [x] Criar `server/integrations/hexstrike-client.mjs`.
- [x] Adicionar `hexstrike` em `/api/capabilities`.
- [x] Criar detector inicial de providers.
- [x] Corrigir path do HexStrike para procurar tambem `IAs/hexstrike-ai`.

### Fase 1 - Auto basico

- [x] Criar `server/auto-agent/provider-detector.mjs`.
- [x] Criar `server/auto-agent/tool-catalog.mjs`.
- [ ] Criar `server/auto-agent/providers/openrouter.mjs`.
- [ ] Criar `server/auto-agent/providers/skynet.mjs`.
- [x] Criar `server/auto-agent/planner.mjs`.
- [x] Criar `POST /api/recon/auto/stream`.
- [ ] Criar CLI `ghostrecon auto --target`.
- [x] Executar loop `observe -> plan -> act -> evaluate`.

Implementado em 2026-07-05:

- `server/auto-agent/provider-detector.mjs`: detecta Codex, Claude Code, Cursor, Skynet, modelo local e OpenRouter.
- `server/auto-agent/tool-catalog.mjs`: monta catalogo inicial de modulos GHOSTRECON + HexStrike intelligence.
- `server/auto-agent/planner.mjs`: cria plano conservador, sem modulos intrusivos por padrao.
- `server/auto-agent/orchestrator.mjs`: executa `observe -> plan -> act -> evaluate` chamando `runPipeline`.
- `server/routes/auto-recon.mjs`: expoe `POST /api/recon/auto/stream` em NDJSON.
- `.env.example`: adiciona variaveis de Modo Auto / HexStrike.

### Fase 2 - Equipe de comandantes

- [ ] Criar `provider-router.mjs`.
- [ ] Criar `council.mjs`.
- [ ] Integrar Codex via `codex exec --json` ou SDK.
- [ ] Integrar Claude Code via `claude -p` ou Agent SDK.
- [ ] Integrar Cursor CLI/headless quando `agent` estiver disponivel.
- [x] Permitir selecionar uma ou varias IAs na UI.

Implementado em 2026-07-05:

- `public/index.html`: adiciona botao `AUTO MODE` ao lado do `RUN RECON` na UI principal, com pop-up para escolher comandantes, modelo OpenRouter, HexStrike e deep passive.
- `ghost-local-v5/ghost-local/frontend/index.html`: adiciona botao `AUTO` na aba GHOSTRECON, card de status e pop-up de selecao.
- O pop-up pergunta alvo, modo (`quick`, `balanced`, `deep`), IAs comandantes e modelo OpenRouter.
- `ghost-local-v5/ghost-local/backend/main.py`: adiciona proxy `/ghostrecon/auto/stream` para chamar o Node em `/api/recon/auto/stream`.

### Fase 3 - HexStrike profundo

- [x] Criar modulo `hexstrike_orchestrator`.
- [x] Normalizar outputs HexStrike para findings GHOSTRECON.
- [x] Criar allowlist inicial por endpoint seguro.
- [ ] Integrar HexStrike MCP como opcional.
- [x] Criar `.cursor/mcp.json` ou guia para Cursor usar `hexstrike_mcp.py`.
- [ ] Criar config Codex/Claude para MCP HexStrike.

Implementado em 2026-07-05:

- `server/modules/hexstrike-orchestrator.mjs`: chama `/api/intelligence/analyze-target` e `/api/intelligence/select-tools`.
- `server/modules/module-registry.mjs`: registra `hexstrike_orchestrator` como modulo do arsenal.
- `server/modules/module-registry-runners.mjs`: adiciona runner do modulo.
- `server/pipeline/phases/validation.mjs`: dispara o modulo quando selecionado.
- `server/tests/hexstrike-orchestrator.test.js`: cobre normalizacao, runner offline e registry.
- `.cursor/mcp.json`: registra o HexStrike MCP local para o Cursor.

### Fase 4 - Module Forge

- [ ] Criar `server/modules/dynamic/pending`.
- [ ] Criar `server/modules/dynamic/approved`.
- [ ] Criar dynamic loader.
- [ ] Criar `module-forge.mjs`.
- [ ] Criar testes automaticos para modulos gerados.
- [ ] Criar UI de aprovacao.
- [ ] Salvar aprendizados em Cortex e playbooks auto-learned.

### Fase 5 - Operacao madura

- [ ] Dashboard de iteracoes auto.
- [ ] Comparar custo/latencia/qualidade por comandante.
- [ ] Aprender quais IAs funcionam melhor por tarefa.
- [ ] Relatorio final com cadeia de decisoes.
- [ ] Exportar plano, comandos, findings, evidencias e modulos criados.

## Configuracao sugerida

```env
# Modo Auto
GHOSTRECON_AUTO_ENABLED=1
GHOSTRECON_AUTO_MAX_ITERATIONS=8
GHOSTRECON_AUTO_DEFAULT_LEADER=auto
GHOSTRECON_AUTO_COMMANDERS=codex,claude-code,cursor,skynet,openrouter
GHOSTRECON_AUTO_FORGE=0
GHOSTRECON_AUTO_FORGE_REQUIRE_APPROVAL=1

# HexStrike
GHOST_HEXSTRIKE_URL=http://127.0.0.1:8888
GHOST_START_HEXSTRIKE=1
HEXSTRIKE_PORT=8888

# Codex
GHOSTRECON_CODEX_BIN=codex
GHOSTRECON_CODEX_MODE=exec

# Claude Code
GHOSTRECON_CLAUDE_CODE_BIN=claude

# Cursor
GHOSTRECON_CURSOR_BIN=cursor
GHOSTRECON_CURSOR_AGENT_BIN=agent

# Skynet / modelo local
GHOSTRECON_SKYNET_URL=http://127.0.0.1:8000/v1/chat/completions
GHOSTRECON_LOCAL_MODEL_BASE_URL=http://127.0.0.1:8001/v1
GHOSTRECON_LOCAL_MODEL_NAME=glm-4.5-air

# OpenRouter
OPENROUTER_API_KEY=
GHOSTRECON_OPENROUTER_ENABLED=1
GHOSTRECON_OPENROUTER_BASE_URL=https://openrouter.ai/api/v1
GHOSTRECON_OPENROUTER_DEFAULT_MODEL=anthropic/claude-sonnet-4.6
GHOSTRECON_OPENROUTER_FALLBACK_MODEL=openai/gpt-5.2
GHOSTRECON_OPENROUTER_LOW_COST_MODEL=openrouter/auto
```

## Criterios de sucesso

- O operador consegue ativar Modo Auto e escolher uma ou varias IAs.
- O sistema mostra apenas comandantes disponiveis.
- Uma IA escolhida consegue gerar um plano JSON valido.
- O GHOSTRECON valida o plano contra escopo, OPSEC e capabilities.
- O executor roda GHOSTRECON e HexStrike sem duplicar acoes pesadas.
- Findings de HexStrike entram normalizados no resultado final.
- O evaluator decide continuar/parar com base em findings novos.
- Module Forge cria um modulo pequeno, testavel e aprovado.
- Modulo aprovado aparece em `/api/capabilities`.

## Fontes oficiais consultadas

- OpenAI Codex Manual: https://developers.openai.com/codex/codex-manual.md
- OpenRouter Quickstart: https://openrouter.ai/docs/quickstart
- OpenRouter API Reference: https://openrouter.ai/docs/api/reference/overview
- OpenRouter Authentication: https://openrouter.ai/docs/api/reference/authentication
- OpenRouter Models API: https://openrouter.ai/docs/guides/overview/models
- Claude Code Overview: https://code.claude.com/docs/en/overview
- Claude Code CLI Reference: https://code.claude.com/docs/en/cli-reference
- Claude Code Agent SDK: https://code.claude.com/docs/en/agent-sdk/overview
- Cursor CLI: https://cursor.com/docs/cli/overview
- Cursor Headless CLI: https://cursor.com/docs/cli/headless
- Cursor MCP: https://cursor.com/docs/mcp.md
- GLM-4.5: https://github.com/zai-org/GLM-4.5
