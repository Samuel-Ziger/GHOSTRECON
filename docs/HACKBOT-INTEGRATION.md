# HackBot no GHOSTRECON

## O que foi reaproveitado

O GHOSTRECON usa o backend do HackBot em `IAs/hackbot` e não o reimplementa.
Foram preservados:

- orquestrador opcional;
- especialistas `researcher`, `analyst`, `document_analyst` e `tutor`;
- contratos tipados `ResearchBrief`, `TriageReport` e `DocumentReport`;
- ferramentas MCP de pesquisa, CWE, SARIF e documentos;
- clientes/servidor ACP e configuração de MCPs externos;
- histórico de sessões e árvore de tracing;
- limites de uso e regras defensivas do projeto original.

A TUI permanece como referência de comportamento. A interface principal fica em
**GhostIA → Multiagentes**; `/hackbot.html` continua como fallback técnico.

## Fluxo

```text
React GhostIA / Multiagentes
  -> API Node /api/hackbot/* (auth + RBAC + CSRF + ownership)
    -> adaptador loopback :8791 (token interno)
      -> agente escolhido
        -> AgentSystem do HackBot + perfil GhostIA/Artex
        `-> codex exec + login local + MCPs selecionados para aquele agente
```

O orquestrador não é obrigatório. Uma conversa pode chamar qualquer
especialista diretamente, preservando o princípio de menor privilégio das
ferramentas de cada agente.

## Modelos por agente

O arquivo `.runtime/hackbot/model-bindings.json` contém somente:

- nome do modelo;
- origem (`direct`, `artex` ou `codex-cli`);
- id do perfil GhostIA, quando usado;
- URL e nome da variável de ambiente somente no modo direto;
- ids dos MCPs habilitados naquela instância Codex, sem comandos, ambiente ou
  credenciais.

Valores de chaves não são gravados nele nem devolvidos pela API. No modo
`artex`, o HackBot recebe uma sessão local curta e chama um bridge autenticado;
a chave do provider e o refresh token do Codex permanecem no Artex. O painel
lista automaticamente os perfis cadastrados no GhostIA e também presets para
OpenAI, OpenRouter/Claude, DeepSeek, Kimi/Moonshot, GLM/Z.AI e Mistral.

No modo `codex-cli`, cada função do HackBot abre uma execução independente do
`codex exec`. Isso permite, por exemplo, configurar o Pesquisador com
`Mind · Codex pessoal` e o Analista com o mesmo modelo, mas sem Mind. O catálogo
lê somente os nomes das tabelas `mcp_servers` do `CODEX_HOME`; comando, args,
`MIND_KEY` e demais valores nunca são copiados para o GHOSTRECON. Por execução,
o GHOSTRECON passa apenas `mcp_servers.<nome>.enabled=true|false` ao Codex.

O painel também traz os seguintes candidatos locais, mas não os baixa nem
afirma que estão instalados:

| Agente | Candidato inicial | Motivo |
|---|---|---|
| Orquestrador | Qwen3-4B-Instruct-2507 Q4_K_M | contexto e síntese geral |
| Pesquisador | Qwen3.5-2B Q4_K_M | consultas focadas e curtas |
| Analista SARIF | Foundation-Sec-1.1-8B-Instruct Q4_K_M | triagem de vulnerabilidades |
| Analista de documentos | Qwen2.5-Coder-1.5B Q4_K_M | código, logs e configuração |
| Tutor | Qwen3.5-2B Q4_K_M | explicações com menor custo |

WhiteRabbitNeo-2.5-Qwen-Coder-7B fica no catálogo como candidato experimental
para comparação nas funções de pesquisa e análise. A escolha só deve virar
padrão depois de avaliação com o mesmo conjunto de casos e métricas.

## Operação

1. Em uma instalação nova, execute `npm run hackbot:sync` para materializar o
   ambiente exatamente como fixado em `IAs/hackbot/uv.lock`.
2. Execute `npm start`. A stack inicia o adaptador em loopback e gera um token
   interno com permissão `0600`.
3. Abra `http://127.0.0.1:3847/ghostia.html` e selecione **Multiagentes**.
4. Em **Modelos**, escolha para cada agente um perfil já salvo no GhostIA. Isso
   reutiliza inclusive **OpenAI API** e **ChatGPT Plan / Codex**. O modo
   **Personalizado** continua disponível para endpoints OpenAI-compatible e
   modelos locais.
5. Para usar o Mind, escolha **Codex CLI · MCPs selecionáveis** no agente,
   marque **Mind · Codex pessoal** e salve. Para outro agente Codex sem Mind,
   deixe essa caixa desmarcada.
6. Em **Chat**, escolha o orquestrador ou um especialista e envie a mensagem.
7. Para análise de arquivo, informe um caminho dentro de `reports/`, `logs/`,
   `.runtime/` ou `IAs/hackbot/samples/` e selecione documento ou SARIF.

ACP e os MCPs do runtime Pydantic continuam disponíveis pelas variáveis
originais `HACKBOT_ACP_URL` e `HACKBOT_MCP_CONFIG`. No caminho Codex, a API web
aceita somente ids descobertos no `CODEX_HOME` ou launchers fixos gerenciados
pelo GHOSTRECON. Seleções desconhecidas são recusadas; a API não aceita comando
MCP arbitrário.

## Decisões de segurança

- sidecar somente em loopback;
- token interno separado da autenticação do operador;
- bridge de inferência do Artex autenticado e limitado a `profile_id`, sem
  endpoint de leitura de chave;
- `ai.run` para conversar e `ai.manage` para alterar modelos;
- CSRF em todas as mutações;
- conversas isoladas pelo `sub` autenticado;
- caminhos de documentos limitados a raízes permitidas;
- erros e respostas de status redigem padrões de chave/token;
- `OPENAI_API_KEY` é removida do ambiente do `codex exec`, mantendo o login do
  plano Codex como origem explícita;
- o Codex roda em `workspace-write` e não usa bypass de sandbox;
- MCP pessoal permanece no Codex; o GHOSTRECON persiste somente a allowlist;
- uma execução simultânea por padrão, pois o servidor MCP upstream mantém o
  documento carregado em estado global;
- transporte MCP em processo como padrão estável; `HACKBOT_MCP_TRANSPORT=stdio`
  mantém o modo upstream disponível para diagnóstico.

## Próximas integrações

Cortex/RAG, memória compartilhada entre agentes e fine-tuning dos modelos
locais são fases posteriores. O baseline deve ser medido antes do fine-tuning
para separar ganho real de regressão ou overfitting.

Consulte `IAs/hackbot/UPSTREAM-NOTICE.md` antes de redistribuir: o checkout
importado não continha licença upstream identificável.
