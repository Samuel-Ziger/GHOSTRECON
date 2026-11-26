# NeuroSploit no GHOSTRECON

O NeuroSploit foi incorporado como **motor de backend** da GhostIA. A interface
web original do projeto não foi importada: configuração, autorização,
acompanhamento, findings e artefatos ficam no cockpit React do GHOSTRECON.

O código importado vive em `engines/neurosploit/`; `.git`, runs e demais
estados da cópia de origem não fazem parte da integração. O projeto original
ao lado do GHOSTRECON permanece intacto.

## Fluxo

```text
Operador
   |
   v
GhostIA / NeuroSploit (React)
   |
   | RBAC + CSRF + ownership + engagement/ROE
   v
API GHOSTRECON /api/neurosploit/*
   |
   | processo isolado por job + token Artex temporário no ambiente
   v
NeuroSploit Rust ---- OpenAI-compatible ----> ponte interna Artex --> API GhostIA
   |
   `---- subscription CLI ----> codex exec --> MCPs selecionados
   v
artefatos privados + findings normalizados --> Cortex
```

O NeuroSploit não mantém um segundo cadastro de chaves. A seleção de modelo
lista os perfis existentes no Artex:

- perfis de API usam a credencial já guardada no cofre do GhostIA;
- perfis `chatgpt-plan` podem usar a ponte normal ou o **Codex CLI** local;
- quando `Codex CLI` está desligado, o backend do Artex converte o perfil para a
  interface compatível consumida pelo NeuroSploit;
- quando `Codex CLI` está ligado, o NeuroSploit chama `codex exec` diretamente e
  não recebe token Artex nem `OPENAI_API_KEY`;
- chave do provider e refresh token Codex não são enviados ao GHOSTRECON ou ao
  NeuroSploit.

No caminho API, o filho recebe somente uma sessão curta do Artex em
`LITELLM_API_KEY`, no seu ambiente. Ela não entra em argv, snapshot, finding,
log ou resposta HTTP. O endpoint genérico usado é
`/api/internal/llm/profiles/:id/v1/chat/completions`.

No caminho Codex, o seletor oferece Mind e os outros MCPs já cadastrados no
`CODEX_HOME`, além de launchers gerenciados do GHOSTRECON. Mind nunca é iniciado
pelo Node, HackBot ou NeuroSploit: o processo Codex lê sua própria configuração
e recebe apenas um override `enabled` para aquela execução. O plano Auto congela
`codexCli` e a lista `mcpServers` no hash antes de executar.

## Modos suportados

| Modo | Entrada | Gate adicional |
| --- | --- | --- |
| `run` | URL/host web | engagement formal e `recon.intrusive` |
| `greybox` | URL/host + repositório | engagement formal e `recon.intrusive` |
| `host` | host autorizado | engagement formal e `recon.intrusive` |
| `aitest` | endpoint de IA autorizado | engagement formal e `recon.intrusive` |
| `whitebox` | caminho local ou repositório HTTPS permitido | raiz local permitida |
| `mobile` | artefato local | raiz local permitida; URL remota recusada |
| `container` | nome da imagem | execução local |
| `skills` | caminho ou repositório permitido | raiz local permitida |

Modos de rede exigem confirmação explícita, referência da autorização,
engagement ativo, alvo dentro do escopo, janela válida e ROE. O GHOSTRECON
recusa a execução antes de criar o processo quando qualquer gate falha.

## Como usar

1. Inicie a stack e abra `http://127.0.0.1:3847/ghostia.html`.
2. Em **Chat Artex**, crie/teste um perfil de API ou conecte o ChatGPT
   Plan/Codex.
3. Abra a aba **NeuroSploit**.
4. Se quiser Mind/MCP, selecione um perfil `ChatGPT Plan`, marque **Executar pelo
   Codex CLI local** e escolha **Mind · Codex pessoal**. Sem essa opção, o
   perfil continua usando a ponte Artex.
5. Selecione modo e entradas. Para rede, selecione também um engagement
   formal ativo e confirme a autorização.
6. Acompanhe fases, logs redigidos, findings, sincronização com Cortex e
   artefatos na mesma tela.

Perfis sem chave ou Codex desconectado aparecem indisponíveis e também são
recusados no servidor. Isso impede contornar a UI com uma chamada direta.

## Uso no Modo Auto

O modal **Auto Mode** agora seleciona o NeuroSploit diretamente. A antiga
tarefa Auto do Artex e as rotas `/api/artex/auto/*` foram removidas. O fluxo é:

1. o GHOSTRECON monta e hashia o plano efetivo, incluindo a identidade SHA-256
   do binário NeuroSploit, `codexCli`, a allowlist MCP e a configuração sem
   credenciais;
2. o operador aprova o plano intrusivo vinculado ao engagement;
3. GHOSTRECON, Vigolium e FrameSeven terminam suas coletas selecionadas;
4. o NeuroSploit recebe `auto-context.json` redigido com plano, outcomes e
   evidências já observadas, evitando repetir coleta sem justificativa;
5. logs e findings retornam no mesmo NDJSON, entram na avaliação Auto e são
   sincronizados com o Cortex;
6. cancelar a sessão Auto encerra também o grupo de processo NeuroSploit.

O perfil API/Codex continua sendo resolvido pelo cofre do GhostIA. O Artex é
usado como ponte OpenAI-compatible temporária somente quando `Codex CLI` está
desligado; ele não cria tarefa, gate, monitor ou relatório Auto paralelo.

## Build e teste

```bash
npm run neurosploit:build
npm run neurosploit:test
npm run ui:typecheck
npm run ui:build
node --test server/tests/neurosploit-integration.test.js
```

No boot, `scripts/start-stack.mjs` tenta recompilar com Cargo em modo offline
quando o binário está ausente ou mais antigo que as fontes. Caso o cache local
não contenha todas as crates, execute `npm run neurosploit:build` uma vez com
acesso à rede. Defina `GHOSTRECON_STACK_NEUROSPLOIT=0` para desativar essa
verificação.

## Estado, retomada e Cortex

Cada job recebe um diretório privado em `.runtime/neurosploit/jobs/<id>`.
Snapshots usam permissão `0600`; o diretório usa `0700`. Os modos REPL
`run`, `whitebox` e `greybox` podem ser pausados e retomados. Depois de reiniciar
a API, um job interrompido fica marcado como retomável, mas precisa novamente
de um perfil pronto. A nova sessão Artex é exigida somente no caminho API.

Findings emitidos pelo motor são normalizados e enviados para validações
manuais/Cortex com proveniência de job, run, modelo, agente, votos, CWE,
severidade e evidência redigida. Validação do motor não é convertida em
validação humana.

## Controles de segurança

- `ai.run` em todas as rotas operacionais;
- `recon.run` para iniciar/retomar;
- `recon.intrusive` para modos de rede;
- CSRF em criação, controle e retomada;
- jobs, logs e artefatos vinculados ao proprietário;
- allowlist de extensões e contenção de caminho no download;
- caminhos locais limitados à raiz do GHOSTRECON, salvo allowlist explícita;
- repositórios remotos restritos a HTTPS em GitHub/GitLab;
- MCP selecionado precisa existir no catálogo; ids desconhecidos falham antes
  da criação do processo;
- o Codex roda em sandbox `workspace-write`, sem o bypass perigoso de sandbox;
- nomes de MCP pessoal são descobertos sem ler ou copiar valores de credencial;
- redação central antes de persistir ou publicar eventos;
- processo separado e grupo de processo encerrável pelo operador.

Para analisar outra raiz local, use uma lista separada pelo delimitador do
sistema:

```dotenv
GHOSTRECON_NEUROSPLOIT_ALLOWED_ROOTS=/srv/codigo-autorizado:/opt/labs
```

Não aponte essa variável para `/` ou para uma home inteira.

## Limites atuais

- A ponte Artex precisa estar online durante execuções por API; no caminho
  `Codex CLI`, ela é usada apenas para listar/resolver o perfil antes do job.
- O relatório e os parsers preservam o formato do NeuroSploit; novos marcadores
  upstream podem exigir atualização do adaptador.
- Pausa/retomada completa é oferecida somente nos modos REPL.
- O NeuroSploit usa os resultados dos módulos selecionados no plano Auto; ele
  não amplia o catálogo, o alvo ou o engagement aprovado.
