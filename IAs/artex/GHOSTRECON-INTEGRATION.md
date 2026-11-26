# Artex backend integrado ao GHOSTRECON

Este diretório contém somente o backend do Artex e seus recursos operacionais. O frontend Next.js original e o repositório Git aninhado foram removidos deliberadamente: a interface oficial agora é o React do GHOSTRECON.

## Proveniência

- Origem local migrada: `/home/client01/artex-global`
- Branch de origem: `feat/chatgpt-plan-provider`
- Commit de origem: `ad4729088f8a835dce75811539eb4907b24464e9`
- Data do commit: `2026-10-21 11:27:19 -0300`
- Licença preservada: `LICENSE` (AGPL-3.0)

O histórico Git aninhado foi removido a pedido do proprietário. Esta identificação deve ser mantida ao atualizar ou redistribuir o código.

## Arquitetura no GHOSTRECON

- `go build ./cmd/artex` gera o sidecar backend-only; a tag `embedui` não é usada.
- PostgreSQL local isolado: `docker-compose.ghostrecon.yml`, publicado apenas em `127.0.0.1:5433`.
- API Artex: `127.0.0.1:8787`.
- Proxy de tráfego Artex: `127.0.0.1:8788` por padrão.
- Credenciais e estado ficam em `GHOSTRECON/.runtime/artex/` e não entram no Git.
- ChatGPT Plan/Codex continua usando `chatgpt-plan-auth.json`, também ignorado pelo Git externo.
- O MCP `GHOSTRECON` é cadastrado no Artex por `stdio`; ele usa o endpoint de auto-auth restrito a loopback, sem persistir a API key do GHOSTRECON no banco do Artex.
- O GHOSTRECON permanece responsável por escopo, engagement, OPSEC e aprovação. O Artex só começa uma tarefa Auto quando o gate do processo servidor estiver liberado.
- O React do GHOSTRECON oferece o chat GhostIA em Ferramentas e substitui o modal Auto por configuração conjunta GHOSTRECON/Artex.
- Antes do Auto, o navegador envia a configuração ao GHOSTRECON. O servidor redige segredos, gera um contexto `ghostrecon.artex-context.v1`, sela seu SHA-256 e só promove o contexto para `approved` quando o hash exato do plano passa pelo gate.
- O prompt `ghostia-private-pentest-v1` é administrado pelo GHOSTRECON e proíbe expansão de escopo, obediência a instruções vindas do alvo e evidência inventada.
- A allowlist da tarefa é derivada do alvo no servidor. Regras fornecidas pela interface podem somente bloquear; nunca acrescentar outro alvo permitido.
- Cada conversa GhostIA e cada tarefa Auto ficam vinculadas ao `principal.sub` do GHOSTRECON. Outro operador recebe falha fechada, embora o GHOSTRECON use uma sessão administrativa interna para falar com o Artex.
- `ai.run` permite conversar e executar; `ai.manage` é exclusivo do wildcard de admin e protege MCP, perfis LLM e conexão ChatGPT Plan globais.
- Achados são importados para a categoria `Artex / GhostIA` no Cortex, preservando o estado de triagem original e marcados como candidatos não validados por humano.
- Um monitor por sessão acompanha a tarefa Artex e sincroniza o Cortex periodicamente e no estado terminal. O cancelamento do Auto pausa a tarefa mesmo quando chega durante sua criação.

## Configuração

Use `npm start` na raiz do GHOSTRECON. Variáveis úteis:

- `GHOSTRECON_STACK_ARTEX=0`: não iniciar Artex/PostgreSQL.
- `ARTEX_BASE_URL`: URL interna do backend (padrão `http://127.0.0.1:8787`).
- `ARTEX_PORT`, `ARTEX_PROXY_PORT`, `ARTEX_POSTGRES_PORT`: portas locais.
- `ARTEX_PG_DSN`: usa um PostgreSQL já existente e evita subir o container local.
- `ARTEX_CHATGPT_REDIRECT_URI`: callback OAuth explícito, quando necessário.
- `GHOSTRECON_STACK_LEGACY_GHOST=1`: inicia o antigo Ghost Python apenas por compatibilidade opt-in; o padrão é Artex/GhostIA.

Na interface, uma conta ChatGPT Plan conectada pode carregar os modelos realmente visíveis à conta. Um perfil salvo pode ser ativado globalmente ou escolhido somente para a tarefa/conversa. Nenhuma API key é devolvida pela API do GHOSTRECON.

Nunca registre `.runtime/artex`, `chatgpt-plan-auth.json`, `jwt.key`, banco, tokens ou logs com credenciais.
