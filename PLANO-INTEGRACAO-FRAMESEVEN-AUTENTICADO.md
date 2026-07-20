# Plano de integração FrameSeven + GHOSTRECON + Vigolium

## Prompt original do operador

```text
certo vamos fazer a integração do frameseven ok ? vamos usar ele com ./bin/frameseven/cli/v1 \
    -url  \
    -tools all \
    -auth-browser \
    -timeout 30s \
    -tool-timeout 5m \
    -concurrency 10 \
    -rate 100 \
    -verbose \
    -out reports/authenticated-full-scan

+eai nos temos no ghsot recon o auth opicional vamos deixar nele uma confirmação em forma de botão interruptor igual aos do projeto quando ele tiver marcado vamos usar o framesvene dessa forma quando não tiver ele não vai usaro auth-broswer, eai quando tiver mercado o ghsotreon deve usar isso tambem essa validação pra conseguir acessar o site e teste ele depois de logado tambem entendeu ? então quando isso tiver confirmado vai aparecer la aba do navegado vai colocar o usuario a senha tudo que foi coletado vai pro ghsotrecon usar e o vigolium tambem esses 3 motores vão usar isso o frameseven ja usa porque e dele eai so precisa passar o que foi coletado pros demais eai no frameservn quando coloca o usario e a senha voltamos pro  terminal e damos enter eai ele fecha o navegador, então quando colocar no ghsotrecon vai aparecer um pop-up que vai fazer o trabalho desse enter, mas ai vai rodar o ghsotrecon, vigolum e o frameseven nessa ordem, o vigolium e o seven agora vão roda como modulos obrigatorio so o vigolium que vai ter a opção de selecionar com o codex ou não eai quando o ghostrecon fizer o clone dos github o vigolium com o modo de fazer uma auditoria em codigo vai executar isso.
```

## Objetivo

Integrar o FrameSeven como executor autenticado opcional do GHOSTRECON, compartilhando o contexto de autenticação com GHOSTRECON e Vigolium, sem expor credenciais em logs, RAG, relatórios ou argumentos persistidos.

## Política de ativação

- Adicionar na UI um interruptor `FrameSeven autenticado` na seção principal de Auth opcional.
- Desligado: não usar `-auth-browser`; executar apenas o fluxo não autenticado.
- Ligado: iniciar o navegador autenticado do FrameSeven e exigir confirmação humana para concluir a coleta.
- O botão de confirmação substitui o `Enter` manual do CLI.
- A autenticação só pode ser usada em alvo autorizado e dentro do escopo informado.

## Fluxo autenticado

1. Operador informa o alvo e ativa `Autenticação opcional`.
2. GHOSTRECON inicia o FrameSeven com `-auth-browser` e os limites configurados.
3. FrameSeven abre a aba do navegador para login.
4. Operador insere usuário e senha diretamente no navegador; o GHOSTRECON não deve capturar nem armazenar a senha.
5. FrameSeven sinaliza que a sessão está pronta.
6. GHOSTRECON exibe um pop-up: `Autenticação concluída — fechar navegador e iniciar auditorias?`.
7. Ao confirmar, o navegador é encerrado de forma cooperativa e a sessão autenticada é exportada por referência segura.
8. Executar na ordem: GHOSTRECON, Vigolium, FrameSeven.
9. Encaminhar somente cookies/token temporários e metadados mínimos aos motores; nunca credenciais brutas.
10. Invalidar e apagar o contexto autenticado ao final, cancelamento ou timeout.

## Comando FrameSeven

```bash
./bin/frameseven/cli/v1 \
  -url <alvo> \
  -tools all \
  -auth-browser \
  -timeout 30s \
  -tool-timeout 5m \
  -concurrency 10 \
  -rate 100 \
  -verbose \
  -out reports/authenticated-full-scan
```

O comando deve ser montado pelo executor, não concatenado com entrada não validada do usuário. O alvo precisa passar pelo mesmo parser e gate de escopo do GHOSTRECON.

## Ordem dos motores

### 1. GHOSTRECON

- Recon e coleta inicial.
- Descoberta de endpoints, parâmetros e clones GitHub autorizados.
- Persistência de evidências sem segredos.

### 2. Vigolium

- Executado como módulo obrigatório da execução FrameSeven autenticada.
- Opção separada para permitir ou não que o Codex selecione/configure o Vigolium.
- Recebe apenas a referência segura da sessão autenticada.
- Quando houver clones GitHub, executar auditoria de código do Vigolium sobre cópias locais já autorizadas.

### 3. FrameSeven

- Executar `tools all` conforme catálogo e limites.
- Reutilizar a sessão autenticada criada pelo próprio fluxo.
- Gravar relatórios em diretório isolado por sessão.
- Emitir progresso, timeout, cancelamento e resumo normalizados para o GHOSTRECON.
- Regenerar o `report.html` original do FrameSeven com os findings deduplicados dos três motores.
- Abrir o relatório HTML integrado em uma nova aba ao final da execução comum.

## Compartilhamento de autenticação

- Criar um `AuthContext` temporário por sessão.
- Preferir arquivo/socket protegido ou mecanismo IPC; nunca passar senha na linha de comando.
- Permitir somente cookies, headers/token e origem/expiração necessários.
- Redigir `Authorization`, `Cookie`, senhas e tokens em logs, RAG, eventos e relatórios.
- Impedir reutilização entre alvos ou sessões.
- Limpar o contexto em `completed`, `cancelled`, `timeout` e reinício do servidor.

## Cancelamento e timeouts

- Cancelar o navegador e os três motores cooperativamente.
- Aplicar timeout separado para autenticação, GHOSTRECON, Vigolium e FrameSeven.
- Encerrar subprocessos descendentes se o cooperativo falhar.
- Registrar qual motor expirou e continuar somente quando for seguro fazê-lo.

## Contratos de integração

- `AuthContext`: estado, origem, expiração, cookies/token redigidos e referência IPC.
- `FrameSevenAdapter`: start, waitForAuth, confirmAuth, run, cancel, collectReport, cleanup.
- `VigoliumAdapter`: receber contexto seguro, executar auditoria web e auditoria de código.
- Eventos NDJSON: `auth_required`, `auth_ready`, `auth_confirmed`, `engine_started`, `engine_progress`, `engine_timeout`, `engine_done`, `auth_cleanup`.

## Critérios de aceite

- Toggle desligado nunca inicia `-auth-browser`.
- Toggle ligado sempre exige confirmação humana antes de fechar o navegador.
- Senha nunca aparece em processo, log, RAG ou relatório.
- GHOSTRECON, Vigolium e FrameSeven usam o mesmo contexto autenticado temporário.
- A ordem dos motores é respeitada.
- Cancelamento remove navegador, subprocessos e contexto autenticado.
- Timeout de um motor é identificado sem deixar processos órfãos.
- Clones GitHub são auditados pelo Vigolium somente quando autorizados e presentes.
- Testes cobrem login bem-sucedido, login recusado, timeout, cancelamento, sessão expirada e alvo fora do escopo.

## Fases de desenvolvimento

1. Validar CLI FrameSeven isoladamente e seu sinal de conclusão de autenticação.
2. Criar `FrameSevenAdapter` local, sem integração com alvos externos.
3. Adicionar toggle, pop-up e eventos de autenticação na UI.
4. Criar `AuthContext` temporário e redator de segredos.
5. Integrar GHOSTRECON → Vigolium → FrameSeven.
6. Integrar auditoria de clones GitHub no Vigolium.
7. Testar cancelamento, timeout, limpeza e retomada.
8. Só então habilitar o recurso para testes autorizados reais.

## Estado atual da implementação

### Implementado

- FrameSeven permanece sem `.git` próprio e integrado como componente versionado `v1` do workspace.
- `server/integrations/frameseven-adapter.mjs` criado.
- Validação de alvo HTTP/HTTPS.
- Montagem segura dos argumentos do CLI sem shell injection.
- Suporte a `tools`, timeout, tool-timeout, concorrência, rate e diretório de saída.
- Suporte condicional à flag `-auth-browser`.
- Eventos de início, progresso, `auth_required` e `auth_confirmed` no adapter.
- Cancelamento por `AbortSignal`, timeout global e captura de stdout/stderr.
- `server/integrations/frameseven-auth-context.mjs` criado.
- Contexto temporário com expiração, estados pending/ready/cleaned e segredo somente em memória.
- Toggle `FrameSeven autenticado` adicionado ao modal do Auto.
- Política `frameSevenAuth` registrada na sessão e enviada ao pipeline.
- Fluxo comum fora do AUTO integrado em `server/integrations/frameseven-runner.mjs`.
- Normalização e deduplicação conjunta de GHOSTRECON, Vigolium e FrameSeven.
- CLI FrameSeven v1 aceita `-merge-findings` e regrava o HTML original com o conjunto combinado.
- `report.html` integrado é aberto pela UI em nova aba.

### Estruturado, mas ainda não conectado ao fluxo real

- O evento `auth_required` está ligado ao pop-up operacional no fluxo normal e no AUTO.
- O `waitForAuth` ainda não está conectado a uma solicitação de aprovação da sessão.
- O AuthContext ainda não é consumido pelo GHOSTRECON ou pelo Vigolium.
- A ordem GHOSTRECON → Vigolium → FrameSeven é executada automaticamente no RUN comum e no AUTO.
- Auditoria de clones GitHub pelo Vigolium ainda não está encadeada ao FrameSeven.

### Ainda não liberado para teste integrado

- Login real pelo navegador dentro do fluxo GHOSTRECON.
- Confirmação que envia Enter ao FrameSeven.
- Compartilhamento de cookies/headers entre os três motores.
- Execução autenticada completa e limpeza pós-execução.

## Estado

Integração operacional implementada em 20/07/2026. O fluxo funciona no RUN comum e no Modo Auto. O CLI v1 exporta a sessão para um arquivo temporário protegido e pausa antes do scan; o adapter carrega o contexto somente em memória, executa GHOSTRECON e Vigolium e então libera o FrameSeven. Ao final, os três resultados passam pela mesma deduplicação e o próprio template HTML do FrameSeven é regravado com todos os achados combinados.

Testes automatizados cobrem a ausência de `-auth-browser` quando desligado, a ordem GHOSTRECON/Vigolium → FrameSeven no fluxo autenticado, compartilhamento temporário e redação de segredos. Teste real contra alvo externo continua condicionado a autorização e login manual do operador.
