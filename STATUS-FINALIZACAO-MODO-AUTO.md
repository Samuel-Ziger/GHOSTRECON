# Status de finalização do Modo Auto

Atualizado em: 2026-07-26

## Finalidade deste documento

Este documento é a fotografia auditável do estado atual do Modo Auto. Ele
separa o que já foi implementado e testado do que ainda precisa ser fechado
antes de considerar o módulo pronto para uso operacional supervisionado.

As fontes de verdade continuam sendo o código, os schemas e os testes. Para o
contrato operacional, consulte também:

- `AGENTS.md`;
- `MODO-AUTO-GHOSTRECON.md`;
- `MELHORIAS-PENDENTES-MODO-AUTO.md`;
- `server/auto-agent/effective-plan.mjs`;
- `server/auto-agent/orchestrator.mjs`;
- `server/auto-agent/schemas/decision.schema.json`.

Este arquivo não apaga o histórico dos planos anteriores. Quando houver
divergência, este status e o comportamento comprovado em teste prevalecem sobre
afirmações aspiracionais antigas.

## Resumo executivo

**Estado atual:** beta supervisionado em fase final de endurecimento.

O Auto já possui planner real, catálogo híbrido, plano efetivo congelado,
quatro níveis de autonomia, RBAC, engagement/ROE, escopo, aprovação humana,
cancelamento, checkpoints, RAG, Forge e integração com motores externos.

Os principais problemas que originaram esta revisão — contrato JSON inválido,
planner travado, timeout que não encerrava o processo, fase CORS bloqueando a
sessão, execução passiva demais no nível 4 e plano diferente do que era
executado — já possuem correções estruturais.

Ainda não é correto declarar o Auto “finalizado”. Restam bloqueadores
concentrados na propagação fatal do Vigolium, confirmação ofensiva manual
vinculada ao plano, regressão consolidada e teste ponta a ponta em laboratório
autorizado.

### Legenda

- **Concluído e validado:** implementação presente e teste local direcionado
  executado sem rede real.
- **Pendente:** alteração de código ou teste ainda necessário.
- **E2E controlado:** teste que depende de navegador, binário ou alvo de
  laboratório explicitamente autorizado e não foi executado nesta revisão.

## O que já foi concluído e validado

### 1. Contrato de decisão e providers

- O planner trabalha em modo somente leitura e não recebe autorização para
  executar rede, editar arquivos ou rodar ferramentas durante a decisão.
- O schema exige `objective`, `reasoningSummary`, `requestedModules` e
  `confidence` entre `0` e `1`.
- Aliases observados em produção, como `request_modules` e
  `execute_modules`, são normalizados para `run_modules` antes da validação.
- As ações canônicas são:
  - `run_modules`;
  - `continue_with_context`;
  - `finish`;
  - `ask_operator`;
  - `forge_module`;
  - `abstain`.
- `forgeRequest` possui contrato completo e só é aceito quando a ação realmente
  é `forge_module`.
- App Server e fallback `codex exec` preservam a causa do erro e possuem
  encerramento de stdin/processo.
- Providers não selecionados não entram no conselho.
- O fallback determinístico não pode elevar autonomia, risco, engines ou
  escopo.

Arquivos principais:

- `server/auto-agent/decision-contract.mjs`;
- `server/auto-agent/planner.mjs`;
- `server/auto-agent/providers/`;
- `server/auto-agent/council/council-runner.mjs`;
- `server/auto-agent/schemas/decision.schema.json`.

### 2. Catálogo híbrido e plano efetivo

- O catálogo deixou de ser a antiga lista passiva fixa.
- Ele combina manifests, capacidades legadas, módulos Forge aprovados,
  FrameSeven, Vigolium e inteligência HexStrike.
- Cada entrada informa origem, disponibilidade, classe de risco, timeout,
  concorrência e outputs quando conhecidos.
- IDs desconhecidos, indisponíveis ou fora da autonomia são recusados.
- Dependências, fases implícitas, engines e Kali são expandidos antes dos gates.
- A classe mais conservadora prevalece quando manifest e capacidade legada
  divergem.
- O plano efetivo é congelado e identificado por SHA-256.
- Identidades aprovadas dos binários FrameSeven e Vigolium entram no catálogo e
  no hash do plano.
- A identidade é revalidada imediatamente antes do processo; troca de binário
  depois da aprovação deve falhar fechado.
- O perfil de planejamento `deep` não é usado como atalho para ligar fases
  legadas que não aparecem no plano.

Arquivos principais:

- `server/auto-agent/tool-catalog.mjs`;
- `server/auto-agent/pipeline-capabilities.mjs`;
- `server/auto-agent/effective-plan.mjs`;
- `bridge/vigolium-binary-integrity.mjs`;
- `server/integrations/frameseven-adapter.mjs`.

### 3. Autonomia, RBAC e aprovação humana

Foram formalizados quatro níveis:

| Nível | ID | Classes máximas |
| --- | --- | --- |
| 1 | `observation` | passiva e passiva profunda |
| 2 | `assisted` | anteriores + ativa |
| 3 | `authorized` | anteriores + intrusiva |
| 4 | `authorized_opsec` | igual ao nível 3, com OPSEC agressivo |

Controles já implementados:

- níveis 3/4 exigem `recon.intrusive` na própria rota;
- níveis 2/3/4 exigem aprovação humana antes da execução;
- autonomia e perfil `aggressive` não substituem autorização;
- o popup apresenta alvo, módulos, engines, risco, limites e hash;
- recusa encerra o plano sem executar “o restante seguro”;
- classe destrutiva permanece fora do planner Auto;
- o conselho pós-pipeline preserva a política e a autonomia da sessão.

Arquivos principais:

- `server/routes/auto-recon.mjs`;
- `server/auto-agent/effective-plan.mjs`;
- `server/auto-agent/orchestrator.mjs`;
- `public/index.html`;
- `server/modules/auth.js`;
- `server/modules/opsec.mjs`.

### 4. Engagement, ROE e escopo formal

Esta frente foi revisada novamente em 2026-07-26.

- Engagement formal sem allowlist agora falha fechado.
- Domínio exato não autoriza subdomínio implicitamente.
- Wildcard autoriza apenas a árvore explicitamente descrita.
- Exclusão de domínio também bloqueia seus descendentes.
- IPv4 e CIDR IPv4 são avaliados pelo mesmo contrato no preflight e no runtime.
- CIDR em `outOfScope` não é truncado para um único IP.
- IPv6 diferente de `/128` continua fail-closed até existir parser completo.
- `body.outOfScope` é combinado com as exclusões do engagement.
- O Auto vincula a autorização do engagement ao plano aprovado.
- O binding é revalidado antes da execução e antes dos motores externos.
- O RUN manual revalida o engagement depois do pipeline e imediatamente antes
  do FrameSeven.
- O Auto autenticado revalida depois do pipeline e imediatamente antes de
  liberar o scan FrameSeven.
- Hosts de Certificate Transparency fora do escopo são descartados.
- Redirects, subdomínios e URLs descobertas continuam sujeitos à política.
- IP derivado de domínio só pode alimentar Shodan ou RDAP quando também estiver
  autorizado em `scopeIps`.

Arquivos principais:

- `server/modules/engagement.mjs`;
- `server/modules/scope.js`;
- `server/pipeline/pipeline-state.mjs`;
- `server/pipeline/phases/discovery.mjs`;
- `server/pipeline/phases/probe.mjs`;
- `server/pipeline/phases/asset-discovery.mjs`;
- `server/routes/recon-stream.mjs`;
- `server/auto-agent/orchestrator.mjs`.

Testes locais direcionados de scope, engagement, RUN, Auto, pipeline e
cancelamento passaram sem chamadas reais de scanner.

### 5. Sessão, checkpoints e retomada

- Sessões ativas têm proprietário.
- Listagem, cancelamento, aprovação e retomada validam ownership.
- Aprovação é single-flight e abort-aware.
- `sessionId` ativo duplicado é recusado.
- Snapshots são gravados atomicamente com permissões restritas.
- Snapshots `running` órfãos são reconciliados como interrompidos.
- Checkpoints v2 só são retomáveis em fronteiras prontas.
- O claim de retomada é atômico e de uso único.
- Alvo, proprietário, autonomia, catálogo, prompt e política de retomada são
  validados.
- Não existe retomada silenciosa no meio de engine, pipeline ou avaliação.
- Estados terminais não voltam a executar.

Arquivos principais:

- `server/auto-agent/active-sessions.mjs`;
- `server/auto-agent/session-store.mjs`;
- `server/auto-agent/orchestrator.mjs`.

### 6. Timeout, cancelamento e assentamento de subprocessos

- O RUN manual e o Auto usam `AbortController`.
- Desconexão do cliente propaga cancelamento ao pipeline e engines.
- O Auto possui deadline por fase.
- Fases em timeout só podem continuar depois do assentamento do trabalho
  anterior.
- Se o trabalho não assentar no período de graça, a run falha fechado.
- `module-runner` envia `SIGTERM`, escala para `SIGKILL` e aguarda `exit/close`.
- Timeout não é declarado concluído enquanto o processo não confirmar
  encerramento.
- Falha em confirmar encerramento gera `PROCESS_UNTERMINATED` fatal.
- O FrameSeven possui proteção equivalente com
  `FRAMESEVEN_PROCESS_UNTERMINATED`.
- Timeouts recuperáveis são registrados como outcome e permitem a próxima fase
  somente quando o estado continua íntegro.
- Cancelamento explícito nunca é convertido em skip recuperável.

Arquivos principais:

- `server/modules/module-runner.mjs`;
- `server/pipeline/phase-executor.mjs`;
- `server/pipeline/run-pipeline.mjs`;
- `server/integrations/frameseven-adapter.mjs`;
- `server/integrations/frameseven-runner.mjs`.

### 7. FrameSeven integrado

O FrameSeven continuará sendo o motor ofensivo da integração, mas as classes
continuam separadas:

- `frameseven_recon`: `recon,cve`, não intrusivo;
- `frameseven_active`: perfil ofensivo explícito, read-oriented e intrusivo;
- `frameseven_authenticated`: o mesmo perfil ofensivo, intrusivo e autenticado.

O perfil ofensivo permitido é congelado como
`recon,access,redirect,misconfig,cve,crawler,content,subdomain,ports,nmap,bannergrab`.
Ele não usa `tools all`. Ferramentas capazes de extração, leitura de arquivo,
execução remota, tentativa de credencial, rajada de carga ou escrita de estado
ficam fora desse perfil.

O que já existe:

- policy central versionada com perfis `recon_v1` e `offensive_v1`;
- encaminhamento explícito de `tools` ao adapter e ao runner;
- recusa de perfil ofensivo sem `offensiveApproved`;
- modos recon, active e authenticated mutuamente exclusivos;
- `finish` e `abstain` não injetam FrameSeven autenticado;
- binário com identidade selada;
- argumentos em array, sem shell;
- timeouts separados para captura, aprovação, preparação e scan;
- `-auth-browser` somente quando o toggle foi ativado;
- sessão origin-bound, TTL e consumo único;
- diretório temporário `0700` e arquivo `0600`;
- confirmação humana depois da captura;
- sessão compartilhada somente após a confirmação;
- limpeza de contexto temporário;
- merge e deduplicação de findings;
- proveniência por motor;
- relatório regenerado a partir de findings normalizados;
- rota de relatório com RBAC, contenção de caminho, extensões permitidas e CSP;
- encerramento TERM/KILL com confirmação;
- `-active-scan` não é enviado pelos wrappers atuais.

Os testes locais `frameseven-integration.test.js`,
`auto-effective-plan.test.js` e `recon-stream-route.test.js` confirmaram os
perfis explícitos, a exclusividade dos modos, a recusa de `tools all` e
`-active-scan`, o gate `offensiveApproved`, o encaminhamento exato do perfil no
RUN e que `GHOSTRECON_CONFIRM_ACTIVE=1` não substitui a confirmação da
requisição. Nenhum scanner ou alvo externo foi executado nesses testes.

Importante: “ofensivo” não significa destrutivo. `FrameSeven -active-scan`,
write probes e qualquer mudança persistente continuam fora deste fluxo e
exigem um gate próprio de laboratório controlado.

Arquivos principais:

- `server/integrations/frameseven-adapter.mjs`;
- `server/integrations/frameseven-auth-context.mjs`;
- `server/integrations/frameseven-report.mjs`;
- `server/integrations/frameseven-runner.mjs`.

### 8. Forge e código gerado

- O planner não escreve o módulo.
- O artefato passa por schema, validação estática, testes, revisão e decisão
  humana.
- Integridade dos artefatos é selada por hash.
- Primeiro canário é vinculado a alvo, activation ID e engagement.
- O canário usa runner forte Bubblewrap em Linux e falha fechado quando ele não
  está disponível.
- Há limites de tempo, memória e saída.
- Rede do host não é liberada ao canário.
- Aprovação não ativa silenciosamente um pacote antigo sem integridade.

### 9. Proteção de segredos e write probes

- Redação central do Auto é aplicada antes de RAG e snapshots.
- Eventos Auto são redigidos antes de atravessar NDJSON.
- Tokens, cookies, `Authorization`, senhas e caminhos locais são tratados como
  dados sensíveis.
- Captura de token permanece opt-in.
- Validação online de segredo é classificada como intrusiva.
- Writes/signup de Supabase e Firebase permanecem desligados no pipeline.
- FTP `STOR` foi separado dos probes de leitura e fica desligado por padrão.
- O Vigolium recebe autenticação por arquivo temporário restrito, não por
  segredo em argv.
- O ambiente filho do Vigolium usa allowlist e não herda tokens/DB/JWT do
  processo pai.

### 10. Redação autenticada do Vigolium

Esta frente foi concluída e validada localmente com fixtures, sem rede externa:

- valores exatos de cookie, token e header são removidos de findings e resumos;
- request, response, body, curl e evidências passam pela redação antes de
  persistência;
- SQLite recebe somente o payload redigido;
- respostas públicas não revelam auth-files nem caminhos absolutos;
- relatórios HTML são sanitizados antes de publicação;
- diretórios e arquivos temporários permanecem `0700`/`0600`;
- cleanup é idempotente e foi exercitado nos testes locais;
- headers com CRLF, NUL ou tamanho inválido são recusados;
- a rota de relatório mantém RBAC, CSP e dados públicos mínimos.

Arquivos principais:

- `bridge/vigolium-auth-transport.mjs`;
- `bridge/vigolium-auth-config.mjs`;
- `bridge/findings-normalizer.mjs`;
- `bridge/vigolium-runner.mjs`;
- `bridge/agent-bridge.mjs`;
- `server/modules/finding-redaction.mjs`;
- `server/routes/vigolium.mjs`.

Passaram os testes direcionados `finding-redaction.test.js`,
`vigolium-auth-config.test.js`, `vigolium-bridge.test.js`,
`vigolium-agent.test.js`, `vigolium-server-client.test.js` em loopback,
`secret-safety.test.js`, `auto-event-redaction.test.js` e
`auto-route-public-data.test.js`. Isso comprova a fronteira local com
mocks/fixtures; o E2E autenticado com navegador, binários e alvo de laboratório
continua pendente.

### 11. PATH e identidade do executável

- Override de `PATH` fornecido por requisição foi desativado.
- Entrada Vigolium `-T/-I` arbitrária está fechada no RUN e no Auto até existir
  enumeração e selo de todos os alvos contidos no arquivo.
- A rota de atualização de ferramentas não altera mais o `PATH` global enquanto
  sessões estão em execução.
- Para atualizar ferramentas, o operador deve configurar o ambiente e reiniciar
  a stack.
- Um teste local confirma que `/api/tool-path-refresh` mantém o `PATH`
  inalterado e continua exigindo CSRF.

## O que ainda falta para finalizar

### P0.1 — Propagar falhas fatais do Vigolium

O helper e as fases já reconhecem falhas fatais, porém alguns catches internos
dos bridges ainda as convertem em `{ ok: false }`.

É necessário:

- propagar `VIGOLIUM_BINARY_IDENTITY_MISMATCH`;
- propagar `PROCESS_ABORTED`;
- propagar `PROCESS_UNTERMINATED`;
- propagar `AbortError`;
- impedir que geração de relatório HTML ou fallback SQLite engulam essas
  falhas;
- impedir que o Auto marque esses casos como `recoverable:true`;
- garantir que FrameSeven e nova iteração não iniciem depois de uma falha fatal
  do Vigolium.

Arquivos:

- `bridge/vigolium-runner.mjs`;
- `bridge/agent-bridge.mjs`;
- `bridge/vigolium-errors.mjs`;
- `server/pipeline/phases/go-engine.mjs`;
- `server/pipeline/phases/go-agent.mjs`;
- `server/pipeline/phase-executor.mjs`;
- `server/auto-agent/orchestrator.mjs`.

### P0.2 — Confirmação manual vinculada ao plano

A variável global `GHOSTRECON_CONFIRM_ACTIVE=1` não satisfaz mais o gate HTTP;
a confirmação precisa estar na requisição atual. Ainda falta tornar o registro
da confirmação integralmente vinculado ao plano ofensivo aprovado.

Para o FrameSeven ofensivo, a confirmação deve ser:

- explícita na requisição atual;
- vinculada ao alvo, engagement, módulos, ferramentas, limites e identidade do
  binário;
- registrada com hash do plano;
- inválida depois de mudança no engagement ou executável.

Uma variável de ambiente não deve aprovar silenciosamente um novo plano
ofensivo.

### P0.3 — Validar dados autenticados no E2E autorizado

A regressão local de redação está concluída. Falta validar, em laboratório
autorizado e sem usar credenciais reais de produção:

- auth-file fornecido e auth-file efêmero com navegador real;
- compartilhamento single-use entre GHOSTRECON, Vigolium e FrameSeven;
- relatório HTML/JSON, SQLite, NDJSON, snapshot e RAG sem segredo;
- cleanup em sucesso, recusa, erro, timeout e cancelamento;
- respostas públicas contendo apenas flags, contagens e nomes seguros de
  headers;
- ausência de browser, processo ou temporário residual.

### P0.4 — Regressão local consolidada

Executar, sem rede externa:

```bash
node --check <arquivos alterados>
node --test server/tests/auth.test.js
node --test server/tests/opsec.test.js
node --test server/tests/scope.test.js
node --test server/tests/engagement.test.js
node --test server/tests/auto-agent.test.js
node --test server/tests/auto-effective-plan.test.js
node --test server/tests/module-runner.test.js
node --test server/tests/pipeline-resilience.test.js
node --test server/tests/process-cancellation.test.js
node --test server/tests/frameseven-integration.test.js
node --test server/tests/vigolium-bridge.test.js
node --test server/tests/vigolium-agent.test.js
node --test server/tests/vigolium-auth-config.test.js
node --test server/tests/finding-redaction.test.js
node --test server/tests/secret-safety.test.js
node --test server/tests/tool-path-route.test.js
GHOSTRECON_NO_HTTP_LISTEN=1 node -e "import('./server/index.js')"
npm run test:cli
npm run test:mcp
```

Depois dos testes direcionados, executar todos os testes locais herméticos,
excluindo explicitamente `pipeline-smoke.test.js`, que pode acessar rede.

### P0.5 — E2E em laboratório autorizado

Somente depois da regressão local:

1. iniciar uma única stack limpa;
2. usar alvo local/intencionalmente vulnerável dentro de engagement formal;
3. testar `observation`;
4. testar `assisted` aprovado e recusado;
5. testar `authorized` com FrameSeven ofensivo;
6. testar `authorized_opsec` com limites definidos;
7. testar FrameSeven autenticado:
   - captura;
   - recusa;
   - aprovação;
   - consumo único;
   - compartilhamento com GHOSTRECON/Vigolium;
   - cleanup;
8. cancelar durante planner, pipeline, aprovação e scan;
9. provocar timeout recuperável de módulo;
10. provocar subprocesso que não encerra e confirmar falha terminal;
11. conferir NDJSON, snapshot, RAG, SQLite e relatórios sem segredos;
12. confirmar ausência de processos, browser e temporários residuais.

Nenhum desses E2E foi executado nesta revisão.

## Pendências P1 que não bloqueiam o próximo teste supervisionado

- Migrar deadlines de fases legadas para deadline individual por módulo.
- Unificar classificação de risco hoje duplicada entre manifest, catálogo,
  OPSEC, RBAC e engagement.
- Substituir progresso amplo de fase por progresso real de cada módulo.
- Integrar FrameSeven ao Tor/proxy estrito.
- Fechar paridade completa de relatório e proveniência entre RUN e Auto.
- Rastrear PID/process-group de todos os sidecars da stack e fornecer
  `stop/status` confiáveis.
- Isolar também o runtime final de módulos Forge aprovados; o canário é
  sandboxed, mas o loader ativo ainda exige endurecimento adicional.
- Definir política de retenção/TTL comum para RAG, relatórios, SQLite e
  evidências autenticadas.

## Critérios objetivos para declarar o Auto finalizado

O Modo Auto só deve sair desta fase quando todos os itens abaixo forem
verdadeiros:

- [ ] o plano efetivo autorizado é exatamente o plano executado;
- [ ] aliases, presets, dependências e engines são expandidos antes dos gates;
- [ ] autonomias 3/4 exigem `recon.intrusive`;
- [ ] todo plano intrusivo exige engagement e aprovação vinculada;
- [ ] escopo bloqueia subdomínios, redirects e IPs não autorizados;
- [ ] timeout só termina depois do assentamento real;
- [ ] cancelamento impede qualquer engine/iteração posterior;
- [ ] identity mismatch de FrameSeven/Vigolium é terminal;
- [x] FrameSeven recon, ofensivo e autenticado são mutuamente exclusivos;
- [x] perfil FrameSeven ofensivo aparece completo no plano/payload de aprovação;
- [x] `tools all`, `-active-scan` e write probes ficam fora dos perfis;
- [ ] contexto autenticado é single-use, redigido e removido;
- [ ] nenhum segredo aparece em argv, log, NDJSON, RAG, SQLite ou relatório;
- [ ] retomada incompatível/repetida falha fechado;
- [ ] testes locais herméticos passam;
- [ ] E2E controlado passa sem processos ou temporários residuais;
- [ ] README e documentos operacionais correspondem ao código final.

## Ordem recomendada para concluir

1. corrigir a propagação fatal do Vigolium;
2. vincular a confirmação manual ofensiva ao plano;
3. executar o E2E autenticado de redação em laboratório autorizado;
4. executar os demais testes direcionados;
5. executar suíte hermética agregada;
6. atualizar README e documentos normativos;
7. executar o E2E em laboratório autorizado;
8. registrar resultados e pendências residuais neste arquivo.

## Estado de liberação

| Caminho | Estado |
| --- | --- |
| Testes locais com fixtures | apto |
| `observation` em alvo controlado | apto para teste supervisionado após regressão final |
| `assisted` em alvo controlado | apto para teste supervisionado após regressão final |
| `authorized` | não liberar antes dos P0 |
| `authorized_opsec` | não liberar antes dos P0 |
| FrameSeven ofensivo | somente engagement autorizado + confirmação humana |
| FrameSeven autenticado real | pendente E2E controlado |
| Operação destrutiva/`-active-scan` | fora do Auto atual |
