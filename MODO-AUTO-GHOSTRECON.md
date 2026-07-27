# Modo Auto GHOSTRECON

> Estado verificado em 2026-07-26: **beta supervisionado**. Este documento
> descreve o contrato operacional atual. Planos e listas de modelos anteriores
> eram propostas de arquitetura e não devem ser usados como fonte de verdade.
> O saldo auditável desta evolução, inclusive bloqueadores ainda abertos, está
> em `STATUS-FINALIZACAO-MODO-AUTO.md`.

## Objetivo

O Modo Auto permite que uma ou mais IAs selecionadas pelo operador planejem e
avaliem um reconhecimento autorizado. A IA não executa ferramentas diretamente
no turno de decisão. O GHOSTRECON continua sendo a autoridade que:

- valida alvo, escopo, RBAC, engagement/ROE e OPSEC;
- constrói o catálogo realmente disponível;
- normaliza e valida a decisão estruturada;
- expande o plano completo, congela-o e calcula seu hash;
- solicita confirmação humana;
- executa somente o plano autorizado;
- limita tempo, processos, iterações, chamadas e contexto;
- redige, registra e avalia os resultados.

Autonomia não representa autorização. Um nível mais alto dá ao planner acesso a
mais classes do catálogo, mas não ignora nenhum gate.

## Fluxo atual

```text
requisição + principal autenticado + alvo
                  │
                  ▼
       seleção/probe dos providers
                  │
                  ▼
 catálogo híbrido filtrado pelos opt-ins
                  │
                  ▼
       contexto e RAG já redigidos
                  │
                  ▼
      planner/conselho somente leitura
                  │
                  ▼
 decisão JSON normalizada e validada
                  │
                  ▼
 checkpoint v2 pronto + claim atômico de uso único
                  │
                  ▼
 expansão de dependências, engines e risco
                  │
                  ▼
 plano efetivo congelado + SHA-256
                  │
                  ▼
 preflight + RBAC + scope + ROE + OPSEC
                  │
                  ▼
 aprovação humana obrigatória nos níveis 2–4
                  │
                  ▼
 GHOSTRECON → Vigolium → FrameSeven
                  │
                  ▼
 observação redigida → nova decisão/encerramento
                  │
                  ▼
 avaliação, snapshot, RAG e status terminal
```

## Catálogo do Auto

O catálogo não é mais a antiga lista fixa de 21 módulos. Ele combina:

1. módulos com manifest no registry;
2. capacidades legadas das fases do pipeline;
3. módulos Forge ativos e íntegros;
4. capacidades explícitas de FrameSeven e Vigolium;
5. o orquestrador de inteligência HexStrike.

Cada entrada informa origem, disponibilidade, classe, requisitos, timeout,
concorrência e outputs quando conhecidos. A presença no catálogo não é
autorização nem garantia de execução: a política da sessão e os gates ainda são
aplicados ao plano efetivo.

Enquanto manifest e capacidade legada coexistirem, a fusão é conservadora: a
classe de maior risco prevalece e requisitos como Kali/autenticação são
combinados, não reduzidos. Isso impede que um manifest desatualizado rebaixe uma
operação que o pipeline ainda trata como ativa ou intrusiva.

### Classes

| Classe | Significado no Auto |
| --- | --- |
| `passive` | OSINT ou coleta pública conservadora |
| `deep_passive` | Análise passiva mais profunda |
| `active` | Probe limitado, sem intenção intrusiva |
| `intrusive` | DAST, fuzzing, enumeração intensa ou validação de maior risco |
| `hexstrike_intel` | Inteligência e recomendação do HexStrike, não execução automática da ferramenta recomendada |
| `destructive` | Nunca exposta ao planner Auto |

Capacidades com finalidade de ataque de credenciais, ocultação de identidade ou
expansão perigosa de escopo ficam fora do Auto mesmo quando a implementação
atual pareça apenas gerar um plano. Entre os IDs explicitamente proibidos estão
`cloud_bruteforce`, `cred_spray`, `identity_rotation`, `kali_proxychains`,
`navegation` e `stealth_requests`.

O Auto também não delega probes destrutivos do FrameSeven. O FrameSeven é o
único motor que mantém perfil ofensivo na integração Auto. Os perfis são
explícitos:

- recon: `recon,cve`;
- ofensivo/autenticado:
  `recon,access,redirect,misconfig,cve,crawler,content,subdomain,ports,nmap,bannergrab`.

Não se usa `tools all` nem se envia `-active-scan`. O perfil ofensivo permanece
intrusivo e não autoriza write probes.

No RUN manual, o plano também é expandido antes do preflight. Se qualquer ID
resultante for intrusivo — inclusive uma capacidade Vigolium/DAST ou o
`frameseven_active` implícito em `includeFrameSeven` — a rota exige engagement
formal e confirmação ativa antes de preparar ou iniciar o processo.

## Níveis de autonomia

Os identificadores transmitidos pela UI/API são estáveis:

| UI | Identificador | Classes permitidas | Aprovação |
| --- | --- | --- | --- |
| 1 | `observation` | `passive`, `deep_passive`, `hexstrike_intel` | Não abre aprovação de plano |
| 2 | `assisted` | anteriores + `active` | Obrigatória antes da execução |
| 3 | `authorized` | anteriores + `intrusive` | Obrigatória; requer `recon.intrusive` |
| 4 | `authorized_opsec` | mesmas classes do nível 3, com OPSEC `aggressive` | Obrigatória; requer `recon.intrusive` |

O nível 4 não é “liberdade total”. Ele não inclui classe destrutiva, não
contorna engagement, não amplia escopo, não habilita write probes e não
substitui a confirmação humana.

Os níveis 3/4 são rejeitados já na rota quando o principal não possui
`recon.intrusive`. Papéis `red` e `admin` normalmente possuem essa capacidade;
o contrato exato de RBAC continua em `docs/AUTH-RBAC.md`.

### Recusa da aprovação

- qualquer recusa nos níveis 2–4 encerra a iteração sem executar pipeline,
  módulo ou engine;
- não existe continuação automática de um “restante seguro” e o plano recusado
  não é silenciosamente reexpandido;
- a recusa e o hash do plano apresentado ficam na trilha da sessão.

Para tentar um conjunto menor, o operador deve iniciar ou aprovar um novo plano,
que será expandido, validado e identificado por outro hash.

## Plano efetivo e invariantes

A decisão da IA não é enviada diretamente ao pipeline. Antes da execução:

1. aliases e IDs são normalizados;
2. apenas módulos existentes, disponíveis e permitidos permanecem;
3. dependências, fases legadas, Kali e engines são expandidos;
4. risco é recalculado sobre a lista expandida;
5. FrameSeven, Vigolium e HexStrike são conferidos contra seus opt-ins;
6. preflight de engagement/escopo e gate OPSEC são executados;
7. o objeto completo é congelado;
8. um hash SHA-256 identifica o plano;
9. o popup mostra alvo, módulos, engines, risco, limites e o hash;
10. o executor recebe exatamente os campos congelados.

Quando FrameSeven ou Vigolium participam, a identidade observada do executável
também entra no catálogo e no plano. Hash, tamanho e metadados são obtidos do
mesmo descritor regular, sem seguir symlink, e a identidade aprovada é
revalidada imediatamente antes de cada `spawn`, inclusive o merge posterior do
FrameSeven. Divergência falha fechado.

O perfil de planejamento `deep` não é repassado como um atalho capaz de habilitar
fases legadas ocultas. No Auto, o modo influencia a escolha explícita do
planner; o perfil entregue ao pipeline permanece limitado para preservar a
igualdade entre o plano aprovado e o executado.

Nenhum adapter ou fallback pode injetar módulos após o último gate. Alteração do
plano exige nova expansão, novo hash e nova validação.

### Gates explícitos no runtime

Além do filtro do catálogo, o caminho Auto aplica gates dentro das fases. Isso
evita que comportamento legado, ativado historicamente por perfil ou pela mera
entrada numa fase, execute algo que não aparece no plano congelado.

Entre as capacidades explicitadas estão:

- `http_probe` e `wafw00f` na fase de probe;
- fetch de bundles do alvo na descoberta de conteúdo, que exige uma análise
  target-touching como `js_intel`/auditoria client-side; Wayback/Common Crawl
  sozinhos não o habilitam;
- `evidence_verification` e `active_param_discovery` na validação;
- `asset_discovery` na descoberta de ativos;
- `high_recheck` e `browser_xss_verify` na finalização;
- ferramentas Kali e follow-ups de serviço, que exigem seus próprios IDs no
  Auto.

Também foram reclassificados como `active` os módulos que consultam diretamente
o alvo, mesmo que antes fossem descritos como passivos, por exemplo headers,
robots/well-known, JavaScript, CORS e auditorias client-side. A política do RUN
manual foi preservada onde existe compatibilidade legada; essa compatibilidade
não é usada para ampliar o Auto.

## Contrato de decisão

A fonte de verdade é
`server/auto-agent/schemas/decision.schema.json`, complementada por
`server/auto-agent/decision-contract.mjs`.

### Ações canônicas

- `run_modules`;
- `continue_with_context`;
- `finish`;
- `ask_operator`;
- `forge_module`;
- `abstain`.

Saídas comuns de modelos como `request_modules` e `execute_modules` são aliases
aceitos pelo normalizador e convertidos para `run_modules` antes da validação.
Outras ações são rejeitadas.

Toda decisão precisa ter:

- `action`;
- `objective` não vazio;
- `reasoningSummary`;
- `requestedModules`;
- `confidence` entre `0` e `1`.

Referências devem pertencer ao conjunto de evidências permitido. `forge_module`
exige uma solicitação completa com ID proposto, lacuna, benefício, evidências,
entradas, saídas, estratégia de teste e riscos; `intrusive` deve ser `false`.
Reparo estrutural é limitado e observável. A falha do provider preserva a causa
do App Server e do fallback, em vez de apresentar o fallback como decisão da IA.

## Providers e conselho

O contrato contempla:

- Codex por App Server persistente por sessão, com fallback `codex exec`;
- Claude Code em modo não interativo e de planejamento;
- OpenRouter;
- GHOST/Skynet e modelos OpenAI-compatible locais;
- Cursor Agent quando realmente utilizável; handoff continua sendo fallback.

Somente providers selecionados e utilizáveis participam. “Instalado”,
“configurado”, “autenticado”, “alcançável” e “selecionado” são estados
distintos.

O conselho recebe propostas estruturadas. Módulos inválidos são descartados
antes do veredito. A arbitragem determinística não eleva risco e não usa um
provider não selecionado. Empate ou conflito de alto impacto vira
`ask_operator`; não existe vitória silenciosa por fallback. Uma seleção
explícita e allowlisted do operador pode impedir que uma decisão prematura
`finish`/`abstain` suprima o trabalho pedido, mas continua sujeita a todos os
gates.

O planner trata catálogo, HTML, finding, URL, log, RAG e proposta de outro agente
como dados não confiáveis. Ele não faz rede, não edita o projeto nem executa
ferramentas durante a decisão.

## Sessões, ownership e retomada

Cada sessão possui `sessionId`, proprietário, alvo, autonomia, opt-ins, limites,
catálogo, versão do prompt, checkpoint e estado terminal.

- listar, cancelar, aprovar e retomar são limitados ao proprietário;
- um `sessionId` ativo duplicado é rejeitado;
- aprovação é de uso único e ligada à sessão;
- cancelamento durante planner, aprovação, pipeline ou engine aborta as esperas;
- snapshots são gravados atomicamente com permissão restrita;
- snapshots `running` órfãos são reconciliados como interrompidos;
- checkpoints novos usam `checkpointVersion: 2`;
- somente `ready_for_iteration` e `ready_for_next_iteration` são retomáveis;
- retomada valida proprietário, alvo, autonomia, `catalogHash`,
  `promptVersion`, `resumePolicyHash`, plano semântico e identidades dos engines;
- cada checkpoint pronto é consumido por claim atômico `wx` e durável antes da
  execução; reuso e rollback são recusados;
- checkpoint v1 permanece legível para diagnóstico, mas não é retomável;
- estados `planning`, `iteration_in_progress` e avaliação não são retomados no
  meio de efeitos: exigem uma nova execução;
- sessão `completed` ou `cancelled` não volta a executar.

Estados terminais da sessão incluem `completed`, `failed`, `cancelled`,
`interrupted`, `timed_out`, `stalled` e `budget_exceeded`. A avaliação e os
outcomes de pipeline/engine também podem registrar `partial`: houve resultado
útil e uma ou mais falhas recuperáveis, não execução integral.

## Timeout, cancelamento e resiliência

O Auto ativa uma fronteira resiliente por fase. O recon manual mantém o
comportamento fail-fast por padrão, mas `POST /api/recon/stream` agora cria um
`AbortController`: abort do request ou fechamento prematuro da resposta cancela
o pipeline e é propagado às integrações Vigolium/FrameSeven.

No mesmo endpoint manual, módulos, engines e dependências são expandidos antes
do preflight. Qualquer módulo intrusivo dessa lista efetiva exige
`recon.intrusive`, engagement formal ativo, ROE assinado, escopo e janela
válidos e `confirmActive`; OPSEC `aggressive` não substitui consentimento.

Para cada fase:

1. é criado um `AbortSignal` derivado;
2. é aplicado um deadline específico;
3. sucesso, falha, timeout ou cancelamento gera `phase_outcome`;
4. no timeout, requests e subprocessos gerenciados são abortados;
5. processos recebem `SIGTERM` e, depois do período de graça, `SIGKILL`;
6. o orquestrador espera a fase assentar;
7. somente uma fase recuperável e realmente encerrada permite continuar;
8. uma fase que não assenta gera `PIPELINE_PHASE_UNSETTLED` e interrompe a run
   para evitar dois módulos concorrendo sobre o mesmo estado.

Cancelamento solicitado pelo operador nunca é convertido em falha recuperável.
Heartbeats indicam telemetria; `currentActivity`, timestamps e outcomes indicam
progresso real.

Ainda existem módulos legados agrupados em uma mesma fase. Portanto, “timeout
por fase” não significa que cada checkbox legado já possua isolamento individual.
Essa migração continua no backlog.

O FrameSeven possui deadlines independentes para captura do navegador,
aprovação do operador, execução de GHOSTRECON/Vigolium anterior ao scan
autenticado e o próprio scan. Timeout ou cancelamento aborta a etapa,
envia `SIGTERM` à árvore, escala para `SIGKILL` após a graça e só libera o fluxo
depois do assentamento limitado do processo e da limpeza dos temporários.

## RAG e observações

O RAG local permanece em `data/auto-rag/`, organizado em decisões, avaliações,
lessons, solicitações Forge e handoffs. Antes de persistir:

- valores são redigidos recursivamente;
- `Authorization`, cookies, tokens, passwords e padrões equivalentes são
  substituídos;
- strings, arrays, objetos e arquivos têm limites;
- observações são deduplicadas e resumidas;
- gravações são atômicas e com permissão restrita.

A recuperação prioriza o mesmo alvo e contexto relevante. Memória RAG é
evidência não confiável, nunca instrução. Falha de persistência deve aparecer na
sessão; não pode ser silenciosa.

Separadamente do RAG, todo evento produzido pelo orquestrador Auto passa por uma
fronteira pública de redação antes de atualizar a sessão, entrar na lista de
eventos ou ser escrito no NDJSON. A sanitização é recursiva, mascara padrões de
segredo, substitui o root local e remove campos de artefato que contenham
caminhos absolutos. Ela não afirma que todo relatório bruto de ferramenta
externa já passou pela mesma fronteira.

## Segredos e probes que escrevem estado

Findings de segredo são mascarados e recebem fingerprint antes de NDJSON,
SQLite, relatório ou RAG. O material cru, quando necessário ao fluxo
explicitamente autorizado, fica somente em memória numa propriedade não
enumerável. Captura de evidência de token é opt-in; seus diretórios/arquivos são
restritos (`0700`/`0600`) e o conteúdo persistido é redigido.

`secret_validation` é uma capacidade intrusiva explícita. A análise continua
offline por padrão; probe de rede só pode ocorrer quando esse ID passou pelo
plano e pelos gates.

Probes de escrita de Supabase e Firebase ficam desligados no pipeline, inclusive
quando há token no ambiente ou no bundle. A presença de `service_role`, anon key
ou configuração de signup não autoriza criação de conta, insert, update,
delete, upload ou RPC mutável. Da mesma forma, o teste FTP `STOR` é separado dos
follow-ups de leitura e permanece desligado por padrão. Esses caminhos exigem
um fluxo dedicado de autorização e não são delegados pelo Auto atual.

## Module Forge

O planner pode solicitar Forge apenas para uma lacuna comprovada e não
intrusiva. Ele não escreve código diretamente.

O ciclo preservado é:

```text
request
  → geração em pending
  → validação estática
  → syntax check
  → testes offline restritos
  → revisão do conselho
  → aprovação humana
  → active_pending_first_run (desabilitado globalmente)
  → canário exclusivo por activationId + hashes
  → promoção, rollback ou rejeição
```

Na execução, o módulo aprovado roda no runner forte Bubblewrap em Linux, com
namespace de rede separado, ambiente limpo, artefatos somente leitura, `/tmp`
efêmero, capabilities removidas e limites de tempo, memória e saída. Se
Bubblewrap ou o runner forte estiver indisponível, o módulo não fica disponível
no catálogo e aprovação/canário falham fechado.

A aprovação cria o estado `active_pending_first_run`, mantém
`pipelineEnabled=false` e emite um `activationId`. Sob lock exclusivo de
lifecycle, a transição compara por CAS o alvo, a integridade exata do artefato e
o binding/version/hash do engagement apresentados ao operador. O engagement é
revalidado dentro do lock, imediatamente antes e depois do canário.

O primeiro canário chama diretamente o runner de módulos dinâmicos: somente o
ID Forge aprovado é executado, sem pipeline legado, DNS, finalize, engines ou
relatórios automáticos. O runner forte exige uma atestação nova, ligada por
`operationId` e challenge, para cada operação de teste/runtime. Timeout e
cancelamento exigem acknowledgement de término e processo realmente assentado;
sem isso a operação falha como `AUTO_FORGE_SANDBOX_UNTERMINATED`. Apenas o
resultado dessa ativação e do artefato selado pode habilitar o pacote;
resultados atrasados, repetidos ou com hash divergente são rejeitados.

Pacotes ativos criados antes do campo `runtimeIntegrity` não são carregados
automaticamente. Eles precisam ser revistos e reaprovados para receber o selo
novo. Isso é uma migração deliberadamente fail-closed.

## Engines opcionais

### HexStrike

`includeHexstrike=true` torna `hexstrike_orchestrator` visível. O módulo atual
importa inteligência e um plano de ferramentas. Uma ferramenta recomendada não
é marcada como executada nem recebe autorização implicitamente.

### Vigolium

`includeVigolium=true` torna suas capacidades visíveis, desde que o binário
esteja disponível. Na política atual ele permanece um motor complementar de
análise defensiva e não recebe o perfil ofensivo do FrameSeven. Estratégias ou
capacidades Vigolium historicamente classificadas como DAST/intrusivas não são
autorizadas pela simples inclusão do motor, pela autonomia 4 nem por
`vigoliumUseCodex`; este último só escolhe o provider do agente.

### FrameSeven

`includeFrameSeven=true` habilita o engine. `frameSevenAuth=true` é um opt-in
adicional, exige autonomia autorizada e abre a confirmação específica do fluxo
do navegador. O contexto autenticado:

- valida a origem;
- tem TTL;
- é consumido uma vez;
- usa diretório `0700` e arquivo `0600`;
- não coloca senha, cookie ou token em argv/log/RAG;
- é removido ao final ou no cancelamento.

No RUN manual, a regra geral é exigir autorização formal para qualquer módulo
intrusivo do plano expandido. `includeFrameSeven=true` seleciona o perfil
ofensivo explícito e read-oriented descrito acima; ele continua classificado
como intrusivo mesmo sem navegador. Antes de iniciar, a rota exige
`recon.intrusive`, engagement formal ativo, ROE assinado, alvo dentro do escopo
e da janela, além de confirmação ativa. `aggressive`, o toggle autenticado ou a
presença do binário não substituem nenhum desses gates. `tools all`,
`-active-scan` e ferramentas com efeitos mutáveis não fazem parte desse perfil.

Os testes locais de integração FrameSeven, plano efetivo Auto e rota RUN
confirmam os perfis versionados, a exclusividade entre
recon/active/authenticated, o gate ofensivo e a ausência de
`tools all`/`-active-scan`. O teste real do popup, navegador e alvo autorizado
continua sendo E2E controlado.

Quando o compartilhamento com Vigolium foi explicitamente autorizado, cookies e
headers são materializados num bundle temporário restrito e passados por
`--auth-file`; valores inline, `Authorization` e `Cookie` são redigidos da
telemetria, e o bundle é removido em `finally`. O transporte seguro não concede
novos módulos nem altera escopo.

O Auto não usa o conjunto destrutivo do FrameSeven. A ordem, quando os motores
foram selecionados, é:

```text
GHOSTRECON → Vigolium → FrameSeven
```

Cada engine produz outcome próprio (`done`, `partial`, `skipped`, `failed`,
`timeout` ou `cancelled`) e conserva sua proveniência.

O adapter posterga o terminal de sucesso até o `report.json` ser validado por
schema, origem e tamanho, normalizado e mesclado. A deduplicação agrega fontes e
evidências em vez de apagar proveniência. Exit code recuperável com relatório
útil, erros/truncamento no relatório ou falha posterior de merge resultam em um
único `engine_partial`; cancelamento continua sendo terminal distinto.

Relatórios válidos sob `reports/` são servidos por
`GET /api/frameseven/reports/:reportId/:file`. O material exposto é regenerado
somente dos findings normalizados/redigidos e limitado a `report.html`,
`report.json` e `report.md`; PDF e artefato bruto do scanner são recusados. A
rota exige `recon.read`, confere owner (salvo papel privilegiado) e binding
histórico de engagement/ROE/escopo. A leitura abre o arquivo com `O_NOFOLLOW`,
usa o mesmo descritor validado e compara `fstat` antes/depois; HTML recebe CSP
`sandbox` sem permissão de scripts, além de `no-store`, `nosniff` e
`Referrer-Policy`.

## API e eventos

Endpoint principal:

```text
POST /api/recon/auto/stream
```

Campos relevantes do payload:

```json
{
  "domain": "alvo-autorizado.example",
  "selectedCommanders": ["codex"],
  "mode": "deep",
  "autonomyLevel": "assisted",
  "includeHexstrike": false,
  "includeVigolium": false,
  "vigoliumUseCodex": false,
  "includeFrameSeven": false,
  "frameSevenAuth": false,
  "engagementId": null
}
```

Rotas de sessão permitem listar, cancelar e resolver aprovação, sempre com RBAC,
CSRF e ownership. Entre os eventos de observabilidade estão:

- `auto_session`;
- `auto_provider_probe`;
- `auto_agent_turn_started` / `completed` / `failed`;
- `auto_effective_plan`;
- `auto_approval_required` / `granted` / `denied`;
- `auto_iteration_started` / `completed`;
- `phase_started` e `phase_outcome`;
- `module_outcome`;
- `engine_started`, `engine_done`, `engine_partial`, `engine_failed`,
  `engine_timeout`, `engine_cancelled`, `engine_skipped`;
- `auto_engine_outcome`;
- `auto_heartbeat`;
- eventos RAG e Forge.

Clientes devem manter compatibilidade com o NDJSON e não interpretar
desconexão do navegador como prova automática de falha do scanner.
Eventos Auto são sanitizados antes de entrar na sessão e no stream; payloads
brutos de subprocessos não devem contornar essa função.

## Verificação local

As regressões centrais podem ser verificadas sem alvo externo:

```bash
node --test \
  server/tests/auto-agent.test.js \
  server/tests/auto-planner-contract.test.js \
  server/tests/auto-effective-plan.test.js \
  server/tests/auto-session-security.test.js \
  server/tests/auto-resume-checkpoint.test.js \
  server/tests/auto-event-redaction.test.js \
  server/tests/auto-route-public-data.test.js \
  server/tests/auto-rag-runtime-security.test.js \
  server/tests/auto-strict-phase-gates.test.js \
  server/tests/auto-content-network-gates.test.js \
  server/tests/pipeline-resilience.test.js \
  server/tests/process-cancellation.test.js \
  server/tests/probe-cancellation.test.js \
  server/tests/kali-execution-policy.test.js \
  server/tests/secret-safety.test.js \
  server/tests/write-probes-safety.test.js \
  server/tests/forge-security.test.js \
  server/tests/recon-stream-route.test.js \
  server/tests/frameseven-integration.test.js \
  server/tests/vigolium-bridge.test.js \
  server/tests/vigolium-agent.test.js
```

Checks complementares:

```bash
node --test server/tests/opsec.test.js
node --test server/tests/auth.test.js
node --test server/tests/engagement.test.js
GHOSTRECON_NO_HTTP_LISTEN=1 node -e "import('./server/index.js')"
```

Esta evolução foi desenhada e testada com executores injetados, mocks e
fixtures. Nenhum scan real de rede, navegador autenticado, DAST, Kali, Nmap,
sqlmap ou alvo externo faz parte da validação documental desta entrega.

## Limitações conhecidas

1. O catálogo é híbrido; ainda há duplicação de classificação entre manifests,
   OPSEC e a lista de capacidades legadas.
2. O limite resiliente é por fase. Módulos legados dentro da mesma fase ainda
   precisam ser migrados para deadlines individuais.
3. O adapter FrameSeven não propaga uma política Tor/proxy estrita. Não trate
   sua seleção como garantia de paridade de transporte OPSEC.
4. A paridade residual de autenticação, proveniência e relatório entre RUN
   normal e Auto ainda precisa de teste ponta a ponta com navegador real
   controlado. Até esse E2E, níveis 3/4 permanecem experimentais.

O backlog atualizado está em
`MELHORIAS-PENDENTES-MODO-AUTO.md`.

## Histórico preservado

### 2026-07-05 — blueprint inicial

Foi definido o princípio comandante/ferramenta/orquestrador, o endpoint NDJSON,
o primeiro catálogo passivo, o detector de providers, o HexStrike intelligence
e a memória Markdown. Tabelas antigas de “melhor modelo” e nomes futuros eram
exemplos aspiracionais e foram removidas do contrato operacional porque
disponibilidade e IDs de modelos mudam.

### 2026-07-14 — decisão real e conselho

Entraram schema de decisão, adaptadores reais, conselho, persistência de turnos,
RAG orientado ao alvo, Forge pending/review/approval e isolamento de geração.

### 2026-07-16 — ciclo de vida

Entraram probes de usabilidade, sessão persistente, limites, cancelamento,
checkpoints, App Server Codex, Cursor Agent opcional, canary/rollback Forge e
reparo JSON limitado.

### 2026-07-20 — estabilização inicial

Execuções reais expuseram falhas de timeout do App Server e stalls no CORS.
Foram adicionados watchdog, cancelamento individual, reconciliação de sessões e
correções iniciais. A afirmação histórica de “desenvolvimento pausado” não é
mais o estado atual.

### 2026-07-25 — plano efetivo e endurecimento

O catálogo passou a cobrir manifests, legado e engines; o plano efetivo ganhou
expansão, hash e aprovação; níveis de autonomia passaram a ter política
explícita; sessões receberam ownership/RBAC; providers e subprocessos ganharam
encerramento em dois estágios; o pipeline Auto ganhou resiliência por fase; RAG
e Forge receberam redação, limites, isolamento e integridade. Probes implícitos
passaram a exigir capacidades explícitas no Auto; classificações divergentes
passaram a escolher o maior risco; write probes e validação online de segredos
foram separados e fechados por padrão.

### 2026-07-26 — retomada, Forge e FrameSeven

Checkpoints v2 passaram a representar somente fronteiras prontas e receberam
claim durável anti-replay. O catálogo passou a vincular identidade dos engines e
integridade Forge. O runtime Forge ganhou runner forte Bubblewrap, ativação
exclusiva por `activationId` e canário hash-bound. Eventos Auto passaram por
redação central antes da sessão/NDJSON. O FrameSeven passou a normalizar e
mesclar `report.json`, emitir um único terminal depois do merge e servir
relatórios por rota autenticada e contida.

Na revisão posterior do mesmo dia, o RUN manual recebeu cancelamento propagado
por `AbortSignal` e engagement/ROE formal para todo plano intrusivo expandido.
Naquele estágio histórico, a integração FrameSeven ainda dependia de
`tools all`; essa seleção foi posteriormente substituída pelos perfis explícitos
recon e ofensivo descritos neste documento. FrameSeven e Vigolium passaram a
revalidar a identidade selada antes de cada processo; o FrameSeven ganhou
deadlines separados por etapa. O lifecycle Forge passou a comparar
alvo/artefato/engagement sob lock, revalidar a autorização antes e depois do
canário e executar somente o módulo dinâmico com atestação por operação.
Relatórios públicos FrameSeven passaram a ser artefatos HTML/JSON/Markdown
regenerados e redigidos, lidos por descritor seguro e autorizados por
owner/engagement.
