# Plano de melhorias do Modo Auto e integração das IAs

Documento de investigação, decisões e evolução do Modo Auto.

Criado em: 2026-07-14

Última revisão: 2026-07-26

> Este arquivo preserva a sequência da investigação. O contrato operacional
> vigente está em `MODO-AUTO-GHOSTRECON.md` e o backlog em
> `MELHORIAS-PENDENTES-MODO-AUTO.md`. Afirmações históricas sobre o que “não
> funciona” não prevalecem sobre o código e os testes atuais.

## Resumo executivo

O problema original tinha duas partes:

1. as IAs eram detectadas, mas não participavam de uma decisão estruturada e
   auditável;
2. mesmo depois da integração dos providers, o plano visto pelos gates não
   correspondia necessariamente a todas as fases e engines que o pipeline podia
   habilitar.

A primeira parte foi tratada nas evoluções de 14 e 16 de julho: providers reais,
contrato JSON, conselho, RAG, sessão iterativa e Module Forge. Execuções reais de
20 de julho revelaram problemas adicionais de timeout, cancelamento e progresso.

A evolução de 25 de julho trata a segunda parte e endurece o ciclo de vida:

- catálogo híbrido ampliado;
- política explícita para quatro autonomias;
- plano efetivo expandido, congelado e identificado por hash;
- RBAC, ownership, engagement/ROE, OPSEC e aprovação sobre o plano completo;
- engines externas opt-in;
- gates explícitos dentro das fases para impedir ações legadas implícitas;
- classificação conservadora entre manifests e catálogo legado;
- timeout com encerramento real de processos;
- resiliência por fase sem sobreposição de trabalho;
- RAG redigido e limitado;
- findings de segredo protegidos e validação online explicitamente intrusiva;
- write probes Supabase/Firebase/FTP separados e desligados por padrão;
- Forge isolado e selado contra adulteração;
- outcomes por fase, módulo e engine;
- status `partial` para resultado útil com falhas recuperáveis.

A evolução de 26 de julho reforça as fronteiras que ainda permitiam replay ou
ambiguidade operacional:

- checkpoint v2 somente nas fronteiras prontas, com claim atômico durável;
- identidade dos engines e integridade Forge vinculadas ao catálogo/plano e
  revalidadas antes de cada processo;
- runner Forge forte Bubblewrap em Linux e ativação exclusiva por
  `activationId`;
- CAS de alvo, artefato e engagement sob lock, com revalidação antes/depois do
  canário dinâmico isolado;
- redação central de eventos antes da sessão e do NDJSON;
- cancelamento propagado também no RUN manual;
- engagement formal e confirmação obrigatórios para todo plano intrusivo
  expandido no RUN; o antigo `tools all` FrameSeven foi substituído por perfis
  explícitos e o perfil ofensivo continua sujeito aos mesmos gates;
- deadlines FrameSeven separados por captura, aprovação, `before_scan` e scan;
- normalização, dedupe e merge do `report.json` FrameSeven antes do terminal;
- relatórios FrameSeven regenerados de findings redigidos e rota autenticada,
  vinculada a owner/engagement, com leitura por descritor seguro.

O Auto continua beta supervisionado. A implementação foi validada localmente
com mocks e fixtures; esta entrega não inclui scan real de rede, browser
autenticado, DAST ou ferramentas Kali.

## Estado atual versus diagnóstico histórico

As seguintes afirmações pertenciam ao diagnóstico de 2026-07-14 e estão
**superadas**:

| Afirmação antiga | Estado atual |
| --- | --- |
| “Codex não é chamado pelo Auto” | Codex possui App Server por sessão e fallback `codex exec` |
| “OpenRouter/Skynet/modelo local só são detectados” | Há adaptadores de decisão estruturada e probes de usabilidade |
| “A lista de módulos é fixa” | O catálogo combina registry, legado, Forge e engines |
| “Não existe schema de decisão” | Schema e normalizador validam ações, campos e evidências |
| “Não existe conselho” | Propostas e revisão passam por arbitragem determinística |
| “Não existe cancelamento compartilhado” | Sessão, providers, pipeline e processos recebem cancelamento |
| “RAG só usa recentes globais” | Recuperação e observações são orientadas ao alvo, redigidas e limitadas |
| “Forge é apenas uma pasta pending” | Há lifecycle, review, aprovação, canário Bubblewrap, ativação hash-bound e integridade |

Fatos operacionais que permanecem verdadeiros:

- Cursor em modo handoff não conta como decisão em tempo real;
- nenhum provider pode ignorar catálogo, RBAC, scope, engagement ou OPSEC;
- recomendação HexStrike não equivale a execução;
- ferramentas externas dependem de instalação e configuração;
- checkpoints v2 retomam apenas fronteiras `ready`; não retomar
  mid-engine/mid-evaluation é o comportamento fail-closed deliberado;
- Forge requer o runner forte Bubblewrap/Linux e falha fechado sem ele.

Limitações ainda abertas:

- módulos legados ainda compartilham deadlines no nível da fase;
- catálogo e classificação ainda são híbridos;
- o adapter FrameSeven ainda não propaga Tor/proxy estrito;
- RUN normal e Auto ainda precisam de paridade residual de autenticação,
  proveniência e relatório, inclusive E2E com navegador real controlado.

## Objetivo de produto

Somente as IAs escolhidas pelo operador podem propor decisões reais. Cada
proposta precisa ser:

- estruturada;
- atribuída a provider/modelo/papel;
- limitada às evidências permitidas;
- validada contra o catálogo da sessão;
- transformada em um plano efetivo determinístico;
- aprovada quando necessário;
- reproduzível por hash e snapshot;
- avaliada depois da execução.

O GHOSTRECON, e não a IA, é a autoridade de execução.

## Ameaças consideradas

### Elevação por catálogo incompleto

Uma IA via apenas módulos passivos enquanto o pipeline podia habilitar Kali,
Vigolium ou fases implícitas por perfil. A correção é catalogar o legado e
expandir tudo antes dos gates.

### Elevação por fallback

Uma saída inválida podia cair em plano determinístico mais amplo. O fallback
agora precisa permanecer dentro da autonomia, opt-ins e classes permitidas.

### Ação desconhecida e contrato parcial

Modelos retornaram `request_modules`, `execute_modules`, `objective` ausente e
`confidence` inválida. Aliases conhecidos são normalizados; campos e invariantes
continuam obrigatórios; ações desconhecidas falham.

### Timeout sem encerramento

Um `Promise.race` podia devolver timeout enquanto App Server, CORS ou subprocesso
continuava ativo. O timeout agora aborta, envia `SIGTERM`, escala para `SIGKILL`
e espera settle. Sem settle, a run para.

### Desconexão no RUN manual

O stream manual podia fechar sem uma autoridade comum de cancelamento. A rota
agora cria um `AbortController` por request e propaga o sinal ao pipeline e às
integrações. O comportamento continua fail-fast, mas desconexão não deixa o
trabalho deliberadamente solto.

### Intrusivo manual sem autorização formal

RBAC e confirmação isolados não provavam escopo, janela nem ROE. O RUN manual
agora expande módulos, engines e dependências antes do preflight; se qualquer
item efetivo for intrusivo, exige cumulativamente `recon.intrusive`, engagement
formal ativo, ROE assinado, alvo dentro do escopo/janela e `confirmActive`. O
FrameSeven é o único motor que mantém perfil ofensivo no Auto; esse perfil é
explícito, read-oriented e não inclui `tools all` nem `-active-scan`.

### Troca de engine depois da aprovação

Validar apenas o caminho do binário permitia TOCTOU entre catálogo/plano e
`spawn`. FrameSeven e Vigolium agora selam hash, tamanho e metadados do arquivo
regular no catálogo/plano e revalidam essa identidade imediatamente antes de
cada processo. O executor não aceita uma identidade nova implicitamente.

### Confusão entre heartbeat e progresso

Heartbeat ativo mascarava fase travada. A sessão registra atividade atual,
timestamps e outcomes; watchdog usa falta de progresso, não a mera existência
de heartbeat.

### Sessão acessível por outro operador

Listagem, cancelamento e aprovação precisavam de vínculo com o principal. O
ownership agora é persistido e conferido nas rotas e na retomada.

### Replay de checkpoint

Um snapshot antigo podia ser restaurado depois de uma iteração já ter começado,
repetindo providers ou engines. Checkpoints v2 agora descrevem apenas planos
prontos e são consumidos por claim `wx` durável. Apenas
`ready_for_iteration`/`ready_for_next_iteration` são retomáveis; v1 continua
legível, mas não retomável, e não há retomada mid-engine/mid-evaluation.

### Persistência de segredos

Findings, URLs, headers e RAG podem conter cookies e tokens. A redação agora é
central, recursiva e aplicada antes das principais gravações do Auto. Eventos
também são sanitizados antes de atualizar a sessão e atravessar o NDJSON.

### Execução implícita dentro de uma fase

Mesmo com um plano correto, fases legadas ainda podiam disparar HTTP/WAF,
verificação, descoberta ativa de parâmetros, takeover, recheck HIGH ou
ferramentas Kali apenas por perfil/entrada na fase. O caminho Auto passou a
exigir IDs explícitos no runtime para essas capacidades. Fontes passivas de URL
também deixaram de autorizar implicitamente o fetch de bundles do alvo.

### Escrita habilitada por credencial descoberta

Token de ambiente, anon key, `service_role` ou configuração pública não podem
ser tratados como autorização para signup, insert, update, delete, upload, RPC
mutável ou FTP `STOR`. Esses writes foram separados dos probes de leitura e
permanecem desligados por padrão.

### Código Forge adulterado

Um pacote aprovado podia mudar antes da execução. O lifecycle sela código,
teste e manifest; o runtime verifica a integridade e falha fechado.

Também havia uma janela entre a autorização mostrada ao operador e o primeiro
canário. A transição agora compara, sob lock, alvo + artefato + binding/version
do engagement e revalida o engagement antes e depois da execução. O canário usa
somente o runner dinâmico; fases legadas, DNS e finalize não participam.

### Relatório trocado ou bruto exposto

Resolver caminho e ler depois permitia corrida com symlink/substituição; servir
o relatório bruto também podia expor material não redigido. A API passou a
regenerar apenas HTML/JSON/Markdown a partir de findings normalizados/redigidos,
abrir com `O_NOFOLLOW`, ler pelo mesmo FD e comparar `fstat`. Owner, engagement e
CSP sem scripts são conferidos na rota protegida.

## Decisões de arquitetura

### 1. Catálogo híbrido temporário

Ainda não é viável migrar todo o pipeline legado para o registry numa única
mudança. O Auto constrói uma visão unificada a partir de:

- `listModuleManifests()`;
- capacidades legadas declaradas em `pipeline-capabilities.mjs`;
- manifests Forge ativos;
- capacidades explícitas de FrameSeven;
- disponibilidade do Vigolium;
- disponibilidade do HexStrike.

Essa é uma ponte. A direção futura é eliminar duplicação e tornar o manifest a
fonte única.

### 2. Classes de risco, não nomes de perfil

O planner escolhe IDs classificados como:

- `passive`;
- `deep_passive`;
- `active`;
- `intrusive`;
- `hexstrike_intel`.

Classe `destructive` é excluída. O perfil de execução (`quick`, `standard`,
`deep`) não substitui classe de risco, OPSEC ou aprovação.

### 3. Quatro autonomias limitadas

| Autonomia | Limite |
| --- | --- |
| `observation` | passivo/deep-passive/inteligência |
| `assisted` | inclui ativo não intrusivo, após aprovação |
| `authorized` | inclui intrusivo, com `recon.intrusive` e gates |
| `authorized_opsec` | mesmo limite de risco, OPSEC agressivo |

Níveis 2–4 exigem confirmação do plano. Níveis 3/4 não são “modo sem limites” e
jamais incluem destrutivo.

### 4. Opt-ins independentes

HexStrike, Vigolium e FrameSeven não entram apenas porque estão instalados.
Cada um exige opt-in da sessão. FrameSeven autenticado e Vigolium/Codex possuem
controles adicionais. Recusar qualquer aprovação encerra sem executar
pipeline, módulo ou engine; não há reexpansão automática de “restante seguro”.

### 5. Plano efetivo imutável

O plano efetivo contém:

- alvo e ação;
- autonomia e perfis;
- módulos solicitados;
- módulos de pipeline;
- lista expandida;
- módulos intrusivos;
- engines e agentes;
- flags Kali/confirm;
- engagement;
- política aplicada;
- identidades seladas de FrameSeven/Vigolium quando habilitados;
- hash SHA-256.

Ele é congelado antes da execução. A UI e a trilha exibem o mesmo hash. Se o
plano mudar, os gates precisam rodar novamente.

Quando manifest e capacidade legada divergem, prevalece a classe de maior
risco, e requisitos como Kali/autenticação são combinados. Depois do freeze,
gates internos das fases conferem novamente capacidades sensíveis para impedir
execução implícita por compatibilidade legada.

### 6. Resiliência somente quando segura

O usuário solicitou que um módulo em timeout fosse registrado e o próximo
continuasse. Isso é correto apenas quando o módulo realmente encerrou e o
estado da pipeline ainda é íntegro.

Por isso:

- erro/timeout recuperável + settle: registra e continua;
- cancelamento do operador: encerra;
- fase crítica: encerra;
- processo/fase sem settle: encerra;
- resultado com falha recuperável: `partial`.

O RUN manual permanece fail-fast por padrão.

Fail-fast não significa sem cancelamento. A rota manual possui
`AbortController` próprio e encaminha o sinal ao pipeline, Vigolium e
FrameSeven quando o request é abortado ou o stream fecha.

### 7. Engines em ordem determinística

Quando selecionados, os motores executam em:

```text
GHOSTRECON → Vigolium → FrameSeven
```

Cada um produz outcome próprio. O FrameSeven não é executado se o pipeline
anterior ainda estiver vivo após um deadline.

O FrameSeven só emite sucesso depois de validar e mesclar seu `report.json`.
Resultado de scan aproveitável, relatório incompleto ou falha recuperável de
merge vira um único `partial`; fontes e evidências são agregadas durante a
deduplicação.

No RUN manual, qualquer item intrusivo do plano expandido exige
`recon.intrusive`, engagement formal ativo com ROE/escopo/janela e
`confirmActive`. O perfil ofensivo FrameSeven usa a lista explícita
`recon,access,redirect,misconfig,cve,crawler,content,subdomain,ports,nmap,bannergrab`
e continua intrusivo mesmo sem auth; `tools all`, `-active-scan` e write probes
ficam de fora. Captura auth, aprovação, `before_scan` e scan do FrameSeven
possuem deadlines separados; timeout/cancelamento faz TERM→KILL e espera
settle/cleanup.

Somente `report.html`, `report.json` e `report.md`, regenerados dos findings
redigidos, são servidos por rota `recon.read`. PDF/raw são recusados; owner e
engagement são validados, e a leitura usa `O_NOFOLLOW` + FD/`fstat`, com CSP
sandbox sem scripts.

### 8. Forge fail-closed

Forge continua limitado a módulos não intrusivos. Geração, validação e testes
não autorizam ativação; há review e aprovação humana. O runtime usa worker
forte Bubblewrap em Linux e verifica hashes. Sem esse sandbox, o módulo fica
indisponível e o canário falha fechado.

Pacotes antigos sem `runtimeIntegrity` não recebem exceção: precisam de nova
revisão e aprovação.

Uma aprovação entra em `active_pending_first_run`, ainda com
`pipelineEnabled=false`, e recebe `activationId`. A aprovação faz CAS de alvo,
integridade do artefato e binding/version/hash do engagement sob lock; o
engagement é revalidado dentro do lock e imediatamente antes/depois do canário.

O primeiro canário chama somente o runner do módulo dinâmico aprovado, com
timeout/abort, zero pipeline legado, DNS, finalize ou engine implícita. Cada
operação do sandbox deve devolver atestação ligada ao `operationId`/challenge;
acknowledgement de kill sem o processo assentar não libera a operação. Somente o
resultado dessa ativação e dos hashes aprovados pode habilitar o pacote;
resultados obsoletos não reativam estado.

### 9. Segredos e writes fail-closed

Findings de segredo são mascarados e recebem fingerprint antes de serialização.
O valor cru necessário a uma validação autorizada permanece apenas em memória e
não é enumerável. Captura é opt-in e os artefatos são redigidos/restritos.

`secret_validation` é uma capacidade intrusiva explícita; sua ausência impede
probe online. Supabase/Firebase não fazem writes/signup no pipeline, ainda que
uma variável de ambiente ou token exista. FTP `STOR` também depende de gate
separado e fica desligado por padrão.

## Componentes envolvidos

| Área | Fonte principal |
| --- | --- |
| Catálogo | `server/auto-agent/tool-catalog.mjs` |
| Capacidades legadas/engines | `server/auto-agent/pipeline-capabilities.mjs` |
| Plano efetivo | `server/auto-agent/effective-plan.mjs` |
| Orquestração | `server/auto-agent/orchestrator.mjs` |
| Contrato | `server/auto-agent/decision-contract.mjs` e `schemas/decision.schema.json` |
| Conselho | `server/auto-agent/council.mjs` |
| Providers | `server/auto-agent/providers/` |
| Sessões/claims | `session-store.mjs` e `active-sessions.mjs` |
| Rotas Auto/Forge/report | `server/routes/auto-recon.mjs` |
| RUN manual/cancelamento | `server/routes/recon-stream.mjs` |
| RAG/eventos/redação | `rag-memory.mjs`, `observation-builder.mjs`, `redaction.mjs` e `orchestrator.mjs` |
| Forge lifecycle/runtime | `server/auto-agent/forge/lifecycle.mjs`, `runtime-loader.mjs`, `sandbox-policy.mjs`, `runtime-worker.mjs` e `bwrap-runner.mjs` |
| Resiliência | `server/pipeline/phase-executor.mjs` |
| Processos gerenciados | `server/lib/process-execution-context.mjs` e module runner |
| Segredos/writes | `server/modules/secret-safety.js`, `secret-validation.js`, audits Supabase/Firebase e política Kali |
| Vigolium auth/identidade | `bridge/vigolium-auth-transport.mjs` e `vigolium-binary-integrity.mjs` |
| FrameSeven execução/report | `server/integrations/frameseven-*.mjs` |
| UI | `public/index.html` |

## Contrato de decisão

Ações canônicas:

```text
run_modules
continue_with_context
finish
ask_operator
forge_module
abstain
```

Aliases conhecidos:

```text
request_modules → run_modules
execute_modules → run_modules
```

Envelope mínimo:

```json
{
  "action": "run_modules",
  "objective": "Mapear a superfície HTTP autorizada",
  "reasoningSummary": [
    "O catálogo oferece módulos não intrusivos adequados ao objetivo."
  ],
  "evidenceRefs": [],
  "requestedModules": ["security_headers"],
  "rejectedModules": [],
  "confidence": 0.82,
  "assumptions": [],
  "operatorQuestion": null,
  "forgeRequest": null
}
```

O normalizador não inventa objetivo ou confiança para aceitar qualquer saída.
Ele aplica aliases limitados, formato e invariantes. Módulos inexistentes,
indisponíveis, fora da autonomia ou sem opt-in não chegam ao pipeline.

## Provider e conselho

O probe separa:

```json
{
  "installed": true,
  "configured": true,
  "authenticated": true,
  "reachable": true,
  "usable": true
}
```

Somente `selected && usable` participa. O App Server Codex é reutilizado por
sessão e fechado no timeout/cancelamento; fallback executa com stdin fechado e
timeout independente.

O conselho usa proposta e revisão estruturadas. Evidência e policy têm poder de
veto. Maioria não torna um módulo inválido aceitável. Empate de alto impacto
pergunta ao operador. O fallback não pode ampliar autonomia.

## Segurança da sessão

O principal autenticado é persistido de forma mínima como proprietário. As
rotas aplicam:

- `recon.run` para iniciar/cancelar/aprovar;
- `recon.read` para listar;
- `recon.intrusive` para níveis 3/4 e aprovação intrusiva;
- CSRF nas operações mutáveis;
- ownership em listagem, cancelamento, aprovação e retomada.

Snapshots são atômicos e restritos. Uma sessão ativa duplicada falha. O
checkpoint v2 vincula alvo, proprietário, autonomia, política, `catalogHash`,
`promptVersion`, `resumePolicyHash`, plano pronto e cadeia de hashes. Somente
fronteiras `ready` são retomáveis e cada hash é consumido por claim atômico
durável. Checkpoint v1 é legível, mas não retomável; execução ou avaliação
interrompida não continua do meio.

## Segurança dos dados

Antes de RAG e observation bundle:

- segredos são redigidos em strings, arrays e objetos;
- objetos têm profundidade e quantidade de chaves limitadas;
- findings são deduplicados;
- previews e arquivos têm limite de bytes;
- escrita usa arquivo temporário restrito e rename atômico.

Antes de eventos e persistência comum, findings `secret` também são protegidos
por máscara + fingerprint. Material cru não é campo JSON. Contexto auth
compartilhado com Vigolium usa `--auth-file` temporário `0600` em diretório
`0700`, redação de argv/log e cleanup em `finally`.

Antes de tocar a sessão ou enviar NDJSON, cada evento Auto passa por sanitização
recursiva. Segredos são redigidos, o root local é substituído e campos de
artefato com caminho absoluto são removidos. Relatórios brutos de engines
externas ainda exigem validação própria e teste ponta a ponta.

RAG é dado não confiável. Nenhuma instrução encontrada num alvo ou numa memória
histórica é promovida para system prompt.

## Segurança do Forge

Requisitos de uma solicitação:

- lacuna comprovada;
- evidência permitida;
- benefício;
- entradas e saídas;
- estratégia offline;
- riscos;
- `intrusive: false`.

O pacote passa por validação estática, syntax check, testes restritos, review,
aprovação e canary. Na execução Bubblewrap:

- não há namespace de rede do host;
- ambiente, imports e filesystem são limitados;
- artefatos são montados somente para leitura e `/tmp` é efêmero;
- subprocessos são bloqueados;
- tempo, memória e output são limitados;
- findings são normalizados/redigidos;
- hashes do pacote são verificados;
- cada operação recebe `operationId`/challenge próprios e precisa atestar o
  sandbox forte;
- timeout/cancelamento exige acknowledgement e settle real do processo.

Sem Linux/Bubblewrap o Forge fica indisponível. O canário inicial não recebe o
perfil manual amplo: chama diretamente apenas o ID aprovado no runner dinâmico,
sem fases legadas/DNS/finalize, com deadline próprio e cancelamento por
desconexão. Alvo, artefato e engagement são comparados sob lock e a autorização
é revalidada antes/depois. A ativação continua desabilitada globalmente até o
canário com `activationId` e hashes correspondentes concluir.

## Implementação por etapas

### Etapa 1 — providers reais (concluída em 2026-07-14)

- [x] seleção somente entre providers marcados;
- [x] contrato comum;
- [x] Codex/OpenRouter/GHOST;
- [x] Claude Code read-only;
- [x] redação de contexto;
- [x] testes offline.

### Etapa 2 — decisão e RAG (concluída)

- [x] schema;
- [x] prompts versionados;
- [x] evidências permitidas;
- [x] decisões persistidas;
- [x] RAG orientado ao alvo;
- [x] observações pós-pipeline.

### Etapa 3 — conselho (concluída)

- [x] planner/reviewer;
- [x] arbitragem determinística;
- [x] confiança/evidência;
- [x] conflito e `ask_operator`;
- [x] nenhuma participação de provider não selecionado.

### Etapa 4 — sessão iterativa (concluída)

- [x] limites;
- [x] checkpoints v2 nas fronteiras `ready`;
- [x] claim durável anti-replay;
- [x] v1 legível, mas não retomável;
- [x] retomada mid-engine/evaluation recusada;
- [x] avaliação pós-pipeline;
- [x] não repetir módulos;
- [x] cancelamento;
- [x] snapshots e RAG.

### Etapa 5 — Forge e lifecycle (concluída localmente)

- [x] pending e proveniência;
- [x] validação/teste/review;
- [x] aprovação;
- [x] canary/rollback;
- [x] Bubblewrap forte em Linux e indisponibilidade fail-closed;
- [x] `active_pending_first_run` + `activationId` hash-bound;
- [x] selo e detecção de adulteração;
- [x] CAS de alvo/artefato/engagement sob lock;
- [x] revalidação de engagement antes/depois do canário;
- [x] canário somente dinâmico e atestação por operação com kill ack + settle.

### Etapa 6 — plano efetivo e políticas (concluída localmente em 2026-07-25)

- [x] catálogo híbrido;
- [x] classes de risco;
- [x] autonomia 1–4;
- [x] plano expandido/hash;
- [x] engines opt-in;
- [x] RBAC e ownership;
- [x] aprovação 2–4.
- [x] classificação conservadora entre manifest/legado;
- [x] gates explícitos por capacidade dentro das fases Auto;
- [x] recusa encerra tudo sem “restante seguro”.

### Etapa 7 — robustez de runtime (parcialmente concluída)

- [x] App Server e CLI com TERM→KILL;
- [x] deadline/settle por fase;
- [x] outcomes e status `partial`;
- [x] cancelamento não recuperável;
- [x] probes/pausas e subprocessos direcionados abort-aware;
- [x] segredos mascarados, `secret_validation` explícito e writes desligados;
- [x] canário Forge restrito;
- [x] redação central de eventos Auto/NDJSON;
- [x] FrameSeven normalizado/mesclado com terminal único `done`/`partial`;
- [x] RUN manual com AbortController e cancelamento propagado;
- [x] gate formal/confirmado para todo plano intrusivo expandido no RUN;
- [x] perfil ofensivo FrameSeven explícito coberto por engagement/ROE,
      `recon.intrusive` e confirmação, sem `tools all` ou `-active-scan`;
- [x] identidade FrameSeven/Vigolium revalidada antes de cada spawn;
- [x] deadlines FrameSeven separados por etapa e TERM→KILL/settle;
- [x] rota owner/engagement para relatórios FrameSeven regenerados,
      HTML/JSON/Markdown e lidos por FD seguro;
- [ ] deadline individual para cada módulo legado;
- [ ] E2E autenticado com navegador real controlado.

### Etapa 8 — paridade residual (pendente)

- [x] normalizador/merge de `report.json` compartilhado entre RUN e Auto;
- [ ] fechar diferenças restantes de plano, auth, proveniência e relatório entre
      RUN e Auto;
- [ ] transportar política Tor/proxy estrita ao FrameSeven;
- [ ] promoção dos níveis 3/4 após canários.

## Testes de regressão

Arquivos centrais:

- `server/tests/auto-agent.test.js`;
- `server/tests/auto-planner-contract.test.js`;
- `server/tests/auto-effective-plan.test.js`;
- `server/tests/auto-session-security.test.js`;
- `server/tests/auto-resume-checkpoint.test.js`;
- `server/tests/auto-event-redaction.test.js`;
- `server/tests/auto-route-public-data.test.js`;
- `server/tests/auto-rag-runtime-security.test.js`;
- `server/tests/auto-strict-phase-gates.test.js`;
- `server/tests/auto-content-network-gates.test.js`;
- `server/tests/pipeline-resilience.test.js`;
- `server/tests/process-cancellation.test.js`;
- `server/tests/probe-cancellation.test.js`;
- `server/tests/kali-execution-policy.test.js`;
- `server/tests/secret-safety.test.js`;
- `server/tests/write-probes-safety.test.js`;
- `server/tests/forge-security.test.js`;
- `server/tests/recon-stream-route.test.js`;
- `server/tests/frameseven-integration.test.js`;
- `server/tests/vigolium-bridge.test.js`;
- `server/tests/vigolium-agent.test.js`.

Comando local:

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

Também são relevantes `auth.test.js`, `opsec.test.js`,
`engagement.test.js`, `scope.test.js` e `module-runner.test.js`.

Esses testes devem permanecer sem rede real. A suíte completa `npm test` contém
cenários potencialmente não herméticos e só deve ser executada depois de revisar
o ambiente.

## Critério de conclusão desta evolução

A evolução local está pronta para revisão quando:

1. o catálogo expõe apenas classes e engines autorizáveis;
2. o hash aprovado é o hash executado;
3. níveis 2–4 abrem confirmação e níveis 3/4 exigem
   `recon.intrusive`;
4. qualquer recusa encerra sem executar pipeline, módulo ou engine;
5. timeout encerra o processo ou interrompe a run como unsettled;
6. falhas recuperáveis geram `partial`;
7. ownership impede controle cruzado de sessões;
8. checkpoint v2 claimed não pode ser reproduzido;
9. RAG, eventos Auto e Forge não persistem segredos das fixtures;
10. Forge compara alvo/artefato/engagement, executa somente o módulo dinâmico e
    falha se atestação/settle forem inválidos;
11. FrameSeven/Vigolium recusam identidade diferente da selada;
12. RUN manual propaga cancelamento e bloqueia qualquer plano intrusivo
    expandido — inclusive o perfil ofensivo FrameSeven explícito — sem
    autorização formal/confirmada;
13. FrameSeven só finaliza após o merge e a rota expõe somente relatórios
    redigidos HTML/JSON/Markdown por owner/engagement;
14. os testes direcionados passam.

Isso autoriza um canário local controlado; não transforma automaticamente os
níveis 3/4 em recurso estável para alvos externos.

## Próxima entrega recomendada

1. executar o E2E autenticado do RUN e do Auto num laboratório autorizado com
   navegador real controlado;
2. migrar módulos legados de maior risco para manifests/runners com deadline
   individual e reduzir a duplicação do catálogo;
3. transportar a política Tor/proxy estrita ao FrameSeven;
4. fechar a paridade residual de plano, auth, proveniência e relatório entre
   RUN e Auto;
5. somente então avaliar a promoção das autonomias 3/4.
