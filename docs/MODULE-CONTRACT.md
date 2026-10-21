# Contrato para modulos GHOSTRECON

Este documento define o formato minimo para novos modulos do pipeline. A regra e simples: modulo novo precisa ser previsivel para executar, limitar recursos, emitir findings normalizados e ser testavel sem rede real quando possivel.

## Manifesto

Cada modulo novo deve declarar estes campos perto do topo do arquivo ou em um registry futuro:

```js
export const moduleManifest = {
  id: 'cookie_session_audit',
  name: 'Cookie / Session Audit',
  category: 'surface',
  intrusive: false,
  requiresAuth: false,
  requiresKali: false,
  timeoutMs: 60_000,
  concurrency: 4,
  outputs: ['finding'],
};
```

Depois de criar o manifesto, adicionar o modulo em `server/modules/module-registry.mjs`.
O endpoint `/api/capabilities` expoe essa lista para a UI e para automacoes futuras.

Campos obrigatorios:

- `id`: slug estavel usado em UI, playbook, testes e logs.
- `name`: nome humano.
- `category`: `discovery`, `surface`, `validation`, `aggressive`, `ai`, `persistence` ou `reporting`.
- `intrusive`: `true` se faz escrita, brute force, fuzzing pesado, spray, exploit ou alteracao de estado.
- `requiresAuth`: `true` se precisa de cookies/tokens do operador.
- `requiresKali`: `true` se depende de ferramenta externa do Kali.
- `timeoutMs`: limite padrao do modulo.
- `concurrency`: limite interno padrao.
- `outputs`: tipos emitidos, normalmente `finding`, `intel`, `artifact` ou `metric`.

## Assinatura de execucao

Modulo novo deve expor uma funcao pura o suficiente para teste:

```js
export async function runCookieSessionAudit(ctx) {
  const {
    target,
    findings = [],
    auth = null,
    modules = [],
    emit = () => {},
    log = () => {},
    fetchImpl = fetch,
    executor = null,
  } = ctx;

  return { findings: [], metrics: {}, artifacts: [] };
}
```

Regras:

- Aceitar `fetchImpl` ou `executor` injetavel para testes.
- Nao ler `req`/`res` diretamente.
- Nao gravar arquivo sem passar por um store/helper existente.
- Nao chamar processo externo diretamente; usar `runProcess` de `server/modules/module-runner.mjs`.
- Nao implementar pool proprio; usar `mapPool` de `server/modules/module-runner.mjs`.
- Nao ler body HTTP inteiro; usar `readResponseSnippet`.

## Findings

Finding minimo:

```js
{
  type: 'cookie_session',
  prio: 'low',
  score: 35,
  value: 'Cookie sem SameSite',
  meta: 'cookie=sessionid; host=app.example.com',
  url: 'https://app.example.com/'
}
```

Regras:

- `type` deve ser estavel e especifico.
- `prio`: `info`, `low`, `med`, `high` ou `critical`.
- `score`: numero entre 0 e 100.
- `value`: frase curta.
- `meta`: detalhe compacto, sem segredos em claro.
- `url`: quando houver origem verificavel.

### Evidência e resultado de execução — revisão de 2026-09-06

Inventário, candidato e falha operacional não são vulnerabilidades confirmadas.
Os IDs públicos dos módulos permanecem estáveis, com estas distinções:

- `firebase_audit`: somente GET; `summary.outcomes` distingue dados observados,
  negação, ausência de dados, erro, timeout e escopo recusado. `summary.status`
  parcial não significa regras seguras. Leitura pública tem impacto não verificado.
- `panel_exposure_audit` e `mysql_3306_intel`: inventário de superfície/serviço,
  sem inferir acesso indevido ou CVE pela presença de painel/porta.
- `dom_clobbering_audit` e `webshell_probe`: candidatos sem verificação de
  execução. O segundo não envia parâmetros de comando.
- ffuf/dirsearch: wrappers retornam `{ state, results, reason?, exitCode? }`;
  `done` com lista vazia exige processo e parse válidos. Erro, timeout e
  cancelamento têm eventos terminais próprios. Dados HTTP são inventário.
- InfoHunter: exit code/parse inválido e timeout não viram sucesso; stderr e
  stdout bruto não são publicados como erro. O pipeline de `info_disclosure_errors`
  preserva falha/cancelamento em vez de emitir `done` incondicional.
- Shannon: relatório IA normalizado como candidato. `cleanup.requested=true`
  confirma somente aceitação do pedido de cancelamento; sem término observado,
  `cleanup.confirmed` continua falso.
- Swarm: indisponível até plano nativo restrito. Autopilot: somente prévia;
  nenhuma saída de exemplo pode ser importada como evidência de scan.

Essas mudanças têm testes com mocks/fixtures; não atestam E2E dos motores reais.

### Snapshots persistidos e cobertura parcial — revisão de 2026-09-09

Um módulo que compara estado histórico deve persistir um envelope versionado,
canônico e verificável. O snapshot precisa registrar versão do formato e do
schema semântico, identidade exata da fonte, hash do conteúdo normalizado e
proveniência suficiente para recusar baseline incompatível ou adulterada.
Migração de formato antigo deve ser explícita e testada; formato desconhecido
falha fechado em vez de ser comparado por aproximação.

Coletores com várias requests devem devolver `outcomes` por tentativa e um
estado agregado. Cobertura incompleta não pode virar sucesso negativo:

- `done`: execução válida e cobertura prevista concluída;
- `done` com `partial: true` no evento terminal: houve resultado utilizável,
  mas alguma origem, camada ou limite ficou incompleto;
- `skipped`: nenhuma tentativa aplicável, com motivo;
- `failed`, `timeout` ou `cancelled`: refletem o encerramento real.

O runner pode usar internamente `status: 'partial'`, mas o evento NDJSON
terminal deve preservar o contrato acima. Métricas e proveniência devem chegar
ao pipeline sem publicar corpo bruto, cookie, token ou header sensível.
Campos textuais de outcome (`reason`/`error`) e logs de runners passam pela
redação central, por limite de tamanho e, no caso do nível de log, por
allowlist antes do evento NDJSON.

#### Contrato atual de `api_contract_diff` — revisão de 2026-09-14

O formato atual é snapshot schema 2 com canonicalização 8. Canonicalizações
2–7 continuam validáveis para leitura, mas não são comparadas silenciosamente
com a 8; a migração v1 é explícita e não vira baseline completo. A versão
canônica persistida também deve corresponder à versão OpenAPI/Swagger original.

A canonicalização 8 valida referências incorporadas por contexto e tipo,
incluindo JSON Pointer, `$dynamicRef` nos dialetos suportados, `operationRef`,
`discriminator.mapping`, `$self`, `$id`, anchors e Schema booleano. Dados de
runtime de Link e keywords que não pertencem ao draft ativo ficam opacos;
dialeto de Schema desconhecido falha com cobertura parcial. Referência interna
ausente, de tipo incorreto ou ambígua produz cobertura `partial`, fica
inelegível como baseline e não gera diff. Referências externas usam o modo
`detect_only_v1`: são inventariadas e redigidas, mas não baixadas nem
resolvidas.

JSON e YAML rejeitam chaves duplicadas, profundidade, cardinalidade e tamanho
excessivos. YAML e JSON grande usam worker cancelável; JSON pequeno usa parser
estrito local para evitar o custo de inicialização. Defaults equivalentes de
Parameter, Header e Request Body Object são normalizados tanto inline quanto em
components, sem ocultar valores não default. O scanner verifica deadline também
durante mapas escalares, mappings e JSON Pointers extensos.

A descoberta testa os dez caminhos conhecidos por origem com concorrência 2 e
commit determinístico; `stealth_requests` reduz a concorrência para 1. Timeout
por request degrada a cobertura e permite continuar. O deadline próprio cancela
requests pendentes, retorna `timeout` e preserva snapshots já materializados;
cancelamento do operador propaga a razão e interrompe a execução.

Falha na leitura remota do baseline com fallback local, ou estouro do limite
cumulativo de bytes, marca o baseline como degradado/parcial e suprime diff.
Falha de gravação remota é reportada separadamente ao chamador.
SQLite possui E2E local com reabertura real. PostgreSQL e Supabase possuem
testes de contrato, transação/compensação e cancelamento com adapters
injetados; isso não atesta disponibilidade, TLS, RLS ou operação de um provider
real. Os hashes verificam consistência do envelope, não autenticidade assinada
da origem.

## OPSEC

Modulo `intrusive: true` deve respeitar:

- engagement/ROE quando o fluxo o exigir; no RUN manual é opcional e validado quando informado
- janela operacional
- confirmacao explicita
- escopo e exclusoes
- perfil OPSEC

Se houver duvida, o modulo deve gerar plano ou finding informativo, nao executar acao ativa.

## Testes

Cada modulo novo deve ter teste em `server/tests/<id>.test.js` cobrindo:

- parsing/normalizacao
- caso positivo
- caso negativo
- timeout/erro controlado
- ausencia de rede real via `fetchImpl` ou `executor`

Antes de merge:

```bash
npm test
npm audit --omit=dev
```
