# GHOSTRECON — AUTH + RBAC (P0)

Documento da camada de controlo de acesso adicionada em `server/modules/auth.js`
e plugada em `server/index.js` + `server/modules/api-extensions.js`.

> Contexto operacional recomendado: **localhost-first**. O default de `HOST` no
> servidor é `127.0.0.1`; se fizer bind não-local, trate esta instância como
> superfície exposta e endureça configuração de auth/segredos.

## TL;DR

```bash
# 1. Gerar uma API key forte
node -e "console.log(require('crypto').randomBytes(32).toString('base64url'))"

# 2. Configurar no .env (ou shell env)
export AUTH_MODE=apikey
export AUTH_API_KEYS="<key-gerada>:red:laptop|<outra>:admin:ci-runner"

# 3. Chamar a API
curl -H "Authorization: Bearer <key>" -H "X-CSRF-Token: <csrf>" \
     -X POST http://127.0.0.1:3847/api/recon/stream \
     -d '{"domain":"example.com","modules":["dns","probe"]}'
```

Sem auth → respostas `401`. Tentar uma rota intrusiva sem o role certo → `403`.

## Modos de auth

| Modo       | Quando usar                         | Como o pedido se autentica |
|------------|--------------------------------------|----------------------------|
| `apikey`   | CLI, CI, lab pessoal (default)       | `Authorization: Bearer <key>` ou `X-API-Key: <key>` |
| `jwt`      | SSO / OIDC / equipa com IdP          | `Authorization: Bearer <jwt>` (HS256 ou RS256) |
| `disabled` | Só dev local em loopback (warn loud) | Principal sintético `disabled:loopback` é injectado para 127.0.0.1/::1 |

`AUTH_DISABLE=1` em qualquer modo → bypass apenas para loopback. Pedidos remotos
continuam a falhar com 401, mesmo com `AUTH_MODE=disabled`. O loopback é
calculado pelo endereço real do socket; `X-Forwarded-For` só é considerado quando
`GHOSTRECON_TRUST_PROXY=1` e a conexão vem de um proxy local/confiável.

### Identidade estável de API key

O `sub` de uma API key usa um identificador HMAC; a key bruta não é usada como
identidade nem exposta na auditoria. Para que ownership, sessões e retomadas
owner-bound reconheçam o mesmo principal depois de reiniciar a API, configure
`AUTH_PRINCIPAL_BINDING_SECRET` com pelo menos 32 bytes.

Quando essa variável não existe, o servidor usa `AUTH_JWT_SECRET` se ele tiver
pelo menos 32 bytes. Sem nenhum segredo persistente, uma chave aleatória é
gerada no boot: a autenticação continua funcionando, mas o identificador de API
key muda no próximo processo e qualquer retomada ligada ao proprietário deve
falhar fechado. O boot emite um aviso nesse caso. Não versione nenhum desses
segredos.

## Roles

```
viewer    → recon.read
operator  → viewer + [recon.run, brain.write, notes.write, validation.write,
                      evidence.capture, cve.enrich]
red       → operator + [recon.intrusive, forge.review, ai.run, shannon.run,
                        project.write, engagement.write, team.lock]
admin     → '*'  (inclui forge.manage; operações destrutivas continuam sujeitas
                  aos gates próprios e ao escopo autorizado)
```

## Scope × Rota

| Scope               | Rota(s)                                                                                     | Verbo  |
|---------------------|---------------------------------------------------------------------------------------------|--------|
| _(allowlist)_       | `/api/health`, `/api/csrf-token`, `/api/inbound/*` (auth própria)                           | GET/POST |
| `recon.read`        | `/api/runs`, `/api/runs/:id`, `/api/runs/:newer/diff/:base`, `/api/runs/:id/diff-summary/:b`, `/api/runs/:id/narrative`, `/api/runs/:id/purple`, `/api/intel/:target`, `/api/playbooks*`, `/api/projects` (GET), `/api/engagements` (GET), `/api/team/locks`, `/api/team/trail`, `/api/brain/*` (GET), `/api/manual-validations/:target` (GET), `/api/anotacao-handoff/:id` (GET), `/api/capabilities`, `/api/project-secret-peers`, `/api/ai/lmstudio-check` | GET |
| `recon.read` (Auto) | `/api/recon/auto/sessions`, `/api/auto-rag/status`, `/api/auto-rag/search`, `/api/frameseven/reports/:reportId/:file` | GET |
| `recon.run`         | `/api/recon/preflight`, `/api/recon/stream`                                                 | POST   |
| `recon.run` (Auto)  | `/api/recon/auto/stream`, cancelamento/aprovação da própria sessão Auto, aprovação FrameSeven e verdict Forge quando combinado com `forge.review` | POST |
| `recon.intrusive`   | _Escala_ aplicada a `/api/recon/preflight` e `/api/recon/stream` sobre o plano expandido; `/api/recon/approval` sempre exige este scope. Inclui Kali, módulos intrusivos, Vigolium/DAST e FrameSeven `offensive_v1`; exige também engagement/ROE/escopo/janela, `confirmActive` e aprovação vinculada | POST |
| `recon.intrusive` (Auto) | _Escala_ aplicada ao stream Auto nos níveis 3/4, Vigolium, FrameSeven autenticado ou plano intrusivo; também é exigida ao resolver aprovação Auto/FrameSeven marcada como intrusiva | POST |
| `forge.review`      | Ler/comparar pacotes Forge; decidir aprovação/rejeição exige cumulativamente `recon.run`, CSRF e engagement formal válido para o canário | GET/POST |
| `forge.manage`      | Promover, habilitar, desabilitar, definir canary e fazer rollback de pacote Forge global | POST |
| `brain.write`       | `/api/brain/categories`, `/api/brain/categories/:id/description`, `/api/brain/link`         | POST   |
| `notes.write`       | `/api/anotacao-handoff`, `/api/auto-rag/note`                                               | POST   |
| `validation.write`  | `/api/manual-validations`                                                                   | POST   |
| `ai.run`            | `/api/ai-reports`, `/api/manual-validations/ai-report`, `/api/manual-validations/annotations-ai`, `/api/pentestgpt-ping` | POST |
| `shannon.run`       | `/api/shannon/prep`                                                                         | POST   |
| `evidence.capture`  | `/api/evidence/capture/:runId`                                                              | POST   |
| `cve.enrich`        | `/api/cve/enrich`                                                                           | POST   |
| `project.write`     | `/api/projects`                                                                             | POST   |
| `engagement.write`  | `/api/engagements`, `/api/engagements/:id/close`, `/api/engagements/checklist`              | POST   |
| `team.lock`         | `/api/team/lock`, `/api/team/unlock`                                                        | POST   |
| `admin` (role)      | `/api/tool-path-refresh`, `/api/team/force-unlock`, `/api/opsec/gate`, `DELETE /api/projects/:name` | POST/DELETE |

> Nota: A escalação `recon.intrusive` é aplicada via `intrusiveCheck` no
> middleware `requireScope` — se um operator (sem `recon.intrusive`) chamar o
> stream apenas com módulos passivos (DNS, probe, wayback…), passa. Se incluir
> qualquer módulo intrusivo, recebe 403. Depois da expansão do plano, qualquer
> módulo intrusivo também exige engagement formal ativo, ROE assinado, alvo
> dentro do escopo/janela, `confirmActive` e aprovação server-issued vinculada
> ao hash; `aggressive` não substitui esses controles.

## Aprovação vinculada do RUN manual

O RUN manual intrusivo usa três requisições autenticadas e protegidas por CSRF:

1. `POST /api/recon/preflight` expande o plano e emite um registro pendente;
2. `POST /api/recon/approval` aceita ou recusa aquele `approvalId`/`planHash`;
3. `POST /api/recon/stream` recompõe o plano e consome a aprovação antes da
   execução.

O preflight passivo exige `recon.run`. Quando a entrada já solicita capacidade
intrusiva, o `intrusiveCheck` exige também `recon.intrusive`; decidir a aprovação
sempre exige `recon.intrusive`. O registro é efêmero, vinculado ao `sub` do
principal, possui TTL e é de uso único. Ele vincula alvo, autorização do
engagement, módulos, opções de execução, ferramentas/limites e fingerprints dos
binários. Mudança, expiração, replay ou outro proprietário falham fechado.

O preflight recebe em memória o mesmo contexto privado necessário para calcular
o binding que será recomposto no stream. Ele não devolve nem persiste os
valores: o plano público contém apenas flags/contagens seguras e o registro
pendente guarda um HMAC opaco. Auth, cookies, headers sensíveis, senhas e paths
continuam fora do plano público. As ações `recon.manual_plan.issue`,
`recon.manual_plan.decision` e `recon.manual_plan.consume` entram na auditoria.

## Auto, Forge e relatórios FrameSeven

As proteções são cumulativas:

- ownership limita listagem, cancelamento, aprovação e retomada à identidade que
  criou a sessão;
- checkpoint v2 e claim anti-replay protegem o ciclo de execução, mas não
  substituem RBAC, CSRF, scope, engagement ou OPSEC;
- verdict Forge exige `forge.review` **e** `recon.run`; aprovação não habilita o
  pacote globalmente, pois o primeiro canário continua
  `active_pending_first_run`/`pipelineEnabled=false` até concluir com o
  `activationId` e os hashes aprovados;
- o canário Forge depende do runner forte Bubblewrap em Linux e falha fechado
  quando ele não está disponível;
- `GET /api/frameseven/reports/:reportId/:file` exige `recon.read` e aplica
  allowlist de HTML/JSON/Markdown públicos regenerados, owner e engagement,
  abertura `O_NOFOLLOW`, leitura pelo mesmo descritor com `fstat`, limite de
  tamanho, `Cache-Control: private, no-store`, `nosniff`, `Referrer-Policy` e
  CSP sandbox para HTML;
- identidades FrameSeven/Vigolium observadas no preflight são seladas no plano
  e revalidadas imediatamente antes dos processos; troca posterior falha
  fechado.

Eventos produzidos pelo orquestrador Auto são redigidos antes de entrar na
sessão e no NDJSON. Essa fronteira não transforma relatórios brutos de
ferramentas externas em dados públicos nem substitui a política de retenção.

## Formato JWT esperado

```json
{
  "alg": "HS256",
  "typ": "JWT"
}
```

Payload:
```json
{
  "sub": "alice",
  "role": "red",
  "scopes": ["recon.read","recon.run","recon.intrusive"],
  "iat": 1745800000,
  "exp": 1745886400,
  "aud": "ghostrecon",
  "iss": "https://auth.exemplo.com"
}
```

Regras:
- `alg: none` é sempre rejeitado.
- `role` é obrigatório e tem de ser um de `viewer|operator|red|admin`.
- `scopes` opcional — pode **restringir** o role mas nunca **expandir** (excepto admin).
- `exp`/`nbf` validados; `aud`/`iss` validados se as variáveis estiverem definidas.

## Audit log

Append-only NDJSON, 1 ficheiro por dia: `logs/audit-YYYY-MM-DD.ndjson`.

Exemplo de entry:

```json
{"ts":"2026-04-28T14:11:23.412Z","decision":"allow","method":"POST","route":"/api/recon/stream","ip":"127.0.0.1","ua":"curl/8.4","sub":"apikey:laptop","role":"red","via":"apikey","scope":"recon.run"}
{"ts":"2026-04-28T14:11:23.501Z","decision":"allow","method":"POST","route":"/api/recon/stream","ip":"127.0.0.1","ua":"curl/8.4","sub":"apikey:laptop","role":"red","via":"apikey","action":"recon.stream.start","target":"example.com","modules":["kali_nmap","sqlmap"],"kaliMode":true,"opsecProfile":"aggressive","profile":"standard","intrusive":true,"engagementId":"ENG-001"}
{"ts":"2026-04-28T14:12:01.118Z","decision":"deny","method":"POST","route":"/api/projects/foo","ip":"127.0.0.1","ua":"curl/8.4","sub":"apikey:laptop","role":"red","via":"apikey","reason":"role_mismatch","roleRequired":"admin"}
```

Use para correlacionar com `runId` da pipeline e investigar quem disparou o quê.

## Migração / Deploy

1. Copia `.env.example` → `.env` e:
   - escolhe `AUTH_MODE`
   - gera ≥1 API key forte (≥24 chars) e atribui a um role
   - define `AUTH_PRINCIPAL_BINDING_SECRET` (≥32 bytes) quando API keys precisam
     manter o mesmo owner após restart
   - define `AUTH_AUDIT_DIR` se quiseres outro destino para o log
2. Reinicia `npm start`. Procura no stdout a linha `[auth] boot {...}` para
   confirmar (`apiKeys`, `jwt.hs256`, `jwt.rs256`, `audit`).
3. Testa que `/api/health` continua aberto e que `/api/recon/stream` exige
   bearer:

```bash
curl -i http://127.0.0.1:3847/api/health
# 200 OK

curl -i -X POST http://127.0.0.1:3847/api/recon/stream
# 401 {"ok":false,"error":"auth required"}
```

Se o servidor arrancar com `HOST` não-local, o boot imprime um aviso explícito
para reforçar que este setup não é o perfil padrão.

## Limitações conhecidas / TODO próximo

- API keys são estáticas (env). Próxima iteração: integração com vault/KMS
  (P0 segredos) e rotação por engagement.
- O CSRF token continua a ser emitido sem auth — é defesa-em-profundidade
  contra cross-site, não substituto da auth. Para uma UI multi-utilizador
  considerar emitir CSRF apenas após login bem-sucedido.
- O Bubblewrap isola especificamente o Forge em Linux.
  `recon.intrusive` ainda é granularidade média para as demais ferramentas;
  partir em `recon.kali`, `recon.sqlmap`, `recon.cloud-bruteforce` etc. continua
  pendente.
- A retomada Auto é intencionalmente limitada a checkpoints v2 `ready`; não há
  retomada mid-engine/mid-evaluation.
- O adapter FrameSeven ainda não propaga Tor/proxy estrito, e o fluxo
  autenticado real continua pendente de teste ponta a ponta controlado.
