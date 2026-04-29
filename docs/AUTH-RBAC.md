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
continuam a falhar com 401, mesmo com `AUTH_MODE=disabled`.

## Roles

```
viewer    → recon.read
operator  → viewer + [recon.run, brain.write, notes.write, validation.write,
                      evidence.capture, cve.enrich]
red       → operator + [recon.intrusive, ai.run, shannon.run,
                        project.write, engagement.write, team.lock]
admin     → '*'  (wildcard, inclui acções destrutivas)
```

## Scope × Rota

| Scope               | Rota(s)                                                                                     | Verbo  |
|---------------------|---------------------------------------------------------------------------------------------|--------|
| _(allowlist)_       | `/api/health`, `/api/csrf-token`, `/api/inbound/*` (auth própria)                           | GET/POST |
| `recon.read`        | `/api/runs`, `/api/runs/:id`, `/api/runs/:newer/diff/:base`, `/api/runs/:id/diff-summary/:b`, `/api/runs/:id/narrative`, `/api/runs/:id/purple`, `/api/intel/:target`, `/api/playbooks*`, `/api/projects` (GET), `/api/engagements` (GET), `/api/team/locks`, `/api/team/trail`, `/api/brain/*` (GET), `/api/manual-validations/:target` (GET), `/api/anotacao-handoff/:id` (GET), `/api/capabilities`, `/api/project-secret-peers`, `/api/ai/lmstudio-check` | GET |
| `recon.run`         | `/api/recon/stream`                                                                         | POST   |
| `recon.intrusive`   | _Escala_ aplicada a `/api/recon/stream` quando o body indica `kaliMode=true`, `opsecProfile='aggressive'`, ou `modules` inclui `kali_*`, `sqlmap`, `sandbox_exec`, `cloud_bruteforce`, `browser_xss_verify`, `race_*`, `cred_spray`, `shannon_whitebox` | POST |
| `brain.write`       | `/api/brain/categories`, `/api/brain/categories/:id/description`, `/api/brain/link`         | POST   |
| `notes.write`       | `/api/anotacao-handoff`                                                                     | POST   |
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
> qualquer módulo intrusivo, recebe 403.

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
- `recon.intrusive` ainda é granularidade média; quando vier o sandbox de
  tooling (P0 sandbox), partir em `recon.kali`, `recon.sqlmap`,
  `recon.cloud-bruteforce` etc. para auditoria mais fina.
