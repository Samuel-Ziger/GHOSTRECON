# GHOSTRECON

Framework de **OSINT e reconhecimento** orientado a **bug bounty** e pentest autorizado. Combina recolha **passiva** (Certificate Transparency, arquivos web, DNS, cabeçalhos, TLS, APIs públicas) com fases **semi‑ativas** (HTTP GET de probing, verificação heurística com evidência) e, opcionalmente, **modo Kali** (nmap, nuclei, ffuf, wpscan, dalfox, whois, searchsploit). Inclui **priorização**, **correlação**, **templates de relatório**, **deduplicação** de achados, persistência em **SQLite** ou **Postgres/Supabase**, **comparação entre runs**, **webhooks** (incluindo **Discord**), e **relatórios em Markdown gerados por IA** (Gemini, OpenRouter ou Anthropic).

Opcionalmente integra **clone local de repositórios GitHub** (com URLs manuais na UI para programas de bug bounty), **Shannon Lite** em `IAs/shannon/` (white-box: `shannon start`, poll de `workflow.log`, relatório em `.shannon/deliverables/`, abertura da **Temporal Web UI** no browser), e **validação HTTP pós-recon** (**PentestGPT** ou qualquer serviço que aceite o payload exportado).

A interface é uma página estática **`index.html`** servida pelo **Express**; o pipeline corre no servidor e envia eventos em **NDJSON** para o browser.

---

## O que a ferramenta faz (visão por fases)

A orquestração está em `server/index.js` (`runPipeline`). A ordem abaixo corresponde ao fluxo real.

### 1. Entrada e contexto

- Valida o **domínio** alvo e normaliza (remove esquema, lower case).
- Regista **módulos** activos, **perfil** (`quick` | `standard` | `deep`), **modo exact match** (aspas nos dorks) e **Modo Kali**.
- **Fora de escopo**: lista vinda de `GHOSTRECON_OUT_OF_SCOPE` e/ou do campo da UI quando o módulo `out_of_scope` está activo. Suporta wildcards tipo `*.cdn.cliente.com`. Filtra hosts e URLs em superfície HTML, sitemaps, corpus de URLs, CSE, etc. (`server/modules/scope.js`).

### 2. Subdomínios e resolução DNS

- **crt.sh** (Certificate Transparency): enumeração de nomes vistos em certificados, quando o módulo `subdomains` está activo.
- **VirusTotal** (`virustotal`): funde hostnames da API com a lista CT, se a chave `VIRUSTOTAL_API_KEY` estiver definida.
- **Subfinder** / **Amass**: só com **Modo Kali** ligado **e** módulos `subfinder` / `amass` marcados; output é fundido e depois **resolvido** (A/AAAA). Até **150** subdomínios (excluindo o apex) são testados em DNS; os que resolvem geram findings `subdomain` com meta de registos DNS e marca `tool=subfinder` quando aplicável.
- Se `subdomains` estiver desactivado mas Kali+enum estiver activo, não há passagem por crt.sh (apenas enum Kali quando seleccionado).

### 3. Enriquecimento DNS (módulo `dns_enrichment`)

- Consultas **MX**, **TXT** (SPF, registos de verificação de terceiros), **DMARC** (`_dmarc.<domínio>`), sobre o apex e uma amostra de subdomínios vivos, com limites de hosts, concorrência e timeouts em `server/config.js`.

### 4. RDAP (módulo `rdap`)

- Consulta **RDAP** do registo do domínio (estado, nameservers, eventos) e gera finding tipo `rdap`. Se o módulo estiver desligado, o pipe `rdap` é marcado como `skip` na UI.

### 5. HTTP alive / probing

- Para o **apex** e subdomínios a considerar (e VirusTotal hosts quando subdomínios passivos estão off), constrói URLs `https://` e `http://` até um máximo que depende do **perfil** (`maxHostsToProbe`: 36 / 80 / 130).
- **GET** com timeout e concorrência configuráveis; extrai **título**, **stack/tecnologias** (`tech.js`), **cabeçalhos de segurança**, **indícios de WAF** nos cabeçalhos/corpo, e **superfície HTML** (links `href` e `action` de formulários) até `htmlSurfaceMaxEndpoints` achados — viram findings `endpoint` com meta `HTML surface`.
- **Stealth** (`stealth_requests` na UI ou `GHOSTRECON_STEALTH=1`): **jitter** aleatório entre pedidos e **User-Agent rotativo** (`request-policy.js`).

### 6. WAF (módulo `wafw00f` e heurística)

- Com módulo **`wafw00f`** ou perfil **não** `quick`, tenta fingerprint via CLI **`wafw00f`** nos hosts HTTPS vivos; finding `intel` tipo WAF.
- Independentemente disso, o probe já infere **Cloudflare** (e similares) e pode emitir `intel` “WAF hint”.

### 7. Fase “surface” (cabeçalhos, TLS, robots, well-known)

Activada se qualquer um de: `security_headers`, `robots_sitemap`, `wellknown_*`.

- **Cabeçalhos de segurança** (`security_headers`): para cada resposta “saudável”, corre `analyzeSecurityHeaders` e gera findings `security` (HSTS, CSP, XFO, etc.).
- **TLS** (`security_headers`): `peekTlsCertificate` na porta 443 — validade, assunto, emissor, SAN; achados `tls`; SANs alimentam mais tarde **asset discovery**.
- **robots.txt / sitemap** (`robots_sitemap`): por origem preferindo HTTPS; extrai **Disallow** como `intel` e URLs de páginas como `endpoint`.
- **`.well-known/security.txt`** e **`.well-known/openid-configuration`**: pedidos com limites próprios; OIDC descobre endpoints e regista-os como `endpoint` com meta OIDC.

### 8. Shodan (módulo `shodan`)

- Com `SHODAN_API_KEY`, resolve IPv4 para uma amostra de hosts e consulta `api.shodan.io/shodan/host/{ip}`; findings `intel` com portas, org, hostnames, CVEs/tags quando existirem.

### 9. OpenAPI / Swagger (módulo `openapi_specs`)

- Para até `openapiMaxOrigins` origens HTTPS, tenta paths comuns (`/openapi.json`, `/swagger.json`, `/v2/api-docs`, …). Se encontrar JSON OAS3/Swagger2 válido, gera `endpoint` para a spec e `param` para nomes de parâmetros extraídos.

### 10. Corpus de URLs (Wayback, Common Crawl, CLI, Katana)

- **Wayback** (`wayback`): CDX, URLs 200 no âmbito `*.domínio`.
- **Common Crawl** (`common_crawl`): índice CDX (URL opcional `GHOSTRECON_CC_CDX_API`).
- **gau** / **waybackurls**: se o módulo estiver marcado **ou** o perfil `deep` (`includeCliArchives`), `archive-tools.js` invoca essas CLIs se existirem no PATH.
- **Katana**: só no perfil **`deep`**, crawl JS a partir de `https://` e `http://` do apex (profundidade 3, até 300 URLs novas no escopo).
- Todo o corpus é filtrado por **out of scope**.

### 11. GraphQL (módulo `graphql_probe`)

- Se o corpus contiver URLs com `graphql` no path, faz **um POST** por URL (até 4 origens distintas) com query de introspecção **mínima**; se a resposta indicar schema ou errors estruturados, emite `intel` sobre alcance de introspecção.

### 12. Endpoints “interessantes”

- `filterInterestingUrls` aplica regex de caminhos sensíveis (`api`, `admin`, `graphql`, `swagger`, etc. em `config.js`).
- Cada URL interessante vira `endpoint` com meta indicando fonte (Wayback, Common Crawl ou “arquivo web”).

### 13. Parâmetros

- `extractParamsFromUrls` agrega nomes de query string do corpus; scoring por nome; findings `param`.
- **Heurísticas passivas**: `intel` “XSS candidate param” e “SQLi candidate param” para nomes típicos (usados depois para **gating** do modo Kali).

### 14. Análise de JavaScript

- Extrai URLs `.js` do corpus; fetch limitado (`maxJsFetch`); `js-analyzer.js` extrai endpoints em strings, insights (ex. hints admin); `secrets.js` procura padrões tipo chaves — findings `js`, `intel`, `secret`.

### 15. Google Dorks e Custom Search

- `dorks.js` gera queries por categoria (directory, config, login, passwords, etc. conforme checkboxes). Cada dork é enviado ao cliente como evento `dork` **e** gravado como finding `dork`.
- **Google CSE** (`google_cse` + `GOOGLE_CSE_KEY` + `GOOGLE_CSE_CX`): executa até `googleCseMaxQueries` queries com delay; URLs cujo host está no escopo viram `endpoint`.

### 16. GitHub, clone local e Pastebin

- **GitHub** (`github`): **Code Search** com token opcional `GITHUB_TOKEN` — findings `secret` (revisão manual). **Repo Search** sugere repositórios candidatos.
- **Clone local** (`GHOSTRECON_GITHUB_CLONE_ENABLED`, pasta `clone/` na raiz, ignorada no Git): até `GHOSTRECON_CLONE_MAX_REPOS` repos com `git clone --depth 1`, limites de tamanho/timeout e **retenção** (`GHOSTRECON_CLONE_RETENTION_DAYS`, default 30 dias). Os clones bem-sucedidos geram findings `intel` com o caminho no disco e alimentam o **Shannon white-box** quando esse módulo está activo.
- **Repos manuais (UI Shannon)**: campo de texto `shannonGithubRepos` no `POST /api/recon/stream` — uma **URL** `https://github.com/org/repo` (ou ramos `/tree/...`), **`org/repo`**, ou várias linhas / separadas por vírgula ou `;`. São fundidos na lista de candidatos ao clone (entradas manuais têm prioridade sobre a mesma `full_name`). Com **só** o módulo **Shannon white-box** (sem «GitHub leaks»), o servidor pode clonar **apenas** esses repos, útil quando o programa fornece o link do código.
- **Pastebin** (`pastebin`): não há API fiável — apenas log a orientar uso dos dorks.

### 17. Validação de secrets (`secret_validation`)

- `secret-validation.js` tenta classificar achados `secret` como **live** / **probable** / **dead** com pedidos HTTP leves; gera findings `secret_validation`.

### 18. Verify (evidência)

- `verify.js`: para até `maxVerifyEndpoints` URLs de endpoints, testa variantes de parâmetros (XSS/SQLi/open redirect/IDOR/LFI) com **redirect manual**, snippets de pedido/resposta, classificação **confirmed** / **probable** / **noisy** e objeto `verification` com hash de evidência.

### 19. Micro-exploit XSS (módulo `micro_exploit`)

- Após verify, `runMicroExploitVariants` com limite de testes; findings adicionais ligados a XSS.

### 20. Descoberta activa de parâmetros

- Em endpoints **sem** query, tenta `discoverParamsActive` (ferramenta externa quando disponível, timeout longo); novos `param` com meta `active_discovery`.

### 21. Modo Kali (`kaliMode` + detecção de ambiente)

Requer SO identificado como Kali (ou `GHOSTRECON_FORCE_KALI=1`) **e** `nmap` no PATH.

- **nmap**: XML parseado → findings `nmap`; argumentos via `GHOSTRECON_NMAP_ARGS` (default `-sV -Pn -T4 --host-timeout 180s`).
- **searchsploit**: até 12 queries únicas derivadas de produto/versão do nmap → findings `exploit`.
- **ffuf** (módulo `kali_ffuf`): wordlist Seclists/dirb, só **HTTP 200**, várias bases (domínio + portas 80/443 descobertas), threads `GHOSTRECON_FFUF_THREADS`.
- **nuclei** (módulo `kali_nuclei`): lista de alvos; perfil `GHOSTRECON_NUCLEI_PROFILE` (`safe`, `bb-passive`, `bb-active`, `high-impact`); depois, se houver **sinais** XSS/SQLi passivos, corre tags `xss` / `sqli` sobre URLs com query (até 30).
- **dalfox**: se `dalfox` no PATH **e** sinais XSS, até `GHOSTRECON_DALFOX_MAX_URLS` URLs (default 12), timeout `GHOSTRECON_DALFOX_TIMEOUT_MS` → findings `dalfox`.
- **wpscan**: só se WordPress foi detectado no probe (`tech`) e `wpscan` existe; JSON parseado para core/tema/plugins.
- **whois**: domínio raiz + amostra de subdomínios (limite via env ou `config.js`).

### 22. Asset discovery e takeover

- `discoverAssetHints`: pistas passivas (CAA, padrões de nomes, SANs TLS).
- `detectTakeoverCandidates` + **CNAME chain** + match de corpo HTTP contra páginas conhecidas de parking — findings `takeover` (candidate vs confirmado).

### 23. Priorização, CVE, correlação, inteligência

- **Priorização v2**: `applyPrioritizationV2` — scores compostos, `attackTier`, `priorityWhy`.
- Anotações em endpoints (ex. `status_consistent`, `auth=required` em paths admin-like).
- **CVE hints**: a partir de strings de tecnologia, gera links **NVD** e **OSV** (lookup manual, log na consola NDJSON).
- **Dedupe semântico**: `semantic-dedupe.js` colapsa famílias redundantes antes das estatísticas finais.
- **Correlação**: `correlation.js` — resumo e parâmetros de risco.
- **Checklist**: `buildExploitChecklist` → eventos `intel` com prefixo `☐ CHECKLIST:`.
- **Sugestões**: `suggestVectors` → mais linhas `intel`.
- **Templates de relatório**: `report-template.js` → eventos `report_template` e `intel` `REPORT:`.

### 24. Persistência e delta

- `saveRun`: grava run completo; **merge** no corpus `bounty_intel` (dedupe por fingerprint).
- Se usares Postgres/Supabase **e** indicares **nome de projeto** na UI, pode gravar **espelho** SQLite em pasta local (`escopo/{projeto}/{domínio}/`) — ver `db.js` / `db-sqlite.js`.
- Compara com o **run anterior do mesmo alvo**: se houver novidades “quentes”, emite `delta_hot` na stream.

### 25. Relatórios IA (opcional)

- Chaves: `GEMINI_API_KEY` ou `GOOGLE_AI_API_KEY`, `OPENROUTER_API_KEY` (ou `ANTHROPIC_API_KEY` directo), e opcionalmente provider local via LM Studio; modelos configuráveis, retries (Gemini/OpenRouter), limites de caracteres do Markdown.
- UI: checkbox de confirmação + `autoAiReports` no POST; servidor pode gerar ficheiros **Markdown** (relatório + próximos passos) e emitir eventos `ai_report`; o conteúdo de “próximos passos” pode ser ecoado no log NDJSON.
- Resiliência IA: Gemini e OpenRouter fazem retentativas em `429` e `5xx` (inclui `503`) com `Retry-After` + backoff; Claude e LM Studio seguem a política de tentativas descrita abaixo.
- Cascata de execução (run automático): **Gemini** (até 3 tentativas, espera fixa padrão 60s entre falhas) → **OpenRouter** (1 tentativa) → **Claude** (1 tentativa) → **LM Studio** (último recurso, se activo no `.env`).
- UI: opção **"LM Studio no final (pré-check obrigatório)"** — valida o LM Studio antes do recon; no servidor o LM Studio **só corre** se todos os providers cloud anteriores falharem (útil porque modelos locais podem demorar muito em *reasoning*).
- **`GHOSTRECON_AI_AUTO=0`**: desliga geração automática no fim do pipeline (podes usar `POST /api/ai-reports` com payload exportado).
- **`GET /api/capabilities`**: inclui `ai`, **`shannon`** e **`pentestgpt`**. O bloco `pentestgpt` resume a **árvore** local (`GHOSTRECON_PENTESTGPT_HOME` / `IAs/PentestGPT`: `pyproject.toml`, Python 3.12+, `uv`, Docker, etc.) e **`http`** — `configured` / `preview` indicam se `GHOSTRECON_PENTESTGPT_URL` está definida no **servidor** (a pré-visualização mascara query strings).

### 26. Shannon Lite (white-box), Temporal e PentestGPT (opcional)

- **Código Shannon**: não está versionado neste repo. Clona o upstream em **`IAs/shannon/`** (instruções em **`IAs/README.md`**; detalhe de arquitectura em **`PLANO_IAS_LOCAIS_GHOSTRECON.md`**). Requer Docker, build (`pnpm` / `./shannon build`) e credencial de IA no ecossistema Shannon (ex. `ANTHROPIC_API_KEY` no `.env` do Shannon).
- **Módulo `shannon_whitebox`**: corre **depois** de verify/Kali/assets e da fase **PRIORITIZE** (`score`), **antes** de **PentestGPT HTTP** — assim o POST de validação inclui os `intel` Shannon no payload. Requer clones neste run e **`GHOSTRECON_SHANNON_AUTO_RUN`** ≠ `0`. O servidor corre **`shannon start`** (via `node …/shannon`) com `-u https://<alvo>/`, `-r <clone absoluto>`, `-w ghostrecon-…`, opcional **`--pipeline-testing`** (`GHOSTRECON_SHANNON_PIPELINE_TESTING=1`). **Fila global** serializa scans. O fim segue **`workflow.log`** no workspace. Lê **`comprehensive_security_assessment_report.md`** em `<clone>/.shannon/deliverables/` e emite findings `intel`. Durante a espera longa, o servidor regista linhas de **keepalive** no log NDJSON para reduzir cortes de stream no browser.
- **UI / pré-check**: linha de estado Shannon, `shannonPrecheck` (default activo) e `shannonSkipDepsVerify` no POST; se o pré-check falhar, o recon é recusado com `error` NDJSON. Botão **Docker pull** chama `POST /api/shannon/prep` e imprime `dockerPullLog` no terminal. **`GHOSTRECON_SHANNON_HOME`**: path absoluto alternativo ao Shannon.
- **Temporal Web UI**: quando o CLI imprime `http://localhost:8233/...`, o servidor envia **`open_url`** na stream; a UI abre numa nova aba (como os dorks). Desliga com **`GHOSTRECON_SHANNON_OPEN_TEMPORAL_UI=0`**.
- **PentestGPT (validação HTTP no Ghost)**: módulo **`pentestgpt_validate`**. Após **`score`**, `POST` JSON para a URL efectiva (**`GHOSTRECON_PENTESTGPT_URL`** ou override `pentestgptUrl` no corpo do recon) com `ghostPayload`. Resposta tolerante: `summary`, `validatedFindings`, `falsePositives` → novos **findings** na UI / SQLite ou cartão **intel** «PentestGPT (resumo)». **`GHOSTRECON_PENTESTGPT_HOME`** ajusta o path da árvore em capabilities (default `IAs/PentestGPT`). Script opcional **`npm run pentestgpt-bridge`** → `pentestgpt-ghost-bridge.mjs`: prompt de sistema focado em **bug bounty** (triagem OSINT/recon, não CTF); substituível com **`GHOSTRECON_PENTESTGPT_BRIDGE_SYSTEM_PROMPT`**. O **agente** upstream GreyDGL (Docker/TUI) é independente — ver **`IAs/README.md`** e **`PLANO_IAS_LOCAIS_GHOSTRECON.md`**.
- **PentestGPT — UI e rotas**: na sidebar, **URL POST (opcional)** envia `pentestgptUrl` por run; **Lembrar** usa `localStorage` (`ghostrecon_pentestgpt_url_override`); **Testar ponte** chama **`POST /api/pentestgpt-ping`** (CSRF) e o servidor faz **`GET`** na origem do endpoint de validação com sufixo **`/health`** (evita CORS no browser). Se o módulo está activo mas **não** há URL no `.env` nem no campo, a UI pergunta se queres continuar (o passo será ignorado).
- **Shannon — resultado na UI**: por repo, finding **`intel`** com título `Shannon white-box: org/repo`, **meta** com `workspace`, caminho do **Markdown** do relatório e **excerto**; em falha, `intel` com fase/erro. O relatório completo fica no disco do workspace Shannon.
- **Ajuda «?» nos Modules**: o botão ao lado de **Modules** abre um guia com todas as categorias, secções dedicadas a **Shannon**, **PentestGPT** (o que faz / o que aparece no Ghost / configuração) e esclarecimento de que as caixas de **IA** não usam `class="mod"` (enviam `autoAiReports` / `aiProviderMode`).

### 27. Webhook

- **`GHOSTRECON_WEBHOOK_URL`**: após gravar run, envia resumo (JSON genérico **ou** mensagem formatada **Discord**). No Discord, o resumo pode incluir linhas opcionais **Shannon** e **PentestGPT** quando há texto resumido; o JSON genérico inclui `shannonSummary` e `pentestgptSummary` no payload.
- Após IA: segundo POST — Discord com **embeds** (relatório + próximos passos) ou JSON `kind: ai_report`.

---

## Interface web (UI)

- Tema **dark / red team**; consumo da stream **NDJSON** (`POST /api/recon/stream`).
- **Perfil** `quick` | `standard` | `deep` (select ou `localStorage` `ghostrecon_profile`).
- **Nome de projeto**: pasta local opcional para SQLite espelhado.
- **Modo Kali**, módulos por categorias (Fontes, OSINT, Secrets, etc.).
- **Fila de dorks**: delay e máximo de abas para abrir Google no browser.
- **Shannon (sidebar)**: módulo **`shannon_whitebox`**, pré-check de dependências, omitir verificação, **repos GitHub (manual)** (textarea → `shannonGithubRepos`), botão **Docker pull** (prep). Na barra de pipeline, **SHANNON** aparece **depois** de PRIORITIZE e **antes** de PENTESTGPT (ordem real do servidor). Linha **`shannonCapLine`** (`GET /api/capabilities` → `shannon`).
- **PentestGPT (sidebar)**: módulo **`pentestgpt_validate`**, linha **`pentestgptCapLine`** (árvore upstream **e** indicador **`POST .env`**), campo **URL POST** opcional + **Lembrar** + **Testar ponte**, **`pipe-pentestgpt`** na barra.
- **Guia de módulos**: botão **?** junto a «Modules» — pop-up com descrição de cada módulo, **Shannon** / **PentestGPT** (função + resultados no Ghost) e nota sobre opções de **IA**.
- **Dismiss** de findings por fingerprint (`localStorage`).
- **Exportação** no browser: **JSON** (payload alinhado com o servidor para IA), **Markdown**, **TXT**.
- **Auth opcional**: `localStorage` `ghostrecon_auth_json` → enviado como `auth` (headers + cookie) para probe/verify.
- **API base**: por defeito mesma origem; outra porta: `localStorage.setItem('ghostrecon_api_base', 'http://127.0.0.1:PORTO')`.
- Abrir `index.html` via `file://` **não** corre o pipeline — é preciso `npm start` (ou Docker).

---

## Segurança do servidor

- **CORS**: apenas origens `http://127.0.0.1:PORT` e `http://localhost:PORT` (PORT do servidor).
- **CSRF**: `GET /api/csrf-token` → header `X-CSRF-Token` obrigatório em `POST /api/recon/stream`, `POST /api/ai-reports`, `POST /api/shannon/prep` e `POST /api/pentestgpt-ping`.
- **Rate limit** opcional por IP em `POST /api/recon/stream` (`GHOSTRECON_RL_*`).
- Corpo JSON limitado a **5 MB**.

---

## Eventos NDJSON (resumo)

| Tipo | Função |
|------|--------|
| `log` | Mensagens (níveis info/warn/success/error/section/find) |
| `progress` | Percentagem da barra |
| `pipe` | Estado de fase (`input`, `subdomains`, `alive`, `surface`, `urls`, `params`, `js`, `dorks`, `secrets`, `shannon`, `verify`, `kali`, `assets`, `score`, `pentestgpt`, …) |
| `stats` | Contadores (subs, endpoints, params, secrets, dorks, high) |
| `finding` | Achado com `fingerprint` |
| `dork` | Query + URL Google |
| `open_url` | Abre `url` numa nova aba (`noopener`) — usado p.ex. para Temporal Web UI quando o Shannon imprime o link |
| `intel` | Linha livre (checklist, sugestões, REPORT) |
| `report_template` | Template estruturado |
| `priority_pass` | Top alvos de alta probabilidade |
| `findings_rescore` | Lista completa após rescoring |
| `delta_hot` | Amostra de achados críticos novos vs run anterior |
| `ai_report` | Início/fim/erro da geração IA |
| `done` | Payload final (`runId`, `intelMerge`, `storage`, caminho SQLite local, etc.) |
| `error` | Falha (domínio inválido, CSRF, rate limit, excepção) |

---

## API HTTP

| Método | Rota | Descrição |
|--------|------|-----------|
| `GET` | `/` | Serve `index.html` |
| `GET` | `/api/health` | `{ ok, service }` |
| `GET` | `/api/csrf-token` | Token CSRF (vinculado ao IP, TTL ~2 h) |
| `GET` | `/api/capabilities` | Kali, PATH, chaves IA, `shannon`, `pentestgpt` (árvore local + `http` se `GHOSTRECON_PENTESTGPT_URL` definida) |
| `POST` | `/api/shannon/prep` | Header `X-CSRF-Token`; corpo `{ "pullUpstream": true }` → `docker pull keygraph/shannon:latest`; resposta inclui `dockerPullLog` |
| `POST` | `/api/pentestgpt-ping` | CSRF; corpo `{ "pentestgptUrl": "…" }` opcional — resolve URL (override ou `.env`), `GET` em `…/health` na mesma origem; JSON `{ ok, healthUrl, status, body }` ou erro |
| `GET` | `/api/ai/lmstudio-check` | Testa conexão com LM Studio local (pré-check da UI) |
| `POST` | `/api/recon/stream` | Corpo JSON (ver abaixo); resposta **NDJSON** |
| `POST` | `/api/ai-reports` | Gera relatórios IA a partir de `payload` (export JSON); opcional webhook |
| `GET` | `/api/runs?limit=` | Lista runs |
| `GET` | `/api/runs/:id` | Run com findings |
| `GET` | `/api/runs/:newerId/diff/:baselineId` | Diff mesmo alvo |
| `GET` | `/api/intel/:target` | Corpus `bounty_intel` deduplicado |

### Corpo típico de `POST /api/recon/stream`

```json
{
  "domain": "example.com",
  "exactMatch": false,
  "kaliMode": false,
  "profile": "standard",
  "modules": ["subdomains", "wayback", "security_headers", "github", "shannon_whitebox", "pentestgpt_validate"],
  "auth": { "headers": {}, "cookie": "" },
  "outOfScope": "staging.example.com, *.cdn.example.com",
  "projectName": "cliente_x",
  "autoAiReports": false,
  "aiProviderMode": "auto",
  "shannonPrecheck": true,
  "shannonSkipDepsVerify": false,
  "shannonGithubRepos": "https://github.com/org/programa-bounty\norg/outro-repo",
  "pentestgptUrl": "http://127.0.0.1:8765/validate"
}
```

Campos opcionais frequentes:

| Campo | Descrição |
|--------|-----------|
| `shannonPrecheck` | `false` desactiva a validação de dependências Shannon no **servidor** (não recomendado). |
| `shannonSkipDepsVerify` | `true` — o servidor não bloqueia o recon se o Shannon não estiver pronto. |
| `shannonGithubRepos` | String multilinha: URLs GitHub e/ou `owner/repo` para **clone manual** (bug bounty). |
| `pentestgptUrl` | Opcional: URL do `POST` de validação **neste run** (sobrepõe `GHOSTRECON_PENTESTGPT_URL` se for `http://` ou `https://`). |
| `modules` | Incluir `"pentestgpt_validate"` para validação HTTP pós-`score` (requer URL no `.env` ou `pentestgptUrl`). |

Cabeçalho: `X-CSRF-Token: <token>`.

`aiProviderMode`:
- `auto` (default): cascata Gemini → OpenRouter → Claude → LM Studio
- `lmstudio_only`: igual a `auto` na ordem de execução; na UI activa só o **pré-check** do LM Studio antes do recon (o LM continua no fim da cascata)

---

## Variáveis de ambiente (referência)

| Variável | Uso |
|----------|-----|
| `PORT` | Porta HTTP (default `3847`) |
| `HOST` | Bind address (default `127.0.0.1`) |
| `GITHUB_TOKEN` | Rate limit GitHub Code Search e Repo Search |
| `GHOSTRECON_GITHUB_CLONE_ENABLED` | `1` (default) ou `0` — clone local de repos candidatos para `clone/` |
| `GHOSTRECON_CLONE_DIR` / `GHOSTRECON_CLONE_MAX_REPOS` / `GHOSTRECON_CLONE_MAX_SIZE_MB` / `GHOSTRECON_CLONE_TIMEOUT_MS` / `GHOSTRECON_CLONE_RETENTION_DAYS` | Pasta, quantidade, MB máx., timeout clone, dias de retenção |
| `GHOSTRECON_SHANNON_HOME` | Path absoluto ao root do Shannon Lite (default `IAs/shannon` sob a raiz do GHOSTRECON) |
| `GHOSTRECON_SHANNON_AUTO_RUN` | `0` — não executar `./shannon start` após clone (só diagnóstico / clone) |
| `GHOSTRECON_SHANNON_MAX_CLONES_PER_RUN` | Máximo de clones a analisar com Shannon por run (default 1, cap 5) |
| `GHOSTRECON_SHANNON_START_TIMEOUT_MS` / `GHOSTRECON_SHANNON_WORKFLOW_TIMEOUT_MS` | Timeout do arranque do CLI e espera pelo `workflow.log` |
| `GHOSTRECON_SHANNON_PIPELINE_TESTING` | `1` — passa `--pipeline-testing` ao Shannon (mais rápido para desenvolvimento) |
| `GHOSTRECON_SHANNON_REPORT_MAX_CHARS` | Truncagem ao ler o relatório Markdown consolidado |
| `GHOSTRECON_SHANNON_OPEN_TEMPORAL_UI` | `0` — não emitir `open_url` para a Temporal Web UI |
| `GHOSTRECON_PENTESTGPT_URL` | URL do `POST` de validação pós-recon (módulo `pentestgpt_validate`) |
| `GHOSTRECON_PENTESTGPT_HOME` | Raiz do clone GreyDGL (capabilities) |
| `GHOSTRECON_PENTESTGPT_ENABLED` / `GHOSTRECON_PENTESTGPT_TIMEOUT_MS` | Activar serviço e timeout HTTP |
| `GHOSTRECON_PENTESTGPT_BRIDGE_PORT` / `GHOSTRECON_PENTESTGPT_BRIDGE_MODEL` | Ponte `pentestgpt-ghost-bridge.mjs` (OpenRouter) |
| `GHOSTRECON_PENTESTGPT_BRIDGE_SYSTEM_PROMPT` | Opcional: substitui o prompt bug bounty da ponte |
| `GOOGLE_CSE_KEY` / `GOOGLE_CSE_CX` | Google Programmable Search (módulo `google_cse`) |
| `GHOSTRECON_DB` | Caminho SQLite global (default `data/bugbounty.db`) |
| `DATABASE_URL` | Postgres directo (prioridade sobre API Supabase) |
| `SUPABASE_URL` + chave | Cliente REST (`SUPABASE_ANON_KEY`, `SUPABASE_PUBLISHABLE_KEY`, `SUPABASE_SERVICE_ROLE_KEY`, ou `SUPABASE_KEY`) |
| `VIRUSTOTAL_API_KEY` | Subdomínios VT |
| `SHODAN_API_KEY` | Lookup passivo Shodan |
| `GHOSTRECON_WEBHOOK_URL` | Webhook pós-recon e pós-IA |
| `GHOSTRECON_RL_MAX` / `GHOSTRECON_RL_WINDOW_MS` | Rate limit POST recon |
| `GHOSTRECON_CC_CDX_API` | URL índice Common Crawl |
| `GHOSTRECON_OUT_OF_SCOPE` | Hosts/patterns fora de escopo (global) |
| `GHOSTRECON_STEALTH` | `1` = stealth como módulo sempre activo |
| `GHOSTRECON_FORCE_KALI` | `1` = assumir ambiente Kali |
| `GHOSTRECON_NMAP_ARGS` | Argumentos nmap |
| `GHOSTRECON_NUCLEI_PROFILE` | `safe` / `bb-passive` / `bb-active` / `high-impact` |
| `GHOSTRECON_FFUF_THREADS` | Threads ffuf (1–64) |
| `GHOSTRECON_DALFOX_MAX_URLS` / `GHOSTRECON_DALFOX_TIMEOUT_MS` | dalfox |
| `GHOSTRECON_WPSCAN_*` | Modo e timeout wpscan |
| `GHOSTRECON_WHOIS_SUBDOMAINS_MAX` | Extra whois |
| `GHOSTRECON_SUBFINDER_TIMEOUT_MS` / `GHOSTRECON_AMASS_TIMEOUT_MS` | Timeouts enum |
| `GEMINI_API_KEY` / `GOOGLE_AI_API_KEY` | IA Gemini |
| `GHOSTRECON_GEMINI_MODEL` / `GHOSTRECON_GEMINI_MAX_RETRIES` | Gemini (retries em 429/5xx/timeout) |
| `OPENROUTER_API_KEY` | IA via OpenRouter |
| `GHOSTRECON_OPENROUTER_MODEL` / `GHOSTRECON_OPENROUTER_HTTP_REFERER` / `GHOSTRECON_OPENROUTER_APP_TITLE` / `GHOSTRECON_OPENROUTER_MAX_RETRIES` | OpenRouter |
| `GHOSTRECON_AI_FALLBACK_WAIT_SEC` | Espera fixa entre tentativas Gemini na cascata (default `60`) |
| `ANTHROPIC_API_KEY` / `GHOSTRECON_CLAUDE_MODEL` | Claude directo (terceiro na cascata, após Gemini e OpenRouter) |
| `GHOSTRECON_LMSTUDIO_ENABLED` / `GHOSTRECON_LMSTUDIO_BASE_URL` / `GHOSTRECON_LMSTUDIO_MODEL` / `GHOSTRECON_LMSTUDIO_API_KEY` | LM Studio local (OpenAI-compatible) |
| `GHOSTRECON_LMSTUDIO_N_CTX` / `GHOSTRECON_LMSTUDIO_MAX_OUTPUT_TOKENS` (ou `GHOSTRECON_LMSTUDIO_MAX_TOKENS`) / `GHOSTRECON_LMSTUDIO_TIMEOUT_MS` / `GHOSTRECON_LMSTUDIO_TEMPERATURE` | Contexto, saída e tempo limite no LM Studio |
| `GHOSTRECON_LMSTUDIO_MAX_INPUT_CHARS` / `GHOSTRECON_LMSTUDIO_CHARS_PER_TOKEN` | Limite opcional do JSON local (senão calcula a partir de `N_CTX`) |
| `GHOSTRECON_AI_AUTO` | `0` desliga IA automática no fim do recon |
| `GHOSTRECON_AI_RELATORIO_MAX_CHARS` / `GHOSTRECON_AI_PROXIMOS_MAX_CHARS` | Truncagem Markdown IA |

Limites numéricos (timeouts, concorrência, caps de URLs, etc.) estão centralizados em `server/config.js`.

---

## Requisitos e execução

- **Node.js 18+** (usa `fetch` nativo). O `Dockerfile` usa Node 22 Alpine.

```bash
npm install
npm start          # produção
npm run dev        # reload com --watch
npm test           # testes em server/tests/ (incl. pentestgpt-capabilities, pentestgpt-local)
npm run test:ai    # smoke das APIs IA (script separado)
```

Abre **http://127.0.0.1:3847** (ou `HOST`/`PORT` definidos).

---

## Base de dados

### Supabase

1. **CLI**: `npm run db:link`, `npm run db:push`, migrações em `supabase/migrations/`.
2. **SQL Editor**: colar `supabase/COPIAR_PARA_SQL_EDITOR.sql` (sem colar o caminho do ficheiro como texto).

### SQLite

- Ficheiro default: **`data/bugbounty.db`**.
- Tabelas principais: **`runs`**, **`findings`**, **`bounty_intel`** (corpus deduplicado por alvo; actualiza `last_seen` / `last_run_id`).
- Com **nome de projeto** na UI e storage remoto: cópia local adicional sob `escopo/...`.

---

## Docker

```bash
docker build -t ghostrecon .
docker run --rm -p 3847:3847 --env-file .env ghostrecon
```

A imagem **não** inclui ferramentas Kali (nmap, nuclei, etc.) — modo passivo apenas.

---

## Estrutura do repositório

```
GHOSTRECON/
├── index.html                 # Frontend
├── package.json
├── .env.example
├── Dockerfile
├── README.md
├── PLANO_IAS_LOCAIS_GHOSTRECON.md   # Plano Shannon / PentestGPT / clone
├── IAs/
│   └── README.md              # Clones Shannon + PentestGPT (pastas em IAs/ ignoradas no Git)
├── clone/                     # Clones git (ignorado no Git; criado em runtime)
├── supabase/                  # CLI, migrações, SQL para editor
└── server/
    ├── index.js               # Express, rotas, pipeline
    ├── load-env.js            # Carrega .env da raiz do repo
    ├── config.js              # Limites, regex “interesting”, UA
    ├── scripts/               # pentestgpt-ghost-bridge.mjs (ponte HTTP opcional)
    ├── modules/               # …, pentestgpt-local.js, pentestgpt-capabilities.js, …
    └── tests/                 # pentestgpt-capabilities.test.js, pentestgpt-local.test.js, …
```

---

## Como estender

- **Novos dorks**: `server/modules/dorks.js` + checkbox em `index.html` com `class="mod"` e o mesmo `value`.
- **Nova fonte passiva**: novo módulo em `modules/`, import e chamada em `runPipeline` com eventos `pipe`/`log` coerentes.
- **Shannon / PentestGPT**: ver `PLANO_IAS_LOCAIS_GHOSTRECON.md`; rotas `GET /api/capabilities`, `POST /api/shannon/prep`, `POST /api/pentestgpt-ping` (CSRF); novos env em `.env.example`.
- **Limites**: `server/config.js`.

---

## Aviso legal

Utiliza apenas contra alvos **autorizados**. O modo passivo ainda gera tráfego HTTP e consultas a terceiros (crt.sh, Archive.org, Google APIs, GitHub, etc.); o **modo Kali** é **intrusivo**. O **Shannon Lite** executa análise white-box e fluxos de pentest autónomo (Docker, Temporal, possíveis testes activos contra a aplicação) — só com programa e permissões explícitas. Cumpre os termos dos programas de bug bounty e a legislação aplicável.
