# GHOSTRECON

Framework de **OSINT e reconhecimento** orientado a **bug bounty** e pentest autorizado. Combina recolha **passiva** (Certificate Transparency, arquivos web, DNS, cabeçalhos, TLS, APIs públicas) com fases **semi‑ativas** (HTTP GET de probing, verificação heurística com evidência) e, opcionalmente, **modo Kali** (nmap, nuclei, ffuf, wpscan, dalfox, whois, searchsploit). Inclui **priorização**, **correlação**, **templates de relatório**, **deduplicação** de achados, persistência em **SQLite** ou **Postgres/Supabase**, **comparação entre runs**, **webhooks** (incluindo **Discord**), e **relatórios em Markdown gerados por IA** (Gemini, OpenRouter ou Anthropic).

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

### 16. GitHub e Pastebin

- **GitHub** (`github`): Code Search API com token opcional `GITHUB_TOKEN`; resultados como `secret` (revisão manual).
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
- **`GET /api/capabilities`**: inclui `ai: { gemini, openrouter, claude, lmstudio, any }`.

### 26. Webhook

- **`GHOSTRECON_WEBHOOK_URL`**: após gravar run, envia resumo (JSON genérico **ou** mensagem formatada **Discord**).
- Após IA: segundo POST — Discord com **embeds** (relatório + próximos passos) ou JSON `kind: ai_report`.

---

## Interface web (UI)

- Tema **dark / red team**; consumo da stream **NDJSON** (`POST /api/recon/stream`).
- **Perfil** `quick` | `standard` | `deep` (select ou `localStorage` `ghostrecon_profile`).
- **Nome de projeto**: pasta local opcional para SQLite espelhado.
- **Modo Kali**, módulos por categorias (Fontes, OSINT, Secrets, etc.).
- **Fila de dorks**: delay e máximo de abas para abrir Google no browser.
- **Dismiss** de findings por fingerprint (`localStorage`).
- **Exportação** no browser: **JSON** (payload alinhado com o servidor para IA), **Markdown**, **TXT**.
- **Auth opcional**: `localStorage` `ghostrecon_auth_json` → enviado como `auth` (headers + cookie) para probe/verify.
- **API base**: por defeito mesma origem; outra porta: `localStorage.setItem('ghostrecon_api_base', 'http://127.0.0.1:PORTO')`.
- Abrir `index.html` via `file://` **não** corre o pipeline — é preciso `npm start` (ou Docker).

---

## Segurança do servidor

- **CORS**: apenas origens `http://127.0.0.1:PORT` e `http://localhost:PORT` (PORT do servidor).
- **CSRF**: `GET /api/csrf-token` → header `X-CSRF-Token` obrigatório em `POST /api/recon/stream` e `POST /api/ai-reports`.
- **Rate limit** opcional por IP em `POST /api/recon/stream` (`GHOSTRECON_RL_*`).
- Corpo JSON limitado a **5 MB**.

---

## Eventos NDJSON (resumo)

| Tipo | Função |
|------|--------|
| `log` | Mensagens (níveis info/warn/success/error/section/find) |
| `progress` | Percentagem da barra |
| `pipe` | Estado de fase (`input`, `subdomains`, `alive`, `surface`, `urls`, `params`, `js`, `dorks`, `secrets`, `verify`, `kali`, `assets`, `score`, …) |
| `stats` | Contadores (subs, endpoints, params, secrets, dorks, high) |
| `finding` | Achado com `fingerprint` |
| `dork` | Query + URL Google |
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
| `GET` | `/api/capabilities` | Kali, ferramentas no PATH, chaves IA configuradas |
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
  "modules": ["subdomains", "wayback", "security_headers"],
  "auth": { "headers": {}, "cookie": "" },
  "outOfScope": "staging.example.com, *.cdn.example.com",
  "projectName": "cliente_x",
  "autoAiReports": false,
  "aiProviderMode": "auto"
}
```

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
| `GITHUB_TOKEN` | Rate limit GitHub Code Search |
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
npm test           # testes em server/tests/
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
├── supabase/                  # CLI, migrações, SQL para editor
└── server/
    ├── index.js               # Express, rotas, pipeline
    ├── load-env.js            # Carrega .env da raiz do repo
    ├── config.js              # Limites, regex “interesting”, UA
    └── modules/               # Um ficheiro por domínio (subdomains, probe, verify, kali-scan, …)
```

---

## Como estender

- **Novos dorks**: `server/modules/dorks.js` + checkbox em `index.html` com `class="mod"` e o mesmo `value`.
- **Nova fonte passiva**: novo módulo em `modules/`, import e chamada em `runPipeline` com eventos `pipe`/`log` coerentes.
- **Limites**: `server/config.js`.

---

## Aviso legal

Utiliza apenas contra alvos **autorizados**. O modo passivo ainda gera tráfego HTTP e consultas a terceiros (crt.sh, Archive.org, Google APIs, GitHub, etc.); o **modo Kali** é **intrusivo**. Cumpre os termos dos programas de bug bounty e a legislação aplicável.
