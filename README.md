# GHOSTRECON

Framework local de recon, OSINT e priorizacao de superficie para bug bounty e pentest autorizado, com pipeline em streaming NDJSON, UI web completa, correlacao de achados e camada de IA (cloud e local).

---

## Visao Geral

O projeto combina:

- **Orquestrador principal em Node.js/Express** (`server/index.js`) com dezenas de modulos de recon.
- **UI web local** (`index.html`) com controle fino de modulos, perfis e fluxo de analise.
- **Paineis auxiliares**: Ghostmap (`mitre-map.html`), Cortex (`cortex.html`), Reporte (`reporte.html`), anotacoes (`anotacao.html`).
- **Persistencia flexivel**: SQLite local, Postgres via `DATABASE_URL`, ou Supabase API.
- **IA em cascata**: Gemini -> OpenRouter -> Claude -> endpoint OpenAI-compatible local.
- **Ghost local** (`ghost-local-v5`) como backend FastAPI para chat, memoria, ingest de runs e endpoint OpenAI-compatible.

Resultado: um stack pronto para **descobrir, validar, priorizar e documentar** achados com mais contexto tecnico.

---

## Principais Capacidades

- **Recon passivo + semi-ativo**: CT logs, Wayback, Common Crawl, RDAP, DNS enrichment, robots/sitemap, headers/TLS, WAF fingerprint, OpenAPI/GraphQL probe.
- **Coleta de leaks e codigo**: GitHub search, clone opcional de repositorios para analise complementar, validacao de secrets.
- **Validacao de evidencia**: verificador de sinais (XSS/SQLi/LFI/redirect/IDOR), micro exploit, webshell probe, descoberta ativa de parametros.
- **Modo Kali opcional**: `nmap`, `nuclei`, `ffuf`, `sqlmap`, `dalfox`, `wpscan`, `subfinder`, `amass`, `xss_vibes` e correlacoes extras.
- **Correlacao e priorizacao**: score, dedupe semantico, CVE hints, templates de relatorio, recheck de achados HIGH.
- **Base de conhecimento**: validacoes manuais + categorias do Cortex + sync opcional para o Ghost (`/memory/teach`).

---

## Arquitetura (alto nivel)

```mermaid
flowchart LR
  A[UI index.html] -->|POST /api/recon/stream| B[Node API server/index.js]
  B --> C[Modulos recon/passivo/semi-ativo]
  B --> D[Persistencia SQLite/Postgres/Supabase]
  B --> E[Correlacao + score + dedupe]
  B --> F[AI reports em cascata]
  B --> G[Ghost KB sync opcional]
  F --> H[Gemini/OpenRouter/Claude]
  F --> I[Ghost local /v1/chat/completions]
  J[Ghost local FastAPI] --> K[/gui /memory /ghostrecon/ingest]
```

---

## Estrutura do Repositorio

```text
GHOSTRECON/
|- server/                       # API principal + pipeline + modulos
|  |- index.js
|  |- modules/                  # 70+ modulos
|  |- tests/                    # 25 testes node --test
|  `- scripts/                  # utilitarios (mitre extract, bridge, smoke IA)
|- scripts/
|  `- start-stack.sh            # sobe Ghost local + API principal
|- ghost-local-v5/
|  |- start                      # wrapper para ghost-local/start.sh
|  |- ghost-local/               # FastAPI local + UI + memoria
|  `- hexstrike-ai/              # integracao opcional HexStrike
|- Xss/xss_vibes/                # scanner auxiliar python
|- supabase/                     # config e migrations SQL
|- index.html                    # UI principal
|- mitre-map.html                # Ghostmap
|- cortex.html                   # modo cerebro
|- reporte.html                  # validacao manual + IA
|- anotacao.html                 # anotacoes tecnicas com IA
|- install.sh                    # instalacao por perfil
|- Dockerfile                    # imagem minima do servidor
`- .env.example                  # referencias de configuracao
```

---

## Requisitos

- Linux Debian/Kali (recomendado para instalacao completa)
- Node.js >= 18 (Docker usa Node 22)
- Python 3 para componentes auxiliares (`ghost-local-v5`, `xss_vibes`)
- `npm` e acesso de rede para APIs/ferramentas opcionais

Para recursos avancados:

- Chaves de API (Gemini, OpenRouter, Shodan, VT, etc.)
- Ferramentas Kali no PATH (quando usar `kaliMode`)
- Docker (opcional para fluxos Shannon/PentestGPT de terceiros)

---

## Instalacao

### 1) Rapida (manual)

```bash
npm install
cp .env.example .env
```

Depois ajuste as variaveis que for usar.

### 2) Instalador por perfil (`install.sh`)

```bash
chmod +x install.sh
./install.sh --profile minimal
# ou:
./install.sh --profile passive
./install.sh --profile full
```

Perfis:

- `minimal`: base Node + deps do projeto.
- `passive`: minimal + ferramentas de recon passivo/auxiliar.
- `full`: passive + stack Kali ampla + Playwright + preparo Ghost local + IAs opcionais.

Flags uteis:

- `--skip-ias`
- `--skip-playwright`
- `--skip-docker`
- `--skip-supabase`
- `--skip-ghost-local`

---

## Como Rodar

### Subir stack completa (recomendado)

```bash
npm start
```

Isso executa `scripts/start-stack.sh`, que:

1. sobe o Ghost local em `:8000` (se disponivel), e
2. inicia a API GHOSTRECON em `:3847`.

### Modos separados

```bash
npm run start:api    # somente API Node (3847)
npm run start:ghost  # somente Ghost local (8000)
npm run dev          # API com watch
```

URLs principais:

- `http://127.0.0.1:3847/` -> UI principal
- `http://127.0.0.1:8000/gui/` -> UI do Ghost local
- `http://127.0.0.1:8000/v1/chat/completions` -> endpoint OpenAI-compatible local

---

## Fluxo Operacional do Pipeline

Resumo real do `runPipeline`:

1. Normaliza alvo e escopo (incluindo lista out-of-scope).
2. Enumera superficie (subs, DNS, RDAP, alive, TLS, headers, robots/sitemap, archive URLs).
3. Extrai parametros/JS/dorks e busca leaks em codigo.
4. Aplica verificacoes de evidencia e provas complementares.
5. Opcional: executa modulos Kali/ativos.
6. Correlaciona, prioriza, deduplica e monta templates.
7. Aplica tags OWASP + MITRE.
8. Persiste run, calcula delta vs run anterior e emite eventos finais.
9. Opcional: gera relatorios IA e envia webhook.

Saida em `POST /api/recon/stream` e em **NDJSON** (eventos `log`, `pipe`, `finding`, `stats`, `done`, etc.).

---

## Modulos e Perfis de Recon

No `index.html`, os modulos sao marcados por checkbox (`class="mod"`). Grupos relevantes:

- **Core passivo**: `subdomains`, `wayback`, `common_crawl`, `rdap`, `dns_enrichment`, `security_headers`, `robots_sitemap`.
- **OSINT/API**: `virustotal`, `shodan`, `google_cse`, `openapi_specs`, `graphql_probe`.
- **Leak/code**: `github`, `pastebin`.
- **Validacao**: `verify_sqli_deep`, `micro_exploit`, `webshell_probe`, `sqlmap`.
- **Kali**: `subfinder`, `amass`, `kali_ffuf`, `kali_nuclei`, `kali_nmap_aggressive`, `kali_nmap_udp`, `mysql_3306_intel`.
- **Integracoes IA**: `shannon_whitebox`, `pentestgpt_validate`.

Perfis:

- `quick`: menor cobertura e menor custo.
- `standard`: equilibrio default.
- `deep`: mais profundidade e volume de superficie.

---

## UI e Paginas

- `index.html`: console principal, stream ao vivo, selecao de modulos e export.
- `mitre-map.html`: timeline/visual de tags MITRE e OWASP.
- `cortex.html`: categorizacao de achados validados.
- `reporte.html`: checklist de validacao manual + relatorio IA sobre subset validado.
- `anotacao.html`: redacao de anotacoes com endpoint de IA de anotacoes.
- `como-usar.html`: guia de operacao da interface.

---

## API (rotas importantes)

### Recon e capacidade

- `GET /api/csrf-token`
- `POST /api/recon/stream`
- `GET /api/capabilities`
- `GET /api/health`
- `POST /api/tool-path-refresh`

### Runs/intel

- `GET /api/runs`
- `GET /api/runs/:id`
- `GET /api/runs/:newerId/diff/:baselineId`
- `GET /api/intel/:target`
- `GET /api/project-secret-peers?project=...`

### Cortex e validacoes

- `GET|POST /api/brain/categories`
- `POST /api/brain/categories/:id/description`
- `POST /api/brain/link`
- `GET /api/brain/category/:id`
- `GET|POST /api/manual-validations*`

### IA e integracoes

- `POST /api/ai-reports`
- `GET /api/ai/lmstudio-check`
- `POST /api/pentestgpt-ping`
- `POST /api/shannon/prep`

> Endpoints mutaveis exigem `X-CSRF-Token`.

---

## Persistencia e Dados

Camadas de armazenamento suportadas:

1. **SQLite local** (default): `data/bugbounty.db`
2. **Postgres via `DATABASE_URL`**
3. **Supabase REST** (`SUPABASE_URL` + chave)

Extras:

- Espelho opcional por projeto em `escopo/<projeto>/<alvo>/ghostrecon.db`
- Arquivo de validacoes em `Validate/<target>/<fingerprint>.json`
- Intel deduplicada por fingerprint em `bounty_intel`
- Correlacao de segredos entre alvos de mesmo projeto (`project_secret_peers`)

---

## Ghost Local (`ghost-local-v5`)

Backend FastAPI com:

- chat em streaming (`/chat/stream`)
- endpoint OpenAI-compatible (`/v1/chat/completions`)
- memoria (`/memory/*`)
- ingest de runs GHOSTRECON (`/ghostrecon/ingest/*`)
- analise guiada de runs (`/ghostrecon/analyze`)
- codescan de repositorio/arquivo/snippet (`/codescan/*`)

Scripts principais:

- `ghost-local-v5/ghost-local/setup.sh`
- `ghost-local-v5/ghost-local/start.sh`
- `ghost-local-v5/start`

HexStrike local pode ser iniciado junto quando `GHOST_START_HEXSTRIKE=1`.

---

## Integracao IA no Servidor Principal

Fluxo de relatorio em cascata (`server/modules/ai-dual-report.js`):

1. Gemini
2. OpenRouter
3. Claude (Anthropic)
4. Local OpenAI-compatible (LM Studio / Ghost)

Chaves e knobs estao em `.env.example`, com destaque para:

- `GEMINI_API_KEY` / `GOOGLE_AI_API_KEY`
- `OPENROUTER_API_KEY`
- `ANTHROPIC_API_KEY`
- `GHOSTRECON_LMSTUDIO_*`
- `GHOSTRECON_AI_*`

Tambem existe bridge opcional para validacao estilo PentestGPT:

```bash
npm run pentestgpt-bridge
```

---

## Variaveis de Ambiente (guia rapido)

O arquivo `.env.example` esta bastante documentado. Ordem pratica de setup:

1. **Obrigatorio basico**
   - `PORT` (default 3847)
2. **Banco**
   - `DATABASE_URL` ou `SUPABASE_URL` + chave
3. **IA**
   - `GEMINI_API_KEY` / `OPENROUTER_API_KEY` / `ANTHROPIC_API_KEY`
   - `GHOSTRECON_LMSTUDIO_*` (para fallback local)
4. **Modulos externos**
   - `VIRUSTOTAL_API_KEY`, `WPSCAN_API_TOKEN`, `GITHUB_TOKEN`, etc.
5. **Operacao**
   - `GHOSTRECON_RL_MAX`, `GHOSTRECON_OUT_OF_SCOPE`, `GHOSTRECON_WEBHOOK_URL`

---

## Scripts NPM

```bash
npm start
npm run start:api
npm run start:ghost
npm run dev
npm test
npm run test:ai
npm run mitre:extract
npm run pentestgpt-bridge
npm run db:link
npm run db:push
npm run db:migration:new
```

---

## Testes

Suite atual: **25 testes** em `server/tests/*.test.js`, cobrindo pontos criticos como:

- parsing e correlacao de findings
- perfil runtime e tooling
- deteccoes (OWASP/MITRE/header/webshell/sqlmap/wpscan)
- integrações e sanitizacao de entrada

Execucao:

```bash
npm test
```

---

## Docker (modo minimo)

Build:

```bash
docker build -t ghostrecon .
docker run --rm -p 3847:3847 --env-file .env ghostrecon
```

Observacoes:

- O `Dockerfile` copia apenas `server/` + `index.html`.
- Paginas adicionais (`mitre-map.html`, `cortex.html`, `reporte.html`, etc.) nao entram por padrao.
- Ferramentas Kali nao estao embutidas nessa imagem minima.

---

## Troubleshooting Rapido

- **Porta 3847 ocupada**: ajuste `PORT` ou finalize processo anterior.
- **CSRF invalido**: sempre buscar token em `GET /api/csrf-token` antes de `POST`.
- **Kali nao disponivel**: validar `GET /api/capabilities` e PATH de ferramentas.
- **IA nao responde**: rodar `npm run test:ai` e checar chaves no `.env`.
- **Ghost local offline**: verificar `ghost-local-v5/ghost-local/ghost.log`.
- **Supabase/Postgres falhando**: revisar `DATABASE_URL` e conectividade TLS.

---

## Uso Responsavel

Ferramenta para **ambientes autorizados**. Mesmo modulos passivos podem gerar trafego e consultas externas. Modulos ativos/Kali e fluxos de verificacao podem ser intrusivos. Respeite escopo contratual, regras de programa e legislacao aplicavel.

