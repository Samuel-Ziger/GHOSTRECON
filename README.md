# GHOSTRECON

Framework **passivo** de OSINT / recon para bug bounty: subdomínios (crt.sh + opcional **VirusTotal**), DNS, HTTP probing com **análise de cabeçalhos de segurança** e **inspeção TLS** (certificado), Wayback (CDX) + **Common Crawl**, **robots.txt / sitemap.xml** nos hosts vivos, **RDAP** (registo de domínio), extração de parâmetros, análise heurística de JS, detecção de possíveis secrets, geração de Google Dorks (URLs de busca + abertura em abas), **opcionalmente descoberta de URLs via Google Programmable Search (Custom Search JSON API)**, gravação em **Supabase (Postgres)** ou **SQLite** (`data/bugbounty.db`: histórico de runs + corpus **deduplicado** por alvo), **comparação entre runs** (API), **webhook** e **rate limit** opcionais na API, correlação e sugestões de vetores. Interface web dark/red team em `index.html`.

## Requisitos

- Node.js **18+** (usa `fetch` nativo)

## Execução

```bash
npm install
npm start
npm test   # testes mínimos (ex.: cabeçalhos de segurança)
```

Abra **http://127.0.0.1:3847** (porta alterável com `PORT=3000 npm start`).$env:PORT=3847
 Stop-Process -Id 21460 -Force

> A UI chama `POST /api/recon/stream`. Abrir só o arquivo `index.html` no disco **não** executa o pipeline — é necessário o servidor.

## Variáveis de ambiente

| Variável | Uso |
|----------|-----|
| `PORT` | Porta HTTP (padrão `3847`) |
| `GITHUB_TOKEN` | Token fine-grained ou classic para aumentar limite da [GitHub Code Search API](https://docs.github.com/en/rest/search/search?apiVersion=2022-11-28#search-code) |
| `GOOGLE_CSE_KEY` | Chave da [Custom Search JSON API](https://developers.google.com/custom-search/v1/overview) |
| `GOOGLE_CSE_CX` | ID do motor (**cx**) em [Programmable Search Engine](https://programmablesearchengine.google.com/) — podes ativar “Search the entire web” |
| `GHOSTRECON_DB` | Caminho opcional do SQLite (padrão `data/bugbounty.db`) — ignorado se `DATABASE_URL` ou API Supabase estiver definida |
| `DATABASE_URL` | **Postgres direto** (string do dashboard: *Connect → Node.js → Direct* ou **Session pooler** se estiveres em rede só IPv4). Tem prioridade sobre `SUPABASE_URL` + chave. |
| `SUPABASE_URL` | URL do projeto para cliente REST (ex. `https://xxxx.supabase.co`) — usado só se **não** existir `DATABASE_URL` |
| `SUPABASE_ANON_KEY` | Chave **anon** (JWT) do dashboard — uso típico no servidor com `.env` (não commits) |
| `SUPABASE_PUBLISHABLE_KEY` | Alternativa à anon, se usares a chave publishable do projeto |
| `SUPABASE_SERVICE_ROLE_KEY` | Opcional: no **servidor** apenas; ignora RLS — preferível em produção com políticas restritas |
| `VIRUSTOTAL_API_KEY` | Subdomínios via API (módulo **virustotal** na UI) |
| `GHOSTRECON_WEBHOOK_URL` | `POST` JSON após recon gravado (`runId`, `target`, `stats`, …) |
| `GHOSTRECON_RL_MAX` | Máx. recons por IP por janela (predef. `12`; `0` = desligado) |
| `GHOSTRECON_RL_WINDOW_MS` | Janela do rate limit em ms (predef. `60000`) |
| `GHOSTRECON_CC_CDX_API` | URL do índice CDX Common Crawl (opcional; senão usa `collinfo.json`) |

### Supabase

#### Opção A — CLI (migrações versionadas, recomendado)

1. **Login** (uma vez): `npx supabase login` — abre o browser para gerar o token.
2. **Ligar o projeto** (na pasta do repo):
   ```bash
   npm run db:link -- --password "A_TUA_DATABASE_PASSWORD"
   ```
   A password está em **Project Settings → Database → Database password** no dashboard.  
   Comando equivalente: `npx supabase link --project-ref lchttisqazjuapczstkm --password "..."`  
   (`npm run db:link` já inclui o `project-ref` deste projeto.)
3. **Aplicar migrações** no remoto:
   ```bash
   npm run db:push
   ```
   A migração inicial **GosthRecon** está em `supabase/migrations/20250325181000_gosthrecon_initial.sql`.
4. **Nova migração** (quando alterares o schema):
   ```bash
   npm run db:migration:new -- nome_descritivo
   ```
   (Se o comando `migration new` bloquear no Windows, cria manualmente um ficheiro `supabase/migrations/YYYYMMDDHHMMSS_nome.sql`.)

5. Copia `.env.example` para **`.env`**. Para o servidor Node, o mais simples é **`DATABASE_URL`** (pacote `postgres`, ver `server/modules/db-pg.js`). Se a password tiver caracteres especiais (`@`, `#`, etc.), usa `encodeURIComponent` na password dentro da URI. Em rede **só IPv4**, o Supabase indica **Session pooler** em vez de “Direct connection”. Alternativa sem `DATABASE_URL`: `SUPABASE_URL` + `SUPABASE_ANON_KEY`. Depois `npm start`.

#### Opção B — SQL Editor (sem CLI)

No dashboard: **SQL** → **New query**. Copia **todo** o ficheiro **`supabase/COPIAR_PARA_SQL_EDITOR.sql`** (a primeira linha deve ser `create table`). **Não** colas o caminho do ficheiro como texto na query.

**Segurança:** não commits chaves; o schema inclui políticas RLS permissivas para `anon` (ok se a chave só existir no servidor). Para produção, prefere `SUPABASE_SERVICE_ROLE_KEY` no Node e políticas mais restritas.

### Google Hacking (URLs reais)

Sem API, a ferramenta só **monta as queries** e pode **abrir o Google** nas abas (como antes). **Não** faz scraping da página de resultados (instável e contra os ToS).

Com **Google CSE** ativado na sidebar e variáveis `GOOGLE_CSE_KEY` + `GOOGLE_CSE_CX`, o servidor executa cada dork (até `googleCseMaxQueries` por run, ver `server/config.js`) na API oficial e adiciona **endpoints** reais cujo host coincide com o alvo. A quota gratuita é tipicamente **100 queries/dia**.

### SQLite (`bugbounty.db`)

Ficheiro predefinido: **`data/bugbounty.db`**. Tabelas:

- **`runs` + `findings`** — cada execução completa (histórico auditável, como antes).
- **`bounty_intel`** — corpus **único por alvo** (dedupe por hash de tipo + valor + URL). Novos recons **acrescentam** só o que ainda não existia; entradas repetidas **atualizam** `last_seen` e `last_run_id`. A UI mostra um aviso abaixo do histórico com quantos artefactos novos foram guardados.

API: `GET /api/intel/:target` — lista o corpus deduplicado para o domínio.

> Se tinhas `data/ghostrecon.db`, o novo ficheiro é outro; usa `GHOSTRECON_DB=.../ghostrecon.db` para continuar na base antiga, ou copia/mescla manualmente.

### Modo Kali (scan ativo — opcional)

Em **Kali Linux**, com `nmap` no PATH, a UI permite **Modo Kali**: após a fase passiva, o servidor corre (se existirem):

- **nmap** — `-sV` por defeito (personalizável com `GHOSTRECON_NMAP_ARGS`, ex. `-A -Pn -T4` — mais lento)
- **searchsploit** — consultas heurísticas a partir de produto/versão do nmap
- **ffuf** — wordlist comum, **apenas respostas HTTP 200**
- **nuclei** — templates contra URLs base (https/http do alvo e hosts com 80/443 no nmap)

Requisitos típicos no Kali: `nmap`, `ffuf`, `nuclei`, `searchsploit`, wordlists em `/usr/share/seclists` ou `dirb`.

| Variável | Uso |
|----------|-----|
| `GHOSTRECON_FORCE_KALI` | `1` = tratar como Kali (testes em WSL/outra distro com ferramentas) |
| `GHOSTRECON_NMAP_ARGS` | Argumentos extra do nmap (substitui o padrão `-sV -Pn -T4 --host-timeout 180s`) |

**Aviso:** isto é **recon/scan ativo**. Usa apenas em **alvos autorizados**.

## Estrutura do projeto

```
goshtrecon/
├── index.html          # Frontend (visual + consumo NDJSON)
├── package.json
├── .env.example
├── supabase/
│   ├── config.toml     # Config local da CLI
│   ├── migrations/                 # Migrações versionadas (`npm run db:push`)
│   └── COPIAR_PARA_SQL_EDITOR.sql  # DDL para colar no dashboard (sem duplicar caminho na query)
├── README.md
└── server/
    ├── index.js        # Express, rota de streaming, orquestração do pipeline
    ├── config.js       # Limites, User-Agent, regex de “interesting”
    └── modules/
        ├── dorks.js    # Templates de dorks (extensível)
        ├── subdomains.js
        ├── dns.js
        ├── probe.js
        ├── tech.js
        ├── wayback.js
        ├── params.js
        ├── js-analyzer.js
        ├── secrets.js
        ├── github.js
        ├── google-cse.js
        ├── kali-scan.js
        ├── db.js           # Fachada: Supabase se env definido, senão SQLite
        ├── db-sqlite.js
        ├── db-supabase.js   # Cliente REST (@supabase/supabase-js)
        ├── db-pg.js         # Postgres direto (DATABASE_URL + postgres)
        ├── db-common.js
        ├── scoring.js
        ├── correlation.js
        ├── intelligence.js
        ├── security-headers.js
        ├── tls-cert.js
        ├── robots-sitemap.js
        ├── commoncrawl.js
        ├── rdap.js
        ├── virustotal.js
        ├── db-compare.js
        └── webhook-notify.js
```

## Como expandir

### Novos dorks

Edite `server/modules/dorks.js`:

1. Adicione uma chave em `DORK_TEMPLATES` com array de funções `(domínioComAspasSeNecessário) => string de query`.
2. Se for categoria de alto risco, inclua o id do módulo no `Set` `HIGH_DORK`.
3. No `index.html`, adicione um checkbox com `class="mod"` e `value="seu_id"` igual à chave.

### Novas fontes passivas

Crie `server/modules/minha-fonte.js` exportando funções puras/async, importe em `server/index.js` e chame no `runPipeline` após emitir logs/`pipe` coerentes com a barra da UI.

### Limites e performance

Ajuste `server/config.js` (`waybackCollapseLimit`, `maxJsFetch`, `probeConcurrency`, `probeTimeoutMs`, `googleCseMaxQueries`, `googleCseDelayMs`).

## API

- `GET /api/health` — status.
- `GET /api/capabilities` — deteta Kali + ferramentas (`nmap`, `ffuf`, `nuclei`, `searchsploit`).
- `GET /api/runs?limit=50` — lista recons gravados (metadados + stats).
- `GET /api/runs/:id` — recon completo com `findings`.
- `GET /api/runs/:newerId/diff/:baselineId` — compara dois runs do **mesmo** alvo: `added` / `removed` (fingerprints iguais ao corpus `bounty_intel`).
- `GET /api/intel/:domain` — artefactos únicos acumulados para o alvo (`bounty_intel`).
- `POST /api/recon/stream` — corpo JSON `{ "domain": "example.com", "exactMatch": false, "modules": ["subdomains", "wayback", "common_crawl", "security_headers", "robots_sitemap", "rdap", "virustotal", ...] }`. Resposta **NDJSON**: `log`, `progress`, `pipe`, `stats`, `finding`, `dork`, `intel`, `done` (inclui `runId` se gravado), `error`. Rate limit opcional: `GHOSTRECON_RL_MAX` / `GHOSTRECON_RL_WINDOW_MS`.

## Docker

Na raiz do repo (expõe a porta `3847`; define `DATABASE_URL` ou SQLite montado em `data/`):

```bash
docker build -t ghostrecon .
docker run --rm -p 3847:3847 --env-file .env ghostrecon
```

## Exportação

O browser gera **JSON**, **Markdown** e **TXT** a partir dos achados acumulados na sessão.

## Aviso legal

Use apenas em alvos que você tem **autorização** para testar. O projeto prioriza técnicas passivas; HTTP GET para probing e CDX ainda são solicitações ativas leves — respeite termos de uso dos serviços (Google, Archive.org, crt.sh, GitHub) e políticas do programa de bug bounty.
