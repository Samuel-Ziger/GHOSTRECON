# GHOSTRECON

Framework local de recon, OSINT, validação e priorização para bug bounty e pentest autorizado, com pipeline em streaming, UI operacional e camada de IA (cloud + local).

---

## O que é esta ferramenta

O `GHOSTRECON` é uma central de investigação de superfície de ataque. Em vez de executar dezenas de ferramentas separadas e depois tentar juntar tudo manualmente, ele organiza todo o ciclo em um fluxo único: descobrir ativos, encontrar sinais de falha, validar o que realmente importa, priorizar por risco e transformar isso em inteligência acionável.

Em termos simples: você aponta um alvo autorizado e a stack devolve **visibilidade**, **contexto**, **prioridade** e **material pronto para decisão técnica**.

---

## O que ele faz na prática

- Mapeia a superfície digital (subdomínios, URLs históricas, headers, DNS, metadados).
- Procura sinais relevantes (possíveis XSS/SQLi/LFI, leaks, exposição de serviços, pontos sensíveis).
- Cruza dados e reduz ruído (dedupe, score, tags OWASP/MITRE).
- Separa o que é apenas ruído do que merece tempo do analista.
- Ajuda a transformar achados em narrativa técnica (reportes, anotações e relatórios com IA).

---

## O poder da stack

- **Velocidade operacional**: sai de “setup de ferramentas” para “investigação real”.
- **Menos cegueira**: correlação entre sinais que normalmente ficam espalhados.
- **Menos falso positivo**: camada de validação e checklist manual.
- **Mais inteligência acumulada**: Cortex + memória local do Ghost reaproveitam conhecimento.
- **Modo escalável**: funciona no básico passivo e evolui para modo Kali/ativo quando necessário.

---

## Componentes principais

### 1) `GHOSTRECON` (núcleo)
É o motor principal: recebe o alvo, executa os módulos de recon, transmite o progresso ao vivo e salva o resultado para comparações futuras.

### 2) `GhostMap`
É o painel visual de risco/tática: mostra o que foi encontrado com leitura orientada por MITRE/OWASP para facilitar entendimento rápido.

### 3) `Cortex`
O “cérebro” da operação. Organiza conhecimento validado em categorias, liga achados por fingerprint e transforma descobertas em base reutilizável.

### 4) `Reporter`
Área de validação manual. Aqui o analista marca o que realmente confirmou, reduz ruído e gera material de reporte com foco no que importa.

### 5) `Anotação`
Editor de anotações técnicas com apoio de IA para acelerar a redação e consolidar aprendizado operacional do run.

### 6) `Ghost Intelligence`
É a camada de IA local para chat, memória, ingestão de runs e análise guiada.

---

## Como usar em poucos minutos

```bash
npm install
cp .env.example .env
npm start

Depois:

UI principal: http://127.0.0.1:3847/
Ghost local (GUI): http://127.0.0.1:8000/gui/
Endpoint OpenAI-compatible local: http://127.0.0.1:8000/v1/chat/completions
Visão técnica detalhada (cirúrgica)
1) Arquitetura geral
flowchart LR
  A[UI principal index.html] -->|POST /api/recon/stream| B[API Node server/index.js]
  B --> C[Pipeline runPipeline]
  C --> D[Modulos recon OSINT validacao]
  C --> E[Persistencia SQLite Postgres Supabase]
  C --> F[Correlacao score dedupe OWASP MITRE]
  C --> G[Relatorios IA em cascata]
  C --> H[Webhook e diff de runs]
  C --> I[Sync opcional para Ghost KB]
  J[Ghost local FastAPI] --> K[/chat /memory /ghostrecon /v1/chat/completions]
  G --> L[Gemini OpenRouter Claude]
  G --> M[Fallback local LM Studio Ghost]
2) Estrutura do repositório
GHOSTRECON/
|- server/                             # API principal, pipeline, módulos
|  |- index.js                         # entrypoint Node/Express
|  |- modules/                         # módulos recon, IA, db, correlação
|  |- tests/                           # 25 testes (node --test)
|  `- scripts/                         # utilitários (MITRE, bridge PentestGPT, smoke IA)
|- scripts/start-stack.sh              # sobe Ghost local + API Node
|- ghost-local-v5/
|  |- start                            # wrapper de start do ghost-local
|  |- ghost-local/
|  |  |- backend/main.py               # FastAPI (chat/memory/ingest/codescan)
|  |  `- frontend/index.html           # Ghost Intelligence
|  `- hexstrike-ai/                    # stack opcional HexStrike + MCP
|- Xss/xss_vibes/                      # scanner auxiliar Python
|- supabase/                           # schema e migrations
|- index.html                          # hub operacional principal
|- mitre-map.html                      # GhostMap
|- cortex.html                         # Cortex
|- reporte.html                        # Reporter/validação manual
|- anotacao.html                       # Anotações com apoio de IA
|- como-usar.html                      # guia de uso UI
|- install.sh                          # instalador por perfil
|- Dockerfile                          # imagem mínima da API
`- .env.example                        # configurações
3) Fluxo de execução ponta a ponta
npm start executa scripts/start-stack.sh.
O script tenta subir o Ghost local em :8000 e valida /health.
Em seguida, sobe a API Node (server/index.js) em :3847.
A UI (index.html) aciona POST /api/recon/stream e recebe NDJSON.
runPipeline() orquestra as fases:
normalização de alvo/escopo,
enumeração de superfície,
extração e enriquecimento,
validações de evidência,
módulo Kali opcional,
correlação/priorização,
persistência + diff.
Com IA habilitada, a stack gera relatórios em cascata (cloud/local).
Opcionalmente, envia webhook e sincroniza conhecimento no Ghost.
4) Camadas funcionais do pipeline
Recon / enumeração
subdomínios, wayback, common crawl, RDAP, DNS enrichment;
security headers, robots/sitemap, probes HTTP/TLS/WAF;
discovery de OpenAPI/GraphQL e superfície histórica.
Leak / código
GitHub search + fluxo opcional de clone para análise complementar;
correlação de segredos por projeto/alvo.
Validação / evidência
verificações para sinais de SQLi/LFI/XSS/redirect/IDOR e correlatos;
probes técnicos específicos (ex.: webshell, sqlmap runner, etc.).
Kali mode (opcional)
integrações com nmap, ffuf, nuclei, sqlmap, wpscan, subfinder, amass, dalfox, xss_vibes;
profundidade depende do perfil e das ferramentas presentes no PATH.
Correlação / priorização
score, dedupe semântico, tags OWASP/MITRE e hints de exploração;
recheck para achados de maior severidade.
5) Interfaces e painéis
index.html: cockpit principal (run, stream ao vivo, filtros, export);
mitre-map.html (GhostMap): visualização MITRE/OWASP e feed ao vivo;
cortex.html: base de conhecimento/categorização de achados validados;
reporte.html (Reporter): checklist manual e consolidação de validações;
anotacao.html: notas técnicas estruturadas + geração com IA;
ghost-local-v5/.../frontend/index.html (Ghost Intelligence): chat/memória/análise local.
6) API principal (rotas técnicas)
Recon e estado
POST /api/recon/stream
GET /api/csrf-token
GET /api/health
GET /api/capabilities
POST /api/tool-path-refresh
Runs / diff / intel
GET /api/runs
GET /api/runs/:id
GET /api/runs/:newerId/diff/:baselineId
GET /api/intel/:target
GET /api/project-secret-peers?project=...
Cortex / validação manual
GET|POST /api/brain/categories
POST /api/brain/categories/:id/description
POST /api/brain/link
GET /api/brain/category/:id
GET|POST /api/manual-validations/:target
POST /api/manual-validations/ai-report
POST /api/manual-validations/annotations-ai
Integrações IA
POST /api/ai-reports
POST /api/pentestgpt-ping
POST /api/shannon/prep
GET /api/ai/lmstudio-check

Observação: rotas mutáveis usam proteção por CSRF (X-CSRF-Token).

7) Ghost local (FastAPI) e Ghost Intelligence

No módulo ghost-local-v5/ghost-local/backend/main.py, o backend local fornece:

streaming de chat (/chat/stream);
endpoint OpenAI-compatible (/v1/chat/completions);
memória (/memory/*);
ingestão e análise de runs do GHOSTRECON (/ghostrecon/ingest/*, /ghostrecon/analyze);
codescan (/codescan/*).
8) Persistência e dados

Camadas suportadas:

SQLite local (data/bugbounty.db) — padrão
Postgres via DATABASE_URL
Supabase API (SUPABASE_URL + chaves)
9) IA em cascata e fallback

Fluxo de relatório IA:

Gemini
OpenRouter
Claude
fallback local (LM Studio ou Ghost local)
10) Instalação por perfil

Perfis:

minimal: base Node
passive: + stack passiva
full: + Kali, IA local e extras
11) Scripts NPM
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
12) Testes automatizados

Inclui 25 testes em server/tests/*.test.js.

13) Docker

Imagem mínima da API (sem painéis auxiliares e ferramentas Kali externas).

14) Variáveis de ambiente

Ordem recomendada:

Básico
Banco
IA
APIs de recon
Operação
15) Troubleshooting rápido
Porta ocupada: ajuste PORT
CSRF: use /api/csrf-token
Kali incompleto: verifique /api/capabilities
IA falhando: npm run test:ai
Ghost offline: verifique logs
DB falhando: valide credenciais
16) Limites e riscos operacionais
Uso apenas autorizado
Módulos ativos podem ser intrusivos
Dependência de APIs externas
Necessidade de higiene de dados locais
17) Uso responsável

Use somente em ambientes com autorização explícita (contrato, programa ou escopo formal).
Respeite a legislação local, políticas do alvo e regras de disclosure.

---

## 18) CLI headless (`ghostrecon`)

Toda a pipeline é acessível em modo headless pela CLI, sem necessidade de UI. Útil
para CI/CD, cron jobs e integração com outros stacks. A CLI reaproveita 100% do
pipeline via `/api/recon/stream` (HTTP+NDJSON), sem forkar lógica.

```bash
# Após npm install
npx ghostrecon run --target example.com --modules crtsh,http,github --output run.json
npx ghostrecon run --target api.example.com --playbook api-first
npx ghostrecon runs --target example.com --limit 10
npx ghostrecon diff --baseline 12 --newer 18 --format summary
npx ghostrecon playbooks
npx ghostrecon playbooks --show api-first
npx ghostrecon export --run 42 --to github --repo myorg/myrepo --severity high
npx ghostrecon projects --add --name acme --description "Acme bounty program"
npx ghostrecon projects --name acme --scope-add "*.acme.com"
```

Principais opções de `run`:

| Opção | Descrição |
|-------|-----------|
| `--target` | Domínio alvo (obrigatório) |
| `--modules` | CSV de módulos (ex.: `crtsh,http,github`) |
| `--playbook` | Perfil pré-configurado (ver `playbooks/`) |
| `--profile` | `standard` · `stealth` · `aggressive` |
| `--output FILE` | Grava JSON agregado final |
| `--format` | `json` · `ndjson` · `summary` |
| `--exact-match` | Subs apenas do alvo exato |
| `--kali` | Módulos Kali (requer ferramentas locais) |
| `--auth-header K=V` | Repetível — headers extras |
| `--auth-cookie` | Cookie bruto para requests autenticadas |
| `--project NAME` | Atribui o run a um projeto |
| `--start-server` | Auto-spawn do API em background |
| `--timeout SEC` | Timeout global (default 1800) |

A CLI usa CSRF token automaticamente e faz auto-start do server local se `--start-server`
for passado (ou erra com mensagem clara caso contrário).

## 19) Scheduler, diff e alertas new-only

O subcomando `schedule` roda recons periódicos e, usando `compareRuns` + o
diff-engine interno, alerta **apenas quando há findings novos** (dedupe por
fingerprint SHA-1 dos achados). Evita ruído de "mesmo alerta todo dia".

```bash
ghostrecon schedule \
  --target api.example.com \
  --interval 6h \
  --playbook api-first \
  --webhook https://discord.com/api/webhooks/XXXXX/YYYYY \
  --min-severity high \
  --only-new
```

- Estado persistido em `.ghostrecon-schedule/<target>.json` (última runId,
  fingerprints vistos, histórico).
- Suporta Discord (embeds nativos), Slack (`text` mrkdwn) e webhook genérico.
- Flag `--once` roda uma única iteração (útil em cron externo). `--max-runs N`
  limita o número total de iterações.
- Interval aceita `30s`, `15m`, `6h`, `2d`.

Endpoint equivalente no server:

```
GET /api/runs/:newerId/diff-summary/:baselineId?minSeverity=medium&onlyNew=1
```

## 20) Playbooks

Playbooks são ficheiros JSON (ou YAML minimalista) em `playbooks/` que
pré-selecionam módulos e perfil de pipeline para cenários comuns.

Bundled:

| Nome | Uso |
|------|-----|
| `api-first` | Superfície API (OpenAPI, GraphQL, params) |
| `wordpress` | WordPress — wpscan, temas, plugins, xmlrpc |
| `cloud-takeover` | CNAMEs órfãos em S3/Azure/GitHub Pages |
| `subdomain-hunt` | Enumeração agressiva (crtsh + VT + amass + subfinder) |
| `secrets-leak` | GitHub code search, wayback, dorks, JS crawl |
| `quick-triage` | Primeiro passo rápido (~60s) |

Ver `playbooks/README.md` para formato completo. Aponte `GHOSTRECON_PLAYBOOKS_DIR`
para diretórios extras (suporta múltiplos paths separados por `:` POSIX ou `;`
Windows).

## 21) Evidências ricas com Playwright

O módulo `server/modules/evidence-capture.js` captura, por finding, screenshot
PNG + DOM snippet + response headers + console logs via Playwright headless. É
invocado sob demanda pelo endpoint:

```
POST /api/evidence/capture/:runId
{
  "minSeverity": "medium",
  "maxCaptures": 25,
  "fullPage": false
}
```

Saída persistida em `.ghostrecon-evidence/<runId>/f<idx>_<slug>.{png,html,json}`.
Os findings recebem `evidence.captures = { screenshot, dom, meta }` — referenciados
diretamente pelo Reporter e pelo export de Markdown/HackerOne.

## 22) CVE enrichment (versão → exploit)

Cruza tech strings (de `tech-versions.js`, banners ou version-page) com:

- OSV.dev (sem API key)
- NVD 2.0 (com ou sem API key)
- ExploitDB search (heurístico, opcional)
- Nuclei templates locais (se `GHOSTRECON_NUCLEI_TEMPLATES_DIR` definido)

Severidade derivada do CVSS. **Banners são degradados em 1 step** (falsos
positivos comuns — servidores mentem versão). Findings têm campos `cve`, `cvss`,
`exploitPublic`, `exploitSources`.

Endpoint:

```
POST /api/cve/enrich
{
  "techStrings": ["nginx/1.18.0", "openssl/1.1.1k"],
  "source": "banner",
  "checkExploits": true
}
```

## 23) Inbound webhooks (hub)

Ferramentas externas (subfinder, amass, nuclei, dnsx, cron scripts) podem
enviar eventos para o GHOSTRECON, que os armazena por target para merge no
próximo recon.

Configure chaves no `.env`:

```
GHOSTRECON_INBOUND_KEYS=subfinder:key1,nuclei:key2
```

Envie eventos com HMAC SHA-256:

```bash
BODY='{"template-id":"cve-2021-44228","matched-at":"https://api.example.com/","info":{"severity":"critical","name":"Log4Shell"}}'
SIG=$(echo -n "$BODY" | openssl dgst -sha256 -hmac "key2" | awk '{print $2}')
curl -X POST http://127.0.0.1:3847/api/inbound/nuclei \
  -H "x-ghostrecon-signature: sha256=$SIG" \
  -H "content-type: application/json" \
  -d "$BODY"
```

Auto-detecta payloads Subfinder/Amass/Nuclei. Leitura via
`GET /api/inbound/:source/:target` (Bearer token = chave da source).

## 24) Projects (multi-alvo)

Agrupa runs por programa/cliente — reduz context switching quando você caça em
vários programas simultaneamente.

```bash
ghostrecon projects --add --name acme --description "Acme bounty"
ghostrecon projects --name acme --scope-add "*.acme.com" --scope-add "api.acme.io"
ghostrecon projects --show acme
ghostrecon run --target api.acme.com --project acme --playbook api-first
```

Storage local em `.ghostrecon-projects/projects.json` (zero dependências extras
de DB). Endpoints:

```
GET    /api/projects
GET    /api/projects/:name
POST   /api/projects          (CSRF)
DELETE /api/projects/:name    (CSRF)
```

## 25) Workflow export (Linear/Jira/GitHub)

Exporta findings de um run como issues em:

- **GitHub Issues** — `--to github --repo owner/name --github-token $GITHUB_TOKEN`
- **Linear** — `--to linear --linear-team TEAM_ID --linear-token $LINEAR_API_KEY`
- **Jira Cloud** — `--to jira --jira-url $BASE --jira-project KEY --jira-user me@ex.com --jira-token $JIRA_TOKEN`
- **Markdown** — `--to markdown --output out.md` (HackerOne/Bugcrowd-ready)

Cada issue carrega: título com severidade, body reprodutível (evidence, OWASP,
MITRE, CVE), labels/priorities mapeadas da severidade, link para o Reporter
(se `GHOSTRECON_REPORTER_BASE` definido). Use `--dry-run` para preview sem
POST.

## 26) Variáveis de ambiente novas

| Variável | Propósito |
|----------|-----------|
| `GHOSTRECON_SERVER` | URL da API usada pela CLI (default `http://127.0.0.1:3847`) |
| `GHOSTRECON_PLAYBOOKS_DIR` | Diretórios extra de playbooks (`:` ou `;`) |
| `GHOSTRECON_PROJECTS_DIR` | Caminho do JSON store de projetos |
| `GHOSTRECON_INBOUND_DIR` | Onde guardar eventos inbound (`.ghostrecon-inbound`) |
| `GHOSTRECON_INBOUND_KEYS` | `source1:key1,source2:key2` (HMAC shared secrets) |
| `GHOSTRECON_NUCLEI_TEMPLATES_DIR` | Dir local de templates Nuclei para match de CVE→exploit |
| `GHOSTRECON_REPORTER_BASE` | URL base do Reporter para links em issues exportados |
| `GITHUB_TOKEN` / `LINEAR_API_KEY` / `JIRA_USER` / `JIRA_TOKEN` | Credenciais para export |

## 27) Tests

Novos testes em `server/tests/` (node --test):

- `cli-args.test.js` — parser de argumentos, parseDuration, kvListToObject
- `diff-engine.test.js` — fingerprint estável, filtros por severidade, shouldAlert
- `playbooks.test.js` — loader + YAML mínimo
- `cve-enrichment.test.js` — parseTechString + OSV/NVD mock + banner degrade
- `inbound-webhooks.test.js` — normalização Nuclei/Subfinder/Amass/custom
- `projects.test.js` — CRUD + scope wildcard
- `workflow-export.test.js` — Markdown + GitHub issue formato

Rodar: `npm test` ou `npm run test:cli` (subset das novas features).

## 28) Proxychains-ng + rotação de IP

`proxychains-ng` agora é uma opção dedicada da UI via módulo
`kali_proxychains` (separada da rotação de identidade/proxy pool).
Quando marcado no run, os scanners do modo Kali rodam por
`proxychains-ng` (chains SOCKS/HTTP/Tor).

Exemplo de `.env`:

```bash
# (opcional para CLI/headless sem UI)
GHOSTRECON_PROXYCHAINS_BIN=proxychains4
GHOSTRECON_PROXYCHAINS_CONF=/etc/proxychains4.conf
GHOSTRECON_PROXYCHAINS_QUIET=1
```

Com isso, ferramentas como `nmap`, `nuclei`, `ffuf`, `dirsearch`, `dalfox`,
`whois`, `sqlmap` e `wpscan` passam a ser executadas via `proxychains4`.

Para excluir uma ferramenta específica do chain:

```bash
GHOSTRECON_PROXYCHAINS_SKIP=nmap
```

