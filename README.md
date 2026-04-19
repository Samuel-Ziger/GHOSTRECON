# GHOSTRECON

Framework local de recon, OSINT, validacao e priorizacao para bug bounty e pentest autorizado, com pipeline em streaming, UI operacional e camada de IA (cloud + local).

---

## O que e esta ferramenta 

O `GHOSTRECON` e uma central de investigacao de superficie de ataque. Em vez de executar dezenas de ferramentas separadas e depois tentar juntar tudo na mao, ele organiza todo o ciclo em um fluxo unico: descobrir ativos, achar sinais de falha, validar o que realmente importa, priorizar por risco e transformar isso em inteligencia acionavel.

Em termos simples: voce aponta um alvo autorizado e a stack devolve **visibilidade**, **contexto**, **prioridade** e **material pronto para decisao tecnica**.

---

## O que ele faz na pratica

- Mapeia superficie digital (subdominios, URLs historicas, headers, DNS, metadados).
- Procura sinais relevantes (possiveis XSS/SQLi/LFI, leaks, exposicao de servicos, pontos sensiveis).
- Cruza dados e reduz ruido (dedupe, score, tags OWASP/MITRE).
- Separa o que e so barulho do que merece tempo do analista.
- Ajuda a transformar achados em narrativa tecnica (reportes, anotacoes e relatorios IA).

---

## O poder da stack 

- **Velocidade operacional**: sai de “setup de ferramentas” para “investigacao real”.
- **Menos cegueira**: correlacao entre sinais que normalmente ficam espalhados.
- **Menos falso positivo**: camada de validacao e checklist manual.
- **Mais inteligencia acumulada**: Cortex + memoria local do Ghost reaproveitam conhecimento.
- **Modo escalavel**: funciona no basico passivo e evolui para modo Kali/ativo quando necessario.

---

## Componentes principais 

### 1) `GHOSTRECON` (nucleo)
E o motor principal: recebe alvo, executa os modulos de recon, transmite o progresso ao vivo e salva o resultado para comparacoes futuras.

### 2) `GhostMao` (no projeto: **Ghostmap**)
No codigo, o nome existente e `Ghostmap` (`mitre-map.html`).  
E o painel visual de risco/tatica: mostra o que foi encontrado com leitura orientada por MITRE/OWASP para facilitar entendimento rapido.

### 3) `Cortex`
O “cerebro” da operacao. Organiza conhecimento validado em categorias, liga achados por fingerprint e transforma descobertas em base reutilizavel.

### 4) `Reporter` (no projeto: **Reporte**)
Area de validacao manual. Aqui o analista marca o que realmente confirmou, reduz ruido e gera material de reporte com foco no que importa.

### 5) `Anotacao`
Editor de anotacoes tecnicas com apoio de IA para acelerar redacao e consolidar aprendizado operacional do run.

### 6) `GhostIntelegince` (no projeto: **Ghost Intelligence**)
No codigo, aparece como `Ghost Intelligence` (frontend do Ghost local).  
E a camada de IA local para chat, memoria, ingestao de runs e analise guiada.

---

## Como usar em poucos minutos

```bash
npm install
cp .env.example .env
npm start
```

Depois:

- UI principal: `http://127.0.0.1:3847/`
- Ghost local (GUI): `http://127.0.0.1:8000/gui/`
- Endpoint OpenAI-compatible local: `http://127.0.0.1:8000/v1/chat/completions`

---

## Visao tecnica detalhada (cirurgica)

## 1) Arquitetura geral

```mermaid
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
```

---

## 2) Estrutura do repositorio

```text
GHOSTRECON/
|- server/                             # API principal, pipeline, modulos
|  |- index.js                         # entrypoint Node/Express
|  |- modules/                         # modulos recon, IA, db, correlacao
|  |- tests/                           # 25 testes (node --test)
|  `- scripts/                         # utilitarios (MITRE, bridge PentestGPT, smoke IA)
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
|- mitre-map.html                      # Ghostmap
|- cortex.html                         # Cortex
|- reporte.html                        # Reporter/validacao manual
|- anotacao.html                       # Anotacoes com apoio IA
|- como-usar.html                      # guia de uso UI
|- install.sh                          # instalador por perfil
|- Dockerfile                          # imagem minima da API
`- .env.example                        # configuracoes
```

---

## 3) Fluxo de execucao ponta a ponta

1. `npm start` executa `scripts/start-stack.sh`.
2. O script tenta subir o Ghost local em `:8000` e valida `/health`.
3. Em seguida sobe a API Node (`server/index.js`) em `:3847`.
4. A UI (`index.html`) aciona `POST /api/recon/stream` e recebe NDJSON.
5. `runPipeline()` orquestra as fases:
   - normalizacao de alvo/escopo,
   - enumeracao de superficie,
   - extracao e enriquecimento,
   - validacoes de evidencia,
   - modulo Kali opcional,
   - correlacao/priorizacao,
   - persistencia + diff.
6. Com IA habilitada, a stack gera relatorios em cascata (cloud/local).
7. Opcionalmente envia webhook e sincroniza conhecimento no Ghost.

---

## 4) Camadas funcionais do pipeline

### Recon / enumeracao
- subdominios, wayback, common crawl, RDAP, DNS enrichment.
- security headers, robots/sitemap, probes HTTP/TLS/WAF.
- discovery de OpenAPI/GraphQL e superficie historica.

### Leak / codigo
- GitHub search + fluxo opcional de clone para analise complementar.
- correlacao de segredos por projeto/alvo.

### Validacao / evidencia
- verificacoes para sinais de SQLi/LFI/XSS/redirect/IDOR e correlatos.
- probes tecnicos especificos (ex.: webshell, sqlmap runner, etc.).

### Kali mode (opcional)
- integracoes com `nmap`, `ffuf`, `nuclei`, `sqlmap`, `wpscan`, `subfinder`, `amass`, `dalfox`, `xss_vibes`.
- profundidade depende do perfil e das ferramentas presentes no PATH.

### Correlacao / priorizacao
- score, dedupe semantico, tags OWASP/MITRE e hints de exploracao.
- recheck para achados de maior severidade.

---

## 5) Interfaces e paineis

- `index.html`: cockpit principal (run, stream ao vivo, filtros, export).
- `mitre-map.html` (Ghostmap): visualizacao MITRE/OWASP e feed ao vivo.
- `cortex.html`: base de conhecimento/categorizacao de achados validados.
- `reporte.html` (Reporter): checklist manual e consolidacao de validacoes.
- `anotacao.html`: notas tecnicas estruturadas + geracao IA.
- `ghost-local-v5/ghost-local/frontend/index.html` (Ghost Intelligence): chat/memoria/analise local.

---

## 6) API principal (rotas tecnicas)

### Recon e estado
- `POST /api/recon/stream`
- `GET /api/csrf-token`
- `GET /api/health`
- `GET /api/capabilities`
- `POST /api/tool-path-refresh`

### Runs / diff / intel
- `GET /api/runs`
- `GET /api/runs/:id`
- `GET /api/runs/:newerId/diff/:baselineId`
- `GET /api/intel/:target`
- `GET /api/project-secret-peers?project=...`

### Cortex / validacao manual
- `GET|POST /api/brain/categories`
- `POST /api/brain/categories/:id/description`
- `POST /api/brain/link`
- `GET /api/brain/category/:id`
- `GET|POST /api/manual-validations/:target`
- `POST /api/manual-validations/ai-report`
- `POST /api/manual-validations/annotations-ai`

### Integracoes IA
- `POST /api/ai-reports`
- `POST /api/pentestgpt-ping`
- `POST /api/shannon/prep`
- `GET /api/ai/lmstudio-check`

Observacao: rotas mutaveis usam protecao por CSRF (`X-CSRF-Token`).

---

## 7) Ghost local (FastAPI) e Ghost Intelligence

No modulo `ghost-local-v5/ghost-local/backend/main.py`, o backend local fornece:

- streaming de chat (`/chat/stream`);
- endpoint OpenAI-compatible (`/v1/chat/completions`);
- memoria (`/memory/*`);
- ingestao e analise de runs do GHOSTRECON (`/ghostrecon/ingest/*`, `/ghostrecon/analyze`);
- codescan (`/codescan/*`).

Scripts importantes:

- `ghost-local-v5/ghost-local/setup.sh`
- `ghost-local-v5/ghost-local/start.sh`
- `ghost-local-v5/start`

Opcional: pode iniciar HexStrike junto com `GHOST_START_HEXSTRIKE=1`.

---

## 8) Persistencia e dados

Camadas suportadas:

1. SQLite local (`data/bugbounty.db`) - padrao.
2. Postgres via `DATABASE_URL`.
3. Supabase API (`SUPABASE_URL` + chaves).

Pontos tecnicos relevantes:

- runs e findings persistidos para historico/delta;
- intel deduplicada por fingerprint;
- correlacao de segredos em projetos com multiplos alvos;
- validacoes manuais e links Cortex armazenados para reaproveitamento.

---

## 9) IA em cascata e fallback

Fluxo de relatorio IA no servidor principal:

1. Gemini.
2. OpenRouter.
3. Claude (Anthropic direto, quando aplicavel).
4. fallback local OpenAI-compatible (LM Studio ou Ghost local).

Variaveis de controle (exemplos):

- `GEMINI_API_KEY` / `GOOGLE_AI_API_KEY`
- `OPENROUTER_API_KEY`
- `ANTHROPIC_API_KEY`
- `GHOSTRECON_LMSTUDIO_*`
- `GHOSTRECON_AI_*`

Integracoes opcionais:

- Shannon (`shannon_whitebox`);
- PentestGPT (`pentestgpt_validate`) + bridge local (`npm run pentestgpt-bridge`).

---

## 10) Instalacao por perfil

### Rapida

```bash
npm install
cp .env.example .env
```

### Instalador orientado (`install.sh`)

```bash
chmod +x install.sh
./install.sh --profile minimal
# ou:
./install.sh --profile passive
./install.sh --profile full
```

Perfis:

- `minimal`: base Node + dependencias de projeto.
- `passive`: `minimal` + stack passiva/auxiliar.
- `full`: `passive` + modo Kali, Playwright, IA local e extras.

Flags uteis:

- `--skip-ias`
- `--skip-playwright`
- `--skip-docker`
- `--skip-supabase`
- `--skip-ghost-local`

---

## 11) Scripts NPM

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

## 12) Testes automatizados

A base inclui **25 testes** em `server/tests/*.test.js`, cobrindo parser, runtime profile, correlacao, deteccoes e integracoes de modulos.

Execucao:

```bash
npm test
```

---

## 13) Docker (imagem minima)

Build/execucao:

```bash
docker build -t ghostrecon .
docker run --rm -p 3847:3847 --env-file .env ghostrecon
```

Importante:

- o `Dockerfile` atual inclui `server/` + `index.html`;
- paineis auxiliares (`mitre-map.html`, `cortex.html`, `reporte.html`, `anotacao.html`) nao entram por padrao nessa imagem;
- ferramentas Kali externas nao fazem parte da imagem minima.

---

## 14) Variaveis de ambiente (mapa pratico)

O arquivo `.env.example` esta comentado em profundidade. Ordem recomendada de configuracao:

1. **Basico**
   - `PORT`
2. **Banco**
   - `DATABASE_URL` ou `SUPABASE_*`
3. **IA**
   - `GEMINI_API_KEY`, `OPENROUTER_API_KEY`, `ANTHROPIC_API_KEY`, `GHOSTRECON_LMSTUDIO_*`
4. **APIs de recon**
   - `VIRUSTOTAL_API_KEY`, `GITHUB_TOKEN`, `SHODAN_API_KEY`, `WPSCAN_API_TOKEN` etc.
5. **Operacao**
   - rate limit, out-of-scope, webhook, knobs de timeout/retries.

---

## 15) Troubleshooting rapido

- Porta ocupada: ajuste `PORT`/`GHOST_PORT` ou finalize processo existente.
- Erro CSRF: obtenha token em `GET /api/csrf-token` antes de POSTs mutaveis.
- Modo Kali incompleto: valide `GET /api/capabilities` e ferramentas no PATH.
- IA falhando: rode `npm run test:ai` e revise variaveis no `.env`.
- Ghost local offline: revise `ghost-local-v5/ghost-local/ghost.log`.
- Falha Postgres/Supabase: valide URL/chaves/TLS e conectividade externa.

---

## 16) Limites e riscos operacionais

- Ferramenta para uso **apenas autorizado**.
- Modulos ativos podem ser intrusivos e gerar trafego relevante.
- Integracoes externas dependem de quota, latencia e disponibilidade de terceiros.
- Exposicao de dados locais (logs/db/artifacts) exige higiene operacional e controle de versionamento.

---

## 17) Uso responsavel

Use somente em ambientes com permissao explicita (contrato, programa, escopo formal).  
Respeite legislacao local, regras de disclosure e politicas do alvo.
