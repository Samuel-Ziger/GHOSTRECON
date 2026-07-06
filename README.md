# GHOSTRECON

GHOSTRECON e uma plataforma local para recon, OSINT, validacao tecnica e organizacao de achados em bug bounty ou pentest autorizado. O projeto junta um servidor Node/Express, uma UI operacional em HTML, pipeline em streaming NDJSON, modulos de seguranca, paineis de analise, integracoes com IA, GhostTrace, GhostMap, GhostDesk, Vigolium e HexStrike.

> Local-first por desenho. A stack foi pensada para rodar no computador do operador, em `127.0.0.1`, com cloud opcional apenas quando o usuario configura chaves de API.

## Aviso De Uso

Use somente em alvos onde voce tem autorizacao explicita. O GHOSTRECON possui muitos modulos passivos, mas tambem pode acionar ferramentas ativas quando o operador habilita modos como Kali, Vigolium, sqlmap, nuclei, ffuf, navegacao, proxy, Tor ou validacoes especificas. O projeto tem gates de OPSEC, CSRF, auth e rate limit, mas a responsabilidade final de escopo e permissao e do operador.

## Status Atual Do Projeto

O repositorio esta organizado como uma stack local completa:

- API principal Node/Express em `server/index.js`.
- UI principal em `public/index.html`.
- Pipeline modular em `server/pipeline/`.
- Modulos e integracoes em `server/modules/`, `server/routes/`, `server/integrations/` e `server/auto-agent/`.
- CLI em `bin/ghostrecon.mjs`.
- IA local em `ghost-local-v5/ghost-local`.
- GhostTrace em `GhostTrace/`.
- GhostMap em `ghostmap/`.
- GhostDesk em `GhostDesk/`.
- HexStrike em `IAs/hexstrike-ai`.
- Playbooks em `playbooks/`.
- Ferramentas auxiliares em `tools/`, `engines/`, `bridge/`, `apps/` e `scripts/`.

## Sumario

- [Inicio Rapido](#inicio-rapido)
- [URLs Locais](#urls-locais)
- [Como Usar Na UI](#como-usar-na-ui)
- [Modo Auto](#modo-auto)
- [HexStrike](#hexstrike)
- [Arquitetura](#arquitetura)
- [Estrutura Do Repositorio](#estrutura-do-repositorio)
- [Pipeline Principal](#pipeline-principal)
- [Modulos E Capacidades](#modulos-e-capacidades)
- [APIs Principais](#apis-principais)
- [CLI](#cli)
- [Variaveis De Ambiente](#variaveis-de-ambiente)
- [Scripts NPM](#scripts-npm)
- [Testes](#testes)
- [Troubleshooting](#troubleshooting)
- [Documentos Relacionados](#documentos-relacionados)

## Inicio Rapido

Requisitos principais:

- Node.js 20 ou superior.
- npm.
- Bash para scripts auxiliares.
- Python 3 para `ghost-local-v5`, HexStrike e algumas ferramentas opcionais.
- Ferramentas externas opcionais: `nmap`, `ffuf`, `nuclei`, `sqlmap`, `subfinder`, `amass`, `katana`, `httpx`, `proxychains4`, Tor, Playwright browsers etc.

Instalacao base:

```bash
npm install
cp .env.example .env
npm start
```

Para rodar apenas a API Node, sem subir a stack auxiliar:

```bash
npm run start:minimal
```

Para rodar a API diretamente:

```bash
npm run start:api
```

Em desenvolvimento local sem autenticar as rotas privilegiadas:

```bash
AUTH_DISABLE=1 npm run start:minimal
```

No Windows/PowerShell:

```powershell
$env:AUTH_DISABLE="1"
npm run start:minimal
```

## URLs Locais

Por padrao:

| Servico | URL | Funcao |
| --- | --- | --- |
| GHOSTRECON Cockpit | `http://127.0.0.1:3847/` | UI principal de recon |
| API Node | `http://127.0.0.1:3847/api/*` | Rotas do backend |
| Reporte | `http://127.0.0.1:3847/reporte.html` | Validacao manual e handoff |
| Cortex | `http://127.0.0.1:3847/cortex.html` | Base de conhecimento |
| GhostMap | `http://127.0.0.1:3847/ghostmap/ghostrecon` | Mapa visual MITRE/OWASP |
| History | `http://127.0.0.1:3847/vigolium-workbench.html` | Workbench, HTTP records e agente |
| Post-Exploitation | `http://127.0.0.1:3847/post-exploitation.html` | Planejamento pos-exploracao |
| Tor Validator | `http://127.0.0.1:3847/tor-validator.html` | Validacao de rota Tor |
| Ghost local | `http://127.0.0.1:8000/gui/` | IA local, memoria e chat |
| GhostTrace | `http://127.0.0.1:3847/anotacao/` | Anotacoes e relatorio |
| HexStrike | `http://127.0.0.1:8888` | Servidor HexStrike, se iniciado |

## Como Usar Na UI

Fluxo normal:

1. Abra `http://127.0.0.1:3847/`.
2. Preencha o alvo em `Target`.
3. Escolha perfil `quick`, `standard` ou `deep`.
4. Marque os modulos desejados.
5. Clique em `RUN RECON`.
6. Acompanhe o terminal e os cards em tempo real.
7. Abra `Ghostmap`, `Reporte`, `Cortex` ou `Vigolium` quando quiser investigar melhor.

Fluxo com validacao manual:

```text
RUN RECON
  -> findings na UI
  -> Reporte
  -> validacao manual
  -> Anotacao / GhostTrace
  -> relatorio e evidencias
```

Fluxo com Modo Auto:

```text
AUTO MODE
  -> escolher IA(s)
  -> escolher modelo OpenRouter, se aplicavel
  -> incluir HexStrike/deep passive
  -> backend monta plano
  -> pipeline executa
  -> avaliacao final aparece no terminal
```

## Modo Auto

O Modo Auto fica na UI principal ao lado do `RUN RECON`, no botao `AUTO MODE`.

Ele chama:

```text
POST /api/recon/auto/stream
```

O objetivo e permitir que uma ou mais IAs atuem como comandantes do recon. A primeira fase ja implementada faz um planner conservador local, detecta provedores disponiveis, monta catalogo de ferramentas, escolhe modulos e chama o pipeline normal do GHOSTRECON.

Comandantes suportados no contrato atual:

- `codex`
- `claude_code`
- `cursor`
- `openrouter`
- `skynet`
- `local_model`

OpenRouter permite escolher o modelo pelo popup. A lista atual vem de `server/auto-agent/provider-detector.mjs`:

- `anthropic/claude-3.7-sonnet`
- `openai/gpt-4.1`
- `google/gemini-2.5-pro`
- `x-ai/grok-4`
- `deepseek/deepseek-r1`
- `z-ai/glm-4.5`
- `qwen/qwen3-coder`
- `meta-llama/llama-4-maverick`

Arquivos principais:

- `server/auto-agent/provider-detector.mjs`
- `server/auto-agent/tool-catalog.mjs`
- `server/auto-agent/planner.mjs`
- `server/auto-agent/orchestrator.mjs`
- `server/routes/auto-recon.mjs`
- `public/index.html`
- `MODO-AUTO-GHOSTRECON.md`

O documento detalhado da visao, papeis por combinacao de IA e fases futuras fica em:

```text
MODO-AUTO-GHOSTRECON.md
```

## HexStrike

A pasta `IAs/hexstrike-ai` contem o HexStrike AI MCP. O GHOSTRECON integra HexStrike de forma conservadora nesta fase:

- Detecta se a pasta existe.
- Detecta `hexstrike_server.py`, `hexstrike_mcp.py` e `requirements.txt`.
- Tenta telemetria no servidor HTTP.
- Exibe status em `/api/capabilities`.
- Permite o modulo `hexstrike_orchestrator`.
- Usa endpoints de inteligencia permitidos para importar findings informacionais.
- Nao executa comandos arbitrarios pelo GHOSTRECON.

Arquivos principais:

- `server/integrations/hexstrike-client.mjs`
- `server/modules/hexstrike-capabilities.mjs`
- `server/modules/hexstrike-orchestrator.mjs`
- `server/tests/hexstrike-capabilities.test.js`
- `server/tests/hexstrike-orchestrator.test.js`

Variaveis uteis:

```bash
GHOSTRECON_HEXSTRIKE_URL=http://127.0.0.1:8888
GHOSTRECON_HEXSTRIKE_HOME=IAs/hexstrike-ai
GHOSTRECON_HEXSTRIKE_TIMEOUT_MS=60000
GHOSTRECON_HEXSTRIKE_HEALTH_DEEP=0
```

Instalacao manual do HexStrike:

```bash
cd IAs/hexstrike-ai
python3 -m venv hexstrike-env
source hexstrike-env/bin/activate
pip install -r requirements.txt
python3 hexstrike_server.py --port 8888
```

No Windows, ative o venv conforme seu shell:

```powershell
cd IAs\hexstrike-ai
py -3 -m venv hexstrike-env
.\hexstrike-env\Scripts\Activate.ps1
pip install -r requirements.txt
python hexstrike_server.py --port 8888
```

## Arquitetura

```text
Usuario
  -> public/index.html
     -> API Node/Express :3847
        -> rotas /api/*
        -> runPipeline()
        -> modulos GHOSTRECON
        -> registry modular
        -> SQLite/Postgres/Supabase
        -> IA cloud/local opcional
        -> HexStrike/Vigolium/Kali opcionais
        -> NDJSON para UI

Servicos auxiliares:
  ghost-local-v5 :8000
  GhostTrace     :3010 via /anotacao
  GhostMap       :3020 via proxy
  GhostDesk      :5173 via proxy
  HexStrike      :8888 quando iniciado
```

Principais camadas:

- `server/index.js`: entrada da API.
- `server/app/register-routes.mjs`: registra rotas.
- `server/routes/`: endpoints HTTP.
- `server/pipeline/run-pipeline.mjs`: entrada do pipeline.
- `server/pipeline/phases/`: fases do recon.
- `server/modules/`: modulos, integrações, storage e validadores.
- `server/modules/module-registry.mjs`: registry de modulos refatorados.
- `server/auto-agent/`: Modo Auto.
- `server/integrations/`: clientes externos, como HexStrike.
- `public/`: paineis HTML.

## Estrutura Do Repositorio

```text
GHOSTRECON/
  server/                  API, rotas, modulos, pipeline e testes
  public/                  UI principal e paineis HTML
  bin/                     CLI ghostrecon
  scripts/                 start stack, instaladores e utilitarios
  bridge/                  bridge Vigolium e capacidades externas
  engines/                 motores locais opcionais
  ghost-local-v5/          IA local FastAPI, memoria e chat
  GhostTrace/              anotacoes e relatorio
  ghostmap/                mapa visual e frontend dedicado
  GhostDesk/               desktop/workbench auxiliar
  apps/                    apps experimentais/auxiliares
  IAs/                     agentes locais, HexStrike, Shannon/PentestGPT quando instalados
  playbooks/               playbooks de recon e checklist
  tools/                   ferramentas auxiliares
  docs/                    documentacao tecnica
  data/                    dados locais
  logs/                    logs locais
  .env.example             configuracao documentada
```

## Pipeline Principal

O pipeline normal e exposto por:

```text
POST /api/recon/stream
```

Ele retorna NDJSON, permitindo que a UI mostre progresso e findings em tempo real.

Fases principais:

1. Normalizacao do alvo e escopo.
2. Auth, CSRF, rate limit e OPSEC gate.
3. Discovery e fingerprint.
4. Coleta passiva: DNS, RDAP, crt.sh, Wayback, CommonCrawl, headers, TLS, robots, sitemap.
5. Superficie web: URLs, parametros, JS, endpoints, OpenAPI, GraphQL.
6. Validacoes e auditorias: headers, CORS, cookies, CSRF, JWT/JWKS, WebSocket, HTTP/3, service worker, DOM, secrets.
7. Modulos opcionais: Kali, Vigolium, sqlmap, Nuclei, ffuf, WPScan, Navegation/Tor.
8. Correlacao, dedupe, scoring, OWASP, MITRE e priorizacao.
9. Persistencia local/remota.
10. IA opcional e relatorios.
11. Webhooks, history, Reporte, GhostMap e Cortex.

## Modulos E Capacidades

`GET /api/capabilities` devolve o estado de:

- Kali/tools externos.
- IA configurada.
- GitHub token.
- Registry de modulos.
- Tool packs externos.
- Shannon.
- PentestGPT.
- HexStrike.
- Vigolium.

Alguns modulos importantes:

- `cookie_session_audit`
- `csrf_flow_audit`
- `jwt_jwks_audit`
- `http3_quic_surface`
- `nginx_http3_cve_2026_42530`
- `panel_exposure_audit`
- `service_worker_audit`
- `api_contract_diff`
- `websocket_recon`
- `hpp_param_pollution`
- `hexstrike_orchestrator`
- `dom_clobbering_audit`
- `email_security_deep`
- `secrets_context_ranker`
- `risk_explainer`
- `vigolium_dast`
- `vigolium_audit`
- `vigolium_swarm`

O registry atual fica em:

```text
server/modules/module-registry.mjs
server/modules/module-registry-runners.mjs
server/modules/module-ids.mjs
```

## APIs Principais

| Rota | Funcao |
| --- | --- |
| `GET /api/csrf-token` | Emite token CSRF |
| `GET /api/setup/auto-auth` | Ajuda setup local de API key |
| `POST /api/recon/stream` | Recon normal em NDJSON |
| `POST /api/recon/auto/stream` | Modo Auto em NDJSON |
| `GET /api/capabilities` | Capacidades locais |
| `GET /api/runs` | Historico de runs |
| `GET /api/runs/:id` | Detalhes de uma run |
| `GET /api/brain/*` | Cortex / memoria |
| `POST /api/manual-validations` | Validacoes manuais |
| `POST /api/anotacao-handoff` | Handoff para GhostTrace |
| `GET /api/tunnel/status` | Status proxy/Tor |
| `POST /api/ai-reports` | Relatorios IA |
| `GET /api/vigolium/*` | Rotas Vigolium |
| `POST /api/ghostcommand/*` | GhostCommand |

## CLI

O binario fica em:

```text
bin/ghostrecon.mjs
```

Uso via npm:

```bash
npm run cli -- --help
```

Ou diretamente:

```bash
node bin/ghostrecon.mjs --help
```

A CLI usa os helpers em:

```text
server/modules/cli/
```

## Variaveis De Ambiente

Copie `.env.example` para `.env` e ajuste o que precisar.

Essenciais:

```bash
PORT=3847
HOST=127.0.0.1
AUTH_DISABLE=1
```

Auth local:

```bash
AUTH_API_KEYS=nome:chave:admin
GHOSTRECON_TRUST_PROXY=0
```

IA:

```bash
GEMINI_API_KEY=
OPENROUTER_API_KEY=
ANTHROPIC_API_KEY=
GHOSTRECON_OPENROUTER_MODEL=
GHOSTRECON_LMSTUDIO_BASE_URL=http://127.0.0.1:8000/v1
GHOSTRECON_LMSTUDIO_MODEL=ghost
```

Modo Auto:

```bash
GHOSTRECON_SKYNET_URL=http://127.0.0.1:8000
GHOSTRECON_OPENROUTER_AUTO_MODEL=anthropic/claude-3.7-sonnet
GHOSTRECON_AUTO_ALLOW_UNCONFIGURED=0
```

HexStrike:

```bash
GHOSTRECON_HEXSTRIKE_URL=http://127.0.0.1:8888
GHOSTRECON_HEXSTRIKE_HOME=IAs/hexstrike-ai
GHOSTRECON_HEXSTRIKE_TIMEOUT_MS=60000
```

Stack:

```bash
GHOSTRECON_STACK_VIGOLIUM=1
GHOSTRECON_STACK_GHOST=1
GHOSTRECON_STACK_GHOSTTRACE=1
GHOSTRECON_STACK_GHOSTMAP=1
GHOSTRECON_STACK_GHOSTDESK=1
```

Para desligar servicos pesados:

```bash
GHOSTRECON_STACK_VIGOLIUM=0
GHOSTRECON_STACK_GHOST=0
GHOSTRECON_STACK_GHOSTTRACE=0
GHOSTRECON_STACK_GHOSTMAP=0
GHOSTRECON_STACK_GHOSTDESK=0
npm start
```

## Scripts NPM

| Script | Funcao |
| --- | --- |
| `npm start` | Sobe stack local completa |
| `npm run start:minimal` | Sobe apenas API Node |
| `npm run start:api` | Sobe `server/index.js` |
| `npm run dev` | API em watch mode |
| `npm test` | Roda todos os testes Node |
| `npm run test:cli` | Testes da CLI |
| `npm run cli -- --help` | CLI |
| `npm run start:ghost` | Ghost local |
| `npm run start:anotacao` | GhostTrace |
| `npm run start:ghostmap` | GhostMap |
| `npm run start:ghostdesk` | GhostDesk |
| `npm run test:ai` | Smoke de APIs IA |
| `npm run mitre:extract` | Gera bundle MITRE |
| `npm run pentestgpt-bridge` | Bridge PentestGPT via OpenRouter |
| `npm run engine:install` | Instala motor Vigolium |
| `npm run engine:build` | Build do motor Vigolium |

## Docker E Instalador

Existe um `Dockerfile` na raiz para imagem minima da API:

```bash
docker build -t ghostrecon .
docker run --rm -p 3847:3847 -e AUTH_DISABLE=1 ghostrecon
```

O script `install.sh` tambem existe para setups por perfil. Use com cuidado, porque ele pode instalar dependencias de sistema e ferramentas externas conforme o perfil escolhido.

```bash
bash install.sh --help
```

## Testes

Todos os testes:

```bash
npm test
```

Testes focados no Modo Auto e HexStrike:

```bash
node --test server/tests/auto-agent.test.js server/tests/hexstrike-capabilities.test.js server/tests/hexstrike-orchestrator.test.js
```

Smoke de import do servidor sem abrir porta:

```bash
GHOSTRECON_NO_HTTP_LISTEN=1 node -e "import('./server/index.js').then(()=>console.log('node app ok'))"
```

No PowerShell:

```powershell
$env:GHOSTRECON_NO_HTTP_LISTEN="1"
node -e "import('./server/index.js').then(()=>console.log('node app ok'))"
```

Observacao: `package.json` exige Node `>=20 <27`. Com Node 18 alguns testes ainda podem rodar, mas dependencias como Supabase avisam que Node 18 esta deprecado.

## Troubleshooting

### A UI abriu, mas as rotas retornam 401

Configure `AUTH_API_KEYS` ou use `AUTH_DISABLE=1` apenas localmente.

### O botao AUTO MODE nao aparece

Recarregue a UI principal com cache limpo:

```text
Ctrl+F5
```

O botao fica na pagina principal `public/index.html`, ao lado de `RUN RECON`.

### HexStrike aparece offline

Confirme se o servidor HexStrike esta no ar:

```bash
curl http://127.0.0.1:8888/api/telemetry
```

Ou inicie manualmente:

```bash
cd IAs/hexstrike-ai
python3 hexstrike_server.py --port 8888
```

### npm start tenta subir muita coisa

Use:

```bash
npm run start:minimal
```

Ou desligue partes:

```bash
GHOSTRECON_STACK_GHOST=0 GHOSTRECON_STACK_GHOSTTRACE=0 npm start
```

### Ferramentas Kali nao aparecem

Rode `GET /api/capabilities` e confira se as ferramentas existem no `PATH`. Em ambientes Windows, muitas delas dependem de WSL/Kali.

### CSRF invalido

A UI deve buscar `GET /api/csrf-token` antes de `POST /api/recon/stream` ou `/api/recon/auto/stream`. Se estiver testando manualmente, envie `X-CSRF-Token`.

### Tor strict bloqueou a run

Veja `docs/TOR.md`. O modo strict exige pre-requisitos como SOCKS, ControlPort, DNSPort, `proxychains4` e validacao anti-leak.

## Documentos Relacionados

- `MODO-AUTO-GHOSTRECON.md`: arquitetura detalhada do Modo Auto.
- `FUSAO-VIGOLIUM.md`: fusao e papel do Vigolium.
- `ANALISE-PROJETO.md`: analise geral antiga do projeto.
- `REFATORACAO.md`: notas de refatoracao.
- `docs/AUTH-RBAC.md`: auth, roles e scopes.
- `docs/TOR.md`: Tor, strict mode e anti-leak.
- `docs/MODULE-CONTRACT.md`: contrato de modulos.
- `GhostTrace/README.md`: area de anotacoes.
- `ghostmap/README.md`: GhostMap.
- `IAs/README.md`: agentes locais.
- `IAs/hexstrike-ai/README.md`: README upstream do HexStrike.
- `playbooks/README.md`: playbooks.

## Licenca E Notas

Veja `NOTICE` e os READMEs das ferramentas integradas. Algumas pastas podem conter projetos externos ou engines opcionais com licencas proprias.
