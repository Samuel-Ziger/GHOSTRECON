<div align="center">

# GHOSTRECON

### Local-first security reconnaissance, validation and intelligence platform

**Transforme superfície de ataque em evidência priorizada — do primeiro domínio ao relatório final.**

[![Node.js](https://img.shields.io/badge/Node.js-20--26-5FA04E?style=for-the-badge&logo=nodedotjs&logoColor=white)](https://nodejs.org/)
[![CLI](https://img.shields.io/badge/CLI-v1.1.0-111827?style=for-the-badge&logo=gnometerminal&logoColor=white)](#linha-de-comando)
[![Tests](https://img.shields.io/badge/Test_Suites-98-22C55E?style=for-the-badge&logo=checkmarx&logoColor=white)](#qualidade-e-testes)
[![Local First](https://img.shields.io/badge/Local--First-Privacy-7C3AED?style=for-the-badge&logo=shield&logoColor=white)](#segurança-por-design)

[Início rápido](#início-rápido) · [Arquitetura](#arquitetura) · [CLI](#linha-de-comando) · [Modo Auto](#modo-auto) · [Configuração](#configuração) · [Documentação](#documentação-técnica)

</div>

---

> [!WARNING]
> Use o GHOSTRECON somente em ativos próprios ou em alvos para os quais você possui autorização explícita. Alguns módulos executam validações ativas e ferramentas ofensivas. Escopo, regras de engajamento e responsabilidade operacional continuam sendo do operador.

## O que é o GHOSTRECON?

O GHOSTRECON é uma plataforma local de **recon, OSINT, validação técnica e gestão de findings** para bug bounty e pentest autorizado. Em vez de juntar scripts desconectados, ele organiza todo o ciclo operacional em uma única experiência:

```text
ALVO → DESCOBERTA → SUPERFÍCIE → VALIDAÇÃO → CORRELAÇÃO → EVIDÊNCIA → RELATÓRIO
```

O núcleo combina uma API Node/Express, streaming NDJSON, cockpit web, CLI, MCP, pipeline modular e persistência local. Ao redor dele, motores e aplicações especializadas ampliam a investigação: **Vigolium**, **FrameSeven**, **GhostTrace**, **GhostMap**, **GhostDesk**, **GHOST local** e **HexStrike**.

### Por que ele é diferente?

- **Local-first:** a operação começa em `127.0.0.1`; cloud e APIs externas são opcionais.
- **Um pipeline, várias interfaces:** cockpit, CLI, MCP e Modo Auto usam o mesmo backend.
- **Passivo por padrão, ativo sob controle:** perfis OPSEC e confirmação explícita protegem módulos intrusivos.
- **Evidência em tempo real:** progresso, findings e eventos trafegam em NDJSON.
- **Recon que acumula memória:** runs, diferenças, decisões e contexto podem ser persistidos e reutilizados.
- **Motores complementares:** Node para orquestração e OSINT; Go/Vigolium para DAST; FrameSeven para análise e relatório integrado.
- **IA sem dependência obrigatória de cloud:** suporte a provedores locais, CLIs instalados e OpenRouter.

## Visão geral

| Camada | O que entrega |
| --- | --- |
| **Cockpit** | Execução, terminal ao vivo, findings, controles OPSEC e acesso aos painéis |
| **Recon Engine** | Descoberta, fingerprint, superfície web, validação, correlação e scoring |
| **Vigolium** | Motor DAST em Go, estratégias `lite`, `balanced` e `deep` |
| **FrameSeven** | Fluxo complementar autenticado, deduplicação e relatório HTML integrado |
| **Modo Auto** | Planejamento e avaliação por agentes de IA com limites, auditoria e memória RAG |
| **CLI + MCP** | Automação por terminal, CI, Cursor e clientes compatíveis com MCP |
| **GhostTrace** | Anotações, evidências, handoff e preparação de relatório |
| **GhostMap** | Visualização de relações, HTTP history e contexto MITRE/OWASP |
| **GhostDesk** | Workbench operacional e consulta de dados locais/remotos |
| **Storage** | SQLite local por padrão; Postgres e Supabase opcionais |

## Início rápido

### Requisitos

- Node.js `>=20 <27`
- npm
- Bash em Linux/macOS ou WSL no Windows
- Python 3 e Go apenas para componentes opcionais

### Opção 1 — somente o núcleo

É o caminho mais rápido para experimentar o cockpit e a API:

```bash
git clone https://github.com/Samuel-Ziger/GHOSTRECON.git
cd GHOSTRECON
npm install
cp .env.example .env
AUTH_DISABLE=1 npm run start:minimal
```

Abra **http://127.0.0.1:3847**.

> [!IMPORTANT]
> `AUTH_DISABLE=1` é aceito somente em loopback e deve ser usado apenas no desenvolvimento local. Para operação persistente, configure API keys ou JWT.

### Opção 2 — stack completa

O instalador trabalha com perfis progressivos:

```bash
bash install.sh --profile minimal
bash install.sh --profile passive
bash install.sh --profile full
```

Depois:

```bash
cp .env.example .env
npm start
```

O `npm start` verifica ou inicia Vigolium, GHOST local, GhostTrace, GhostMap, GhostDesk, HexStrike e a API. Cada serviço pode ser desligado individualmente no `.env`.

### Primeiro recon

Pelo cockpit:

1. Informe um domínio autorizado em **Target**.
2. Escolha o perfil e os módulos.
3. Revise os controles de escopo e OPSEC.
4. Execute **RUN RECON**.
5. Acompanhe eventos e findings em tempo real.
6. Continue a investigação no Reporte, GhostTrace, GhostMap ou History.

Pela CLI:

```bash
npm run cli -- run \
  --target example.com \
  --playbook quick-triage \
  --format summary
```

## Como o fluxo funciona

```mermaid
flowchart LR
    A[Target + Scope] --> B{Interface}
    B -->|Cockpit| C[API Express]
    B -->|CLI| C
    B -->|MCP| C
    B -->|Modo Auto| C
    C --> D[OPSEC + Auth + CSRF]
    D --> E[Pipeline NDJSON]
    E --> F[Discovery]
    F --> G[Surface Mapping]
    G --> H[Validation]
    H --> I[Correlation + Scoring]
    I --> J[(SQLite / Postgres)]
    I --> K[GhostTrace / GhostMap]
    I --> L[Reports / Webhooks]
    E -. opcional .-> M[Vigolium + FrameSeven + Kali]
    E -. opcional .-> N[AI Council + RAG]
```

O endpoint principal é `POST /api/recon/stream`. Ele produz NDJSON para que qualquer cliente acompanhe o pipeline sem esperar o término completo da execução.

### Fases do pipeline

1. Normalização do alvo, escopo e contexto do engagement.
2. Autenticação, CSRF, rate limit e gate OPSEC.
3. Descoberta de ativos, DNS, RDAP, CT logs e fingerprint.
4. Coleta de superfície: HTTP, TLS, headers, HTML, JavaScript, APIs e arquivos conhecidos.
5. Validações especializadas e ferramentas externas autorizadas.
6. Normalização, deduplicação semântica, correlação, OWASP/MITRE e scoring.
7. Persistência, diff entre runs, relatórios, webhooks e handoffs.

## Capacidades

O backend reúne mais de 160 módulos e integrações. A disponibilidade efetiva depende do perfil, das ferramentas instaladas e das credenciais configuradas.

<details>
<summary><strong>Descoberta e OSINT</strong></summary>

- crt.sh, VirusTotal, RDAP, DNS enrichment e CT monitoring
- Subfinder, Amass, Wayback, CommonCrawl e GitHub search/clone
- enumeração de subdomínios, origem, tecnologias, TLS e takeover
- Shodan, dorks, Pastebin e descoberta de ativos

</details>

<details>
<summary><strong>Web, API e client-side</strong></summary>

- OpenAPI/Swagger, GraphQL, WebSocket e parâmetros
- análise de HTML, JavaScript, source maps e service workers
- CORS, headers, cookies, CSRF, JWT/JWKS e fluxos de autenticação
- DOM XSS, prototype pollution, postMessage, JSONP e open redirect
- Firebase, Supabase/RLS, low-code, Lovable e exposição de painéis

</details>

<details>
<summary><strong>Validação e ferramentas externas</strong></summary>

- Nuclei, ffuf, nmap, sqlmap, WPScan, dalfox e dirsearch
- Vigolium DAST, FrameSeven e HexStrike
- IDOR/BOLA, race harness, OOB collaborator e micro-exploit
- proxychains, rotação de identidade, Navegation e Tor strict
- captura HTTP, replay e evidência técnica

</details>

<details>
<summary><strong>Inteligência e operação</strong></summary>

- correlação, chaining, risk explanation e bounty estimation
- histórico, baseline/diff, projetos, engagement e team locks
- narrativas MITRE, purple-team export e workflow export
- relatórios Gemini, OpenRouter, Anthropic ou modelo local
- memória Auto RAG, Cortex e integração com Obsidian

</details>

Consulte o estado real da máquina a qualquer momento:

```bash
curl http://127.0.0.1:3847/api/capabilities
```

## Playbooks

O repositório inclui 11 playbooks prontos para transformar intenção em uma seleção reproduzível de módulos.

| Playbook | Foco |
| --- | --- |
| `quick-triage` | Primeiro passe rápido e discreto |
| `api-first` | OpenAPI, GraphQL, endpoints e parâmetros |
| `client-surface-hunt` | SPA/PWA, XSS, auth client-side e source maps |
| `subdomain-hunt` | Enumeração e enriquecimento de subdomínios |
| `cloud-takeover` | CNAMEs órfãos e takeover em cloud |
| `secrets-leak` | GitHub, bundles, arquivos históricos e segredos |
| `wordpress` | Superfície WordPress e WPScan |
| `firebase-client-auth-hunt` | Firebase, regras, storage e auth no frontend |
| `lovable-hunt` | Lovable, Supabase, RLS e aplicações vibe-coded |
| `lowcode-hunt` | Bubble, Webflow, OutSystems, Mendix e Appsmith |
| `full-recon` | Cobertura máxima passiva + ativa; exige autorização explícita |

```bash
npm run cli -- playbooks
npm run cli -- run --target api.example.com --playbook api-first
```

## Linha de comando

A CLI atual é a `v1.1.0-cli` e pode ser chamada por `npm run cli --` ou pelo binário `ghostrecon` após link/instalação do pacote.

```bash
npm run cli -- --help
```

### Operação básica

```bash
# Recon passivo rápido
npm run cli -- run -t example.com --playbook quick-triage --format summary

# Combinar playbook e módulos
npm run cli -- scan -t api.example.com \
  --playbook api-first \
  --modules graphql_recon,cors_audit \
  --output api-run.json

# Node + Vigolium
npm run cli -- scan -t example.com \
  --engine both \
  --strategy balanced \
  --modules rdap,vigolium_dast

# Módulos ativos exigem ACK explícito
npm run cli -- run -t example.com \
  --opsec-profile aggressive \
  --confirm-active \
  --modules kali_nuclei,kali_ffuf
```

### Workflow operacional

```bash
npm run cli -- runs --target example.com --limit 5
npm run cli -- diff --baseline 12 --newer 18 --format summary
npm run cli -- schedule --target example.com --interval 6h --playbook api-first
npm run cli -- export --run 42 --to github --repo org/repo --severity high
```

A CLI também oferece `projects`, `engagement`, `narrative`, `purple`, `team`, `replay`, `obsidian` e `phish-infra`.

## Modo Auto

O Modo Auto transforma provedores de IA em comandantes do recon. Ele pode planejar uma run, selecionar módulos, acompanhar resultados, produzir avaliação pós-pipeline e gravar decisões para execuções futuras.

```text
CONTEXTO + CAPABILITIES + MEMÓRIA
              ↓
         CONSELHO DE IAs
              ↓
       PLANO JSON VALIDADO
              ↓
       PIPELINE GHOSTRECON
              ↓
    AVALIAÇÃO + RAG + HANDOFF
```

Provedores contemplados pelo contrato atual incluem Codex, Claude Code, Cursor, OpenRouter, GHOST/modelo local e endpoints OpenAI-compatible. A disponibilidade depende da instalação e configuração local.

> [!NOTE]
> O Modo Auto está em evolução controlada. Limites de iteração, tempo, chamadas, custo, redaction e confirmação humana fazem parte do desenho; revise o plano antes de autorizar módulos ativos.

Arquivos de decisão e memória ficam em `data/auto-rag/`, organizados como Markdown pesquisável. O fluxo principal usa `POST /api/recon/auto/stream`.

Leia [MODO-AUTO-GHOSTRECON.md](MODO-AUTO-GHOSTRECON.md) para arquitetura, papéis do conselho, Module Forge e roadmap.

## MCP

O servidor MCP em `mcp/ghostrecon-mcp.mjs` conecta clientes compatíveis ao mesmo backend usado pelo cockpit e pela CLI. A configuração local do Cursor está em `.cursor/mcp.json`.

Principais grupos de tools:

- health, capabilities, módulos e playbooks;
- planejamento e execução de recon normal ou Auto;
- runs, diff e inteligência por alvo;
- status e inteligência HexStrike;
- leitura, busca e escrita controlada no Auto RAG.

O MCP reutiliza autenticação, CSRF, streaming NDJSON e o gate OPSEC do backend. Módulos intrusivos continuam exigindo `confirmActive=true`.

## Ecossistema local

| Serviço | Endereço padrão | Papel |
| --- | --- | --- |
| GHOSTRECON | `http://127.0.0.1:3847/` | Cockpit e API principal |
| Reporte | `http://127.0.0.1:3847/reporte.html` | Validação manual e handoff |
| Cortex | `http://127.0.0.1:3847/cortex.html` | Conhecimento e contexto |
| History | `http://127.0.0.1:3847/vigolium-workbench.html` | HTTP history e workbench |
| GhostMap | `http://127.0.0.1:3847/ghostmap/ghostrecon` | Grafo e visualizações |
| GhostTrace | `http://127.0.0.1:3847/anotacao/` | Anotações e evidências |
| Tor Validator | `http://127.0.0.1:3847/tor-validator.html` | Verificação de rota Tor |
| GHOST local | `http://127.0.0.1:8000/gui/` | IA local, memória e chat |
| GhostDesk | `http://127.0.0.1:5173/` | Workbench auxiliar |
| HexStrike | `http://127.0.0.1:8888` | Servidor HexStrike opcional |

## Arquitetura

```text
GHOSTRECON/
├── server/
│   ├── app/                 registro e composição da aplicação
│   ├── routes/              endpoints HTTP
│   ├── pipeline/            dispatcher, estado e fases do recon
│   ├── modules/             módulos, storage, auth e integrações
│   ├── auto-agent/          conselho, providers, RAG e Module Forge
│   ├── integrations/        FrameSeven e HexStrike
│   └── tests/               testes Node
├── public/                  cockpit e painéis HTML
├── bin/                     CLI v1
├── mcp/                     servidor MCP
├── bridge/                  bridge e catálogo Vigolium
├── engines/                 binários locais opcionais
├── playbooks/               estratégias reproduzíveis
├── GhostTrace/              anotações e relatórios
├── ghostmap/                visualização e captura
├── GhostDesk/               workbench auxiliar
├── ghost-local-v5/          IA local
├── FrameSeven/              engine complementar
├── IAs/                     agentes e integrações de IA
├── apps/GhostCommand/       app Android operacional
├── tools/                   ferramentas auxiliares
├── data/                    SQLite, runs e memória local
└── docs/                    contratos e segurança
```

### Motores

O pipeline suporta três abordagens complementares:

| Modo | Uso ideal |
| --- | --- |
| `node` | OSINT, recon, correlação e módulos nativos GHOSTRECON |
| `go` | DAST pelo motor Vigolium |
| `both` | Cobertura combinada com findings normalizados e deduplicados |

```bash
npm run engine:install
npm run engine:build
npm run cli -- scan -t example.com --engine both --strategy lite
```

## Segurança por design

O GHOSTRECON trata segurança operacional como parte do pipeline, não como detalhe de implantação:

- bind padrão em `127.0.0.1`;
- autenticação por API key ou JWT;
- bypass de desenvolvimento limitado ao loopback;
- proteção CSRF em operações mutáveis;
- rate limit para recon;
- RBAC e scopes;
- gate OPSEC por perfil e módulo;
- confirmação explícita para ações intrusivas;
- Tor strict com validação anti-leak e fail-closed;
- redaction de segredos em history e contexto cloud;
- limites de tempo, memória, saída e custo para ferramentas/agentes.

> [!CAUTION]
> Não exponha `HOST=0.0.0.0` sem autenticação forte, TLS/reverse proxy confiável e revisão de `GHOSTRECON_TRUST_PROXY`. Nunca use `AUTH_DISABLE=1` em uma interface pública.

Veja [docs/AUTH-RBAC.md](docs/AUTH-RBAC.md) e [docs/TOR.md](docs/TOR.md).

## Configuração

Toda a configuração disponível e seus valores recomendados estão comentados em [.env.example](.env.example).

### Núcleo

```dotenv
PORT=3847
HOST=127.0.0.1
AUTH_MODE=apikey
AUTH_API_KEYS=minha-chave:admin:operador-local
```

### Persistência

SQLite local é o padrão. Para Postgres direto ou Supabase:

```dotenv
DATABASE_URL=postgresql://usuario:senha@127.0.0.1:5432/ghostworkflow
GHOSTRECON_REMOTE_FALLBACK_SQLITE=1
```

### IA opcional

```dotenv
GEMINI_API_KEY=
OPENROUTER_API_KEY=
ANTHROPIC_API_KEY=
GHOSTRECON_LMSTUDIO_BASE_URL=http://127.0.0.1:8000/v1
GHOSTRECON_LMSTUDIO_MODEL=ghost
```

### Controle da stack

```dotenv
GHOSTRECON_STACK_VIGOLIUM=1
GHOSTRECON_STACK_GHOST=1
GHOSTRECON_STACK_GHOSTTRACE=1
GHOSTRECON_STACK_GHOSTMAP=1
GHOSTRECON_STACK_GHOSTDESK=1
GHOSTRECON_STACK_HEXSTRIKE=1
```

Defina qualquer item como `0` para não iniciá-lo com `npm start`.

## Scripts úteis

| Comando | Ação |
| --- | --- |
| `npm start` | Inicia a stack local |
| `npm run start:minimal` | Inicia somente a API Node |
| `npm run start:api` | Executa diretamente `server/index.js` |
| `npm run dev` | API com watch mode |
| `npm run cli -- --help` | Abre a CLI |
| `npm test` | Executa a suíte Node |
| `npm run test:cli` | Executa testes da CLI |
| `npm run start:ghost` | Inicia a IA local |
| `npm run start:anotacao` | Inicia o GhostTrace |
| `npm run start:ghostmap` | Inicia o GhostMap |
| `npm run start:ghostdesk` | Inicia o GhostDesk |
| `npm run engine:install` | Instala o motor Vigolium |
| `npm run engine:build` | Compila o motor Vigolium local |

## Docker

A imagem da raiz contém o núcleo Node, a UI e os recursos necessários para operação mínima:

```bash
docker build -t ghostrecon .
docker run --rm \
  -p 3847:3847 \
  -e HOST=0.0.0.0 \
  -e AUTH_API_KEYS=troque-esta-chave:admin:docker \
  ghostrecon
```

Serviços auxiliares possuem requisitos próprios e não fazem parte dessa imagem mínima.

## API essencial

| Método | Rota | Função |
| --- | --- | --- |
| `GET` | `/api/health` | Saúde da API |
| `GET` | `/api/csrf-token` | Emissão de token CSRF |
| `GET` | `/api/capabilities` | Capacidades detectadas |
| `POST` | `/api/recon/stream` | Recon normal em NDJSON |
| `POST` | `/api/recon/auto/stream` | Recon comandado por IA |
| `GET` | `/api/runs` | Histórico de runs |
| `GET` | `/api/runs/:id` | Resultado de uma run |
| `POST` | `/api/ai-reports` | Relatório por IA |
| `POST` | `/api/manual-validations` | Registro de validação manual |
| `POST` | `/api/anotacao-handoff` | Handoff para GhostTrace |
| `GET` | `/api/tunnel/status` | Estado de proxy/Tor |

Rotas privilegiadas exigem autenticação; rotas mutáveis também podem exigir `X-CSRF-Token`.

## Qualidade e testes

O projeto possui 98 arquivos de teste Node cobrindo pipeline, autenticação, OPSEC, módulos, storage, CLI, Modo Auto, Vigolium, FrameSeven, HexStrike e integrações.

```bash
# Suíte completa
npm test

# CLI
npm run test:cli

# Smoke de import sem abrir porta
GHOSTRECON_NO_HTTP_LISTEN=1 node -e "import('./server/index.js).then(() => console.log('node app ok'))"
```

## Troubleshooting

<details>
<summary><strong>A UI abre, mas a API retorna 401</strong></summary>

Configure `AUTH_API_KEYS` no `.env`. Para desenvolvimento estritamente local, use `AUTH_DISABLE=1`.

</details>

<details>
<summary><strong>O npm start tenta iniciar serviços demais</strong></summary>

Use `npm run start:minimal` ou desligue serviços com `GHOSTRECON_STACK_<SERVIÇO>=0`.

</details>

<details>
<summary><strong>Ferramentas externas não aparecem</strong></summary>

Consulte `/api/capabilities` e confirme se os binários estão no `PATH`. Algumas ferramentas dependem de Linux, Kali ou WSL.

</details>

<details>
<summary><strong>Tor strict bloqueia a execução</strong></summary>

Esse modo falha fechado quando SOCKS, DNSPort, ControlPort, proxychains ou a validação anti-leak não estão corretos. Consulte [docs/TOR.md](docs/TOR.md).

</details>

<details>
<summary><strong>HexStrike aparece offline</strong></summary>

Verifique `GHOSTRECON_HEXSTRIKE_URL`, o ambiente Python e o health endpoint do serviço na porta `8888`.

</details>

## Documentação técnica

- [Modo Auto e conselho de IAs](MODO-AUTO-GHOSTRECON.md)
- [Autenticação, RBAC e scopes](docs/AUTH-RBAC.md)
- [Tor strict e proteção anti-leak](docs/TOR.md)
- [Contrato de módulos](docs/MODULE-CONTRACT.md)
- [Integração autenticada do FrameSeven](PLANO-INTEGRACAO-FRAMESEVEN-AUTENTICADO.md)
- [Estado e evolução do FrameSeven](FRAMESEVEN-INTEGRACAO-FUTURA.md)
- [Fusão GHOSTRECON + Vigolium](FUSAO-VIGOLIUM.md)
- [Melhorias pendentes do Modo Auto](MELHORIAS-PENDENTES-MODO-AUTO.md)

## Licenças e terceiros

O repositório integra componentes com licenças próprias. O código do Vigolium permanece sob **AGPL-3.0**, incluindo as obrigações aplicáveis a modificações e operação em rede. Antes de redistribuir a stack, consulte [NOTICE](NOTICE), `vigolium/LICENSE`, `vigolium/THIRD_PARTY_NOTICES.md` e as licenças das demais dependências.

---

<div align="center">

### Recon é coleta. Inteligência é saber o que validar em seguida.

**GHOSTRECON — map the surface, validate the signal, keep the evidence.**

</div>
