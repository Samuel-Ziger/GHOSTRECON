<div align="center">

# GHOSTRECON

### Local-first security reconnaissance, validation and intelligence platform

**Transforme superfície de ataque em evidência priorizada — do primeiro domínio ao relatório final.**

[![Node.js](https://img.shields.io/badge/Node.js-20--26-5FA04E?style=for-the-badge&logo=nodedotjs&logoColor=white)](https://nodejs.org/)
[![CLI](https://img.shields.io/badge/CLI-v1.1.0-111827?style=for-the-badge&logo=gnometerminal&logoColor=white)](#linha-de-comando)
[![Tests](https://img.shields.io/badge/Tests-Local_Fixtures-22C55E?style=for-the-badge&logo=checkmarx&logoColor=white)](#qualidade-e-testes)
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
- **Motores complementares:** Node para orquestração e OSINT; Go/Vigolium para
  DAST; FrameSeven para análise, merge de findings e relatórios servidos por
  rota autenticada.
- **IA sem dependência obrigatória de cloud:** suporte a provedores locais, CLIs instalados e OpenRouter.

## Visão geral

| Camada | O que entrega |
| --- | --- |
| **Cockpit** | Execução, terminal ao vivo, findings, controles OPSEC e acesso aos painéis |
| **Recon Engine** | Descoberta, fingerprint, superfície web, validação, correlação e scoring |
| **Vigolium** | Motor DAST em Go, estratégias `lite`, `balanced` e `deep` |
| **FrameSeven** | Fluxo complementar autenticado, normalização/merge de findings e relatórios protegidos por `recon.read` |
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

O Modo Auto é um orquestrador **supervisionado**. Seu contrato exige que as IAs
selecionadas proponham um plano e que o GHOSTRECON expanda, gateie e execute
exatamente o objeto congelado. A implementação cobre o plano externo, mas ainda
não satisfaz essa invariante para a expansão interna do Vigolium nem para a
política de rede dentro de todos os engines.

> [!CAUTION]
> O Auto não está finalizado. `observation` é apenas piloto passivo controlado;
> `assisted` fica restrito a laboratório; `authorized`,
> `authorized_opsec`, Vigolium Auto e FrameSeven ofensivo/autenticado estão
> implementados experimentalmente, mas não estão liberados e devem permanecer
> desabilitados por política enquanto os P0 permanecerem abertos.

```text
CONTEXTO REDIGIDO + CATÁLOGO + RAG
                  ↓
             CONSELHO DE IAs
                  ↓
          DECISÃO JSON VALIDADA
                  ↓
        CHECKPOINT V2 + CLAIM ÚNICO
                  ↓
 PLANO EXTERNO EXPANDIDO + HASH
 (VIGOLIUM INTERNO AINDA PENDENTE)
                  ↓
       RBAC + ESCOPO + ROE + OPSEC
                  ↓
          APROVAÇÃO HUMANA 2–4
                  ↓
 GHOSTRECON → Vigolium → FrameSeven
                  ↓
       AVALIAÇÃO + RAG + HANDOFF
```

O catálogo do Auto combina manifests, fases legadas, módulos Forge ativos e
engines externas. Cada item externo é classificado como `passive`,
`deep_passive`, `active`, `intrusive` ou `hexstrike_intel`. A resolução interna
do Vigolium ainda não é expandida integralmente antes dos gates e pode carregar
capabilities de escrita ou tentativa de credencial que não aparecem
individualmente no popup. Por isso o opt-in do Vigolium não deve ser usado até
essa expansão falhar fechado e writes/credential probes serem separados.

### Autonomia

| Nível | Identificador | Política |
| --- | --- | --- |
| 1 | `observation` | Passivo/deep-passive e inteligência; não abre gate de execução ativa |
| 2 | `assisted` | Pode propor ações não intrusivas; exige confirmação do plano |
| 3 | `authorized` | Pode propor módulos intrusivos autorizados; exige `recon.intrusive`, engagement/ROE aplicável e confirmação |
| 4 | `authorized_opsec` | Mesmo limite de risco do nível 3, com perfil OPSEC `aggressive`; não autoriza ações destrutivas |

HexStrike, Vigolium e FrameSeven aparecem no catálogo somente quando seus
respectivos toggles são ativados. O modo autenticado do FrameSeven exige opt-in
adicional e confirmação própria; segredos e cookies não entram em argv, RAG ou
logs. Quando mais de um motor é selecionado, a ordem é
**GHOSTRECON → Vigolium → FrameSeven**.

As identidades dos executáveis FrameSeven e Vigolium são calculadas durante o
catálogo/preflight, seladas no plano efetivo e revalidadas imediatamente antes
de cada `spawn`. Troca de binário, hash, tamanho ou metadado depois da aprovação
falha fechado em vez de promover silenciosamente uma nova identidade.

O ciclo de retomada usa checkpoints v2 nas fronteiras
`ready_for_iteration`/`ready_for_next_iteration`. Cada plano pronto é consumido
por um claim atômico e durável antes da execução; reuso e rollback são
recusados. Checkpoints v1 continuam legíveis para diagnóstico, mas não são
retomáveis, e não existe retomada no meio de engine ou avaliação. O orçamento
temporal, porém, ainda é reiniciado no resume e nem todos os limites fazem parte
da política de compatibilidade.

Módulos Forge aprovados usam um runner forte Bubblewrap em Linux. Sem esse
sandbox, o catálogo os marca como indisponíveis e aprovação/canário falham
fechado. A aprovação cria uma ativação ainda não executável globalmente; apenas
o primeiro canário exclusivo, vinculado ao `activationId` e aos hashes
aprovados, pode habilitar o pacote. Alvo, integridade do artefato e versão/hash
do engagement são comparados atomicamente sob lock; o engagement é revalidado
antes e depois do canário. Esse canário executa somente o módulo dinâmico
aprovado, sem pipeline legado, DNS ou finalização. Cada operação do sandbox
recebe uma atestação própria e timeout/cancelamento só assenta após confirmação
de encerramento do processo.

Nos níveis 2–4, recusar a aprovação encerra sem executar pipeline, módulo ou
engine; não existe continuação automática de um “restante seguro”. O runtime
também exige IDs explícitos para ações que antes podiam ocorrer implicitamente
numa fase, como HTTP/WAF, verify, descoberta ativa de parâmetros,
assets/takeover, recheck HIGH, browser XSS e ferramentas/follow-ups Kali.
Fontes passivas de URL não habilitam sozinhas o fetch de bundles do alvo.

Findings de segredo são mascarados antes de eventos/persistência.
`secret_validation` é intrusivo e explícito. Writes/signup de
Supabase/Firebase e FTP `STOR` ficam desligados por padrão e não são habilitados
pela simples presença de token, anon key, `service_role` ou variável de
ambiente. Quando auth é compartilhado com Vigolium, ele segue por arquivo
temporário restrito, não por argv/log.

O timeout do Auto é aplicado por fase e os runners gerenciados possuem
TERM→KILL. Ainda existem caminhos em que cancelamento/falha fatal é capturado,
um módulo é marcado como `done` ou uma avaliação `partial` fecha a sessão como
`completed`. A UI também abandona o stream em qualquer evento `error`, inclusive
recuperável. Até a correção, o terminal exibido não é prova de conclusão real.

No RUN manual, qualquer módulo intrusivo encontrado depois da expansão de
aliases, engines e dependências exige cumulativamente `recon.intrusive`,
engagement formal ativo, ROE assinado, alvo dentro do escopo e da janela, além
de `confirmActive` **e** uma aprovação emitida pelo servidor e vinculada ao
plano; perfil `aggressive` não substitui esses gates. Isso inclui qualquer
capacidade Vigolium já classificada como intrusiva quando solicitada.

O protocolo do RUN intrusivo é
`POST /api/recon/preflight` → `POST /api/recon/approval` →
`POST /api/recon/stream`. O preflight calcula um SHA-256 sobre alvo, binding do
engagement, módulos efetivos, opções de execução, ferramentas/limites
FrameSeven, configuração Vigolium e identidades dos binários. A aprovação é
efêmera, ligada ao operador, possui TTL e só pode ser consumida uma vez; qualquer
mudança exige novo preflight. Auth, cookies, headers sensíveis, senhas e paths
locais não entram no plano público.

Na UI, o popup mostra módulos, engines, ferramentas, limites, hash do plano e
fingerprints SHA-256 abreviados dos binários. Os demais clientes mantêm o mesmo
gate, mas não a mesma interação: a CLI exige TTY e a digitação do prefixo do
hash; o MCP devolve `approval_required` para aprovação separada pela UI/API; o
GhostWatch, em VPS privada com `GHOSTWATCH_TRUSTED_OPERATOR=1` e gates
cumulativos (confirm-active, API key red/admin, alvo em `domains.txt`, API
loopback), pode consumir `/api/recon/approval` sem TTY; sem esses gates continua
fail-closed e bloqueia o alvo. A variável `GHOSTRECON_CONFIRM_ACTIVE` não aprova
um plano HTTP. Setup: `bash scripts/setup-ghostrecon-vps.sh` — ver
`docs/GHOSTWATCH-VPS.md`.
Na política atual do Auto, o FrameSeven é o único motor que mantém um perfil
ofensivo. Esse perfil usa a lista explícita e read-oriented
`recon,access,redirect,misconfig,cve,crawler,content,subdomain,ports,nmap,bannergrab`;
não usa `tools all` nem envia `-active-scan`. Por continuar intrusivo, exige os
mesmos gates mesmo sem `-auth-browser`. O adapter FrameSeven aplica deadlines
separados para captura autenticada, aprovação humana, trabalho anterior ao scan
e scan, com encerramento
`SIGTERM` → `SIGKILL` e espera limitada de assentamento.

O adapter ainda não transporta a `scopePolicy` formal para dentro do CLI.
Redirects, crawler, subdomínios, IPs e portas descobertas não têm contenção
comprovada pela allowlist do engagement; o perfil ofensivo/autenticado não está
liberado e deve permanecer desabilitado por política.

No FrameSeven, o terminal de sucesso só é emitido depois de validar, normalizar
e mesclar o `report.json`. Evidência útil com erro recuperável de scan, relatório
incompleto ou falha de merge gera um único `engine_partial`. A rota protegida
serve somente `report.html`, `report.json` e `report.md` regenerados a partir
dos findings normalizados e redigidos; PDF e arquivos brutos não são públicos.
`GET /api/frameseven/reports/:reportId/:file` exige `recon.read`, valida owner e
binding de engagement, abre o arquivo com `O_NOFOLLOW`, lê pelo mesmo descritor,
confere `fstat` e aplica CSP sandbox sem scripts ao HTML.

Antes de atualizar a sessão ou escrever NDJSON, todo evento produzido pelo
orquestrador Auto passa por redação recursiva central. Segredos são mascarados,
o root local é substituído e caminhos absolutos de artefatos são omitidos. Essa
fronteira não substitui o teste ponta a ponta de artefatos produzidos por
ferramentas externas.

Provedores contemplados pelo contrato incluem Codex, Claude Code, Cursor,
OpenRouter, GHOST/modelo local e endpoints OpenAI-compatible. A disponibilidade
depende da instalação e configuração local. Quando todos os selecionados estão
indisponíveis, o backend ainda pode usar baseline determinístico sem um estado
degradado explícito. O RAG ainda não é particionado por principal/engagement, e
consentimento, custo e política para providers externos precisam ser
verificáveis antes de evidência autenticada. O endpoint principal é
`POST /api/recon/auto/stream`.

> [!IMPORTANT]
> Autonomia é uma política de seleção, nunca autorização do alvo. Níveis 3/4
> não estão liberados e devem permanecer desabilitados por política;
> `assisted` também não está liberado operacionalmente.

Pendências centrais: expansão interna do Vigolium; scope em todos os engines e
redirects; propagação fatal de cancelamento/timeout; outcomes e terminais
verdadeiros; deadline absoluto no resume; cleanup aguardado; RAG isolado;
engagement para ações ativas; relatório Auto consolidado; readiness real do
catálogo; regressão hermética e E2E controlado.

Leia [MODO-AUTO-GHOSTRECON.md](MODO-AUTO-GHOSTRECON.md) para o contrato
operacional, [STATUS-FINALIZACAO-MODO-AUTO.md](STATUS-FINALIZACAO-MODO-AUTO.md)
para a fotografia verificável da evolução atual e
[MELHORIAS-PENDENTES-MODO-AUTO.md](MELHORIAS-PENDENTES-MODO-AUTO.md)
para as limitações atuais.

## MCP

O servidor MCP em `mcp/ghostrecon-mcp.mjs` conecta clientes compatíveis ao mesmo backend usado pelo cockpit e pela CLI. A configuração local do Cursor está em `.cursor/mcp.json`.

O MCP do HexStrike usa `mcp/hexstrike-mcp-launcher.mjs`: sobe a API local em
`http://127.0.0.1:8888` se estiver offline e então expõe `hexstrike_mcp.py` via
stdio. Logs coloridos do cliente vão para
`IAs/hexstrike-ai/hexstrike-mcp-client.log` para não quebrar a discovery no Cursor.

Principais grupos de tools:

- health, capabilities, módulos e playbooks;
- planejamento e execução de recon normal ou Auto;
- runs, diff e inteligência por alvo;
- status e inteligência HexStrike;
- leitura, busca e escrita controlada no Auto RAG.

O MCP reutiliza autenticação, CSRF, streaming NDJSON e o gate OPSEC do backend.
Módulos intrusivos continuam exigindo `confirmActive=true`. O MCP executa o
preflight, mas não decide a aprovação: ele devolve `approval_required` com
`approvalId` e hash seguros. O operador deve aprovar separadamente pela UI/API,
com o mesmo principal, e então repetir a tool com
`manualApprovalId`/`manualApprovalHash`.

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
- redação de segredos em history, contexto cloud, sessão e eventos NDJSON do
  Auto;
- limites de tempo, memória, saída e custo para ferramentas/agentes;
- plano efetivo congelado e identificado por hash antes da execução Auto;
- preflight e aprovação manual owner-bound, com TTL, hash e consumo único;
- checkpoint Auto v2 com claim atômico durável e proteção contra replay;
- sessões Auto isoladas por operador e aprovação humana de uso único;
- recusa de aprovação Auto fail-closed, sem execução parcial do plano;
- gates de capacidade dentro das fases Auto, além do filtro do catálogo;
- segredos mascarados e write probes separados/desligados por padrão;
- encerramento em dois estágios (`SIGTERM` → `SIGKILL`) para processos
  gerenciados;
- cancelamento do RUN manual propagado por `AbortSignal`;
- identidade FrameSeven/Vigolium selada e revalidada antes de cada processo;
- Forge fail-closed quando o sandbox forte Bubblewrap não está disponível;
- aprovação Forge vinculada atomicamente a alvo, artefato e engagement;
- relatórios FrameSeven sanitizados servidos por rota autenticada, com owner,
  engagement, descritor seguro e allowlist HTML/JSON/Markdown.

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
AUTH_PRINCIPAL_BINDING_SECRET=gere-um-segredo-dedicado-com-ao-menos-32-bytes
GHOSTRECON_MANUAL_APPROVAL_TTL_MS=120000
GHOSTRECON_VIGOLIUM_AUTH_ROOT=./.runtime/vigolium-sessions
```

O TTL da aprovação manual é limitado pelo servidor entre 1 segundo e 15
minutos. O registro fica somente em memória; reiniciar a API invalida
aprovações pendentes.

`AUTH_PRINCIPAL_BINDING_SECRET` deriva por HMAC a identidade estável das API
keys sem persistir a própria key. Se ele não estiver definido, um
`AUTH_JWT_SECRET` com pelo menos 32 bytes é usado; sem nenhum dos dois, o binding
é válido somente durante aquele boot e retomadas owner-bound após restart
falham fechado.

Auth-files existentes do Vigolium só são aceitos dentro de
`GHOSTRECON_VIGOLIUM_AUTH_ROOT` (padrão
`.runtime/vigolium-sessions`). A raiz deve existir, pertencer ao processo e, em
POSIX, usar `0700`; use `0600` nos arquivos e não use symlink ou hardlink. O
servidor sela a identidade no preflight, copia os bytes validados para um
diretório temporário privado por execução e remove essa cópia no cleanup. O
caminho original e os segredos não entram no plano público nem em argv/log.

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
| `POST` | `/api/recon/preflight` | Expansão e emissão do plano manual seguro |
| `POST` | `/api/recon/approval` | Decisão sobre o plano manual intrusivo |
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

A suíte Node cobre pipeline, autenticação, OPSEC, módulos, storage, CLI, Modo
Auto, Vigolium, FrameSeven, HexStrike e integrações. Para alterações no Auto,
comece pelos testes locais e sem rede:

```bash
# Gates herméticos separados usados pela CI
npm run test:core
npm run test:auto:hermetic
npm run test:integrations

node --test \
  server/tests/auto-agent.test.js \
  server/tests/auto-planner-contract.test.js \
  server/tests/auto-effective-plan.test.js \
  server/tests/auto-session-security.test.js \
  server/tests/auth-principal-restart.test.js \
  server/tests/auto-rag-runtime-security.test.js \
  server/tests/auto-strict-phase-gates.test.js \
  server/tests/auto-content-network-gates.test.js \
  server/tests/pipeline-resilience.test.js \
  server/tests/process-cancellation.test.js \
  server/tests/probe-cancellation.test.js \
  server/tests/kali-execution-policy.test.js \
  server/tests/secret-safety.test.js \
  server/tests/write-probes-safety.test.js \
  server/tests/forge-security.test.js \
  server/tests/manual-recon-approval.test.js \
  server/tests/recon-stream-route.test.js \
  server/tests/ui-consent-contract.test.js \
  server/tests/frameseven-integration.test.js \
  server/tests/vigolium-bridge.test.js \
  server/tests/vigolium-agent.test.js

# CLI
npm run test:cli
npm run test:mcp

# Smoke de import sem abrir porta
GHOSTRECON_NO_HTTP_LISTEN=1 node -e "import('./server/index.js').then(() => console.log('node app ok'))"
```

O gate padrão `npm test` é hermético e exclui smokes de rede. Use
`npm run test:network` somente em ambiente autorizado e controlado. O estado
corrente do gate deve ser confirmado pela execução dos comandos acima; falhas
temporárias não são documentadas aqui como contrato permanente.

`GET /api/capabilities` inclui uma matriz `support` versionada. Ela distingue
nível de suporte, política operacional e readiness observada; disponibilidade
de um binário nunca concede autorização nem substitui RBAC, scope, engagement,
OPSEC ou aprovação humana.

Mocks e fixtures não substituem o E2E controlado de navegador, DAST,
cancelamento, restart, contenção de escopo, redação e cleanup.

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
- [Status de finalização do Modo Auto](STATUS-FINALIZACAO-MODO-AUTO.md)
- [Melhorias pendentes do Modo Auto](MELHORIAS-PENDENTES-MODO-AUTO.md)
- [Autenticação, RBAC e scopes](docs/AUTH-RBAC.md)
- [Tor strict e proteção anti-leak](docs/TOR.md)
- [Contrato de módulos](docs/MODULE-CONTRACT.md)
- [Arquivo histórico de planos](docs/arquivo/README.md)

## Licenças e terceiros

O repositório integra componentes com licenças próprias. O código do Vigolium permanece sob **AGPL-3.0**, incluindo as obrigações aplicáveis a modificações e operação em rede. Antes de redistribuir a stack, consulte [NOTICE](NOTICE), `vigolium/LICENSE`, `vigolium/THIRD_PARTY_NOTICES.md` e as licenças das demais dependências.

---

<div align="center">

### Recon é coleta. Inteligência é saber o que validar em seguida.

**GHOSTRECON — map the surface, validate the signal, keep the evidence.**

</div>
