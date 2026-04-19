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
