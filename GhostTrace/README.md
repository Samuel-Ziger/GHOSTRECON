# GhostTrace

> Plataforma operacional ofensiva para documentação viva de Pentest, Red Team e Bug Bounty.  
> O operador opera. A plataforma documenta. A IA padroniza. O DOCX sai pronto.

Não é um gerador de relatório. É o **sistema operacional do pentester** — registro de cadeia de ataque, evidências, pivots, credenciais e timeline, com saída automática para relatório enterprise-grade.

## Status

**Fase atual:** protótipo funcional full-stack no cliente + API FastAPI opcional.

| Área | Estado |
|------|--------|
| Frontend Next.js | Operacional — persistência `localStorage`, shell completo |
| API FastAPI + SQLite | Sync de projetos (`PUT /projects/{id}/sync`) |
| IA (Gemini / Anthropic / OpenRouter) | Chamadas reais via rotas Next.js `/api/ai/*` |
| Relatório | Preview HTML, export **DOCX** (cliente) e **JSON** (`ReportShape`) |
| Attack chain | Visualização + **editor** (nós, passos, links) |
| Timeline / evidências | Criação e upload com persistência local |
| Scripts Windows / Kali | Instalador + arranque em background |

**Próximas fases:** auth OAuth2, PostgreSQL, parsers (Nmap, Nuclei, LinPEAS…), knowledge base com embeddings.

## Stack

### Frontend
- **Next.js 15** (App Router) + TypeScript strict
- Tailwind CSS, Framer Motion, TipTap, cmdk, Zustand (persist)
- Geist Sans / Mono

### Backend (opcional)
- **FastAPI** + SQLite (`backend/ghosttrace.db`)
- Pydantic espelhando `src/lib/types`

### IA
- Adaptador comum: **Gemini**, **Anthropic**, **OpenRouter**
- API keys em `localStorage` (protótipo) — nunca em git

## Início rápido

### Pré-requisitos
- **Node.js 18+** e npm
- **Python 3.10+** e pip (API e scripts de instalação)

### Windows — instalar e subir (recomendado)

```powershell
# 1ª vez
.\scripts\windows\install.ps1

# Subir API + web em background (continua rodando)
.\scripts\windows\start-daemon.ps1
# ou: npm run start:win
# ou duplo clique: scripts\windows\start.cmd

# Parar
.\scripts\windows\stop.ps1
```

Com janelas visíveis (debug): `.\scripts\windows\start.ps1` ou `npm run start:win:gui`

### Kali / Linux

```bash
chmod +x scripts/kali/*.sh
./scripts/kali/install.sh

# Background (nohup — sobrevive ao fechar o terminal)
./scripts/kali/start.sh
# ou: npm run start:kali

./scripts/kali/stop.sh
./scripts/kali/status.sh
```

No Kali a web/API escutam em `0.0.0.0` por padrão — acesse `http://<IP>:3000` na LAN.

### Manual (só frontend)

```bash
cp .env.example .env.local   # ajuste NEXT_PUBLIC_API_URL se usar a API
npm install
npm run dev
# http://localhost:3000 → /projects
```

### API separada

```bash
npm run api:install
npm run api:dev
# http://127.0.0.1:8787/health
```

Porta **8787** (evita conflito com reservas do Windows na 8000).

## Variáveis de ambiente

Crie `.env.local` na raiz (copie de `.env.example`):

```env
NEXT_PUBLIC_APP_NAME=GhostTrace
NEXT_PUBLIC_APP_VERSION=0.1.0
NEXT_PUBLIC_API_URL=http://localhost:8787
```

| Variável (scripts) | Padrão | Descrição |
|--------------------|--------|-----------|
| `GHOSTTRACE_API_PORT` | `8787` | Porta FastAPI |
| `GHOSTTRACE_WEB_PORT` | `3000` | Porta Next.js |
| `GHOSTTRACE_API_HOST` | `0.0.0.0` (Kali) | Bind da API no Linux |

## Scripts npm

| Comando | Descrição |
|---------|-----------|
| `npm run dev` | Next.js em desenvolvimento |
| `npm run build` | Build de produção |
| `npm run api:dev` | FastAPI com reload |
| `npm run install:win` | Instalador Windows |
| `npm run install:kali` | Instalador Kali/Linux |
| `npm run start:win` | Sobe tudo em background (Windows) |
| `npm run start:win:gui` | Sobe com janelas PowerShell |
| `npm run stop:win` | Para serviços Windows |
| `npm run start:kali` | Sobe em background (Kali) |
| `npm run stop:kali` | Para serviços Kali |
| `npm run type-check` | Verificação TypeScript |

## Estrutura do repositório

```
GhostTrace/
├── backend/                 # FastAPI + SQLite
│   └── app/
├── docs/                    # ARCHITECTURE.md, REPORT_TEMPLATE.md
├── scripts/
│   ├── windows/             # install, start, start-daemon, stop, status
│   └── kali/                # install.sh, start.sh, stop.sh, status.sh
└── src/
    ├── app/                 # App Router + /api/ai/*
    ├── components/          # ui, layout, providers
    ├── features/            # vulnerabilities, timeline, attack-chain, reports, ai
    └── lib/
        ├── types/           # contratos (fonte para Pydantic)
        ├── mock/            # Zustand store + seed LocBook
        ├── ai/              # AIAdapter + providers
        ├── api/             # cliente HTTP + sync com backend
        └── report/          # ReportShape + export JSON
```

Documentação detalhada: [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) · [`docs/REPORT_TEMPLATE.md`](docs/REPORT_TEMPLATE.md)

## Módulos

| Módulo | Descrição |
|--------|-----------|
| Workspace de projeto | Lista, criação, dashboard com KPIs |
| Vulnerabilidades | Editor TipTap, steps, POCs, triage heurístico, **Aprimorar com IA** |
| Timeline ofensiva | Feed SIEM + compositor de eventos |
| Attack chain | Grafo por host + **editor** de nós e passos |
| Evidence manager | Upload de imagens/arquivos (local) |
| Credential vault | Tabela com reveal/copy |
| Relatório | Preview HTML, wizard IA, **export DOCX** e JSON |
| Configurações | API keys dos providers de IA |

## Configurar IA

1. Abra **Configurações** (`/settings`)
2. Cole a API key (Gemini, Anthropic ou OpenRouter) e salve
3. Use **Aprimorar** no editor de vuln ou **Gerar com IA** no relatório

As chaves ficam no `localStorage` do navegador. No backend futuro: vault criptografado.

## Filosofia

1. **Velocidade operacional** vence tudo.
2. A **cadeia de ataque** é o produto. Findings isolados são commodity.
3. **IA é copiloto**, não autor — expande e padroniza, nunca inventa evidência.
4. **Template como fonte da verdade** — o data model nasce do DOCX de referência (LocBook / BancoCN).

## Logs e dados locais

| Caminho | Conteúdo |
|---------|----------|
| `.ghosttrace/logs/` | Logs API/web (scripts em background) |
| `.ghosttrace/run/` | PIDs dos processos |
| `backend/ghosttrace.db` | SQLite da API |
| `localStorage` | Estado Zustand + API keys |

---

**Inspirado em:** Notion + Dradis + PlexTrac + IA ofensiva.  
**Para:** red teams, consultorias de segurança e bug hunters profissionais.
