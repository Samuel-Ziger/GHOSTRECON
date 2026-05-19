# GhostTrace — Arquitetura

> Plataforma operacional ofensiva para documentação viva de Pentest, Red Team e Bug Bounty.
> Esta primeira fase é o **protótipo visual** do frontend, com mock layer in-memory.

## Princípios

1. **Velocidade operacional vence tudo.** Cada interação do operador em campo precisa custar menos esforço do que abrir um arquivo `.md`. Atalhos de teclado, command palette, autosave.
2. **A cadeia de ataque é o produto.** Vulnerabilidades isoladas são commodity. O que diferencia um relatório enterprise é mostrar como o atacante entrou, pivotou e escalou. O modelo de dados é centrado em `AttackChain` linkando `Vulnerability` + `TimelineEvent`.
3. **IA é copiloto, não autor.** A IA expande, padroniza, melhora — nunca inventa evidência, CVE, exploit ou impacto.
4. **Template como fonte da verdade.** O data model nasce dos campos do DOCX de referência (ver `REPORT_TEMPLATE.md`). Tudo que existe no relatório existe no modelo, na mesma forma.
5. **Sem CRUD genérico.** A UI é especializada por contexto ofensivo: editor de vuln, timeline tipo SIEM, attack chain visual, vault de credenciais.

## Stack

### Frontend (esta fase)
- **Next.js 14** App Router — SSR/streaming, route groups para shells distintos
- **TypeScript strict** — contratos rigorosos
- **Tailwind CSS** — design tokens via CSS vars, sem CSS-in-JS
- **Framer Motion** — transições do shell, command palette
- **TipTap** — editor markdown rico para campos longos (description, scenario, recommendation)
- **Lucide React** — ícones consistentes
- **Geist Sans / Geist Mono** — tipografia (`next/font`)

### Backend (próxima fase)
- FastAPI + PostgreSQL + Redis + Celery
- Alembic para migrations
- python-docx + Jinja2 + Pandoc para geração de relatório
- Autenticação OAuth2 + RBAC (operator/reviewer/client)

### IA
- Adaptador comum `AIAdapter` com 3 implementações: Gemini, OpenRouter, Anthropic
- Embeddings locais (sentence-transformers) → Knowledge Base reutilizável de findings
- Suporte a LLM local (Ollama) para clientes paranoicos

## Estrutura de pastas

```
GhostTrace/
├── docs/                          documentação técnica
├── public/                        assets estáticos
└── src/
    ├── app/                       Next.js App Router
    │   ├── layout.tsx             root layout + fonts + theme
    │   ├── globals.css            CSS vars + Tailwind base
    │   ├── page.tsx               landing → redirect /projects
    │   └── (operator)/            app shell autenticado
    │       ├── layout.tsx         Sidebar + TopBar + StatusBar
    │       ├── projects/
    │       │   ├── page.tsx       lista
    │       │   └── new/page.tsx   wizard criação
    │       ├── projects/[id]/     contexto de projeto ativo
    │       │   ├── layout.tsx     project context provider
    │       │   ├── page.tsx       dashboard
    │       │   ├── vulnerabilities/
    │       │   ├── timeline/
    │       │   ├── attack-chain/
    │       │   ├── evidence/
    │       │   ├── credentials/
    │       │   └── report/
    │       └── settings/page.tsx  API keys de IA, preferências
    ├── components/
    │   ├── ui/                    primitives reutilizáveis
    │   ├── layout/                Sidebar, TopBar, StatusBar, CommandPalette
    │   └── icons/                 ícones custom (GhostTrace mark)
    ├── features/                  módulos do produto
    │   ├── projects/              ProjectCard, NewProjectForm
    │   ├── vulnerabilities/       VulnEditor, SeverityBadge, VulnList, FieldEnhanceButton
    │   ├── timeline/              TimelineFeed, EventCard, EventComposer
    │   ├── attack-chain/          ChainCanvas, ChainNode, MermaidView
    │   ├── evidence/              ScreenshotGrid, FileUploader
    │   ├── credentials/           VaultTable
    │   ├── reports/               ReportPreview, ReportWizard, ProviderPicker
    │   └── ai/                    AIAssistantButton, AIProviderConfig
    ├── lib/
    │   ├── types/                 contratos TS espelham futuro Pydantic
    │   ├── mock/                  store in-memory + seed LocBook
    │   ├── ai/                    AIAdapter + implementações
    │   ├── report/                ReportShape + futura ponte DOCX
    │   └── utils/                 cn, severity, formatters
    └── styles/
        └── tokens.ts              design tokens em TS
```

## Design system

### Tokens

| Token | Valor | Uso |
|---|---|---|
| `--bg` | `hsl(222 14% 6%)` | fundo da app |
| `--surface` | `hsl(222 14% 9%)` | cards, painéis |
| `--surface-2` | `hsl(222 14% 12%)` | inputs, hover |
| `--border` | `hsl(222 14% 18%)` | divisórias 1px |
| `--fg` | `hsl(220 14% 96%)` | texto principal |
| `--fg-muted` | `hsl(220 8% 60%)` | texto secundário |
| `--fg-dim` | `hsl(220 8% 42%)` | placeholder, hint |
| `--accent` | `hsl(152 95% 50%)` | brand neon green |
| `--sev-critical` | `#ff3366` | severidade crítica |
| `--sev-high` | `#ff8a3d` | severidade alta |
| `--sev-medium` | `#ffcc33` | severidade média |
| `--sev-low` | `#3dd6a8` | severidade baixa |
| `--sev-info` | `#5b9bff` | severidade informacional |

### Assinaturas visuais

- 1px borders sempre, nunca mais grossas
- Severidades exibidas com barra vertical à esquerda na cor da severidade
- Background com grid pontilhado 8×8 sutil no shell
- Hover/focus com glow via `box-shadow` em accent a baixa opacidade
- Tipografia: Geist Sans para UI, Geist Mono para timestamps, comandos, KPIs e brand
- Animações ≤150ms ease-out, snappy

## Data model (TypeScript → Pydantic)

Definido em `src/lib/types/`. Tipos centrais:

- `Project` — cliente, escopo, metodologia, datas, ferramentas
- `Vulnerability` — title, severity, status, CVSS, CWE, tags, targets, description, attackScenario, recommendation, remediationNotes, additionalNotes, steps[], pocs[]
- `ReproStep` — order, text, command?, screenshots[]
- `ProofOfConcept` — title, description, code{lang,content}, screenshots[]
- `TimelineEvent` — ts, type (recon/creds/rce/privesc/pivot/exfil/…), host, title, details, vulnerabilityId?
- `AttackChainNode` — host, ip, privilege (unauth/user/root), steps[], nextNodeIds[]
- `Evidence` — filename, mime, size, vulnerabilityIds[]
- `Credential` — user, context, value, source, host
- `AIProvider` — id (gemini/openrouter/anthropic), apiKey, model

Cada tipo é a tradução TS direta dos campos do template LocBook (ver `REPORT_TEMPLATE.md`).

## Camada de IA

```ts
interface AIAdapter {
  id: 'gemini' | 'openrouter' | 'anthropic';
  enhanceField(opts: {
    field: 'description' | 'attackScenario' | 'recommendation' | 'remediationNotes';
    input: string;
    vuln: Vulnerability;
  }): Promise<string>;
  generateExecutiveSummary(project: Project, vulns: Vulnerability[]): Promise<string>;
  classifySeverity(input: string): Promise<{ severity: Severity; cvss?: string; rationale: string }>;
}
```

Implementações em `lib/ai/providers/{gemini,openrouter,anthropic}.ts`. API keys armazenadas em `localStorage` durante o protótipo, em vault criptografado quando o backend existir.

## Pipeline de relatório

```
Vulnerability[] + Project + TimelineEvent[] + AttackChain
    ↓ (Report Wizard escolhe escopo + provider IA)
ReportShape (JSON canônico)
    ↓ (renderer HTML — preview no protótipo)
HTML Report Preview ───→ (futuro) python-docx + Jinja → BancoCN.docx
```

O `ReportShape` é o contrato entre o frontend e o renderizador DOCX. Definido em `lib/report/shape.ts`.

## Próximas fases (fora deste protótipo)

1. Backend FastAPI + PostgreSQL + Alembic
2. Autenticação OAuth2 + multi-tenancy
3. Geração real de DOCX (python-docx + Jinja2)
4. Parsers automáticos (Nmap, LinPEAS, Nuclei, ffuf, sqlmap)
5. Knowledge Base de findings reutilizáveis (embeddings)
6. Integração com captura de screenshot (Flameshot / ShareX / clipboard watcher)
7. Suporte a LLM local (Ollama) para clientes com requisito de privacidade
