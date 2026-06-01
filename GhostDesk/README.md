# GhostDesk

Painel de **gestão de pentests integrado ao GHOSTRECON**. Não é um app separado: o backend é um **módulo Node nativo** do GHOSTRECON que reaproveita a mesma camada de dados (`runs` / `findings` / `bounty_intel` — SQLite, Postgres **ou Supabase**, transparente) e o `projects.mjs`. O frontend é um painel **Vue 3** que fala com a API do GHOSTRECON.

> A ideia: gerenciar **todos os scans feitos pelo GHOSTRECON** e ler o que está no **Supabase**, agrupando por projeto e cliente.

## Arquitetura

```
GhostDesk (Vue 3, :5173)
   │  proxy /api → 127.0.0.1:3847
   ▼
GHOSTRECON server (Express, :3847)
   ├─ server/modules/ghostdesk.mjs        ← rotas /api/ghostdesk/* (auth por scope)
   ├─ server/modules/ghostdesk-store.mjs  ← clientes + vínculo projeto↔cliente (JSON)
   ├─ db.js  → runs / findings / bounty_intel   (SQLite | Postgres | Supabase)
   └─ projects.mjs → programas + attachRunToProject
```

Nada de Laravel/JWT próprio: o GhostDesk **reusa a autenticação do GHOSTRECON** (API key + scopes/roles, com auto-auth loopback). Leituras exigem `recon.read`; escritas exigem `project.write`.

## Backend — já integrado

Os arquivos foram adicionados ao GHOSTRECON (não dentro de `GhostDesk/`):

- `server/modules/ghostdesk.mjs` — router montado em `server/index.js` via `registerGhostDeskRoutes(app, { validateCsrfToken })`.
- `server/modules/ghostdesk-store.mjs` — entidade "cliente" (que o GHOSTRECON não tinha) + mapa projeto→cliente, em `.ghostrecon-ghostdesk/ghostdesk.json`.

### Rotas `/api/ghostdesk/*`

| Método | Rota | Scope | O quê |
|--------|------|-------|-------|
| GET | `/overview` | recon.read | KPIs: scans, alvos, projetos, clientes, findings por prioridade |
| GET | `/scans` · `/scans/:id` | recon.read | Lista/detalha **runs do GHOSTRECON** |
| POST | `/scans/:id/attach` | project.write | Anexa um run a um projeto |
| GET | `/projects` | recon.read | Projetos (`projects.mjs`) + cliente vinculado |
| POST | `/projects/:name/client` | project.write | Vincula projeto a cliente |
| GET/POST/DELETE | `/clients` | read / write | CRUD de clientes |
| GET | `/intel/:target` | recon.read | Corpus deduplicado (**Supabase**/`bounty_intel`) |
| GET | `/search?q=` | recon.read | Busca global (clientes/projetos/scans) |

## Frontend

```bash
cd GhostDesk/frontend
npm install
npm run dev          # http://localhost:5173 (proxy /api → :3847)
```

Garanta o GHOSTRECON rodando (`npm start` na raiz). O painel pega a API key via `/api/setup/auto-auth` (loopback) e o token CSRF automaticamente — sem login manual. Views: **Dashboard**, **Scans**, **Projetos**, **Clientes**, **Intel (Supabase)**.

Para usar Supabase como fonte: configure `SUPABASE_URL` + chave no `.env` do GHOSTRECON (o `db.js` roteia sozinho). O Dashboard/Intel mostram a origem ativa.

## Segurança

- Reusa auth/scopes/roles do GHOSTRECON (sem segundo sistema de credenciais).
- Mutações exigem `project.write` **e** token CSRF (`X-CSRF-Token`).
- Aditivo: não altera rotas nem o pipeline existentes do GHOSTRECON.
- Validação e sanitização de entrada no `ghostdesk-store.mjs`.

## Próximos passos

- Vincular evidências/anotações (handoff para GhostTrace) por scan.
- Relatório por projeto reusando o gerador do GHOSTRECON (DOCX/IA).
- Dashboard executivo read-only por cliente (role `viewer`).
```

## Relatório (DOCX) a partir de um scan

No painel **Scans**, ao abrir um scan, o botão **📄 Gerar relatório (DOCX)**:

1. monta o pacote de findings via `GET /api/ghostdesk/scans/:id/report-payload` (mesmo contrato `GhostreconFinding` do Reporter);
2. reusa o handoff existente do GHOSTRECON (`POST /api/anotacao-handoff` → id one-time);
3. abre `/anotacao/ghostrecon/import?handoff=<id>` no **GhostTrace**, de onde sai o **DOCX** pelo exportador (`GhostTrace/src/features/reports/docx-exporter.ts`), já alinhado ao template LocBook/BancoCN (capa, introdução, sumários, vulnerabilidades por severidade, detalhamento com Descrição/Cenário/Recomendação/Tags/CVSS/Ativos, notas sempre presentes, Histórico de reteste e **screenshots embutidos no Proof of Concept**).

Requer o GhostTrace rodando (`npm run start:anotacao`).

## Botão no GHOSTRECON → GhostDesk

O cockpit principal (`index.html`) ganhou o botão **GhostDesk** (ao lado de Reporte/Pós-Exploração), via `openGhostDeskPage()`. Ele abre o painel em `:5173` (dev Vite) ou, quando o GhostDesk for servido pelo próprio GHOSTRECON, na origem atual. Override opcional: `localStorage['ghostrecon_ghostdesk_url']`.
