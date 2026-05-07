# VPS — GHOSTRECON sem UI (motor embutido)

Três passos na VPS (Kali/Debian):

1. **Clone completo do repositório GHOSTRECON** (`server/`, `playbooks/` e `vps-recon-workflow/` na mesma árvore). Copiar só a pasta `vps-recon-workflow` não chega para o pipeline; neste caso defina **`GHOSTRECON_REPO_ROOT`** para a raiz onde estão `server/` e `playbooks/`.

```bash
cd /opt/GHOSTRECON          # exemplo: raiz do clone
cd vps-recon-workflow

# 2) MESMO .env do GHOSTRECON (opcional se só existir ../.env):
# cp ../.env ./.env
#    (cron-run.sh exporta GHOSTRECON_ENV_FILE=../.env quando não há .env local)

# 3) Instalar dependências + cron a cada 6 h
chmod +x install.sh cron-install.sh setup-cron.sh scripts/cron-run.sh
bash install.sh --cron
```

O que corre sozinho a cada 6 h:

1. Lê **Supabase** → actualiza **`../subdomains.txt`** na raiz do GHOSTRECON (por defeito) ou `WORKFLOW_DOMAINS_FILE`
2. Para cada domínio (apex primeiro, depois subdomínios), corre o **mesmo pipeline** que o GHOSTRECON (sem interface, sem `app.listen`)
3. Compara com **SQLite** local — só o **novo** vai no **webhook**
4. Resumo PT em `ai_summary_pt`: **Gemini** primeiro; se falhar ou não houver chave, **OpenRouter** (`OPENROUTER_API_KEY`). Campo `ai_summarizer` indica qual foi usada.

Variáveis que costumam faltar no `.env` além do GHOSTRECON puro:

- `WORKFLOW_VPS_WEBHOOK_URL` — webhook **só do modo VPS** (tem prioridade sobre `WORKFLOW_WEBHOOK_URL` se ambos existirem)
- `WORKFLOW_WEBHOOK_URL` — fallback genérico se `WORKFLOW_VPS_WEBHOOK_URL` não estiver definido
- Tabela Supabase de domínios (`docs/supabase-workflow_domains.sql`) + `WORKFLOW_*` no `.env.example`

Teste manual (sem esperar o cron):

```bash
cd /opt/GHOSTRECON/vps-recon-workflow
node scripts/sync-domains.mjs
node scripts/run-pipeline.mjs
```

Só cron (reinstalar bloco; idempotente):

```bash
bash cron-install.sh
# ou intervalo personalizado:
bash cron-install.sh --hours 6
# pré-visualizar sem alterar o crontab:
bash cron-install.sh --dry-run
```

O job chama `scripts/cron-run.sh` (caminho absoluto), que define `GHOSTRECON_ENV_FILE` para o `.env` na raiz do GHOSTRECON quando não existir `.env` dentro de `vps-recon-workflow`.

Atalho legado: `bash setup-cron.sh` (equivale a `cron-install.sh`).

Log do cron: `logs/cycle.log`
