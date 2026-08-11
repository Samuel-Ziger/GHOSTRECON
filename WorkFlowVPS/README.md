# Mini-ASM — Pipeline de Reconhecimento Contínuo

Mini-ASM (*Attack Surface Management*) leve, autónomo e pensado para VPS pequenas. O pipeline ingere descobertas do **GhostRecon** (lendo o **Postgres da própria VPS** — modelo "VPS = banco"; também suporta SQLite/NDJSON como fallback), expande ápices novos com `subfinder` / `assetfinder`, valida hosts vivos com `httpx`, fingerprint com `whatweb`, varre com `nuclei`, faz checagens leves de vulnerabilidades, calcula o **diff entre ciclos** e envia um relatório resumido (via **Google Gemini**) para o **Discord**.

> **Armazenamento:** o GhostRecon grava direto no Postgres desta VPS (via `DATABASE_URL`) e este workflow lê o mesmo banco (`source_postgres.enabled: true`). Sem Supabase, sem cópia de arquivos `.db`.

> Foco: pouco ruído no canal — só novidades. Operação 24/7 via cron, `systemd.timer` ou scheduler interno.

---

## Funcionalidades

- **Ingestão incremental** a partir de `*.db` (esquema GhostRecon: `runs`, `findings`, `bounty_intel`) e ficheiros NDJSON.
- **Coleta opcional** de novos ápices com `subfinder` + `assetfinder`.
- **Validação HTTP** com `httpx` (status, título, IP, tecnologias).
- **Fingerprinting** com `whatweb` + heurísticas internas (ex.: detecção de WordPress, builders/AI sites via `lovable_detect`).
- **Scan dirigido** com `nuclei` (tags e severidades configuráveis, rate-limit).
- **Checagens leves** de SQLi/LFI em URLs com query string, opcional `sqlmap` em parâmetros "bons".
- **Serviços de rede**: FTP anónimo, SMB null session (`smbclient`), `rpcclient` enumeração.
- **WordPress**: `wpscan` resumido para alvos detetados.
- **OSINT GitHub** (token obrigatório) sobre hosts novos do ciclo.
- **Diff de snapshots**: só dispara notificações quando há novidades reais; a primeira execução grande não faz spam (`suppress_full_first_baseline`).
- **Relatório com Google Gemini** no canal `news`; fallback para resumo determinístico se a API falhar.
- **Erros do pipeline** vão para um webhook separado, com explicação em PT-PT pelo Gemini.
- Persistência em **SQLite** (`database/asm.db`) e dump dos últimos achados em `results/last_nuclei.json`.

---

## Arquitetura

```
┌──────────────────────────────┐   ┌──────────────────────┐
│ GhostRecon Postgres (RO)     │   │ NDJSON/SQLite (RO,    │
│ runs/findings/bounty_intel   │   │ fallback opcional)   │
└───────────┬──────────────────┘   └───────────┬──────────┘
            │ leitura incremental (cursor por fonte)      │
            └────────────────┬──────────────-------------┘
                             ▼
              ┌──────────────────────────────┐
              │  ingest_phase  (modules/*)   │
              │  • upsert hosts/apex         │
              │  • subfinder/assetfinder     │
              │  • OSINT GitHub              │
              └──────────────┬───────────────┘
                             ▼
              ┌──────────────────────────────┐
              │       scan_phase             │
              │  httpx → whatweb → nuclei    │
              │  + SQLi/LFI/SMB/FTP/RPC      │
              │  + wpscan (quando aplicável) │
              └──────────────┬───────────────┘
                             ▼
              ┌──────────────────────────────┐
              │ diff_engine: before vs after │
              └──────────────┬───────────────┘
                             ▼
            Discord (Gemini summary) + asm.db + logs
```

---

## Estrutura do projeto

```
recon/
├── main.py                  # Orquestrador (CLI: --once, --no-notify, --config, --no-scheduler)
├── config.yaml              # Configuração principal do pipeline
├── requirements.txt         # Dependências Python
├── install.sh               # Bootstrap (venv + cron 06:00/18:00 + baseline silenciosa)
├── .env.example             # Modelo das variáveis sensíveis
├── modules/
│   ├── collector.py         # subfinder + assetfinder
│   ├── database.py          # SQLite (asm.db) + cursores incrementais
│   ├── diff_engine.py       # Eventos entre snapshots
│   ├── fingerprint.py       # Flags a partir de httpx/whatweb
│   ├── gemini_client.py     # Sumário de novidades e explicação de erros
│   ├── github_osint.py      # Pesquisa code-search no GitHub
│   ├── lovable_detect.py    # Heurística para sites gerados por IA / builders
│   ├── notifier.py          # Discord webhooks
│   ├── nuclei_scan.py       # Wrapper do nuclei (JSONL)
│   ├── scheduler.py         # APScheduler para o modo contínuo
│   ├── subphase_reader.py   # Leitor incremental de SQLite + NDJSON
│   ├── validator.py         # httpx probing
│   ├── vuln_checks.py       # SQLi/LFI/sqlmap/SMB/FTP/RPC + intel da homepage
│   └── wordpress.py         # Resumo de wpscan
├── systemd/
│   ├── mini-asm.service
│   └── mini-asm.timer
├── cache/  database/  logs/  results/    # Criadas pelo install.sh
```

---

## Pré-requisitos

- **Python 3.12+** com `python3-venv`.
- **Linux** (Debian/Kali). Funciona em outros Unix, mas `install.sh` assume `apt` / `crontab`.
- Ferramentas externas no `PATH` (todas opcionais — o pipeline degrada com elegância se faltar algo, mas o útil é tê-las):
  - `httpx` (ProjectDiscovery), `nuclei`, `subfinder`, `assetfinder`
  - `whatweb`, `wpscan`, `sqlmap`
  - `smbclient`, `rpcclient`

O `install.sh` apenas avisa o que falta — não instala estas ferramentas.

---

## Instalação rápida

```bash
git clone https://github.com/Samuel-Ziger/WorkFlowVPS.git recon
cd recon
cp .env.example .env       # preencha os tokens/webhooks
chmod +x install.sh
./install.sh
```

O script cria `.venv`, instala dependências, prepara diretórios, regista um cron em **06:00 e 18:00** e dispara uma **baseline silenciosa** (`--once --no-notify`) para popular a base de dados sem inundar o Discord.

### Instalação manual

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
mkdir -p logs cache results database
cp .env.example .env   # editar
python main.py --once --no-notify
```

---

## Configuração

### `.env`

Variáveis sensíveis (nunca commitar — já está no `.gitignore`):

| Variável | Uso |
|---|---|
| `ASM_DISCORD_NEWS` | Webhook do canal de novidades. |
| `ASM_DISCORD_ERROR` | Webhook do canal de erros do pipeline. |
| `ASM_DATABASE_URL` | Opcional. Se definido, o banco interno do workflow usa Postgres em vez de `database/asm.db`. |
| `GHOSTRECON_SOURCE_DATABASE_URL` | Opcional. DSN Postgres de leitura para `runs`, `findings` e `bounty_intel` gravadas pelo GhostRecon. |
| `GEMINI_API_KEY` | Sumário das novidades e explicação de erros. Opcional (fallback determinístico). |
| `GITHUB_TOKEN` | OSINT GitHub (code-search) sobre hosts novos. |
| `WPSCAN_API_TOKEN` | Vulns enriquecidas no `wpscan`. |
| `VIRUSTOTAL_API_KEY` | Reservado para integrações futuras. |
| `OPENROUTER_API_KEY` / `GHOSTRECON_OPENROUTER_MODEL` | Hooks com a stack GhostRecon. |
| `SUPABASE_URL` / `SUPABASE_PUBLISHABLE_KEY` | Hooks com a stack GhostRecon. |

### `config.yaml`

Os campos mais relevantes:

| Campo | Default | Descrição |
|---|---|---|
| `interval_hours` | `12` | Intervalo do scheduler interno (modo contínuo). |
| `source_postgres.enabled` | `true` | **Modo ativo.** Lê incrementalmente o Postgres do GhostRecon (runs/findings/bounty_intel). |
| `source_sqlite_globs` | `[]` | Desligado no modo Postgres. Fallback opcional para bases `.db` locais. |
| `source_ndjson_paths` | `[]` | NDJSON com `url`/`host`/`value`/`findings`. |
| `database_url_env` | `ASM_DATABASE_URL` | Variavel que ativa Postgres para o banco interno do workflow. |
| `database_path` | `database/asm.db` | SQLite do Mini-ASM. |
| `max_hosts_per_cycle` | `120` | Limite de hosts revalidados por ciclo (além dos novos). |
| `concurrency.*`, `timeouts.*` | — | Calibrados para uma VPS pequena. |
| `nuclei_tags`, `nuclei_severity`, `nuclei_rate_limit` | `exposure,…` / `info–critical` / `15` | Perfil leve para evitar scans agressivos. |
| `collector.enabled` | `true` | Liga `subfinder` + `assetfinder` em novos ápices. |
| `discord.suppress_full_first_baseline` | `true` | Não notifica em ciclos com 100+ eventos quando a base ainda está vazia. |
| `discord.no_news_message` | mensagem PT | Texto fixo quando o ciclo não traz novidades. |
| `gemini.model` | `gemini-2.0-flash` | Modelo do resumo. |
| `github.*` | — | Limites e paginação do OSINT. |
| `sqlmap.enabled` | `false` | Liga `sqlmap` em parâmetros "bons" (ex.: `?id=numérico`). |

Os webhooks podem ser definidos no `.env` (preferido) **ou** no `config.yaml`. O `.env` tem prioridade.

### Modo Postgres na VPS (ativo por padrão)

Este é o modelo atual: o GhostRecon (na máquina de recon) grava direto no Postgres **desta VPS** via `DATABASE_URL`, e o workflow lê o **mesmo** banco. `source_postgres.enabled: true` já vem ligado no `config.yaml`.

```env
# .env do WorkFlowVPS na VPS (Postgres local da VPS)
ASM_DATABASE_URL=postgresql://asm_worker:SENHA@127.0.0.1:5432/ghostworkflow
GHOSTRECON_SOURCE_DATABASE_URL=postgresql://asm_reader:SENHA@127.0.0.1:5432/ghostworkflow
```

No lado do **GhostRecon** (na máquina de recon), aponte para o Postgres da VPS:

```env
# .env do GhostRecon
GHOSTRECON_SUPABASE_AUTO=1
DATABASE_URL=postgresql://ghostrecon:SENHA@SEU_IP_VPS:5432/ghostworkflow
GHOSTRECON_DATABASE_SSL=1   # se a conexão exigir TLS
```

> Exponha o Postgres da VPS com cuidado: prefira `pg_hba`/firewall restringindo ao IP de recon, ou um túnel SSH (`ssh -L 5432:127.0.0.1:5432 vps`) e use `127.0.0.1` no `DATABASE_URL`.

Se quiser usar o mesmo usuario/DSN para o estado do workflow e para ler os runs do GhostRecon, deixe `GHOSTRECON_SOURCE_DATABASE_URL` vazio; o `fallback_dsn_env: ASM_DATABASE_URL` sera usado.

#### Setup do Postgres na VPS (uma vez)

```bash
# 1) Postgres
sudo apt update && sudo apt install -y postgresql

# 2) Banco + usuario (ajuste a senha)
sudo -u postgres psql <<'SQL'
CREATE DATABASE ghostworkflow;
CREATE USER ghost WITH PASSWORD 'TROQUE_A_SENHA';
GRANT ALL PRIVILEGES ON DATABASE ghostworkflow TO ghost;
SQL

# 3) Schema do GhostRecon (runs / findings / bounty_intel)
psql "postgresql://ghost:TROQUE_A_SENHA@127.0.0.1:5432/ghostworkflow" -f sql/ghostrecon_schema.sql

# 4) .env do WorkFlowVPS
#   ASM_DATABASE_URL=postgresql://ghost:TROQUE_A_SENHA@127.0.0.1:5432/ghostworkflow
#   GHOSTRECON_SOURCE_DATABASE_URL=postgresql://ghost:TROQUE_A_SENHA@127.0.0.1:5432/ghostworkflow

# 5) Testar o ciclo
.venv/bin/python main.py --once --no-notify
```

Enquanto o GhostRecon ainda não grava nesse Postgres, as tabelas ficam vazias e o ciclo
roda sem hosts — o aviso `nenhum DSN foi encontrado` desaparece assim que o `.env` acima existir.

---

## Uso

```bash
# Ciclo único (ideal para cron)
python main.py --once

# Ciclo único sem notificações (baseline ou debug)
python main.py --once --no-notify

# Config alternativo
python main.py --once --config /caminho/para/outro.yaml

# Modo contínuo (APScheduler — usa interval_hours do config.yaml)
python main.py
```

### Cron (instalado por `install.sh`)

```
0 6,18 * * * cd /opt/recon && /opt/recon/.venv/bin/python /opt/recon/main.py --once --config /opt/recon/config.yaml >> /opt/recon/logs/cron.log 2>&1
```

### systemd

```bash
sudo cp systemd/mini-asm.service /etc/systemd/system/
sudo cp systemd/mini-asm.timer   /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now mini-asm.timer
systemctl list-timers | grep mini-asm
```

O `mini-asm.timer` dispara o `service` cinco minutos depois do boot e a cada 12 horas.

---

## Notificações

- **Canal `news`**: mensagem em PT-PT com um resumo das novidades do ciclo (Gemini). Sem novidades → mensagem fixa configurável. Primeira execução grande → suprimida.
- **Canal `error`**: stack trace recortado (~3500 chars) + explicação do Gemini, com `error_explain_retries` para resiliência.

Se faltar o webhook, o evento é só logado.

---

## Logs e dados

- `logs/asm_<timestamp>.log` — `loguru` com rotação (`10 MB`) e retenção (`7 days`).
- `logs/cron.log` — saída do cron.
- `database/asm.db` — assets, ciclos e cursores de leitura.
- `results/last_nuclei.json` — últimos 500 achados crus do `nuclei`.
- `cache/` — workspace temporário do `subfinder` etc.

---

## Aviso legal

Esta ferramenta é destinada **exclusivamente** a testes de segurança autorizados (bug bounty in-scope, pentests contratados, infra própria). Operar contra alvos sem autorização escrita é ilegal. O autor não se responsabiliza por uso indevido.

---

## Licença

Sem licença explícita — todos os direitos reservados ao autor enquanto não for adicionada uma. Abra uma issue se pretende reutilizar.
