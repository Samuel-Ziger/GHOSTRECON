# GhostWatch VPS — sentinela full-stack

Operação contínua de bug bounty numa VPS privada: lê `domains.txt`, atualiza CVEs, roda `full-recon` + Vigolium (deep/Codex) + FrameSeven, compara com o run anterior e alerta no Discord **somente** novidades.

## Bootstrap (um comando)

```bash
bash scripts/setup-ghostrecon-vps.sh
```

O script:

1. Faz patch idempotente do `.env` (preserva secrets; força flags VPS)
2. `chmod 600 .env`
3. Cria `domains.txt` template se não existir
4. Instala deps / symlink `ghostrecon` (opcional `--skip-deps`)
5. Instala systemd:
   - `ghostrecon-api.service` (API em `127.0.0.1`)
   - `ghostrecon-ghostwatch.service` (oneshot + `flock`)
   - timer **01:00** e **10:00** (`America/Sao_Paulo`)
6. Valida webhook, bins (Vigolium/FrameSeven/Codex) e tools Kali

Flags úteis:

```bash
bash scripts/setup-ghostrecon-vps.sh --dry-run
bash scripts/setup-ghostrecon-vps.sh --skip-systemd   # só .env + domains
bash scripts/setup-ghostwatch-vps.sh                  # alias → mesmo script
```

## domains.txt

Um apex/host por linha. Comentários com `#`.

```text
# meus programas
exemplo.com
alvo2.com
```

Sync manual:

```bash
npm run cli -- ghostwatch sync-domains --file domains.txt
# primeira vez (cria baseline sem Discord):
npm run cli -- ghostwatch sync-domains --file domains.txt --bootstrap --confirm-active --start-server
```

No sweep agendado, o GhostWatch sincroniza o arquivo automaticamente (`GHOSTWATCH_SYNC_DOMAINS=1`).

## Ciclo de um sweep

1. `flock` — se o ciclo anterior ainda roda, o novo sai sem overlap
2. Sync `domains.txt` → watchlist (novos enable; removidos disable)
3. `ensure-cve-web-db` (TTL 24h; falha de rede **não** aborta)
4. Por alvo, sequencial:
   - sem baseline → pula (ou roda se `--bootstrap`)
   - preflight do plano efetivo
   - se intrusivo: **trusted-operator** aprova via API (gates abaixo)
   - stream: full-recon + `engine=both` + `strategy=deep` + Codex + FrameSeven
5. Diff vs run anterior → Discord se `only-new` + severidade ≥ medium

## Trusted operator (aprovação headless)

Todas as condições são obrigatórias:

| Gate | Valor |
|---|---|
| `GHOSTWATCH_TRUSTED_OPERATOR` | `1` |
| `--confirm-active` / `GHOSTWATCH_CONFIRM_ACTIVE` | ligado |
| API key | role `red` ou `admin` em `AUTH_API_KEYS` |
| Alvo | presente e enabled na watchlist / `domains.txt` |
| API | URL loopback (`127.0.0.1` / `localhost`) |

Sem isso o GhostWatch **falha fechado** (não inicia stream intrusivo).

## Bloco `.env` VPS

```bash
HOST=127.0.0.1
GHOSTWATCH_TRUSTED_OPERATOR=1
GHOSTWATCH_CONFIRM_ACTIVE=1
GHOSTWATCH_PLAYBOOK=full-recon
GHOSTWATCH_OPSEC_PROFILE=aggressive
GHOSTWATCH_INCLUDE_FRAMESEVEN=1
GHOSTWATCH_CVE_UPDATE=1
GHOSTWATCH_SYNC_DOMAINS=1
GHOSTRECON_ENGINE=both
GHOSTRECON_VIGOLIUM_STRATEGY=deep
GHOSTRECON_VIGOLIUM_USE_CODEX=1
GHOSTRECON_VIGOLIUM_VPS_PROFILE=1
GHOSTRECON_CVE_AUTO_UPDATE=1
GHOSTRECON_CVE_AUTO_UPDATE_TTL_HOURS=24
GHOSTRECON_NAVIGATOR_MODE=0
GHOSTRECON_TOR_REQUIRED=0
GHOSTRECON_TOR_STRICT=0
GHOSTRECON_WEBHOOK_URL=https://discord.com/api/webhooks/...
```

Webhook: use `GHOSTRECON_WEBHOOK_URL` (também aceita `GHOSTWATCH_WEBHOOK` / `DISCORD_WEBHOOK`).

## O que roda / o que não roda

**Liga:** módulos do `full-recon`, Kali tools no PATH, Vigolium deep + Codex, FrameSeven `offensive_v1`.

**Desliga:** Tor, Navigator, proxychains, FrameSeven `-auth-browser` (sem sessão autenticada unattended).

Módulos que dependem de credenciais externas auto-pulam se a env faltar.

## Operação diária

```bash
# status
systemctl status ghostrecon-api.service
systemctl list-timers | grep ghostrecon-ghostwatch

# forçar um ciclo agora
sudo systemctl start ghostrecon-ghostwatch.service

# logs
journalctl -xeu ghostrecon-ghostwatch.service --no-pager -n 120

# watchlist
npm run cli -- ghostwatch list
```

## Discord

- Baseline / primeiro run → **silêncio**
- Sem novidade ≥ medium → **silêncio**
- Novidade → mensagem GhostWatch com contagem, hosts novos e findings notáveis
- Fingerprint evita spam do mesmo delta

## Pré-requisitos na VPS

- Node ≥ 20, npm, python3 (coletor CVE)
- Binário Vigolium (`engines/vigolium` ou PATH)
- FrameSeven CLI (`FrameSeven/bin/frameseven/cli/v1`)
- Codex no PATH + login/plano (se `USE_CODEX=1`)
- Ferramentas Kali desejadas: nmap, nuclei, ffuf, subfinder, …
- Autorização explícita dos alvos em `domains.txt` (bug bounty / escopo próprio)

## Segurança

- API só em loopback
- Nunca `AUTH_DISABLE=1` em interface pública
- `.env` com permissão `600`
- Trusted-operator **não** substitui autorização do programa de bug bounty
- `STORAGE=sqlite` local é o caminho default; `DATABASE_URL` postgres só entra se mudar `GHOSTRECON_STORAGE` / sync
