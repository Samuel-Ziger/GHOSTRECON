# GhostCommand

Android control app for the GHOSTRECON VPS.

The app calls the VPS endpoints:

- `GET /api/ghostcommand/status`
- `POST /api/ghostcommand/recon`
- `POST /api/ghostcommand/gate/close`

Required headers:

- `X-API-Key`: a GHOSTRECON API key with `recon.run`
- `X-GhostCommand-Key`: the mobile command key from `.env`

The VPS also enforces the source IP allowlist. Default allowed IP:

```text
162.243.54.185
```

If the public HTTPS endpoint is behind Nginx/Caddy and Node receives traffic from
`127.0.0.1`, set this in `.env` so the server reads the first `X-Forwarded-For`
only from the trusted local proxy:

```env
GHOSTRECON_TRUST_PROXY=1
```

Keep firewall rules limited to the VPN IP whenever possible.

## VPS Setup

From the GHOSTRECON repository on the VPS:

```bash
bash scripts/setup-ghostcommand-vps.sh
sudo systemctl restart ghostrecon-api.service
```

The setup script creates:

- `GHOSTCOMMAND_API_KEY`
- `GHOSTCOMMAND_ALLOWED_IP=162.243.54.185`
- `ghostcommand-open.timer`, opening the gate daily at 08:00 America/Sao_Paulo

Manual gate commands:

```bash
node server/scripts/ghostcommand-gate.mjs status
node server/scripts/ghostcommand-gate.mjs open manual
node server/scripts/ghostcommand-gate.mjs close manual
```

## App Setup

Generate a one-line setup token on the VPS and paste it into the app:

```bash
node server/scripts/ghostcommand-mobile-config.mjs http://IP_DA_VPS:3847
```

It prints:

```text
GHOSTCOMMAND_CONFIG=...
```

Open GhostCommand, paste that line into `Cole GHOSTCOMMAND_CONFIG`, tap
`Importar configuracao`, then `Salvar configuracao`. After saving, the app hides
the VPS/API key fields and keeps only the target command screen. Use `Editar` to
change the saved config later.

For direct IP testing, the app allows HTTP cleartext traffic. For production,
prefer HTTPS through a reverse proxy or private tunnel.

## API Smoke Test

Run this from the allowed IP/VPN path:

```bash
export VPS='https://your-vps.example'
export GHOSTRECON_KEY='...'
export GHOSTCOMMAND_KEY='...'

curl -sS "$VPS/api/ghostcommand/status" \
  -H "X-API-Key: $GHOSTRECON_KEY" \
  -H "X-GhostCommand-Key: $GHOSTCOMMAND_KEY"

curl -sS -X POST "$VPS/api/ghostcommand/recon" \
  -H "Content-Type: application/json" \
  -H "X-API-Key: $GHOSTRECON_KEY" \
  -H "X-GhostCommand-Key: $GHOSTCOMMAND_KEY" \
  -d '{"target":"example.com"}'
```
