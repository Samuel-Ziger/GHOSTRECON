# GHOSTRECON — Tor routing

Documento da camada Tor: como o pipeline de recon sai pela rede Tor com
isolation por target, NEWNYM programático, DNS leak detection e enforcement.

> Foco red-team / bug bounty. Quando o programa de bounty pede sair de IP
> dedicado, **desligue** o enforcement Tor. Quando precisa de anonimato real
> contra o alvo, **ligue** `tor.required=true` + `perTargetCircuit=true`.

## Componentes

```
tools/Navegation/navegation.sh      ─ instala+configura /etc/tor/torrc
server/modules/navegation.js        ─ wrapper, status, validateTorPath
server/modules/tor-control.js       ─ ControlPort: NEWNYM, GETINFO, health
server/modules/socks5-dispatcher.js ─ undici Agent que tunela fetch via SOCKS5
server/modules/identity-controller  ─ ativa o dispatcher no fetch do recon
server/index.js                     ─ /api/tunnel/* + tor.required no /recon/stream
```

## Configuração de Tor (torrc) aplicada pelo playbook

```ini
SocksPort 127.0.0.1:9050 IsolateDestAddr IsolateClientAuth IsolateSOCKSAuth
TransPort 127.0.0.1:9040
DNSPort 127.0.0.1:5353
VirtualAddrNetwork 10.192.0.0/10
AutomapHostsOnResolve 1
ControlPort 127.0.0.1:9051
CookieAuthentication 1
CookieAuthFileGroupReadable 1
AvoidDiskWrites 1
ClientUseIPv4 1
ClientUseIPv6 0
SafeSocks 1
WarnUnsafeSocks 1
```

Decisões:

- **SocksPort 9050 com isolation flags** — `IsolateDestAddr` cria circuit
  novo por host de destino; `IsolateSOCKSAuth` cria circuit por
  par `(user,pass)` no SOCKS handshake. O `socks5-dispatcher.js` injecta
  user/pass únicos por target quando `perTargetCircuit=true` ⇒ alvo X e Y
  saem por circuits independentes, mesmo no mesmo run.
- **TransPort 9040** (não 9050). 9050 é convenção do SocksPort; juntar tudo
  no mesmo porto era o bug do template anterior.
- **DNSPort 5353** evita conflito com systemd-resolved/dnsmasq e não exige
  porta privilegiada.
- **ControlPort 9051 + cookie** — o `tor-control.js` lê o cookie binário
  (`/run/tor/control.authcookie`, 32 bytes) e autentica por handshake. Permite
  emitir `SIGNAL NEWNYM`, `GETINFO status/bootstrap-phase`, `circuit-status`.
- **SafeSocks 1** rejeita SOCKS clientes que façam DNS local (forçando o uso
  de `socks5h://` no pool — mitigação contra DNS leak.

## Pool de proxies

```bash
# .env
GHOSTRECON_PROXY_POOL=socks5h://127.0.0.1:9050
GHOSTRECON_TOR_ISOLATE=1
GHOSTRECON_TOR_REQUIRED=1   # opcional, força enforcement
```

`identity-controller.mjs` detecta `socks5://` ou `socks5h://` no pool e usa
o **`socks5-dispatcher.js`** em vez do `undici.ProxyAgent` (que só fala HTTP
CONNECT). Sem isto, qualquer entry SOCKS5 era silenciosamente ignorada.

## Body do `/api/recon/stream`

```json
{
  "domain": "example.com",
  "modules": ["dns", "probe", "wayback"],
  "tor": {
    "required": true,
    "newnymBeforeRun": true,
    "perTargetCircuit": true,
    "dnsLeakHost": "check.torproject.org"
  }
}
```

Comportamento por flag:

- `required: true` → antes do pipeline, executa `quickValidateTor`. Aborta com
  `error` no stream se: (a) o IP via SOCKS5 == IP directo, (b) `IsTor=false`
  no check.torproject.org, (c) bootstrap não está em `done`.
- `newnymBeforeRun: true` → emite `SIGNAL NEWNYM` no ControlPort antes do
  primeiro fetch.
- `perTargetCircuit: true` (default quando `required=true`) → injecta
  `user:pass` únicos no `socks5h://...@127.0.0.1:9050` para que o Tor crie
  circuit dedicado a este target.

## Endpoints

| Rota                     | Verbo | Scope          | Descrição                                  |
|--------------------------|-------|----------------|---------------------------------------------|
| `/api/tunnel/status`     | GET   | recon.read     | Estado dos serviços systemd (tor, openvpn) |
| `/api/tunnel/health`     | GET   | recon.read     | ControlPort: bootstrap, version, circuits  |
| `/api/tunnel/validate`   | GET   | recon.read     | Validação completa (IP+IsTor+DNS leak)     |
| `/api/tunnel/newnym`     | POST  | recon.run      | Emite `SIGNAL NEWNYM` (CSRF + auth)        |
| `/api/tunnel/enable`     | POST  | role: admin    | Corre `navegation.sh up`                   |
| `/api/tunnel/disable`    | POST  | role: admin    | Corre `navegation.sh down`                 |

## DNS leak detection

`validateNavegationTorPath` compara:

1. **IP directo** — `curl https://api.ipify.org`.
2. **IP via Tor** — `curl --socks5-hostname 127.0.0.1:9050 https://check.torproject.org/api/ip`.
3. **DNS direto** — `dns.resolve4('check.torproject.org')` no Node.

Se IP directo == IP via Tor → **proxy bypass** (Tor não está a ser usado).
Se DNS direto resolve mas o pipeline não usa SOCKS5h → potencial DNS leak
(o resolver do SO sabe quais hosts vamos visitar). O documento marca
`dnsLeak.systemDnsActive=true` como sinal informativo.

Para zero DNS leaks: usar `socks5h://` (não `socks5://`) no pool.

## Stream isolation (circuit por target)

Sem isolation, todos os requests do run partilham circuit. Adversário com
observação no exit + entry node consegue correlacionar. Com
`IsolateSOCKSAuth` activo no torrc + user/pass únicos no SOCKS handshake,
cada `(user,pass)` resulta num circuit dedicado.

`socks5-dispatcher.js` exporta `isolatedSocksUser(prefix, salt)` e
`injectIsolationCredentials(href, user, pass)` para o caller construir
URLs como:

```
socks5h://gr-iso-lqj7l8x-9k7d2x:eng-xpto@127.0.0.1:9050
```

O `identity-controller.mjs` aplica isto automaticamente quando
`opts.isolate=true` (que `GHOSTRECON_TOR_ISOLATE=1` ou `tor.perTargetCircuit`
ativam).

## NEWNYM programático

O ControlPort permite ao Node sinalizar Tor a usar circuits novos para
streams subsequentes (não corta circuits existentes — é "next streams"
apenas).

```js
import { newnym } from './server/modules/tor-control.js';
await newnym();              // depende do cookie em /run/tor/control.authcookie
```

Cookie auth:
- Default: `/run/tor/control.authcookie`, `/var/run/tor/control.authcookie`,
  `/var/lib/tor/control_authcookie`. O Node precisa de permissão de leitura
  (CookieAuthFileGroupReadable 1 no torrc + utilizador no grupo `debian-tor`).
- Override: `GHOSTRECON_TOR_CONTROL_COOKIE_PATH=/path/custom`.
- Fallback password: `GHOSTRECON_TOR_CONTROL_PASSWORD=plaintext` (raw, não
  o hash; o Node faz `AUTHENTICATE "..."`).

Limite: o Tor só aceita NEWNYM a cada **10 segundos** por default.

## Bridges (obfs4)

Para alvos/redes que bloqueiam saídas Tor conhecidas:

```bash
export GHOSTRECON_TOR_BRIDGES='obfs4 1.2.3.4:443 ABCDEF... cert=... iat-mode=0
obfs4 5.6.7.8:443 GHIJKL... cert=... iat-mode=0'
sudo bash tools/Navegation/navegation.sh up
```

O playbook injecta `UseBridges 1`, `ClientTransportPlugin obfs4 ...` e cada
linha do env como `Bridge ...` no torrc.

## Modo "tor-strict" — anti-leak central

Toggle único `GHOSTRECON_TOR_STRICT=1` (ou `tor.strict=true` no body do
`/api/recon/stream`) activa um pacote completo de hardening anti-leak:

1. **Node DNS lockdown** — `dns.setServers(['127.0.0.1:5353'])` aponta o
   resolver do processo para o `DNSPort` do Tor, e
   `dns.setDefaultResultOrder('ipv4first')` evita AAAA queries que possam
   bind por outro stack. Qualquer `dns.resolve*` do código nosso ou de libs
   passa por Tor.

2. **proxychains.conf efémero** — `server/modules/tor-strict.js` escreve em
   `<repo>/.runtime/proxychains.conf` um config com:
   ```
   strict_chain
   proxy_dns
   remote_dns_subnet 224
   tcp_read_time_out 15000
   tcp_connect_time_out 8000
   [ProxyList]
   socks5  127.0.0.1 9050
   ```
   `strict_chain` recusa ligar se o SOCKS falhar (em vez de fallback para
   directo); `proxy_dns` tunela queries DNS pela própria SOCKS.

3. **Wrap automático de tools externas** — `kali-scan.js`, `sqlmap-runner.js`,
   `curl-probe.mjs` chamam `wrapCommand(cmd, args)` antes de cada `spawn()`.
   Defaults wrap-eados:
   ```
   nmap masscan rustscan
   ffuf gobuster dirsearch feroxbuster wfuzz
   nuclei dalfox wpscan sqlmap
   curl wget httpx
   whois
   dig nslookup host drill
   amass subfinder assetfinder shuffledns
   ```
   Comandos não-listados (`python3`, `node`, `bash`) **não** são wrapped — só
   tools externas que fazem rede. Para acrescentar: `GHOSTRECON_TOR_STRICT_WRAP_ADD="rustscan,zmap"`.

4. **Refuse to run** — quando o wrapper falha (e.g. `proxychains4` não está
   no `$PATH`), `wrapCommand()` devolve `refuse:true` e o caller aborta com
   erro explícito. **Não há fallback silencioso para directo.**

5. **Header hygiene** — `identity-controller.mjs` chama
   `sanitizeOutboundHeaders()` antes de cada fetch:
   - **Strip:** `Referer`, `Origin`, `X-Forwarded-For`, `X-Real-IP`,
     `X-Client-IP`, `CF-Connecting-IP`, `True-Client-IP`,
     `X-Cluster-Client-IP`, `Forwarded`, `Via`, e cookies cujo `domain=`
     não bata o target.
   - **Substituir:** `User-Agent` por `Mozilla/5.0 (Windows NT 10.0; rv:115.0)
     Gecko/20100101 Firefox/115.0` (Tor Browser-like), `Accept-Language`
     por `en-US,en;q=0.5`, `DNT: 1`, `Upgrade-Insecure-Requests: 1`.
   - **Remove:** `sec-ch-ua*` (Chrome client-hints que delatam fingerprint).

6. **Bloqueio de fetch directo** — quando o identity controller não
   consegue obter um dispatcher SOCKS, `fetchWithPolicy` lança
   `'tor-strict: dispatcher SOCKS não disponível — fetch directo bloqueado'`
   em vez de cair para `fetch()` directo.

7. **Auto-config** — `initTorStrict()` activa ao boot:
   - `GHOSTRECON_PROXYCHAINS=1`
   - `GHOSTRECON_PROXYCHAINS_CONF=<.runtime/proxychains.conf>`
   - `GHOSTRECON_PROXYCHAINS_QUIET=1`
   - `GHOSTRECON_PROXY_POOL=socks5h://127.0.0.1:9050` (se vazio)
   - `GHOSTRECON_TOR_ISOLATE=1` (se vazio)
   - `GHOSTRECON_TOR_REQUIRED=1` (se vazio)

### Pré-requisitos validados antes de cada run strict

`strictPrereqs()` valida 7 sinais:
| name              | check                                                    |
|-------------------|----------------------------------------------------------|
| proxychains4      | binary no `$PATH`                                        |
| tor.socks         | TCP connect a 127.0.0.1:9050                              |
| tor.dns           | UDP listener / TCP connect a 127.0.0.1:5353               |
| tor.control       | TCP connect a 127.0.0.1:9051                              |
| proxychains.conf  | ficheiro existe e é legível                               |
| node.dns.locked   | `dns.getServers()` inclui `:5353`                         |
| proxy_pool.socks  | `GHOSTRECON_PROXY_POOL` contém `socks5*://`              |

Se algum falhar, `/api/recon/stream` aborta com `error: 'tor.strict: pré-requisitos em falta'`
e lista `missing: [...]`. Ver `/api/tunnel/strict-check` para diagnóstico.

### Endpoints adicionais do strict

| Rota                                | Verbo | Scope        | Descrição                              |
|-------------------------------------|-------|--------------|----------------------------------------|
| `/api/tunnel/strict-check`          | GET   | recon.read   | Resultado de `strictPrereqs()`         |
| `/api/tunnel/telemetry/:runId`      | GET   | recon.read   | requests, requestsViaTor, exitIps, ratio|

### Telemetria por run

`identity-controller.mjs` em strict mantém contadores:
```json
{
  "requests": 142,
  "requestsViaTor": 142,
  "newnyms": 3,
  "exitIps": ["185.220.101.5", "185.220.101.42"],
  "leaksDetected": 0,
  "proxyKindCounts": { "direct": 0, "http": 0, "socks": 142 },
  "torRatio": 1.0
}
```

Use `/api/tunnel/telemetry/<requestRunId>` (o `requestRunId` vem no primeiro
evento `meta` do stream NDJSON).

### Verificar que funciona

```bash
sudo bash tools/Navegation/navegation.sh up

cat >> .env <<EOF
GHOSTRECON_TOR_STRICT=1
EOF

npm run start:api
# stdout deve ter: [tor-strict] activo {...}

curl -H "Authorization: Bearer $KEY" http://127.0.0.1:3847/api/tunnel/strict-check
# {"ok":true, "checks":[...], "missing":[]}

curl -H "Authorization: Bearer $KEY" -H "X-CSRF-Token: $CSRF" \
  -X POST http://127.0.0.1:3847/api/recon/stream \
  -d '{"domain":"example.com","modules":["dns","probe"],"tor":{"strict":true,"newnymBeforeRun":true}}' | head -10
# meta event com requestRunId, depois logs

# Validar: nenhuma query DNS para o target deve aparecer no resolver de sistema
sudo tcpdump -i any 'port 53 and not port 5353' &
# … run … tcpdump deve ficar vazio para o domínio target
```

### Limitações conhecidas

- Em **Windows**, `bash`/`/dev/tcp` não estão disponíveis: `strictPrereqs()`
  marca os checks de TCP/UDP como OK por falta de probe — não é validação
  real. Usa Linux/WSL para strict.
- Algumas tools (e.g. `nmap -sU` para UDP scan) não funcionam por SOCKS
  porque proxychains só intercepta TCP. Em strict, scans UDP são bloqueados
  efectivamente — usa `--privileged` + `nmap-tor` patch ou aceita que UDP
  recon é incompatível com Tor.
- Se o alvo bloqueia exit nodes Tor, vais ver muitos 403/captcha. Usa
  bridges obfs4 ou aceita o leak operacional de sair sem Tor.

## Audit

Eventos relevantes no `logs/audit-YYYY-MM-DD.ndjson`:

```json
{"action":"recon.stream.start","tor":{"required":true,"exitIp":"185.220.101.5","bootstrap":"done","perTargetCircuit":true,"newnymBefore":true}}
{"action":"recon.stream.tor_required","decision":"deny","reason":"tor_validation_failed"}
{"action":"tunnel.newnym","ok":true}
```

## Limitações conhecidas

- O DNS leak test é heurístico. Para validação real, capturar tráfego
  `/dev/eth0` durante um run e verificar se há queries DNS para o domínio
  alvo fora da porta 9050.
- ControlPort cookie path varia conforme distro / build do Tor — o módulo
  testa 3 candidatos default e respeita override.
- IPv6 literal não é suportado pelo dispatcher inline (use `socks5h://` +
  hostname).
- NEWNYM tem rate-limit interno do Tor (≥10s entre sinais).
