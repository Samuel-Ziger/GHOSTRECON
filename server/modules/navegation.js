import { access, mkdir, readFile, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import dns from 'node:dns/promises';
import net from 'node:net';
import { spawn } from 'node:child_process';
import { torHealth, ensureBootstrapped } from './tor-control.js';
import { runProcess } from './module-runner.mjs';

const USER_TORRC_LINES = [
  'SocksPort 127.0.0.1:9050 IsolateDestAddr IsolateClientAuth IsolateSOCKSAuth',
  'TransPort 127.0.0.1:9040',
  'DNSPort 127.0.0.1:5353',
  'VirtualAddrNetwork 10.192.0.0/10',
  'AutomapHostsOnResolve 1',
  'ControlPort 127.0.0.1:9051',
  'CookieAuthentication 1',
  'CookieAuthFileGroupReadable 1',
  'AvoidDiskWrites 1',
  'ClientUseIPv4 1',
  'ClientUseIPv6 0',
  'SafeSocks 1',
  'WarnUnsafeSocks 1',
];

/** Modo Navigator activo — só então o pipeline toca em Navegation/Tor setup. */
export function isNavigatorModeActive({ navigatorMode = false, navegation = null } = {}) {
  if (navigatorMode === true) return true;
  if (navegation && typeof navegation === 'object' && navegation.enabled === true) return true;
  return String(process.env.GHOSTRECON_NAVIGATOR_MODE || '0').trim() === '1';
}

function sleep(ms) {
  return new Promise((r) => setTimeout(r, ms));
}

function portOpen(host, port, timeoutMs = 1200) {
  return new Promise((resolve) => {
    const sock = net.connect({ host, port });
    const t = setTimeout(() => {
      try {
        sock.destroy();
      } catch {
        /* ignore */
      }
      resolve(false);
    }, timeoutMs);
    sock.on('connect', () => {
      clearTimeout(t);
      try {
        sock.destroy();
      } catch {
        /* ignore */
      }
      resolve(true);
    });
    sock.on('error', () => {
      clearTimeout(t);
      resolve(false);
    });
  });
}

/**
 * Tor em modo utilizador: torrc em .runtime/tor/ — sem sudo, sem /etc/tor/torrc.
 */
export async function ensureUserTorStack(rootDir, opts = {}) {
  const torDir = join(rootDir, '.runtime', 'tor');
  const dataDir = join(torDir, 'data');
  const torrcPath = join(torDir, 'torrc');
  const pidFile = join(torDir, 'tor.pid');
  await mkdir(dataDir, { recursive: true });

  const torrc = [
    `DataDirectory ${dataDir}`,
    `PidFile ${pidFile}`,
    ...USER_TORRC_LINES,
    '',
  ].join('\n');
  await writeFile(torrcPath, torrc, 'utf8');

  const socksHost = String(opts.socksHost || '127.0.0.1');
  const socksPort = Number(opts.socksPort || 9050);
  if (await portOpen(socksHost, socksPort)) {
    return {
      ok: true,
      started: false,
      userMode: true,
      torrcPath,
      message: `Tor já activo em ${socksHost}:${socksPort}`,
    };
  }

  let child = null;
  try {
    child = spawn('tor', ['-f', torrcPath], {
      detached: true,
      stdio: 'ignore',
    });
    child.once('error', () => {
      /* Tor is optional in tests and user-mode setup can report a clean failure. */
    });
    child.unref();
  } catch {
    /* Tor missing or not spawnable; the port check below will return ok=false. */
  }

  const waitMs = Math.max(500, Number(opts.bootstrapWaitMs || 2500));
  await sleep(waitMs);
  const up = await portOpen(socksHost, socksPort, 2000);
  return {
    ok: up,
    started: up,
    userMode: true,
    torrcPath,
    message: up
      ? `Tor iniciado (modo utilizador, ${torrcPath})`
      : 'Tor não respondeu em 127.0.0.1:9050 — instala `tor` no PATH ou activa o serviço manualmente',
  };
}

function toStep(line) {
  const s = String(line || '').trim();
  if (!s || s.startsWith('#')) return null;
  return s;
}

export async function loadNavegationPlaybook(rootDir) {
  const toolsDir = join(rootDir, 'tools', 'Navegation');
  const legacyDir = join(rootDir, 'node_modules', 'Navegation');
  const candidates = [
    join(toolsDir, 'navegation.sh'),
    join(toolsDir, 'navegation.py'),
    join(legacyDir, 'navegation.sh'),
    join(legacyDir, 'navegation.py'),
  ];
  let filePath = '';
  for (const p of candidates) {
    try {
      await access(p);
      filePath = p;
      break;
    } catch {
      /* try next */
    }
  }
  if (!filePath) throw new Error('Navegation playbook não encontrado em tools/Navegation nem node_modules/Navegation');
  const raw = await readFile(filePath, 'utf8');
  const steps = raw
    .split(/\r?\n/)
    .map(toStep)
    .filter(Boolean)
    .slice(0, 80);
  return { filePath, steps };
}

export async function executeNavegationPlaybook(rootDir, opts = {}) {
  const userMode = opts.userMode !== false && String(process.env.GHOSTRECON_NAVEGATION_SYSTEM || '0').trim() !== '1';
  const action = String(opts.action || 'up').trim().toLowerCase();

  if (userMode && action === 'up') {
    const stack = await ensureUserTorStack(rootDir, opts);
    return {
      ok: stack.ok,
      code: stack.ok ? 0 : 1,
      command: 'tor -f .runtime/tor/torrc (user mode)',
      stdout: stack.message || '',
      stderr: stack.ok ? '' : stack.message || '',
      timedOut: false,
      filePath: stack.torrcPath,
      userMode: true,
    };
  }

  if (userMode && action === 'status') {
    const torUp = await portOpen('127.0.0.1', 9050);
    const out = `tor=${torUp ? 'active' : 'inactive'}\nopenvpn=skipped-user-mode`;
    return {
      ok: true,
      code: torUp ? 0 : 3,
      command: 'status (user mode)',
      stdout: out,
      stderr: '',
      timedOut: false,
      filePath: join(rootDir, '.runtime', 'tor', 'torrc'),
      userMode: true,
    };
  }

  const nav = await loadNavegationPlaybook(rootDir);
  const timeoutMs = Math.max(10_000, Number(opts.timeoutMs || 900_000));
  const dryRun = Boolean(opts.dryRun);
  const isShell = nav.filePath.endsWith('.sh');
  const cmd = isShell ? 'bash' : 'python3';
  const args = [nav.filePath];
  if (isShell) args.push(action);
  if (dryRun) args.push('--dry-run');
  const res = await runProcess(cmd, args, {
    timeoutMs,
    rejectOnError: false,
    rejectOnTimeout: false,
    label: cmd,
  });
  return {
    ok: !res.timedOut && res.code === 0,
    code: res.timedOut ? 124 : res.code,
    command: `${cmd} ${args.join(' ')}`,
    stdout: res.stdout,
    stderr: res.stderr,
    timedOut: res.timedOut,
    filePath: nav.filePath,
  };
}

export async function getNavegationTunnelStatus(rootDir) {
  const res = await executeNavegationPlaybook(rootDir, { action: 'status', dryRun: false, timeoutMs: 20_000 });
  const out = `${res.stdout || ''}\n${res.stderr || ''}`;
  const tor = (out.match(/tor=([a-z-]+)/i) || [])[1] || 'unknown';
  const openvpn = (out.match(/openvpn=([a-z-]+)/i) || [])[1] || 'unknown';
  return {
    ok: res.ok || res.code === 3,
    tor,
    openvpn,
    active: tor === 'active' || openvpn === 'active',
    code: res.code,
    command: res.command,
  };
}

function runSimple(cmd, args, timeoutMs = 20_000, signal = null) {
  return runProcess(cmd, args, {
    timeoutMs,
    signal,
    rejectOnError: false,
    rejectOnTimeout: false,
    label: cmd,
  }).then((res) => {
    return {
      ok: !res.timedOut && res.code === 0,
      code: res.timedOut ? 124 : res.code,
      stdout: res.stdout,
      stderr: res.stderr,
      timedOut: res.timedOut,
    };
  });
}

function safeJsonParse(text) {
  try {
    return JSON.parse(String(text || '').trim());
  } catch {
    return null;
  }
}

// Endpoints de fallback para o IP check pelo Tor — se o primário falhar,
// passamos ao seguinte. Mantemos um campo IsTor onde existir; senão derivamos.
const TOR_IP_CHECKS = [
  { url: 'https://check.torproject.org/api/ip', extract: (j) => ({ ip: j.IP || j.ip, isTor: j.IsTor === true }) },
  { url: 'https://api.ipify.org?format=json',    extract: (j) => ({ ip: j.ip,        isTor: null }) },
  { url: 'https://ifconfig.co/json',             extract: (j) => ({ ip: j.ip,        isTor: null }) },
];

async function resolveDirect(host) {
  try {
    const a = await dns.resolve4(host);
    return a[0] || null;
  } catch {
    return null;
  }
}

async function curlSocks(url, timeoutSec = 15, signal = null) {
  return runSimple(
    'curl',
    ['-sS', '--max-time', String(timeoutSec), '--socks5-hostname', '127.0.0.1:9050', url],
    Math.max(1_000, timeoutSec * 1_000 + 1_000),
    signal,
  );
}

/**
 * Tenta cada endpoint até obter um JSON válido com IP via SOCKS5h.
 */
async function torIpProbe(signal = null) {
  for (const ep of TOR_IP_CHECKS) {
    if (signal?.aborted) throw signal.reason || new Error('Tor IP probe cancelado');
    const res = await curlSocks(ep.url, 15, signal);
    const json = safeJsonParse(res.stdout);
    if (!json) continue;
    const x = ep.extract(json) || {};
    if (x.ip) {
      return {
        ok: res.ok,
        ip: String(x.ip).trim(),
        isTor: x.isTor === true ? true : x.isTor === false ? false : null,
        endpoint: ep.url,
        code: res.code,
        stderr: res.stderr ? String(res.stderr).slice(0, 240) : '',
      };
    }
  }
  return { ok: false, ip: null, isTor: null, endpoint: null, code: -1, stderr: 'todos os IP-check endpoints falharam' };
}

/**
 * Valida o caminho Tor real, com:
 *   - IP direto (sistema) vs IP via SOCKS5 (Tor)
 *   - IsTor flag do check.torproject.org (quando disponível)
 *   - DNS leak test (resolução directa vs via SOCKS5h)
 *   - ControlPort health (bootstrap, circuits, version) via tor-control.js
 *
 * Retorna validated=true só quando:
 *   tor.ok && tor.ip != null && tor.ip != direct.ip && (isTor !== false) && !dnsLeak
 */
export async function validateNavegationTorPath(rootDir, opts = {}) {
  const dnsLeakHost = String(opts.dnsLeakHost || 'check.torproject.org');
  const status = await getNavegationTunnelStatus(rootDir);
  const direct = await runSimple('curl', ['-sS', '--max-time', '12', 'https://api.ipify.org?format=json']);
  const torIp = await torIpProbe();

  const directJson = safeJsonParse(direct.stdout) || {};
  const directIp = String(directJson.ip || '').trim() || null;

  // ── DNS leak test ─────────────────────────────────────────────────────────
  // Se a resolução directa do host devolve IP igual à resolução remota (impossível
  // distinguir aqui sem root) — fazemos algo mais simples: comparamos o IP directo
  // do recon com o IP que aparece na visita Tor (se o exit IP == IP local, leak).
  const directHostIp = await resolveDirect(dnsLeakHost);
  const dnsLeak = Boolean(
    directIp && torIp.ip && directIp === torIp.ip
  );
  // Sinal complementar: a resolução A direita pelo SO devolveu algo? Se sim, o
  // pipeline pode estar a fazer DNS direto antes do SOCKS, vazando intenção.
  const systemDnsActive = Boolean(directHostIp);

  // ── ControlPort / bootstrap ───────────────────────────────────────────────
  let control = null;
  try { control = await torHealth(); } catch (e) { control = { error: e?.message || String(e) }; }

  const validated = Boolean(
    status.active &&
      torIp.ok &&
      torIp.ip &&
      directIp &&
      torIp.ip !== directIp &&
      torIp.isTor !== false &&
      !dnsLeak &&
      control?.bootstrap?.tag === 'done'
  );

  const reasons = [];
  if (!status.active) reasons.push('serviço Tor não está active no systemd');
  if (!torIp.ok) reasons.push('IP-check via SOCKS5 falhou (tor proxy não responde)');
  if (torIp.ok && !torIp.ip) reasons.push('SOCKS5 respondeu mas sem IP no JSON');
  if (torIp.isTor === false) reasons.push('check.torproject.org reportou IsTor=false');
  if (directIp && torIp.ip && directIp === torIp.ip) reasons.push('IP directo == IP via Tor (DNS leak / proxy bypass)');
  if (control?.bootstrap && control.bootstrap.tag !== 'done') {
    reasons.push(`Tor bootstrap em curso (tag=${control.bootstrap.tag}, progress=${control.bootstrap.progress}%)`);
  }
  if (control?.control && !control.control.ok) reasons.push(`ControlPort: ${control.control.error || 'sem auth'}`);

  return {
    ok: true,
    status,
    direct: {
      ok: direct.ok,
      ip: directIp,
      code: direct.code,
      stderr: direct.stderr ? String(direct.stderr).slice(0, 240) : '',
    },
    tor: torIp,
    dnsLeak: { leaked: dnsLeak, systemDnsActive, dnsLeakHost, directHostIp },
    control,
    validated,
    reasons,
  };
}

/**
 * Versão "barata" para chamar do /api/recon/stream antes de iniciar o pipeline.
 * Não corre o systemctl status (que precisa de spawn) — usa apenas tor-control.js
 * + um único IP-check via SOCKS. Falha rápida.
 */
export async function quickValidateTor({ timeoutMs = 8_000, signal = null } = {}) {
  const t0 = Date.now();
  const torIp = await torIpProbe(signal);
  if (signal?.aborted) throw signal.reason || new Error('Validação Tor cancelada');
  let control;
  try { control = await torHealth({ signal }); } catch (e) {
    if (signal?.aborted) throw signal.reason || e;
    control = { error: e?.message || String(e) };
  }
  const directRes = await runSimple(
    'curl',
    ['-sS', '--max-time', '6', 'https://api.ipify.org?format=json'],
    Math.min(7_000, Math.max(1_000, Number(timeoutMs) || 8_000)),
    signal,
  );
  const directJson = safeJsonParse(directRes.stdout) || {};
  const directIp = String(directJson.ip || '').trim() || null;
  const validated = Boolean(
    torIp.ok && torIp.ip && directIp && torIp.ip !== directIp && torIp.isTor !== false &&
    control?.bootstrap?.tag === 'done'
  );
  return {
    validated,
    durationMs: Date.now() - t0,
    direct: { ip: directIp },
    tor: torIp,
    control,
  };
}
