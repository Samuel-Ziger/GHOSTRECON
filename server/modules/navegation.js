import { access, readFile } from 'node:fs/promises';
import { join } from 'node:path';
import { spawn } from 'node:child_process';
import dns from 'node:dns/promises';
import { torHealth, ensureBootstrapped } from './tor-control.js';

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
  const nav = await loadNavegationPlaybook(rootDir);
  const timeoutMs = Math.max(10_000, Number(opts.timeoutMs || 900_000));
  const dryRun = Boolean(opts.dryRun);
  const action = String(opts.action || 'up').trim().toLowerCase();
  const isShell = nav.filePath.endsWith('.sh');
  const cmd = isShell ? 'bash' : 'python3';
  const args = [nav.filePath];
  if (isShell) args.push(action);
  if (dryRun) args.push('--dry-run');
  return new Promise((resolve) => {
    const child = spawn(cmd, args, { stdio: ['ignore', 'pipe', 'pipe'] });
    const out = [];
    const err = [];
    let killed = false;
    const t = setTimeout(() => {
      killed = true;
      try {
        child.kill('SIGKILL');
      } catch {
        /* ignore */
      }
    }, timeoutMs);
    child.stdout.on('data', (d) => out.push(d));
    child.stderr.on('data', (d) => err.push(d));
    child.on('error', (e) => {
      clearTimeout(t);
      resolve({
        ok: false,
        code: -1,
        command: `${cmd} ${args.join(' ')}`,
        stdout: Buffer.concat(out).toString('utf8'),
        stderr: `${Buffer.concat(err).toString('utf8')}\n${e?.message || e}`,
        timedOut: false,
        filePath: nav.filePath,
      });
    });
    child.on('close', (code) => {
      clearTimeout(t);
      resolve({
        ok: !killed && code === 0,
        code: killed ? 124 : code,
        command: `${cmd} ${args.join(' ')}`,
        stdout: Buffer.concat(out).toString('utf8'),
        stderr: Buffer.concat(err).toString('utf8'),
        timedOut: killed,
        filePath: nav.filePath,
      });
    });
  });
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

function runSimple(cmd, args, timeoutMs = 20_000) {
  return new Promise((resolve) => {
    const child = spawn(cmd, args, { stdio: ['ignore', 'pipe', 'pipe'] });
    const out = [];
    const err = [];
    let killed = false;
    const t = setTimeout(() => {
      killed = true;
      try {
        child.kill('SIGKILL');
      } catch {
        /* ignore */
      }
    }, timeoutMs);
    child.stdout.on('data', (d) => out.push(d));
    child.stderr.on('data', (d) => err.push(d));
    child.on('error', (e) => {
      clearTimeout(t);
      resolve({ ok: false, code: -1, stdout: '', stderr: String(e?.message || e), timedOut: false });
    });
    child.on('close', (code) => {
      clearTimeout(t);
      resolve({
        ok: !killed && code === 0,
        code: killed ? 124 : code,
        stdout: Buffer.concat(out).toString('utf8'),
        stderr: Buffer.concat(err).toString('utf8'),
        timedOut: killed,
      });
    });
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

async function curlSocks(url, timeoutSec = 15) {
  return runSimple('curl', ['-sS', '--max-time', String(timeoutSec), '--socks5-hostname', '127.0.0.1:9050', url]);
}

/**
 * Tenta cada endpoint até obter um JSON válido com IP via SOCKS5h.
 */
async function torIpProbe() {
  for (const ep of TOR_IP_CHECKS) {
    const res = await curlSocks(ep.url);
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
export async function quickValidateTor({ timeoutMs = 8_000 } = {}) {
  const t0 = Date.now();
  const torIp = await torIpProbe();
  let control;
  try { control = await torHealth(); } catch (e) { control = { error: e?.message || String(e) }; }
  const directRes = await runSimple('curl', ['-sS', '--max-time', '6', 'https://api.ipify.org?format=json'], 7_000);
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

