import { access, readFile } from 'node:fs/promises';
import { join } from 'node:path';
import { spawn } from 'node:child_process';

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

export async function validateNavegationTorPath(rootDir) {
  const status = await getNavegationTunnelStatus(rootDir);
  const direct = await runSimple('curl', ['-sS', '--max-time', '12', 'https://api.ipify.org?format=json']);
  const tor = await runSimple('curl', ['-sS', '--max-time', '15', '--socks5-hostname', '127.0.0.1:9050', 'https://check.torproject.org/api/ip']);
  const directJson = safeJsonParse(direct.stdout) || {};
  const torJson = safeJsonParse(tor.stdout) || {};
  const directIp = String(directJson.ip || '').trim() || null;
  const torIp = String(torJson.IP || torJson.ip || '').trim() || null;
  const isTor = torJson.IsTor === true;
  return {
    ok: true,
    status,
    direct: {
      ok: direct.ok,
      ip: directIp,
      code: direct.code,
      stderr: direct.stderr ? String(direct.stderr).slice(0, 240) : '',
    },
    tor: {
      ok: tor.ok,
      ip: torIp,
      isTor,
      code: tor.code,
      stderr: tor.stderr ? String(tor.stderr).slice(0, 240) : '',
    },
    validated: Boolean(status.active && tor.ok && isTor),
  };
}

