/**
 * Tor ControlPort client (RFC: tor-spec/control-spec.txt) — sem deps externas.
 *
 * Funcionalidades:
 *   - Cookie auth (lê /run/tor/control.authcookie por default).
 *   - HASHEDPASSWORD auth (env GHOSTRECON_TOR_CONTROL_PASSWORD).
 *   - NEWNYM (rotação de circuit/identity sinalizada).
 *   - GETINFO status/bootstrap-phase, GETINFO version, GETINFO circuit-status.
 *   - Helper waitBootstrapped() faz polling até "TAG=done".
 *
 * Uso:
 *   import { newnym, getBootstrap, ensureBootstrapped, getCircuits } from './tor-control.js';
 *   await newnym();                       // assume host/port/cookie de env
 *   const b = await getBootstrap();        // { progress: 100, tag: 'done', summary: 'Done' }
 *   await ensureBootstrapped({ timeoutMs: 60_000 });
 *   const c = await getCircuits();
 *
 * Env:
 *   GHOSTRECON_TOR_CONTROL_HOST    default 127.0.0.1
 *   GHOSTRECON_TOR_CONTROL_PORT    default 9051
 *   GHOSTRECON_TOR_CONTROL_COOKIE_PATH  override do path do cookie
 *   GHOSTRECON_TOR_CONTROL_PASSWORD     fallback HASHEDPASSWORD (raw — NÃO o hash)
 *
 * Notas red-team:
 *   NEWNYM apenas sinaliza ao Tor que o próximo circuit deve ser fresco —
 *   circuits existentes continuam até expirarem. Para isolação garantida por
 *   target use SOCKS user/pass únicos (IsolateSOCKSAuth) — ver socks5-dispatcher.js.
 */

import net from 'node:net';
import fs from 'node:fs';
import { promisify } from 'node:util';

const sleep = promisify(setTimeout);

const COOKIE_CANDIDATES = [
  '/run/tor/control.authcookie',
  '/var/run/tor/control.authcookie',
  '/var/lib/tor/control_authcookie',
];

function controlHost() { return String(process.env.GHOSTRECON_TOR_CONTROL_HOST || '127.0.0.1').trim() || '127.0.0.1'; }
function controlPort() { return Number(process.env.GHOSTRECON_TOR_CONTROL_PORT || 9051); }

function readCookie() {
  const explicit = String(process.env.GHOSTRECON_TOR_CONTROL_COOKIE_PATH || '').trim();
  const list = explicit ? [explicit, ...COOKIE_CANDIDATES] : COOKIE_CANDIDATES;
  for (const p of list) {
    try {
      const buf = fs.readFileSync(p);
      if (buf.length === 32) return { path: p, hex: buf.toString('hex') };
    } catch { /* try next */ }
  }
  return null;
}

/**
 * Conecta + autentica + retorna um helper { send, close }.
 */
async function connectControl({ timeoutMs = 8_000 } = {}) {
  const host = controlHost();
  const port = controlPort();
  return new Promise((resolve, reject) => {
    const sock = net.connect({ host, port });
    let buf = '';
    let to = setTimeout(() => {
      try { sock.destroy(); } catch { /* ignore */ }
      reject(new Error(`Tor ControlPort: timeout ligar a ${host}:${port}`));
    }, timeoutMs);
    sock.setEncoding('utf8');
    sock.on('error', (e) => { clearTimeout(to); reject(e); });
    sock.on('connect', () => {
      clearTimeout(to);
      const helper = {
        async send(line, { multi = false } = {}) {
          return new Promise((res, rej) => {
            buf = '';
            const onData = (chunk) => {
              buf += chunk;
              // Cada resposta termina com linha "250 OK\r\n" ou similar; split por \r\n.
              if (multi) {
                if (/\r?\n250 OK\r?\n$/.test(buf) || /\r?\n2\d\d [^\r\n]*\r?\n$/.test(buf)) {
                  sock.removeListener('data', onData);
                  res(buf);
                }
              } else {
                if (/\r?\n$/.test(buf)) {
                  sock.removeListener('data', onData);
                  res(buf);
                }
              }
            };
            const onErr = (e) => { sock.removeListener('data', onData); rej(e); };
            sock.on('data', onData);
            sock.once('error', onErr);
            sock.write(`${line}\r\n`);
          });
        },
        close() { try { sock.write('QUIT\r\n'); sock.end(); } catch { /* ignore */ } },
        sock,
      };

      const cookie = readCookie();
      const password = String(process.env.GHOSTRECON_TOR_CONTROL_PASSWORD || '').trim();
      const auth = async () => {
        if (cookie) {
          const r = await helper.send(`AUTHENTICATE ${cookie.hex}`, { multi: true });
          if (!/^250 /.test(r)) throw new Error(`Tor ControlPort cookie auth falhou: ${r.trim()}`);
          return { method: 'cookie', cookiePath: cookie.path };
        }
        if (password) {
          const r = await helper.send(`AUTHENTICATE "${password.replace(/"/g, '\\"')}"`, { multi: true });
          if (!/^250 /.test(r)) throw new Error(`Tor ControlPort password auth falhou: ${r.trim()}`);
          return { method: 'password' };
        }
        // Tor permite NULL auth se CookieAuthentication 0 e HashedControlPassword vazia.
        const r = await helper.send('AUTHENTICATE', { multi: true });
        if (!/^250 /.test(r)) throw new Error(`Tor ControlPort sem auth (NULL) rejeitada: ${r.trim()}`);
        return { method: 'null' };
      };
      auth()
        .then((authInfo) => resolve({ helper, authInfo }))
        .catch((e) => { try { sock.destroy(); } catch { /* ignore */ } reject(e); });
    });
  });
}

/**
 * Sinaliza NEWNYM — Tor escolhe novos circuits para subsequentes streams.
 * Há um rate limit interno no Tor (default 10s) entre NEWNYMs.
 */
export async function newnym({ timeoutMs = 5_000 } = {}) {
  const { helper } = await connectControl({ timeoutMs });
  try {
    const r = await helper.send('SIGNAL NEWNYM', { multi: true });
    const ok = /^250 OK/m.test(r);
    if (!ok) throw new Error(`NEWNYM falhou: ${r.trim()}`);
    return { ok: true, raw: r.trim() };
  } finally {
    helper.close();
  }
}

function parseBootstrap(raw) {
  // Ex: 250-status/bootstrap-phase=NOTICE BOOTSTRAP PROGRESS=100 TAG=done SUMMARY="Done"
  const out = { progress: null, tag: null, summary: null };
  const m = raw.match(/PROGRESS=(\d+)[^\n]*TAG=([A-Za-z_-]+)[^\n]*SUMMARY="([^"]*)"/);
  if (m) {
    out.progress = Number(m[1]);
    out.tag = m[2];
    out.summary = m[3];
  } else {
    const p = raw.match(/PROGRESS=(\d+)/);
    if (p) out.progress = Number(p[1]);
  }
  return out;
}

export async function getBootstrap({ timeoutMs = 5_000 } = {}) {
  const { helper } = await connectControl({ timeoutMs });
  try {
    const raw = await helper.send('GETINFO status/bootstrap-phase', { multi: true });
    return parseBootstrap(raw);
  } finally {
    helper.close();
  }
}

export async function ensureBootstrapped({ timeoutMs = 60_000, intervalMs = 2_000 } = {}) {
  const start = Date.now();
  let last = null;
  while (Date.now() - start < timeoutMs) {
    try {
      last = await getBootstrap({ timeoutMs: 4_000 });
      if (last.tag === 'done' || last.progress === 100) return { ok: true, ...last };
    } catch (e) {
      last = { error: e?.message || String(e) };
    }
    await sleep(intervalMs);
  }
  return { ok: false, ...(last || {}), reason: 'timeout' };
}

export async function getCircuits({ timeoutMs = 5_000 } = {}) {
  const { helper } = await connectControl({ timeoutMs });
  try {
    const raw = await helper.send('GETINFO circuit-status', { multi: true });
    const lines = raw.split(/\r?\n/);
    const circuits = [];
    for (const line of lines) {
      // Formato: 250+circuit-status= seguido de várias linhas, terminado em "."
      const m = line.match(/^(\d+)\s+(LAUNCHED|BUILT|EXTENDED|FAILED|CLOSED)\s+(\S+)/);
      if (m) {
        circuits.push({ id: Number(m[1]), state: m[2], path: m[3] });
      }
    }
    return { ok: true, circuits, raw };
  } finally {
    helper.close();
  }
}

export async function getVersion({ timeoutMs = 5_000 } = {}) {
  const { helper } = await connectControl({ timeoutMs });
  try {
    const raw = await helper.send('GETINFO version', { multi: true });
    const m = raw.match(/version=(\S+)/);
    return { ok: true, version: m ? m[1] : null, raw: raw.trim() };
  } finally {
    helper.close();
  }
}

/** Health resumido para /api/tunnel/health. */
export async function torHealth() {
  const out = {
    control: { ok: false, host: controlHost(), port: controlPort(), authMethod: null, error: null },
    bootstrap: null,
    version: null,
    circuits: { count: 0, built: 0 },
  };
  try {
    const { helper, authInfo } = await connectControl({ timeoutMs: 4_000 });
    out.control.ok = true;
    out.control.authMethod = authInfo.method;
    try {
      const v = await helper.send('GETINFO version', { multi: true });
      const m = v.match(/version=(\S+)/);
      out.version = m ? m[1] : null;
    } catch { /* ignore */ }
    try {
      const b = await helper.send('GETINFO status/bootstrap-phase', { multi: true });
      out.bootstrap = parseBootstrap(b);
    } catch { /* ignore */ }
    try {
      const cs = await helper.send('GETINFO circuit-status', { multi: true });
      const lines = cs.split(/\r?\n/);
      for (const line of lines) {
        const m = line.match(/^(\d+)\s+(LAUNCHED|BUILT|EXTENDED|FAILED|CLOSED)/);
        if (m) {
          out.circuits.count += 1;
          if (m[2] === 'BUILT') out.circuits.built += 1;
        }
      }
    } catch { /* ignore */ }
    helper.close();
  } catch (e) {
    out.control.error = e?.message || String(e);
  }
  return out;
}
