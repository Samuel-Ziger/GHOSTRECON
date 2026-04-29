/**
 * Tor tunnel — testes para socks5-dispatcher e tor-control.
 *
 * Não dependem de Tor real:
 *   - SOCKS5: usa um servidor TCP local que faz o handshake mínimo
 *     (NOAUTH ou USER/PASS) e responde 0x00 ao CONNECT.
 *   - tor-control: usa servidor TCP local que fala o protocolo do Tor
 *     ControlPort para AUTHENTICATE/SIGNAL NEWNYM/GETINFO.
 */
import test from 'node:test';
import assert from 'node:assert/strict';
import net from 'node:net';

import {
  isSocksUrl,
  parseSocksUrl,
  socks5Handshake,
  isolatedSocksUser,
  injectIsolationCredentials,
  createSocksDispatcher,
} from '../modules/socks5-dispatcher.js';

function startEchoOk(port = 0) {
  return new Promise((resolve) => {
    const s = net.createServer((c) => {
      c.on('data', (b) => c.write(b));
    });
    s.listen(port, '127.0.0.1', () => resolve(s));
  });
}

/**
 * SOCKS5 server "fake": aceita NOAUTH (e USER/PASS se sinalizado), responde
 * succeeded a qualquer CONNECT, depois conecta ao destino real e ponteia.
 *
 * @param {{requireAuth?:boolean, expectedUser?:string, expectedPass?:string}} opts
 */
function startSocks5Server(opts = {}) {
  return new Promise((resolve) => {
    const s = net.createServer((c) => {
      let stage = 'method';
      let buf = Buffer.alloc(0);
      let target = null;
      c.on('data', (chunk) => {
        buf = Buffer.concat([buf, chunk]);
        if (stage === 'method') {
          if (buf.length < 2) return;
          const nMethods = buf[1];
          if (buf.length < 2 + nMethods) return;
          const methods = buf.slice(2, 2 + nMethods);
          buf = buf.slice(2 + nMethods);
          if (opts.requireAuth) {
            if (!methods.includes(0x02)) {
              c.write(Buffer.from([0x05, 0xff]));
              c.end();
              return;
            }
            c.write(Buffer.from([0x05, 0x02]));
            stage = 'auth';
          } else {
            if (!methods.includes(0x00)) {
              c.write(Buffer.from([0x05, 0xff]));
              c.end();
              return;
            }
            c.write(Buffer.from([0x05, 0x00]));
            stage = 'connect';
          }
        }
        if (stage === 'auth') {
          if (buf.length < 2) return;
          if (buf[0] !== 0x01) { c.end(); return; }
          const ulen = buf[1];
          if (buf.length < 2 + ulen + 1) return;
          const plen = buf[2 + ulen];
          if (buf.length < 2 + ulen + 1 + plen) return;
          const user = buf.slice(2, 2 + ulen).toString('utf8');
          const pass = buf.slice(3 + ulen, 3 + ulen + plen).toString('utf8');
          buf = buf.slice(3 + ulen + plen);
          if (opts.expectedUser && user !== opts.expectedUser) {
            c.write(Buffer.from([0x01, 0x01]));
            c.end();
            return;
          }
          if (opts.expectedPass && pass !== opts.expectedPass) {
            c.write(Buffer.from([0x01, 0x01]));
            c.end();
            return;
          }
          c.write(Buffer.from([0x01, 0x00]));
          stage = 'connect';
        }
        if (stage === 'connect') {
          if (buf.length < 4) return;
          const atyp = buf[3];
          let addrEnd;
          if (atyp === 0x01) addrEnd = 4 + 4;
          else if (atyp === 0x03) {
            if (buf.length < 5) return;
            addrEnd = 4 + 1 + buf[4];
          } else if (atyp === 0x04) addrEnd = 4 + 16;
          else { c.end(); return; }
          const need = addrEnd + 2;
          if (buf.length < need) return;
          let host;
          if (atyp === 0x01) host = `${buf[4]}.${buf[5]}.${buf[6]}.${buf[7]}`;
          else if (atyp === 0x03) host = buf.slice(5, addrEnd).toString('utf8');
          else host = '::1';
          const port = buf.readUInt16BE(addrEnd);
          buf = buf.slice(need);
          target = { host, port };
          // Resposta succeeded com BND.ADDR=0.0.0.0:0
          c.write(Buffer.from([0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0]));
          stage = 'tunnel';
          // Tunela para o destino real: liga e ponteia
          const upstream = net.connect({ host: target.host, port: target.port });
          upstream.on('connect', () => {
            c.pipe(upstream);
            upstream.pipe(c);
            if (buf.length) upstream.write(buf);
          });
          upstream.on('error', () => c.end());
        }
      });
      c.on('error', () => { /* ignore */ });
    });
    s.listen(0, '127.0.0.1', () => resolve(s));
  });
}

// ─── isSocksUrl / parseSocksUrl ─────────────────────────────────────────────
test('isSocksUrl identifica socks5/socks5h/socks4', () => {
  assert.equal(isSocksUrl('socks5://127.0.0.1:9050'), true);
  assert.equal(isSocksUrl('socks5h://x:y@127.0.0.1:9050'), true);
  assert.equal(isSocksUrl('socks4a://h:9050'), true);
  assert.equal(isSocksUrl('http://1.2.3.4:8080'), false);
  assert.equal(isSocksUrl(''), false);
});

test('parseSocksUrl extrai host/port/user/pass + remoteDns', () => {
  const a = parseSocksUrl('socks5h://alice:s%40nha@127.0.0.1:9050');
  assert.equal(a.host, '127.0.0.1');
  assert.equal(a.port, 9050);
  assert.equal(a.user, 'alice');
  assert.equal(a.pass, 's@nha');
  assert.equal(a.remoteDns, true);

  const b = parseSocksUrl('socks5://1.1.1.1:1080');
  assert.equal(b.user, '');
  assert.equal(b.pass, '');
  assert.equal(b.remoteDns, false);

  assert.throws(() => parseSocksUrl('http://x'));
});

// ─── socks5Handshake direto ─────────────────────────────────────────────────
test('SOCKS5 handshake NOAUTH → CONNECT succeeded', async () => {
  const echo = await startEchoOk();
  const proxy = await startSocks5Server();
  try {
    const tcp = net.connect({ host: '127.0.0.1', port: proxy.address().port });
    await new Promise((r) => tcp.once('connect', r));
    await socks5Handshake(tcp, { user: '', pass: '' }, {
      host: '127.0.0.1', port: echo.address().port, remoteDns: false,
    });
    // Já tunelado — agora um echo round-trip
    tcp.write(Buffer.from('ping'));
    const back = await new Promise((r) => tcp.once('data', (b) => r(b.toString())));
    assert.equal(back, 'ping');
    tcp.destroy();
  } finally {
    proxy.close(); echo.close();
  }
});

test('SOCKS5 handshake USER/PASS aceita credentials válidas', async () => {
  const echo = await startEchoOk();
  const proxy = await startSocks5Server({ requireAuth: true, expectedUser: 'u', expectedPass: 'p' });
  try {
    const tcp = net.connect({ host: '127.0.0.1', port: proxy.address().port });
    await new Promise((r) => tcp.once('connect', r));
    await socks5Handshake(tcp, { user: 'u', pass: 'p' }, {
      host: '127.0.0.1', port: echo.address().port, remoteDns: false,
    });
    tcp.write(Buffer.from('hello'));
    const back = await new Promise((r) => tcp.once('data', (b) => r(b.toString())));
    assert.equal(back, 'hello');
    tcp.destroy();
  } finally {
    proxy.close(); echo.close();
  }
});

test('SOCKS5 handshake USER/PASS rejeita credentials erradas', async () => {
  const proxy = await startSocks5Server({ requireAuth: true, expectedUser: 'u', expectedPass: 'p' });
  try {
    const tcp = net.connect({ host: '127.0.0.1', port: proxy.address().port });
    await new Promise((r) => tcp.once('connect', r));
    await assert.rejects(
      () => socks5Handshake(tcp, { user: 'u', pass: 'wrong' }, {
        host: '1.1.1.1', port: 80, remoteDns: false,
      }),
      /SOCKS5 auth: rejeitada/,
    );
    try { tcp.destroy(); } catch { /* ignore */ }
  } finally {
    proxy.close();
  }
});

test('SOCKS5 handshake remoteDns (socks5h) envia ATYP=0x03', async () => {
  // Vamos espreitar no servidor o ATYP recebido
  let receivedAtyp = null;
  const echo = await startEchoOk();
  const proxy = net.createServer((c) => {
    let buf = Buffer.alloc(0);
    let stage = 'm';
    c.on('data', (chunk) => {
      buf = Buffer.concat([buf, chunk]);
      if (stage === 'm') {
        if (buf.length < 3) return;
        c.write(Buffer.from([0x05, 0x00]));
        buf = buf.slice(2 + buf[1]);
        stage = 'c';
      }
      if (stage === 'c') {
        if (buf.length < 5) return;
        receivedAtyp = buf[3];
        // truncar e responder succeeded mínimo
        c.write(Buffer.from([0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0]));
        const upstream = net.connect({ host: '127.0.0.1', port: echo.address().port });
        upstream.on('connect', () => { c.pipe(upstream); upstream.pipe(c); });
      }
    });
  });
  await new Promise((r) => proxy.listen(0, '127.0.0.1', r));
  try {
    const tcp = net.connect({ host: '127.0.0.1', port: proxy.address().port });
    await new Promise((r) => tcp.once('connect', r));
    await socks5Handshake(tcp, { user: '', pass: '' }, {
      host: 'check.torproject.org', port: 443, remoteDns: true,
    });
    assert.equal(receivedAtyp, 0x03, 'esperava ATYP=domain (0x03)');
    tcp.destroy();
  } finally {
    proxy.close(); echo.close();
  }
});

// ─── isolatedSocksUser / injectIsolationCredentials ─────────────────────────
test('isolatedSocksUser produz strings únicas com prefix', () => {
  const a = isolatedSocksUser('gr', 'engX');
  const b = isolatedSocksUser('gr', 'engX');
  assert.match(a, /^gr-engX-/);
  assert.notEqual(a, b);
});

test('injectIsolationCredentials escreve user:pass no SOCKS URL', () => {
  const out = injectIsolationCredentials('socks5h://127.0.0.1:9050', 'user1', 'pass1');
  const u = new URL(out);
  assert.equal(decodeURIComponent(u.username), 'user1');
  assert.equal(decodeURIComponent(u.password), 'pass1');
});

test('injectIsolationCredentials ignora não-SOCKS', () => {
  assert.equal(injectIsolationCredentials('http://x', 'a', 'b'), 'http://x');
});

// ─── createSocksDispatcher (integração ligeira) ─────────────────────────────
test('createSocksDispatcher devolve undici.Agent funcional para HTTP plano', async () => {
  // Mini-servidor HTTP plano que devolve "OK"
  const httpServer = net.createServer((c) => {
    c.on('data', () => {
      c.write('HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nOK');
      c.end();
    });
  });
  await new Promise((r) => httpServer.listen(0, '127.0.0.1', r));
  const httpPort = httpServer.address().port;

  const proxy = await startSocks5Server();
  try {
    const dispatcher = await createSocksDispatcher(`socks5://127.0.0.1:${proxy.address().port}`);
    const undici = await import('undici');
    const res = await undici.fetch(`http://127.0.0.1:${httpPort}/`, { dispatcher });
    const text = await res.text();
    assert.equal(res.status, 200);
    assert.equal(text, 'OK');
  } finally {
    proxy.close(); httpServer.close();
  }
});

// ─── tor-control: cookie + AUTHENTICATE + NEWNYM + GETINFO ──────────────────
import fs from 'node:fs';
import os from 'os';
import path from 'path';
import { newnym, getBootstrap, ensureBootstrapped, getCircuits, torHealth } from '../modules/tor-control.js';

function startFakeTorControl({ cookieHex = null, bootstrapDone = true } = {}) {
  return new Promise((resolve) => {
    const s = net.createServer((c) => {
      c.setEncoding('utf8');
      let buf = '';
      let authed = false;
      c.on('data', (chunk) => {
        buf += chunk;
        let idx;
        while ((idx = buf.indexOf('\r\n')) >= 0) {
          const line = buf.slice(0, idx);
          buf = buf.slice(idx + 2);
          handle(line);
        }
      });
      function handle(line) {
        if (/^AUTHENTICATE\b/i.test(line)) {
          if (cookieHex) {
            if (line.includes(cookieHex)) { authed = true; c.write('250 OK\r\n'); }
            else c.write('515 Authentication failed\r\n');
          } else {
            authed = true;
            c.write('250 OK\r\n');
          }
        } else if (!authed) {
          c.write('514 Authentication required\r\n');
        } else if (/^SIGNAL NEWNYM\b/i.test(line)) {
          c.write('250 OK\r\n');
        } else if (/^GETINFO version\b/i.test(line)) {
          c.write('250-version=0.4.7.13\r\n250 OK\r\n');
        } else if (/^GETINFO status\/bootstrap-phase\b/i.test(line)) {
          if (bootstrapDone) {
            c.write('250-status/bootstrap-phase=NOTICE BOOTSTRAP PROGRESS=100 TAG=done SUMMARY="Done"\r\n250 OK\r\n');
          } else {
            c.write('250-status/bootstrap-phase=NOTICE BOOTSTRAP PROGRESS=80 TAG=conn_done_or SUMMARY="Connecting"\r\n250 OK\r\n');
          }
        } else if (/^GETINFO circuit-status\b/i.test(line)) {
          c.write('250+circuit-status=\r\n1 BUILT $A=node1,$B=node2 BUILD_FLAGS=NEED_CAPACITY\r\n2 BUILT $C=node3,$D=node4\r\n.\r\n250 OK\r\n');
        } else if (/^QUIT\b/i.test(line)) {
          c.write('250 closing connection\r\n');
          c.end();
        } else {
          c.write('510 Unrecognized command\r\n');
        }
      }
    });
    s.listen(0, '127.0.0.1', () => resolve(s));
  });
}

test('tor-control: AUTHENTICATE NULL + NEWNYM', async () => {
  const fake = await startFakeTorControl({ cookieHex: null });
  try {
    process.env.GHOSTRECON_TOR_CONTROL_HOST = '127.0.0.1';
    process.env.GHOSTRECON_TOR_CONTROL_PORT = String(fake.address().port);
    process.env.GHOSTRECON_TOR_CONTROL_COOKIE_PATH = '/tmp/__nope__';
    const r = await newnym({ timeoutMs: 3_000 });
    assert.equal(r.ok, true);
  } finally {
    fake.close();
  }
});

test('tor-control: AUTHENTICATE com cookie hex', async () => {
  const cookie = Buffer.alloc(32, 0xab);
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'gr-tor-'));
  const cookiePath = path.join(tmp, 'control.authcookie');
  fs.writeFileSync(cookiePath, cookie);
  const fake = await startFakeTorControl({ cookieHex: cookie.toString('hex') });
  try {
    process.env.GHOSTRECON_TOR_CONTROL_HOST = '127.0.0.1';
    process.env.GHOSTRECON_TOR_CONTROL_PORT = String(fake.address().port);
    process.env.GHOSTRECON_TOR_CONTROL_COOKIE_PATH = cookiePath;
    const r = await newnym({ timeoutMs: 3_000 });
    assert.equal(r.ok, true);
  } finally {
    fake.close();
  }
});

test('tor-control: getBootstrap/ensureBootstrapped done', async () => {
  const fake = await startFakeTorControl({ bootstrapDone: true });
  try {
    process.env.GHOSTRECON_TOR_CONTROL_PORT = String(fake.address().port);
    process.env.GHOSTRECON_TOR_CONTROL_COOKIE_PATH = '/tmp/__nope__';
    const b = await getBootstrap({ timeoutMs: 3_000 });
    assert.equal(b.tag, 'done');
    assert.equal(b.progress, 100);
    const ok = await ensureBootstrapped({ timeoutMs: 3_000, intervalMs: 200 });
    assert.equal(ok.ok, true);
  } finally {
    fake.close();
  }
});

test('tor-control: torHealth devolve estrutura completa', async () => {
  const fake = await startFakeTorControl();
  try {
    process.env.GHOSTRECON_TOR_CONTROL_PORT = String(fake.address().port);
    process.env.GHOSTRECON_TOR_CONTROL_COOKIE_PATH = '/tmp/__nope__';
    const h = await torHealth();
    assert.equal(h.control.ok, true);
    assert.equal(h.control.authMethod, 'null');
    assert.equal(h.bootstrap.tag, 'done');
    assert.equal(h.version, '0.4.7.13');
    assert.ok(h.circuits.count >= 2);
  } finally {
    fake.close();
  }
});

test('tor-control: ensureBootstrapped timeout quando não está done', async () => {
  const fake = await startFakeTorControl({ bootstrapDone: false });
  try {
    process.env.GHOSTRECON_TOR_CONTROL_PORT = String(fake.address().port);
    process.env.GHOSTRECON_TOR_CONTROL_COOKIE_PATH = '/tmp/__nope__';
    const r = await ensureBootstrapped({ timeoutMs: 600, intervalMs: 200 });
    assert.equal(r.ok, false);
    assert.equal(r.reason, 'timeout');
  } finally {
    fake.close();
  }
});

// ─── getCircuits parse ──────────────────────────────────────────────────────
test('tor-control: getCircuits extrai BUILT circuits', async () => {
  const fake = await startFakeTorControl();
  try {
    process.env.GHOSTRECON_TOR_CONTROL_PORT = String(fake.address().port);
    process.env.GHOSTRECON_TOR_CONTROL_COOKIE_PATH = '/tmp/__nope__';
    const r = await getCircuits({ timeoutMs: 3_000 });
    assert.equal(r.ok, true);
    assert.ok(r.circuits.length >= 2);
    assert.ok(r.circuits.every((c) => c.state === 'BUILT'));
  } finally {
    fake.close();
  }
});
