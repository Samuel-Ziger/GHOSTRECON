/**
 * SOCKS5 dispatcher para undici — sem dependências externas.
 *
 * undici.ProxyAgent só fala HTTP CONNECT; SOCKS5 fica de fora. Para que o
 * GHOSTRECON consiga puxar fetch() pelo Tor (SOCKS5 nativo no porto 9050) ou
 * por qualquer SOCKS5 do GHOSTRECON_PROXY_POOL, este módulo implementa o
 * connect handshake SOCKS5 (RFC 1928 + RFC 1929) inline e devolve um
 * `undici.Agent` cujo connect tunela o socket TCP através do proxy.
 *
 * Suporta:
 *   - socks5://host:port               (sem auth, resolução DNS local)
 *   - socks5://user:pass@host:port     (RFC 1929 username/password)
 *   - socks5h://host:port              (resolução DNS via SOCKS — usar com Tor)
 *   - socks5h://user:pass@host:port    (idem com auth — bom para isolation)
 *
 * Recomendado para Tor:
 *   socks5h://recon-<runId>:<random>@127.0.0.1:9050
 *   → o user:pass único faz IsolateSOCKSAuth criar circuit dedicado por target.
 */

import net from 'node:net';
import tls from 'node:tls';

let _undici = null;
async function loadUndici() {
  if (_undici !== null) return _undici;
  try { _undici = await import('undici'); } catch { _undici = false; }
  return _undici;
}

export function isSocksUrl(s) {
  return /^socks(5h?|4a?):\/\//i.test(String(s || ''));
}

export function parseSocksUrl(href) {
  const u = new URL(href);
  const proto = u.protocol.replace(/:$/, '').toLowerCase();
  if (!/^socks(5h?|4a?)$/.test(proto)) throw new Error(`scheme não SOCKS: ${proto}`);
  return {
    proto,
    remoteDns: proto === 'socks5h' || proto === 'socks4a',
    host: u.hostname,
    port: Number(u.port) || 1080,
    user: u.username ? decodeURIComponent(u.username) : '',
    pass: u.password ? decodeURIComponent(u.password) : '',
  };
}

const SOCKS5_REPLIES = {
  0x00: 'succeeded',
  0x01: 'general failure',
  0x02: 'connection not allowed',
  0x03: 'network unreachable',
  0x04: 'host unreachable',
  0x05: 'connection refused',
  0x06: 'TTL expired',
  0x07: 'command not supported',
  0x08: 'addr type not supported',
};

/**
 * State machine do handshake SOCKS5 num socket TCP já ligado ao proxy.
 * Estados: 'method' → ('auth' →) 'connect' → 'done'.
 *
 * @param {net.Socket} sock
 * @param {{user?:string,pass?:string}} cfg
 * @param {{host:string,port:number,remoteDns:boolean}} target
 */
export function socks5Handshake(sock, cfg, target) {
  return new Promise((resolve, reject) => {
    let state = 'method';
    let buf = Buffer.alloc(0);

    const cleanup = () => {
      sock.removeListener('error', onErr);
      sock.removeListener('close', onClose);
      sock.removeListener('data', onData);
    };
    const fail = (msg) => { cleanup(); reject(msg instanceof Error ? msg : new Error(String(msg))); };
    const done = () => { cleanup(); resolve(); };

    const onErr = (e) => fail(e);
    const onClose = () => fail('SOCKS5: socket fechou durante handshake');
    const onData = (chunk) => {
      buf = Buffer.concat([buf, chunk]);
      // eslint-disable-next-line no-constant-condition
      while (true) {
        if (state === 'method') {
          if (buf.length < 2) return;
          if (buf[0] !== 0x05) return fail('SOCKS5: ver != 5 na resposta de método');
          const method = buf[1];
          buf = buf.slice(2);
          if (method === 0x00) { sendConnect(); state = 'connect'; continue; }
          if (method === 0x02) {
            if (!cfg.user) return fail('SOCKS5: proxy exige auth user/pass');
            sendAuth(); state = 'auth'; continue;
          }
          if (method === 0xff) return fail('SOCKS5: nenhum método aceitável');
          return fail(`SOCKS5: método inesperado 0x${method.toString(16)}`);
        }
        if (state === 'auth') {
          if (buf.length < 2) return;
          if (buf[0] !== 0x01) return fail('SOCKS5 auth: versão inválida');
          if (buf[1] !== 0x00) return fail('SOCKS5 auth: rejeitada (status != 0)');
          buf = buf.slice(2);
          sendConnect(); state = 'connect'; continue;
        }
        if (state === 'connect') {
          if (buf.length < 5) return;
          if (buf[0] !== 0x05) return fail('SOCKS5 connect: ver != 5');
          const rep = buf[1];
          if (rep !== 0x00) return fail(`SOCKS5 connect: ${SOCKS5_REPLIES[rep] || `rep=0x${rep.toString(16)}`}`);
          const atyp = buf[3];
          let addrLen;
          if (atyp === 0x01) addrLen = 4;
          else if (atyp === 0x04) addrLen = 16;
          else if (atyp === 0x03) addrLen = 1 + buf[4];
          else return fail(`SOCKS5 connect: ATYP inválido 0x${atyp.toString(16)}`);
          const need = 4 + addrLen + 2;
          if (buf.length < need) return;
          buf = buf.slice(need);
          if (buf.length > 0) {
            // dados extra já chegados (raro com upstream HTTP/HTTPS): empurra de volta
            sock.unshift(buf);
          }
          return done();
        }
        return; // safety
      }
    };

    function sendAuth() {
      const u = Buffer.from(cfg.user || '', 'utf8');
      const p = Buffer.from(cfg.pass || '', 'utf8');
      if (u.length > 255 || p.length > 255) return fail('SOCKS5 auth: user/pass > 255 bytes');
      const frame = Buffer.concat([
        Buffer.from([0x01, u.length]), u,
        Buffer.from([p.length]), p,
      ]);
      sock.write(frame);
    }
    function sendConnect() {
      let addrFrame;
      if (target.remoteDns) {
        const h = Buffer.from(target.host, 'utf8');
        if (h.length > 255) return fail('SOCKS5: hostname > 255 bytes');
        addrFrame = Buffer.concat([Buffer.from([0x03, h.length]), h]);
      } else if (net.isIPv4(target.host)) {
        const parts = target.host.split('.').map((n) => Number(n) & 0xff);
        addrFrame = Buffer.concat([Buffer.from([0x01]), Buffer.from(parts)]);
      } else if (net.isIPv6(target.host)) {
        return fail('SOCKS5: IPv6 literal não suportado pelo dispatcher inline; use socks5h://');
      } else {
        const h = Buffer.from(target.host, 'utf8');
        addrFrame = Buffer.concat([Buffer.from([0x03, h.length]), h]);
      }
      const portBuf = Buffer.alloc(2);
      portBuf.writeUInt16BE(target.port, 0);
      const frame = Buffer.concat([Buffer.from([0x05, 0x01, 0x00]), addrFrame, portBuf]);
      sock.write(frame);
    }

    sock.on('error', onErr);
    sock.on('close', onClose);
    sock.on('data', onData);

    // 1) Negociação inicial: VER NMETHODS METHODS
    const methods = cfg.user ? Buffer.from([0x05, 0x02, 0x00, 0x02]) : Buffer.from([0x05, 0x01, 0x00]);
    sock.write(methods);
  });
}

/**
 * Devolve um undici.Agent que tunela cada upstream-connect através do SOCKS5.
 *
 * @returns {Promise<import('undici').Dispatcher>}
 */
export async function createSocksDispatcher(proxyHref, agentOpts = {}) {
  const undici = await loadUndici();
  if (!undici || !undici.Agent) throw new Error('undici não disponível — instala dependências');
  const cfg = parseSocksUrl(proxyHref);

  function connect(opts, cb) {
    const targetHost = opts.hostname;
    const targetPort = Number(opts.port) || (opts.protocol === 'https:' ? 443 : 80);
    const isHttps = opts.protocol === 'https:';
    const tcp = net.connect({ host: cfg.host, port: cfg.port });
    let settled = false;
    const fail = (e) => {
      if (settled) return;
      settled = true;
      try { tcp.destroy(); } catch { /* ignore */ }
      cb(e);
    };
    tcp.once('error', fail);
    tcp.once('connect', () => {
      socks5Handshake(tcp, cfg, { host: targetHost, port: targetPort, remoteDns: cfg.remoteDns })
        .then(() => {
          if (settled) return;
          settled = true;
          if (isHttps) {
            const tlsSock = tls.connect({
              socket: tcp,
              servername: opts.servername || targetHost,
              ALPNProtocols: opts.ALPNProtocols,
              rejectUnauthorized: opts.rejectUnauthorized !== false,
            });
            tlsSock.once('secureConnect', () => cb(null, tlsSock));
            tlsSock.once('error', (e) => cb(e));
          } else {
            cb(null, tcp);
          }
        })
        .catch(fail);
    });
  }

  return new undici.Agent({
    connect,
    keepAliveTimeout: 10_000,
    keepAliveMaxTimeout: 30_000,
    ...agentOpts,
  });
}

/**
 * Gera credenciais SOCKS únicas para activar IsolateSOCKSAuth do Tor,
 * dedicando um circuit por (user,pass).
 */
export function isolatedSocksUser(prefix = 'gr', salt = 'iso') {
  const rnd = Math.random().toString(36).slice(2, 10);
  const ts = Date.now().toString(36);
  return `${prefix}-${salt}-${ts}-${rnd}`;
}

export function injectIsolationCredentials(href, user, pass = 'x') {
  if (!isSocksUrl(href)) return href;
  const u = new URL(href);
  u.username = encodeURIComponent(user);
  u.password = encodeURIComponent(pass);
  return u.toString();
}
