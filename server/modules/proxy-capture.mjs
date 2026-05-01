/**
 * proxy-capture.mjs
 *
 * Proxy HTTP/HTTPS MITM integrado ao GHOSTRECON.
 * Captura tráfego do browser do operador — similar ao Burp Suite Proxy.
 *
 * HTTP  : intercepta request/response completo.
 * HTTPS : CONNECT tunnel → TLS MITM → request/response completo.
 *         Requer CA instalada no browser (GET /api/proxy/ca.crt).
 *
 * Certs gerados com OpenSSL CLI (disponível no Kali).
 * Fallback sem MITM: apenas registra host/porta no CONNECT.
 *
 * Uso:
 *   const p = createProxyCapture({ onCapture, port: 8081 });
 *   await p.start();
 *   p.stop();
 */

import net from 'node:net';
import http from 'node:http';
import https from 'node:https';
import tls from 'node:tls';
import { execSync, spawnSync } from 'node:child_process';
import { existsSync, readFileSync, mkdirSync, writeFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { createHash } from 'node:crypto';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const CERTS_DIR = path.join(__dirname, '..', '..', '.runtime', 'proxy-certs');
const CA_KEY  = path.join(CERTS_DIR, 'ca.key');
const CA_CERT = path.join(CERTS_DIR, 'ca.crt');
const HOSTS_DIR = path.join(CERTS_DIR, 'hosts');

const DEFAULT_PORT = 8081;
const MAX_BODY = 1 * 1024 * 1024; // 1 MB

// ── OPENSSL HELPERS ───────────────────────────────────────────────────────────

function opensslAvailable() {
  try { execSync('openssl version', { stdio: 'pipe' }); return true; }
  catch { return false; }
}

function ensureCaExists() {
  mkdirSync(CERTS_DIR, { recursive: true });
  mkdirSync(HOSTS_DIR, { recursive: true });
  if (existsSync(CA_CERT) && existsSync(CA_KEY)) return true;
  if (!opensslAvailable()) return false;
  try {
    execSync(
      `openssl genrsa -out "${CA_KEY}" 4096 2>/dev/null && ` +
      `openssl req -new -x509 -days 3650 -key "${CA_KEY}" -out "${CA_CERT}" ` +
      `-subj "/C=BR/O=GHOSTRECON/CN=GHOSTRECON Proxy CA" 2>/dev/null`,
      { shell: '/bin/bash', stdio: 'pipe' },
    );
    return true;
  } catch { return false; }
}

function hostCertDir(hostname) {
  const safe = hostname.replace(/[^a-zA-Z0-9.-]/g, '_').slice(0, 80);
  return path.join(HOSTS_DIR, safe);
}

function ensureHostCert(hostname) {
  const dir = hostCertDir(hostname);
  const certPath = path.join(dir, 'cert.pem');
  const keyPath  = path.join(dir, 'key.pem');
  if (existsSync(certPath) && existsSync(keyPath)) {
    return { key: readFileSync(keyPath), cert: readFileSync(certPath) };
  }
  mkdirSync(dir, { recursive: true });
  const sanConf = path.join(dir, 'san.cnf');
  writeFileSync(sanConf,
    `[req]\nreq_extensions = v3_req\ndistinguished_name = req_distinguished_name\n` +
    `[req_distinguished_name]\n[v3_req]\nsubjectAltName = DNS:${hostname},DNS:*.${hostname}\n`,
  );
  try {
    execSync(
      `openssl genrsa -out "${keyPath}" 2048 2>/dev/null && ` +
      `openssl req -new -key "${keyPath}" -out "${dir}/csr.pem" -subj "/CN=${hostname}" 2>/dev/null && ` +
      `openssl x509 -req -in "${dir}/csr.pem" -CA "${CA_CERT}" -CAkey "${CA_KEY}" ` +
      `-CAcreateserial -out "${certPath}" -days 825 -sha256 ` +
      `-extensions v3_req -extfile "${sanConf}" 2>/dev/null`,
      { shell: '/bin/bash', stdio: 'pipe' },
    );
    return { key: readFileSync(keyPath), cert: readFileSync(certPath) };
  } catch {
    return null;
  }
}

// ── BODY COLLECTOR ────────────────────────────────────────────────────────────

function collectBody(stream) {
  return new Promise((resolve) => {
    const chunks = [];
    let total = 0;
    stream.on('data', (c) => {
      total += c.length;
      if (total <= MAX_BODY) chunks.push(c);
    });
    stream.on('end', () => resolve(Buffer.concat(chunks).toString('utf8').slice(0, MAX_BODY)));
    stream.on('error', () => resolve(''));
    stream.on('close', () => resolve(Buffer.concat(chunks).toString('utf8').slice(0, MAX_BODY)));
  });
}

function normalizeHeaders(raw) {
  const out = {};
  if (!raw) return out;
  if (typeof raw.forEach === 'function') {
    raw.forEach((v, k) => { out[k.toLowerCase()] = v; });
    return out;
  }
  for (const [k, v] of Object.entries(raw)) out[k.toLowerCase()] = String(v);
  return out;
}

function shortId() {
  return createHash('sha256').update(String(Date.now() + Math.random())).digest('hex').slice(0, 8);
}

// ── FORWARD HTTP REQUEST ──────────────────────────────────────────────────────

function forwardRequest(clientReq, clientRes, onCapture, targetOverride = null) {
  let targetUrl;
  try {
    const raw = targetOverride || clientReq.url;
    targetUrl = /^https?:\/\//i.test(raw) ? raw : `http://${clientReq.headers.host}${raw}`;
    new URL(targetUrl); // validate
  } catch {
    clientRes.writeHead(400).end('Bad Request');
    return;
  }

  const parsed = new URL(targetUrl);
  const isHttps = parsed.protocol === 'https:';
  const mod = isHttps ? https : http;
  const port = Number(parsed.port) || (isHttps ? 443 : 80);

  const reqHeaders = { ...clientReq.headers };
  delete reqHeaders['proxy-connection'];
  delete reqHeaders['proxy-authorization'];

  const started = Date.now();
  const entry = {
    id: shortId(),
    ts: new Date().toISOString(),
    source: 'browser',
    method: clientReq.method,
    url: targetUrl,
    requestHeaders: normalizeHeaders(reqHeaders),
    requestBody: '',
    status: null,
    statusText: '',
    durationMs: null,
    responseHeaders: {},
    responseBody: '',
    mimeType: '',
    responseSize: null,
    error: '',
  };

  const proxyReq = mod.request(
    {
      hostname: parsed.hostname,
      port,
      path: parsed.pathname + parsed.search,
      method: clientReq.method,
      headers: reqHeaders,
      rejectUnauthorized: false,
    },
    (proxyRes) => {
      entry.status = proxyRes.statusCode;
      entry.statusText = proxyRes.statusMessage || '';
      entry.responseHeaders = normalizeHeaders(proxyRes.headers);
      entry.mimeType = (proxyRes.headers['content-type'] || '').split(';')[0].trim();
      entry.durationMs = Date.now() - started;
      entry.responseSize = Number(proxyRes.headers['content-length'] || 0) || null;

      clientRes.writeHead(proxyRes.statusCode, proxyRes.headers);
      const chunks = [];
      let total = 0;
      proxyRes.on('data', (c) => {
        clientRes.write(c);
        total += c.length;
        if (total <= MAX_BODY) chunks.push(c);
      });
      proxyRes.on('end', () => {
        clientRes.end();
        entry.responseBody = Buffer.concat(chunks).toString('utf8').slice(0, MAX_BODY);
        entry.responseSize = entry.responseSize || total;
        onCapture?.(entry);
      });
      proxyRes.on('error', () => { clientRes.end(); onCapture?.(entry); });
    },
  );

  proxyReq.on('error', (e) => {
    entry.error = e.message;
    entry.durationMs = Date.now() - started;
    onCapture?.(entry);
    if (!clientRes.headersSent) clientRes.writeHead(502).end('Bad Gateway: ' + e.message);
  });

  // Pipe + capture request body
  const reqChunks = [];
  let reqTotal = 0;
  clientReq.on('data', (c) => {
    proxyReq.write(c);
    reqTotal += c.length;
    if (reqTotal <= MAX_BODY) reqChunks.push(c);
  });
  clientReq.on('end', () => {
    proxyReq.end();
    entry.requestBody = Buffer.concat(reqChunks).toString('utf8').slice(0, MAX_BODY);
  });
  clientReq.on('error', () => proxyReq.destroy());
}

// ── HTTPS MITM ────────────────────────────────────────────────────────────────

function handleConnect(clientReq, clientSocket, head, onCapture, mitmEnabled) {
  const [hostname, portStr] = (clientReq.url || '').split(':');
  const port = Number(portStr) || 443;

  if (!mitmEnabled) {
    // Transparent tunnel — only metadata captured
    const serverSocket = net.connect(port, hostname, () => {
      clientSocket.write('HTTP/1.1 200 Connection Established\r\n\r\n');
      serverSocket.write(head);
      serverSocket.pipe(clientSocket);
      clientSocket.pipe(serverSocket);
    });
    serverSocket.on('error', () => clientSocket.destroy());
    clientSocket.on('error', () => serverSocket.destroy());
    onCapture?.({
      id: shortId(),
      ts: new Date().toISOString(),
      source: 'browser',
      method: 'CONNECT',
      url: `https://${hostname}:${port}`,
      requestHeaders: normalizeHeaders(clientReq.headers),
      requestBody: '',
      status: 200,
      statusText: 'Tunnel (no MITM)',
      durationMs: null,
      responseHeaders: {},
      responseBody: '(HTTPS tunnel — sem MITM)',
      mimeType: '',
      responseSize: null,
      error: '',
    });
    return;
  }

  const creds = ensureHostCert(hostname);
  if (!creds) {
    // Fall back to transparent
    return handleConnect(clientReq, clientSocket, head, onCapture, false);
  }

  // Respond to CONNECT
  clientSocket.write('HTTP/1.1 200 Connection Established\r\n\r\n');

  // Wrap client in TLS server
  const tlsServer = new tls.TLSSocket(clientSocket, {
    isServer: true,
    key: creds.key,
    cert: creds.cert,
    rejectUnauthorized: false,
  });

  tlsServer.on('error', () => {});
  clientSocket.on('error', () => {});

  // Parse the decrypted HTTP from client
  const innerHttp = http.createServer();
  innerHttp.emit('connection', tlsServer);
  innerHttp.on('request', (innerReq, innerRes) => {
    innerReq.url = `https://${hostname}:${port}${innerReq.url}`;
    forwardRequest(innerReq, innerRes, onCapture, innerReq.url);
  });
}

// ── PROXY SERVER ──────────────────────────────────────────────────────────────

export function createProxyCapture({ onCapture = null, port = DEFAULT_PORT, mitmEnabled = true } = {}) {
  let server = null;
  let running = false;
  let capturedCount = 0;
  const _mitmEnabled = { value: mitmEnabled };

  const caReady = ensureCaExists();

  const handler = (req, res) => {
    forwardRequest(req, res, (e) => {
      capturedCount++;
      onCapture?.(e);
    });
  };

  function start() {
    return new Promise((resolve, reject) => {
      if (running) { resolve({ ok: true, port, already: true }); return; }
      server = http.createServer(handler);
      server.on('connect', (req, socket, head) => {
        handleConnect(req, socket, head, (e) => { capturedCount++; onCapture?.(e); }, _mitmEnabled.value && caReady);
      });
      server.on('error', reject);
      server.listen(port, '127.0.0.1', () => {
        running = true;
        resolve({ ok: true, port, caReady, mitmEnabled: _mitmEnabled.value && caReady });
      });
    });
  }

  function stop() {
    return new Promise((resolve) => {
      if (!server || !running) { resolve({ ok: true }); return; }
      server.close(() => {
        running = false;
        server = null;
        resolve({ ok: true });
      });
    });
  }

  return {
    start,
    stop,
    status() {
      return {
        running,
        port,
        capturedCount,
        caReady,
        mitmEnabled: _mitmEnabled.value && caReady,
        caCertPath: caReady ? CA_CERT : null,
      };
    },
    setMitm(enabled) { _mitmEnabled.value = Boolean(enabled); },
    get caCertPath() { return caReady ? CA_CERT : null; },
    get caCert() { return caReady ? readFileSync(CA_CERT, 'utf8') : null; },
  };
}

export const PROXY_DEFAULT_PORT = DEFAULT_PORT;
export { CA_CERT as PROXY_CA_CERT_PATH };
