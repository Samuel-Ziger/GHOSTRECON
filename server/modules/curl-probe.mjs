import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import crypto from 'node:crypto';
import { isStrict, wrapCommand as torStrictWrap } from './tor-strict.js';
import { positiveIntEnv, runProcess } from './module-runner.mjs';

export const CURL_PROBE_METHODS = Object.freeze(['GET', 'HEAD', 'OPTIONS']);
const CORS_ORIGINS = ['https://attacker.tld', 'null', 'https://evil.example'];
const SENSITIVE_HEADERS = new Set(['authorization', 'cookie', 'set-cookie', 'x-api-key', 'proxy-authorization']);
const TOOL_STDOUT_MAX_BYTES = positiveIntEnv('GHOSTRECON_TOOL_STDOUT_MAX_BYTES', 16 * 1024 * 1024, {
  max: 128 * 1024 * 1024,
});
const TOOL_STDERR_MAX_BYTES = positiveIntEnv('GHOSTRECON_TOOL_STDERR_MAX_BYTES', 2 * 1024 * 1024, {
  max: 32 * 1024 * 1024,
});

function runProc(cmd, args, timeoutMs, { signal = null } = {}) {
  if (isStrict()) {
    const w = torStrictWrap(cmd, args);
    if (w.refuse) return Promise.reject(new Error(`tor-strict: ${w.reason}`));
    cmd = w.cmd;
    args = w.args;
  }
  return runProcess(cmd, args, {
    timeoutMs,
    signal,
    stdoutMaxBytes: TOOL_STDOUT_MAX_BYTES,
    stderrMaxBytes: TOOL_STDERR_MAX_BYTES,
    label: cmd,
  });
}

function isAbortError(error) {
  return error?.name === 'AbortError' || error?.code === 'PROCESS_ABORTED';
}

function resolveCurlProfile(profile = 'standard') {
  const p = String(profile || 'standard').toLowerCase();
  if (p === 'stealth') return { timeoutSec: 20, useHttp2: false };
  if (p === 'aggressive') return { timeoutSec: 28, useHttp2: true };
  if (p === 'quick') return { timeoutSec: 10, useHttp2: true };
  return { timeoutSec: 16, useHttp2: true };
}

function safeEvidenceUrl(value) {
  try {
    const parsed = new URL(String(value || ''));
    for (const key of parsed.searchParams.keys()) parsed.searchParams.set(key, '<redacted>');
    parsed.username = '';
    parsed.password = '';
    return parsed.toString();
  } catch {
    return '<invalid-url>';
  }
}

function safeProxyLabel(value) {
  if (!value) return null;
  try {
    const parsed = new URL(String(value));
    return `${parsed.protocol}//${parsed.hostname}:${parsed.port || 'default'}`;
  } catch {
    return '<configured-proxy>';
  }
}

function safeCurlMetrics(metrics = {}) {
  return {
    ...metrics,
    redirect_url: metrics.redirect_url ? safeEvidenceUrl(metrics.redirect_url) : '',
    url_effective: metrics.url_effective ? safeEvidenceUrl(metrics.url_effective) : '',
  };
}

function resolveCurlProxy(identityCtrl = null) {
  // Em strict, proxychains lida com o tunneling — devolver null para evitar
  // SOCKS-over-SOCKS via flag --proxy do curl.
  if (isStrict()) return null;
  const fromCtrl = identityCtrl?.getCurrentProxy?.();
  if (fromCtrl) return fromCtrl;
  return null;
}

function safeHeaderMap(headers = {}) {
  const out = {};
  for (const [k, v] of Object.entries(headers || {})) {
    const key = String(k || '').toLowerCase();
    if (!key) continue;
    if (SENSITIVE_HEADERS.has(key)) out[key] = '<redacted>';
    else if (key === 'location' && /^https?:\/\//i.test(String(v || ''))) out[key] = safeEvidenceUrl(v);
    else out[key] = String(v || '').slice(0, 500);
  }
  return out;
}

function parseHeaderBlocks(raw) {
  const blocks = String(raw || '')
    .split(/\r?\n\r?\n/)
    .map((b) => b.trim())
    .filter(Boolean);
  const last = blocks[blocks.length - 1] || '';
  const lines = last.split(/\r?\n/);
  const statusLine = lines[0] || '';
  const headers = {};
  for (const ln of lines.slice(1)) {
    const idx = ln.indexOf(':');
    if (idx <= 0) continue;
    const k = ln.slice(0, idx).trim().toLowerCase();
    const v = ln.slice(idx + 1).trim();
    headers[k] = v;
  }
  return { statusLine, headers };
}

function bodyHash(s) {
  return crypto.createHash('sha256').update(String(s || '')).digest('hex');
}

async function readUtf8FileSnippet(file, maxBytes) {
  let handle = null;
  try {
    handle = await fs.open(file, 'r');
    const buffer = Buffer.alloc(Math.max(1, Number(maxBytes) || 1));
    const { bytesRead } = await handle.read(buffer, 0, buffer.length, 0);
    return buffer.subarray(0, bytesRead).toString('utf8');
  } catch {
    return '';
  } finally {
    if (handle) await handle.close().catch(() => {});
  }
}

function oneLineCurl({ method, url, auth, extraHeaders = {}, body = null }) {
  const parts = ['curl', '-sS', '-X', method];
  if (auth?.cookie) parts.push('-H', '"Cookie: <redacted>"');
  if (auth?.headers && typeof auth.headers === 'object') {
    for (const [k, v] of Object.entries(auth.headers)) {
      if (!k || v == null) continue;
      parts.push('-H', `"${String(k)}: <redacted>"`);
    }
  }
  for (const [k, v] of Object.entries(extraHeaders || {})) {
    parts.push('-H', `"${String(k)}: ${String(v).replace(/"/g, '\\"')}"`);
  }
  if (body != null) parts.push('--data-raw', `"${String(body).replace(/"/g, '\\"')}"`);
  parts.push(`"${safeEvidenceUrl(url)}"`);
  return parts.join(' ');
}

function curlConfigQuote(value) {
  return String(value ?? '')
    .replace(/[\r\n]+/g, ' ')
    .replace(/\\/g, '\\\\')
    .replace(/"/g, '\\"');
}

function buildSensitiveCurlConfig(auth, proxy = null, url = '') {
  const lines = [
    `url = "${curlConfigQuote(url)}"`,
    // Sobrescreve http_proxy/https_proxy do ambiente; um proxy só entra pelo
    // snapshot de identidade aprovado.
    `proxy = "${curlConfigQuote(proxy || '')}"`,
  ];
  if (auth?.cookie) {
    lines.push(`header = "Cookie: ${curlConfigQuote(auth.cookie)}"`);
  }
  if (auth?.headers && typeof auth.headers === 'object') {
    for (const [rawName, rawValue] of Object.entries(auth.headers)) {
      const name = String(rawName || '').trim().replace(/[^A-Za-z0-9!#$%&'*+.^_`|~-]/g, '');
      if (!name || rawValue == null) continue;
      lines.push(`header = "${name}: ${curlConfigQuote(rawValue)}"`);
    }
  }
  return lines.join('\n');
}

async function execCurl({
  url,
  method = 'GET',
  auth = null,
  profile = 'standard',
  proxy = null,
  extraHeaders = {},
  body = null,
  signal = null,
}) {
  const normalizedMethod = String(method || '').toUpperCase();
  if (!CURL_PROBE_METHODS.includes(normalizedMethod)) {
    throw new Error(`curl_probe: método recusado (${normalizedMethod || 'vazio'})`);
  }
  if (body != null) throw new Error('curl_probe: corpo de requisição recusado');
  const cfg = resolveCurlProfile(profile);
  const tmpDir = await fs.mkdtemp(path.join(os.tmpdir(), 'ghostrecon-curl-probe-'));
  const headersFile = path.join(tmpDir, 'headers.txt');
  const bodyFile = path.join(tmpDir, 'body.txt');
  try {
    await fs.chmod(tmpDir, 0o700);
    const args = [
      '-q',
      '-sS',
      '--tlsv1.2',
      '--compressed',
      '--proto',
      '=http,https',
      '--max-filesize',
      '1048576',
      '--max-redirs',
      '0',
      '-m',
      String(cfg.timeoutSec),
      '-g',
      '-X',
      normalizedMethod,
      '-D',
      headersFile,
      '-o',
      bodyFile,
      '-w',
      '{"http_code":"%{http_code}","time_total":"%{time_total}","redirect_url":"%{redirect_url}","size_download":"%{size_download}","remote_ip":"%{remote_ip}","url_effective":"%{url_effective}"}',
      '-A',
      'GhostRecon-curl-probe/1.0',
    ];
    if (cfg.useHttp2) args.push('--http2');
    const sensitiveConfig = buildSensitiveCurlConfig(auth, proxy, url);
    const requestConfigFile = path.join(tmpDir, 'request.curlrc');
    await fs.writeFile(requestConfigFile, `${sensitiveConfig}\n`, {
      encoding: 'utf8',
      mode: 0o600,
      flag: 'wx',
    });
    await fs.chmod(requestConfigFile, 0o600);
    args.push('--config', requestConfigFile);
    for (const [k, v] of Object.entries(extraHeaders || {})) args.push('-H', `${k}: ${v}`);

    const proc = await runProc(
      'curl',
      args,
      Math.max(20_000, cfg.timeoutSec * 1000 + 5000),
      { signal },
    );
    const responseBody = await readUtf8FileSnippet(bodyFile, 1024 * 1024);
    const headerRaw = await readUtf8FileSnippet(headersFile, 512 * 1024);
    const parsed = parseHeaderBlocks(headerRaw);
    let metrics = {};
    try {
      metrics = safeCurlMetrics(JSON.parse(String(proc.stdout || '{}').trim() || '{}'));
    } catch {
      metrics = {};
    }
    const status = Number(metrics.http_code || 0);
    const exitCode = Number(proc.code);
    const complete = exitCode === 0 && Number.isInteger(status) && status >= 100 && status <= 599;
    return {
      ok: complete,
      exitCode,
      outcome: complete ? 'done' : exitCode === 28 ? 'timeout' : exitCode === 63 ? 'response_too_large' : 'failed',
      status,
      body: responseBody,
      bodyHash: bodyHash(responseBody),
      bodySize: Buffer.byteLength(responseBody, 'utf8'),
      headers: parsed.headers,
      statusLine: parsed.statusLine,
      metrics,
      stderr: '',
      truncated: Number(proc.code) === 63,
      curlTemplate: oneLineCurl({ method: normalizedMethod, url, auth, extraHeaders }),
    };
  } catch (e) {
    if (isAbortError(e)) throw e;
    return { ok: false, status: 0, body: '', bodyHash: bodyHash(''), bodySize: 0, headers: {}, metrics: {}, error: e?.message || String(e) };
  } finally {
    await fs.rm(tmpDir, { recursive: true, force: true }).catch(() => {});
  }
}

function collectProbeUrls(target, findings = [], maxUrls = 12, urlAllowed = () => true) {
  const out = [];
  const seen = new Set();
  for (const f of findings || []) {
    if (f?.type !== 'endpoint') continue;
    const u = String(f.value || '');
    if (!/^https?:\/\//i.test(u)) continue;
    let parsed;
    try { parsed = new URL(u); } catch { continue; }
    if (parsed.username || parsed.password) continue;
    if (seen.has(parsed.href) || urlAllowed(parsed.href) !== true) continue;
    seen.add(parsed.href);
    out.push(parsed.href);
    if (out.length >= maxUrls) break;
  }
  if (!out.length && target) {
    const candidate = /^https?:\/\//i.test(String(target))
      ? String(target)
      : `https://${String(target).replace(/\/+$/, '')}/`;
    try {
      const parsed = new URL(candidate);
      if (!parsed.username && !parsed.password && urlAllowed(parsed.href) === true) out.push(parsed.href);
    } catch {
      // Alvo inválido: nenhum probe.
    }
  }
  return out;
}

async function persistEvidence(rows, { enabled = false } = {}) {
  if (!enabled) return null;
  if (!rows.length) return null;
  const dir = path.resolve(process.cwd(), '.ghostrecon-curl-probe');
  await fs.mkdir(dir, { recursive: true, mode: 0o700 });
  await fs.chmod(dir, 0o700);
  const file = path.join(dir, `${new Date().toISOString().replace(/[:.]/g, '-')}.jsonl`);
  const lines = rows.map((r) => JSON.stringify(r)).join('\n') + '\n';
  await fs.writeFile(file, lines, { encoding: 'utf8', mode: 0o600, flag: 'wx' });
  await fs.chmod(file, 0o600);
  return file;
}

export async function runCurlProbeModule({
  target,
  findings = [],
  auth = null,
  profile = 'standard',
  identityCtrl = null,
  log = null,
  signal = null,
  urlAllowed = () => true,
  persist = String(process.env.GHOSTRECON_CURL_PROBE_PERSIST_EVIDENCE || '') === '1',
  execCurlImpl = execCurl,
}) {
  const logFn = typeof log === 'function' ? log : () => {};
  if (signal?.aborted) {
    const error = signal.reason instanceof Error ? signal.reason : new Error('curl_probe cancelado');
    if (!error.name || error.name === 'Error') error.name = 'AbortError';
    if (!error.code) error.code = 'PROCESS_ABORTED';
    throw error;
  }
  const exec = (options) => execCurlImpl({ ...options, signal });
  const urls = collectProbeUrls(target, findings, 12, urlAllowed);
  if (!urls.length) return [];
  const proxy = resolveCurlProxy(identityCtrl);
  const out = [];
  const evidenceRows = [];
  let successfulExecutions = 0;
  for (const url of urls) {
    const evidenceUrl = safeEvidenceUrl(url);
    logFn(`curl_probe: ${evidenceUrl}`, 'info');
    const baseAuth = await exec({ url, method: 'GET', auth, profile, proxy });
    const baseNoAuth = auth
      ? await exec({ url, method: 'GET', auth: null, profile, proxy })
      : baseAuth;
    const withOrigin = await exec({
      url,
      method: 'GET',
      auth,
      profile,
      proxy,
      extraHeaders: { Origin: CORS_ORIGINS[0] },
    });
    const head = await exec({ url, method: 'HEAD', auth, profile, proxy });
    const options = await exec({ url, method: 'OPTIONS', auth, profile, proxy });
    successfulExecutions += [baseAuth, baseNoAuth, withOrigin, head, options]
      .filter((row, index, all) => row?.ok === true && all.indexOf(row) === index)
      .length;
    const methodRows = [
      { method: 'GET', status: baseAuth.status, size: baseAuth.bodySize },
      { method: 'HEAD', status: head.status, size: head.bodySize },
      { method: 'OPTIONS', status: options.status, size: options.bodySize },
    ];
    const advertisedMethods = [...new Set(
      String(options.headers?.allow || '')
        .split(',')
        .map((method) => method.trim().toUpperCase())
        .filter((method) => /^[A-Z]{3,12}$/.test(method)),
    )];
    const advertisedMutating = advertisedMethods.filter((method) => (
      ['POST', 'PUT', 'PATCH', 'DELETE'].includes(method)
    ));
    if (options.ok === true && advertisedMutating.length) {
      out.push({
        type: 'http_method_advertised',
        prio: 'low',
        score: 45,
        value: `OPTIONS anuncia métodos mutáveis: ${advertisedMutating.join(', ')}`,
        url: evidenceUrl,
        meta: 'source=curl_probe • classification=inventory • nenhum método mutável foi enviado',
        verification: {
          classification: 'inventory',
          evidence: {
            source: 'curl_probe',
            url: evidenceUrl,
            method: 'OPTIONS',
            status: options.status,
            allow: advertisedMethods,
            requestSnippet: oneLineCurl({ method: 'OPTIONS', url, auth }),
          },
          verifiedAt: new Date().toISOString(),
        },
      });
    }

    if (auth) {
      const sameStatus = baseAuth.status === baseNoAuth.status;
      const sameBody = Boolean(baseAuth.bodyHash) && baseAuth.bodyHash === baseNoAuth.bodyHash;
      const sameType = String(baseAuth.headers?.['content-type'] || '')
        === String(baseNoAuth.headers?.['content-type'] || '');
      if (baseAuth.ok === true && baseNoAuth.ok === true && !baseAuth.truncated && !baseNoAuth.truncated && sameStatus && sameBody && sameType && baseNoAuth.status >= 200 && baseNoAuth.status < 300) {
        out.push({
          type: 'auth_surface_equivalent',
          prio: 'info',
          score: 25,
          value: 'Resposta autenticada e anônima equivalentes; endpoint pode ser público',
          url: evidenceUrl,
          meta: `source=curl_probe • classification=inventory • status=${baseNoAuth.status} • não é prova de auth bypass`,
          verification: {
            classification: 'inventory',
            evidence: {
              source: 'curl_probe',
              url: evidenceUrl,
              method: 'GET',
              status: baseNoAuth.status,
              authenticatedBodyHash: baseAuth.bodyHash,
              anonymousBodyHash: baseNoAuth.bodyHash,
            },
            verifiedAt: new Date().toISOString(),
          },
        });
      }
    }

    const acao = String(withOrigin.headers?.['access-control-allow-origin'] || '');
    const acac = String(withOrigin.headers?.['access-control-allow-credentials'] || '');
    const reflectedCredentialedOrigin = acao === CORS_ORIGINS[0] && acac.trim() === 'true';
    const wildcardCredentialCombination = acao === '*' && acac.trim() === 'true';
    if (withOrigin.ok === true && withOrigin.status >= 200 && withOrigin.status < 300 && (reflectedCredentialedOrigin || wildcardCredentialCombination)) {
      out.push({
        type: 'cors_policy_candidate',
        prio: reflectedCredentialedOrigin ? 'med' : 'low',
        score: reflectedCredentialedOrigin ? 56 : 28,
        value: reflectedCredentialedOrigin
          ? 'Origin externo refletido com credenciais permitidas'
          : 'Combinação CORS wildcard + credentials observada (navegadores bloqueiam wildcard credenciado)',
        url: evidenceUrl,
        meta: `source=curl_probe • classification=candidate • acao=${acao} • acac=${acac} • browser_read=not_verified • impact=not_verified`,
        verification: {
          classification: 'candidate',
          evidence: {
            source: 'curl_probe',
            url: evidenceUrl,
            method: 'GET',
            status: withOrigin.status,
            requestSnippet: oneLineCurl({
              method: 'GET',
              url,
              auth,
              extraHeaders: { Origin: CORS_ORIGINS[0] },
            }),
            responseSnippet: JSON.stringify({ acao, acac }),
            curlMetrics: safeCurlMetrics(withOrigin.metrics),
            curlHeaders: safeHeaderMap(withOrigin.headers),
          },
          verifiedAt: new Date().toISOString(),
        },
      });
    }
    evidenceRows.push({
      ts: new Date().toISOString(),
      source: 'curl_probe',
      url: evidenceUrl,
      proxy: safeProxyLabel(proxy),
      baseAuth: {
        status: baseAuth.status,
        metrics: safeCurlMetrics(baseAuth.metrics),
        headers: safeHeaderMap(baseAuth.headers),
        bodyHash: baseAuth.bodyHash,
        bodySize: baseAuth.bodySize,
      },
      baseNoAuth: {
        status: baseNoAuth.status,
        metrics: safeCurlMetrics(baseNoAuth.metrics),
        headers: safeHeaderMap(baseNoAuth.headers),
        bodyHash: baseNoAuth.bodyHash,
        bodySize: baseNoAuth.bodySize,
      },
      cors: {
        origin: CORS_ORIGINS[0],
        status: withOrigin.status,
        headers: safeHeaderMap(withOrigin.headers),
      },
      methods: methodRows,
    });
  }

  if (successfulExecutions === 0) {
    throw new Error('curl_probe: nenhuma requisição produziu resposta utilizável');
  }

  const evidenceFile = await persistEvidence(evidenceRows, { enabled: persist }).catch(() => null);
  if (evidenceFile) logFn(`curl_probe: evidências em ${evidenceFile}`, 'info');
  return out;
}
