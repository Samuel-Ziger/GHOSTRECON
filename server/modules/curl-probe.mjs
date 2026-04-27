import { spawn } from 'node:child_process';
import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import crypto from 'node:crypto';

const METHODS = ['GET', 'HEAD', 'OPTIONS', 'POST', 'PUT', 'PATCH', 'DELETE'];
const CORS_ORIGINS = ['https://attacker.tld', 'null', 'https://evil.example'];
const SENSITIVE_HEADERS = new Set(['authorization', 'cookie', 'set-cookie', 'x-api-key', 'proxy-authorization']);

function runProc(cmd, args, timeoutMs) {
  return new Promise((resolve, reject) => {
    const child = spawn(cmd, args, { stdio: ['ignore', 'pipe', 'pipe'] });
    const out = [];
    const err = [];
    let killed = false;
    const t = setTimeout(() => {
      killed = true;
      try {
        child.kill('SIGKILL');
      } catch {}
      reject(new Error(`${cmd} timeout (${timeoutMs}ms)`));
    }, timeoutMs);
    child.stdout.on('data', (d) => out.push(d));
    child.stderr.on('data', (d) => err.push(d));
    child.on('error', (e) => {
      clearTimeout(t);
      reject(e);
    });
    child.on('close', (code) => {
      clearTimeout(t);
      if (killed) return;
      resolve({ code, stdout: Buffer.concat(out).toString('utf8'), stderr: Buffer.concat(err).toString('utf8') });
    });
  });
}

function resolveCurlProfile(profile = 'standard') {
  const p = String(profile || 'standard').toLowerCase();
  if (p === 'stealth') return { timeoutSec: 20, retry: 1, retryDelaySec: 2, useHttp2: false };
  if (p === 'aggressive') return { timeoutSec: 28, retry: 3, retryDelaySec: 1, useHttp2: true };
  if (p === 'quick') return { timeoutSec: 10, retry: 1, retryDelaySec: 1, useHttp2: true };
  return { timeoutSec: 16, retry: 2, retryDelaySec: 1, useHttp2: true };
}

function resolveCurlProxy(identityCtrl = null) {
  const fromCtrl = identityCtrl?.getCurrentProxy?.();
  if (fromCtrl) return fromCtrl;
  const envPool = String(process.env.GHOSTRECON_PROXY_POOL || '')
    .split(/[,;\n]/)
    .map((s) => s.trim())
    .filter(Boolean);
  return envPool[0] || null;
}

function safeHeaderMap(headers = {}) {
  const out = {};
  for (const [k, v] of Object.entries(headers || {})) {
    const key = String(k || '').toLowerCase();
    if (!key) continue;
    out[key] = SENSITIVE_HEADERS.has(key) ? '<redacted>' : String(v || '').slice(0, 500);
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

function oneLineCurl({ method, url, auth, extraHeaders = {}, body = null }) {
  const parts = ['curl', '-sS', '-X', method];
  if (auth?.cookie) parts.push('-H', `"Cookie: ${String(auth.cookie).replace(/"/g, '\\"')}"`);
  if (auth?.headers && typeof auth.headers === 'object') {
    for (const [k, v] of Object.entries(auth.headers)) {
      if (!k || v == null) continue;
      parts.push('-H', `"${String(k)}: ${String(v).replace(/"/g, '\\"')}"`);
    }
  }
  for (const [k, v] of Object.entries(extraHeaders || {})) {
    parts.push('-H', `"${String(k)}: ${String(v).replace(/"/g, '\\"')}"`);
  }
  if (body != null) parts.push('--data-raw', `"${String(body).replace(/"/g, '\\"')}"`);
  parts.push(`"${url}"`);
  return parts.join(' ');
}

async function execCurl({
  url,
  method = 'GET',
  auth = null,
  profile = 'standard',
  proxy = null,
  extraHeaders = {},
  body = null,
}) {
  const cfg = resolveCurlProfile(profile);
  const tmpDir = await fs.mkdtemp(path.join(os.tmpdir(), 'ghostrecon-curl-probe-'));
  const headersFile = path.join(tmpDir, 'headers.txt');
  const bodyFile = path.join(tmpDir, 'body.txt');
  try {
    const args = [
      '-sS',
      '--fail-with-body',
      '--tlsv1.2',
      '--compressed',
      '-L',
      '--max-redirs',
      '2',
      '--retry',
      String(cfg.retry),
      '--retry-delay',
      String(cfg.retryDelaySec),
      '--retry-connrefused',
      '-m',
      String(cfg.timeoutSec),
      '-g',
      '-X',
      method,
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
    if (proxy) args.push('--proxy', String(proxy));
    if (auth?.cookie) args.push('-H', `Cookie: ${String(auth.cookie)}`);
    if (auth?.headers && typeof auth.headers === 'object') {
      for (const [k, v] of Object.entries(auth.headers)) {
        if (!k || v == null) continue;
        args.push('-H', `${k}: ${String(v)}`);
      }
    }
    for (const [k, v] of Object.entries(extraHeaders || {})) args.push('-H', `${k}: ${v}`);
    if (body != null) args.push('--data-raw', String(body));
    else if (method !== 'GET' && method !== 'HEAD' && method !== 'OPTIONS') args.push('--data', '{}');
    args.push(url);

    const proc = await runProc('curl', args, Math.max(20_000, cfg.timeoutSec * 1000 + 5000));
    const body = await fs.readFile(bodyFile, 'utf8').catch(() => '');
    const headerRaw = await fs.readFile(headersFile, 'utf8').catch(() => '');
    const parsed = parseHeaderBlocks(headerRaw);
    let metrics = {};
    try {
      metrics = JSON.parse(String(proc.stdout || '{}').trim() || '{}');
    } catch {
      metrics = {};
    }
    const status = Number(metrics.http_code || 0);
    return {
      ok: true,
      status,
      body,
      bodyHash: bodyHash(body),
      bodySize: Buffer.byteLength(body, 'utf8'),
      headers: parsed.headers,
      statusLine: parsed.statusLine,
      metrics,
      stderr: proc.stderr,
      curlTemplate: oneLineCurl({ method, url, auth, extraHeaders, body }),
    };
  } catch (e) {
    return { ok: false, status: 0, body: '', bodyHash: bodyHash(''), bodySize: 0, headers: {}, metrics: {}, error: e?.message || String(e) };
  } finally {
    await fs.rm(tmpDir, { recursive: true, force: true }).catch(() => {});
  }
}

function collectProbeUrls(target, findings = [], maxUrls = 12) {
  const out = [];
  const seen = new Set();
  for (const f of findings || []) {
    if (f?.type !== 'endpoint') continue;
    const u = String(f.value || '');
    if (!/^https?:\/\//i.test(u)) continue;
    if (seen.has(u)) continue;
    seen.add(u);
    out.push(u);
    if (out.length >= maxUrls) break;
  }
  if (!out.length && target) out.push(`https://${target.replace(/\/+$/, '')}/`);
  return out;
}

async function persistEvidence(rows) {
  if (!rows.length) return null;
  const dir = path.resolve(process.cwd(), '.ghostrecon-curl-probe');
  await fs.mkdir(dir, { recursive: true });
  const file = path.join(dir, `${new Date().toISOString().replace(/[:.]/g, '-')}.jsonl`);
  const lines = rows.map((r) => JSON.stringify(r)).join('\n') + '\n';
  await fs.writeFile(file, lines, 'utf8');
  return file;
}

function looksLikeLoginUrl(url) {
  return /\/(login|signin|sign-in|auth|admin|panel|wp-login|account)(\/|$|\?)/i.test(String(url || ''));
}

function toFormUrlEncoded(obj = {}) {
  return Object.entries(obj)
    .map(([k, v]) => `${encodeURIComponent(String(k))}=${encodeURIComponent(String(v ?? ''))}`)
    .join('&');
}

async function runLoginSqliProbe({ url, auth, profile, proxy }) {
  if (!looksLikeLoginUrl(url)) return null;
  const payloads = [
    { user: "admin' OR '1'='1' -- ", pass: 'x' },
    { user: "' OR '1'='1' -- ", pass: "' OR '1'='1' -- " },
  ];
  const baselineBody = toFormUrlEncoded({ user: 'ghostrecon_invalid_user', password: 'ghostrecon_invalid_pass' });
  const base = await execCurl({
    url,
    method: 'POST',
    auth,
    profile,
    proxy,
    extraHeaders: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: baselineBody,
  });
  const candidates = [];
  for (const p of payloads) {
    const formA = toFormUrlEncoded({ user: p.user, password: p.pass });
    const formB = toFormUrlEncoded({ username: p.user, password: p.pass });
    const formC = toFormUrlEncoded({ email: p.user, password: p.pass });
    for (const body of [formA, formB, formC]) {
      const r = await execCurl({
        url,
        method: 'POST',
        auth,
        profile,
        proxy,
        extraHeaders: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body,
      });
      const statusDiff = r.status !== base.status;
      const locationDiff = String(r.headers?.location || '') !== String(base.headers?.location || '');
      const cookieAppeared = !base.headers?.['set-cookie'] && Boolean(r.headers?.['set-cookie']);
      const bodyChanged = r.bodyHash !== base.bodyHash;
      const suspicious =
        (r.status >= 200 && r.status < 400 && statusDiff) ||
        (locationDiff && /dashboard|admin|panel|home|account/i.test(String(r.headers?.location || ''))) ||
        (cookieAppeared && bodyChanged);
      candidates.push({ baseline: base, probe: r, statusDiff, locationDiff, cookieAppeared, bodyChanged, suspicious });
    }
  }
  return candidates.find((c) => c.suspicious) || null;
}

export async function runCurlProbeModule({ target, findings = [], auth = null, profile = 'standard', identityCtrl = null, log = null }) {
  const logFn = typeof log === 'function' ? log : () => {};
  const urls = collectProbeUrls(target, findings);
  if (!urls.length) return [];
  const proxy = resolveCurlProxy(identityCtrl);
  const out = [];
  const evidenceRows = [];
  for (const url of urls) {
    logFn(`curl_probe: ${url}`, 'info');
    const baseAuth = await execCurl({ url, method: 'GET', auth, profile, proxy });
    const baseNoAuth = await execCurl({ url, method: 'GET', auth: null, profile, proxy });
    const withOrigin = await execCurl({
      url,
      method: 'GET',
      auth,
      profile,
      proxy,
      extraHeaders: { Origin: CORS_ORIGINS[0] },
    });
    const methodRows = [];
    for (const m of METHODS) {
      const r = await execCurl({ url, method: m, auth, profile, proxy });
      methodRows.push({ method: m, status: r.status, size: r.bodySize });
      if (['PUT', 'PATCH', 'DELETE'].includes(m) && r.status >= 200 && r.status < 300) {
        out.push({
          type: 'curl_method_exposed',
          prio: 'high',
          score: 88,
          value: `${m} retornou ${r.status} em endpoint potencialmente mutável`,
          url,
          meta: `curl_probe • method=${m} • status=${r.status} • bytes=${r.bodySize}`,
          verification: {
            classification: 'probable',
            evidence: {
              source: 'curl_probe',
              url,
              method: m,
              status: r.status,
              requestSnippet: r.curlTemplate,
              responseSnippet: String(r.body || '').slice(0, 220).replace(/\s+/g, ' '),
              curlMetrics: r.metrics,
              curlHeaders: safeHeaderMap(r.headers),
            },
            verifiedAt: new Date().toISOString(),
          },
        });
      }
    }
    if (auth && baseNoAuth.status >= 200 && baseNoAuth.status < 300) {
      out.push({
        type: 'curl_auth_bypass',
        prio: 'high',
        score: 90,
        value: `GET sem Authorization retornou ${baseNoAuth.status} (auth bypass provável)`,
        url,
        meta: `curl_probe • with_auth=${baseAuth.status} • without_auth=${baseNoAuth.status}`,
        verification: {
          classification: 'probable',
          evidence: {
            source: 'curl_probe',
            url,
            method: 'GET',
            status: baseNoAuth.status,
            requestSnippet: baseNoAuth.curlTemplate,
            responseSnippet: String(baseNoAuth.body || '').slice(0, 220).replace(/\s+/g, ' '),
            curlMetrics: baseNoAuth.metrics,
            curlHeaders: safeHeaderMap(baseNoAuth.headers),
          },
          verifiedAt: new Date().toISOString(),
        },
      });
    }
    const acao = String(withOrigin.headers?.['access-control-allow-origin'] || '');
    const acac = String(withOrigin.headers?.['access-control-allow-credentials'] || '');
    if ((acao === CORS_ORIGINS[0] || acao === '*') && /true/i.test(acac)) {
      out.push({
        type: 'curl_cors_permissive',
        prio: 'med',
        score: 70,
        value: `CORS permissivo (acao=${acao} acac=${acac})`,
        url,
        meta: `curl_probe • active_origin_test`,
        verification: {
          classification: 'probable',
          evidence: {
            source: 'curl_probe',
            url,
            method: 'GET',
            status: withOrigin.status,
            requestSnippet: withOrigin.curlTemplate,
            responseSnippet: JSON.stringify({ acao, acac }),
            curlMetrics: withOrigin.metrics,
            curlHeaders: safeHeaderMap(withOrigin.headers),
          },
          verifiedAt: new Date().toISOString(),
        },
      });
    }
    let diffFinding = null;
    try {
      const u = new URL(url);
      if (u.searchParams.size) {
        const first = [...u.searchParams.keys()][0];
        u.searchParams.set(first, `${u.searchParams.get(first) || '1'}'`);
        const mut = await execCurl({ url: u.href, method: 'GET', auth, profile, proxy });
        const hdrDiff = ['content-type', 'location', 'server']
          .filter((k) => String(mut.headers?.[k] || '') !== String(baseAuth.headers?.[k] || ''));
        const changed = mut.status !== baseAuth.status || mut.bodyHash !== baseAuth.bodyHash || hdrDiff.length;
        if (changed) {
          diffFinding = {
            type: 'curl_response_diff',
            prio: 'med',
            score: 72,
            value: `Diff de resposta entre baseline e payload mutado em ?${first}=`,
            url: u.href,
            meta: `curl_probe • status ${baseAuth.status}->${mut.status} • size ${baseAuth.bodySize}->${mut.bodySize} • headers_diff=${hdrDiff.join(',') || 'none'}`,
            verification: {
              classification: 'probable',
              evidence: {
                source: 'curl_probe',
                url: u.href,
                method: 'GET',
                status: mut.status,
                requestSnippet: mut.curlTemplate,
                responseSnippet: `status:${baseAuth.status}->${mut.status} body_hash:${baseAuth.bodyHash.slice(0, 10)}->${mut.bodyHash.slice(0, 10)}`,
                curlMetrics: { baseline: baseAuth.metrics, mutated: mut.metrics },
                curlHeaders: { baseline: safeHeaderMap(baseAuth.headers), mutated: safeHeaderMap(mut.headers) },
              },
              verifiedAt: new Date().toISOString(),
            },
          };
        }
      }
    } catch {}
    if (diffFinding) out.push(diffFinding);

    if (String(process.env.GHOSTRECON_CURL_PROBE_LOGIN_SQLI || '1') !== '0') {
      const loginProbe = await runLoginSqliProbe({ url, auth, profile, proxy });
      if (loginProbe) {
        const bp = loginProbe.baseline;
        const rp = loginProbe.probe;
        out.push({
          type: 'curl_login_sqli_suspect',
          prio: 'high',
          score: 91,
          value: `Possível SQLi/auth bypass em login (${bp.status} -> ${rp.status})`,
          url,
          meta: `curl_probe_login_sqli • status_diff=${loginProbe.statusDiff ? 'yes' : 'no'} • location_diff=${loginProbe.locationDiff ? 'yes' : 'no'} • cookie_new=${loginProbe.cookieAppeared ? 'yes' : 'no'}`,
          verification: {
            classification: 'probable',
            evidence: {
              source: 'curl_probe',
              url,
              method: 'POST',
              status: rp.status,
              requestSnippet: rp.curlTemplate,
              responseSnippet: `baseline=${bp.status}/${bp.bodyHash.slice(0, 10)} probe=${rp.status}/${rp.bodyHash.slice(0, 10)} location=${String(rp.headers?.location || '').slice(0, 140)}`,
              curlMetrics: { baseline: bp.metrics, probe: rp.metrics },
              curlHeaders: { baseline: safeHeaderMap(bp.headers), probe: safeHeaderMap(rp.headers) },
            },
            verifiedAt: new Date().toISOString(),
          },
        });
      }
    }

    evidenceRows.push({
      ts: new Date().toISOString(),
      source: 'curl_probe',
      url,
      proxy: proxy || null,
      baseAuth: {
        status: baseAuth.status,
        metrics: baseAuth.metrics,
        headers: safeHeaderMap(baseAuth.headers),
        bodyHash: baseAuth.bodyHash,
        bodySize: baseAuth.bodySize,
      },
      baseNoAuth: {
        status: baseNoAuth.status,
        metrics: baseNoAuth.metrics,
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

  const evidenceFile = await persistEvidence(evidenceRows).catch(() => null);
  if (evidenceFile) logFn(`curl_probe: evidências em ${evidenceFile}`, 'info');
  return out;
}

