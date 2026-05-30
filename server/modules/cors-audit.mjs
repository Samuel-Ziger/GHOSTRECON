/**
 * cors-audit.mjs
 *
 * Auditoria generalista de CORS — detecta misconfigurations comuns:
 *
 *  1. Wildcard Access-Control-Allow-Origin: *
 *  2. Credenciais + reflexão de Origin arbitrária
 *  3. Origin desconhecida provoca HTTP 500 (middleware CORS sem tratamento)
 *  4. Preflight OPTIONS inconsistente
 *
 * Probes ativos via HTTP(S); não depende de alvo específico.
 */

import https from 'node:https';
import http from 'node:http';

const TIMEOUT_MS = 12_000;
const UA = 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36';
export const EVIL_ORIGIN = 'https://attacker.example';

const COMMON_API_PATHS = [
  '/health',
  '/healthz',
  '/ready',
  '/status',
  '/api/health',
  '/api/v1/health',
  '/api/status',
];

function makeFinding({ type, value, score, url, meta, owasp, mitre, cvss }) {
  const prio = score >= 85 ? 'critical' : score >= 70 ? 'high' : score >= 50 ? 'medium' : score >= 30 ? 'low' : 'info';
  return { type, value, score, prio, url, meta: meta || {}, owasp, mitre, cvss: cvss || null, source: 'cors_audit' };
}

async function rawRequest(url, { method = 'GET', headers = {}, body = null } = {}) {
  return new Promise((resolve) => {
    let parsed;
    try { parsed = new URL(url); } catch { return resolve({ status: null, headers: {}, body: '', error: 'invalid_url' }); }

    const mod = parsed.protocol === 'https:' ? https : http;
    const opts = {
      hostname: parsed.hostname,
      port: parsed.port || (parsed.protocol === 'https:' ? 443 : 80),
      path: parsed.pathname + parsed.search,
      method,
      timeout: TIMEOUT_MS,
      headers: {
        'User-Agent': UA,
        Accept: '*/*',
        ...headers,
        ...(body ? { 'Content-Length': Buffer.byteLength(body) } : {}),
      },
    };

    const req = mod.request(opts, (res) => {
      const resHeaders = {};
      for (const [k, v] of Object.entries(res.headers || {})) resHeaders[k.toLowerCase()] = v;
      let buf = '';
      res.setEncoding('utf8');
      res.on('data', (c) => { buf += c; if (buf.length > 8192) req.destroy(); });
      res.on('end', () => resolve({ status: res.statusCode, headers: resHeaders, body: buf, error: null }));
    });

    req.on('error', (e) => resolve({ status: null, headers: {}, body: '', error: e.message }));
    req.on('timeout', () => { req.destroy(); resolve({ status: null, headers: {}, body: '', error: 'timeout' }); });
    if (body) req.write(body);
    req.end();
  });
}

function headerVal(headers, name) {
  const v = headers?.[String(name).toLowerCase()];
  if (Array.isArray(v)) return String(v[0] || '');
  return String(v || '');
}

function hasVaryOrigin(headers) {
  return /origin/i.test(headerVal(headers, 'vary'));
}

function isSuccess(status) {
  return status >= 200 && status < 300;
}

/**
 * Analisa respostas baseline vs Origin maliciosa (testável sem rede).
 */
export function analyzeCorsResponses({ url, baseline, withOrigin, preflight = null }) {
  const findings = [];
  if (!baseline?.status) return findings;

  const baseAcao = headerVal(baseline.headers, 'access-control-allow-origin');
  const baseAcac = /true/i.test(headerVal(baseline.headers, 'access-control-allow-credentials'));
  const originAcao = headerVal(withOrigin?.headers, 'access-control-allow-origin');
  const originAcac = /true/i.test(headerVal(withOrigin?.headers, 'access-control-allow-credentials'));
  const originStatus = withOrigin?.status;

  if (baseAcao === '*' || originAcao === '*') {
    findings.push(makeFinding({
      type: 'cors_wildcard',
      value: 'CORS permissivo: Access-Control-Allow-Origin: * — qualquer origem pode ler a resposta',
      score: 74,
      url,
      meta: {
        baselineAcao: baseAcao || null,
        originAcao: originAcao || null,
        baselineStatus: baseline.status,
        originStatus: originStatus ?? null,
      },
      owasp: 'A02:2021',
      mitre: 'T1190',
      cvss: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N',
    }));
  }

  const reflected = originAcao === EVIL_ORIGIN || originAcao === 'null';
  if (reflected && (originAcac || baseAcac)) {
    findings.push(makeFinding({
      type: 'cors_credentials_reflected',
      value: `CORS reflete Origin arbitrária com Access-Control-Allow-Credentials: true (${EVIL_ORIGIN})`,
      score: 88,
      url,
      meta: {
        acao: originAcao,
        acac: true,
        baselineStatus: baseline.status,
        originStatus: originStatus ?? null,
      },
      owasp: 'A02:2021',
      mitre: 'T1190',
      cvss: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N',
    }));
  }

  const corsSignals = baseAcac || hasVaryOrigin(baseline.headers) || hasVaryOrigin(withOrigin?.headers);
  const apiLike = /\/(health|api|graphql|v\d)\b/i.test(url) || corsSignals;

  if (
    isSuccess(baseline.status)
    && originStatus === 500
    && apiLike
  ) {
    findings.push(makeFinding({
      type: 'cors_origin_server_error',
      value: 'Origin desconhecida provoca HTTP 500 — middleware CORS lança exceção não tratada',
      score: 92,
      url,
      meta: {
        evilOrigin: EVIL_ORIGIN,
        baselineStatus: baseline.status,
        originStatus: 500,
        varyOrigin: hasVaryOrigin(baseline.headers) || hasVaryOrigin(withOrigin?.headers),
        allowCredentials: baseAcac || originAcac,
        bodySnippet: String(withOrigin?.body || '').slice(0, 180).replace(/\s+/g, ' '),
        remediation: 'Rejeitar origens não permitidas com 403 — não propagar exceção do middleware CORS',
      },
      owasp: 'A02:2021',
      mitre: 'T1190',
      cvss: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:H',
    }));
  }

  if (preflight?.status != null) {
    const pfAcao = headerVal(preflight.headers, 'access-control-allow-origin');
    if (isSuccess(baseline.status) && preflight.status === 500) {
      findings.push(makeFinding({
        type: 'cors_preflight_server_error',
        value: 'Preflight OPTIONS com Origin maliciosa retorna HTTP 500',
        score: 86,
        url,
        meta: {
          evilOrigin: EVIL_ORIGIN,
          preflightStatus: 500,
          baselineStatus: baseline.status,
        },
        owasp: 'A02:2021',
        mitre: 'T1190',
      }));
    } else if (reflected && pfAcao === EVIL_ORIGIN && /true/i.test(headerVal(preflight.headers, 'access-control-allow-credentials'))) {
      findings.push(makeFinding({
        type: 'cors_preflight_credentials_reflected',
        value: 'Preflight OPTIONS reflete Origin arbitrária com credenciais',
        score: 84,
        url,
        meta: { preflightStatus: preflight.status, acao: pfAcao },
        owasp: 'A02:2021',
        mitre: 'T1190',
      }));
    }
  }

  return findings;
}

/**
 * Monta URLs para probe CORS a partir do recon.
 */
export function collectCorsProbeUrls({ probeResults = [], findings = [], domain = '', max = 14 } = {}) {
  const urls = new Set();
  const origins = new Set();

  for (const { r } of probeResults || []) {
    if (!r?.ok || !r.url) continue;
    if (r.status <= 0 || r.status >= 500) continue;
    try {
      const u = new URL(r.url);
      if (u.protocol !== 'https:' && u.protocol !== 'http:') continue;
      origins.add(`${u.protocol}//${u.host}`);
      urls.add(u.href.split('#')[0]);
    } catch { /* skip */ }
  }

  for (const origin of origins) {
    for (const p of COMMON_API_PATHS) {
      try { urls.add(new URL(p, origin).href); } catch { /* skip */ }
    }
  }

  for (const f of findings || []) {
    const u = f.url || f.value;
    if (typeof u !== 'string' || !/^https?:\/\//i.test(u)) continue;
    try {
      const parsed = new URL(u);
      if (domain && !parsed.hostname.endsWith(String(domain).replace(/^\.+/, ''))) continue;
      urls.add(parsed.href.split('#')[0]);
    } catch { /* skip */ }
  }

  return [...urls].slice(0, max);
}

async function probeCorsUrl(url, log) {
  log?.(`[cors-audit] ${url}`, 'info');
  const baseline = await rawRequest(url, { method: 'GET' });
  if (baseline.error) return { url, findings: [], error: baseline.error };

  const withOrigin = await rawRequest(url, {
    method: 'GET',
    headers: { Origin: EVIL_ORIGIN },
  });

  const preflight = await rawRequest(url, {
    method: 'OPTIONS',
    headers: {
      Origin: EVIL_ORIGIN,
      'Access-Control-Request-Method': 'GET',
      'Access-Control-Request-Headers': 'content-type,authorization',
    },
  });

  const findings = analyzeCorsResponses({ url, baseline, withOrigin, preflight });
  return { url, findings, baseline: { status: baseline.status }, withOrigin: { status: withOrigin.status } };
}

/**
 * @param {object} opts
 * @param {Array} opts.probeResults
 * @param {Array} [opts.findings]
 * @param {string} [opts.domain]
 * @param {Function} [opts.log]
 */
export async function runCorsAudit(opts = {}) {
  const { probeResults = [], findings = [], domain = '', log = null } = opts;
  const urls = collectCorsProbeUrls({ probeResults, findings, domain });
  if (!urls.length) {
    log?.('[cors-audit] Nenhuma URL para probe', 'info');
    return { findings: [], summary: { skipped: 'sem URLs', probed: 0 } };
  }

  log?.(`[cors-audit] Iniciando em ${urls.length} URL(s)`, 'info');
  const all = [];
  const seen = new Set();
  const results = {};

  for (const url of urls) {
    try {
      const r = await probeCorsUrl(url, log);
      results[url] = { baseline: r.baseline?.status, origin: r.withOrigin?.status, error: r.error || null };
      for (const f of r.findings || []) {
        const key = `${f.type}::${url}`;
        if (seen.has(key)) continue;
        seen.add(key);
        all.push(f);
      }
    } catch (e) {
      log?.(`[cors-audit] Erro em ${url}: ${e.message}`, 'warn');
      results[url] = { error: e.message };
    }
  }

  const critical = all.filter((f) => f.score >= 85).length;
  const high = all.filter((f) => f.score >= 70 && f.score < 85).length;
  log?.(`[cors-audit] Concluído: ${all.length} achado(s) — ${critical} crítico(s), ${high} alto(s)`, all.length ? 'warn' : 'info');

  return {
    findings: all,
    summary: { total: all.length, critical, high, probed: urls.length, results },
  };
}
