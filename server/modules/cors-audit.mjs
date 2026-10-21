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
const DEFAULT_PHASE_TIMEOUT_MS = 180_000;
const UA = 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36';
export const EVIL_ORIGIN = 'https://attacker.example';
export const SECOND_EVIL_ORIGIN = 'https://unrelated.invalid';

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
  const prio = score >= 85 ? 'critical' : score >= 70 ? 'high' : score >= 50 ? 'med' : score >= 30 ? 'low' : 'info';
  return { type, value, score, prio, url, meta: { ...meta, browserReadVerified: false, impactVerified: false }, owasp, mitre, cvss: null, source: 'cors_audit' };
}

async function rawRequest(url, { method = 'GET', headers = {}, body = null, signal = null } = {}) {
  return new Promise((resolve) => {
    let settled = false;
    let hardTimer;
    const finish = (value) => {
      if (settled) return;
      settled = true;
      clearTimeout(hardTimer);
      signal?.removeEventListener('abort', onAbort);
      resolve(value);
    };
    let req;
    const onAbort = () => {
      req?.destroy();
      finish({ status: null, headers: {}, body: '', error: 'aborted' });
    };
    if (signal?.aborted) return finish({ status: null, headers: {}, body: '', error: 'aborted' });
    let parsed;
    try { parsed = new URL(url); } catch { return resolve({ status: null, headers: {}, body: '', error: 'invalid_url' }); }
    if (!['http:', 'https:'].includes(parsed.protocol) || parsed.username || parsed.password) return finish({ status: null, headers: {}, body: '', error: 'invalid_url' });

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

    req = mod.request(opts, (res) => {
      const resHeaders = {};
      for (const [k, v] of Object.entries(res.headers || {})) resHeaders[k.toLowerCase()] = v;
      let buf = '';
      res.setEncoding('utf8');
      res.on('data', (c) => {
        buf += String(c).slice(0, 8192 - buf.length);
        if (buf.length >= 8192) {
          finish({ status: res.statusCode, headers: resHeaders, body: '', truncated: true, error: null });
          req.destroy();
        }
      });
      res.on('end', () => finish({ status: res.statusCode, headers: resHeaders, body: buf, error: null }));
      res.on('error', () => finish({ status: null, headers: {}, body: '', error: 'response_error' }));
      res.on('aborted', () => finish({ status: null, headers: {}, body: '', error: 'response_aborted' }));
    });

    signal?.addEventListener('abort', onAbort, { once: true });
    req.on('error', (e) => finish({ status: null, headers: {}, body: '', error: signal?.aborted ? 'aborted' : e.message }));
    req.on('timeout', () => { req.destroy(); finish({ status: null, headers: {}, body: '', error: 'timeout' }); });
    // Garantia independente do timeout de socket do Node: alguns servidores
    // mantêm a conexão aberta sem produzir atividade.
    hardTimer = setTimeout(() => {
      finish({ status: null, headers: {}, body: '', error: 'timeout' });
      req.destroy();
    }, TIMEOUT_MS);
    if (body) req.write(body);
    req.end();
  });
}

function headerVal(headers, name) {
  const v = headers?.[String(name).toLowerCase()];
  if (Array.isArray(v)) return v.map(String).join(', ');
  return String(v || '');
}

function hasVaryOrigin(headers) {
  return headerVal(headers, 'vary').split(',').some((value) => value.trim().toLowerCase() === 'origin');
}

function allowsCredentials(headers) {
  // Fetch requires this case-sensitive value on the actual CORS response.
  return headerVal(headers, 'access-control-allow-credentials').trim() === 'true';
}

function isSuccess(status) {
  return status >= 200 && status < 300;
}

/**
 * Analisa respostas baseline vs Origin maliciosa (testável sem rede).
 */
export function analyzeCorsResponses({
  url,
  baseline,
  withOrigin,
  withSecondOrigin = null,
  preflight = null,
  authenticated = false,
}) {
  const findings = [];
  if (!baseline?.status) return findings;

  const baseAcao = headerVal(baseline.headers, 'access-control-allow-origin');
  const baseAcac = allowsCredentials(baseline.headers);
  const originAcao = headerVal(withOrigin?.headers, 'access-control-allow-origin');
  const originAcac = allowsCredentials(withOrigin?.headers);
  const originStatus = withOrigin?.status;
  const secondAcao = headerVal(withSecondOrigin?.headers, 'access-control-allow-origin');
  const secondAcac = allowsCredentials(withSecondOrigin?.headers);

  if (baseAcao === '*' || originAcao === '*') {
    findings.push(makeFinding({
      type: 'cors_wildcard',
      value: 'CORS público observado: Access-Control-Allow-Origin: * (inventário)',
      score: 18,
      url,
      meta: {
        baselineAcao: baseAcao || null,
        originAcao: originAcao || null,
        baselineStatus: baseline.status,
        originStatus: originStatus ?? null,
        evidenceStatus: 'inventory',
        note: 'Wildcard sem credenciais pode ser intencional para recurso público; classificar pelo conteúdo e contexto.',
      },
      owasp: 'A02:2021',
      mitre: 'T1190',
      cvss: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N',
    }));
  }

  const reflected = originAcao === EVIL_ORIGIN;
  const secondReflected = secondAcao === SECOND_EVIL_ORIGIN;
  if (
    reflected
    && secondReflected
    && isSuccess(originStatus)
    && isSuccess(withSecondOrigin?.status)
    && originAcac
    && secondAcac
  ) {
    findings.push(makeFinding({
      type: 'cors_credentials_reflected',
      value: 'CORS reflete duas origens não relacionadas com credenciais (impacto não verificado)',
      score: authenticated ? 62 : 58,
      url,
      meta: {
        acao: originAcao,
        acac: true,
        baselineStatus: baseline.status,
        originStatus: originStatus ?? null,
        secondAcao,
        secondOriginStatus: withSecondOrigin?.status ?? null,
        authenticatedEvidence: authenticated,
        evidenceStatus: authenticated ? 'authenticated_candidate' : 'unauthenticated_candidate',
        confidence: authenticated ? 'high' : 'medium',
      },
      owasp: 'A02:2021',
      mitre: 'T1190',
      cvss: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N',
    }));
  }

  if (
    isSuccess(baseline.status)
    && originStatus === 500
  ) {
    findings.push(makeFinding({
      type: 'cors_origin_server_error',
      value: 'Origin desconhecida provocou HTTP 500 (erro operacional; não prova falha CORS)',
      score: 24,
      url,
      meta: {
        evilOrigin: EVIL_ORIGIN,
        baselineStatus: baseline.status,
        originStatus: 500,
        varyOrigin: hasVaryOrigin(baseline.headers) || hasVaryOrigin(withOrigin?.headers),
        allowCredentials: baseAcac || originAcac,
        remediation: 'Rejeitar origens não permitidas com 403 — não propagar exceção do middleware CORS',
        evidenceStatus: 'operational_error',
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
        value: 'Preflight OPTIONS com Origin não permitida retorna HTTP 500 (erro operacional)',
        score: 22,
        url,
        meta: {
          evilOrigin: EVIL_ORIGIN,
          preflightStatus: 500,
          baselineStatus: baseline.status,
          evidenceStatus: 'operational_error',
        },
        owasp: 'A02:2021',
        mitre: 'T1190',
      }));
    } else if (
      reflected
      && secondReflected
      && isSuccess(preflight.status)
      && isSuccess(originStatus)
      && isSuccess(withSecondOrigin?.status)
      && pfAcao === EVIL_ORIGIN
      && allowsCredentials(preflight.headers)
    ) {
      findings.push(makeFinding({
        type: 'cors_preflight_credentials_reflected',
        value: 'Preflight OPTIONS reflete Origin arbitrária com credenciais',
        score: authenticated ? 60 : 56,
        url,
        meta: {
          preflightStatus: preflight.status,
          acao: pfAcao,
          secondAcao,
          authenticatedEvidence: authenticated,
          evidenceStatus: authenticated ? 'authenticated_candidate' : 'unauthenticated_candidate',
        },
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
      const normalizedDomain = String(domain).replace(/^\.+/, '').toLowerCase();
      const hostname = parsed.hostname.toLowerCase();
      if (normalizedDomain && hostname !== normalizedDomain && !hostname.endsWith(`.${normalizedDomain}`)) continue;
      urls.add(parsed.href.split('#')[0]);
    } catch { /* skip */ }
  }

  return [...urls].slice(0, max);
}

async function probeCorsUrl(url, log, signal, {
  requestImpl = rawRequest,
  urlAllowed = null,
  authenticated = false,
} = {}) {
  log?.(`[cors-audit] ${url}`, 'info');
  if (urlAllowed && !urlAllowed(url)) return { url, findings: [], error: 'out_of_scope' };
  const request = async (init) => {
    if (signal?.aborted) throw signal.reason || new DOMException('The operation was aborted', 'AbortError');
    const response = await requestImpl(url, { ...init, signal });
    if (signal?.aborted) throw signal.reason || new DOMException('The operation was aborted', 'AbortError');
    return response;
  };
  const baseline = await request({ method: 'GET' });
  if (baseline.error) return { url, findings: [], error: baseline.error };

  const withOrigin = await request({
    method: 'GET',
    signal,
    headers: { Origin: EVIL_ORIGIN },
  });

  const withSecondOrigin = await request({
    method: 'GET',
    signal,
    headers: { Origin: SECOND_EVIL_ORIGIN },
  });

  const preflight = await request({
    method: 'OPTIONS',
    signal,
    headers: {
      Origin: EVIL_ORIGIN,
      'Access-Control-Request-Method': 'GET',
      'Access-Control-Request-Headers': 'content-type,authorization',
    },
  });

  const findings = analyzeCorsResponses({
    url,
    baseline,
    withOrigin,
    withSecondOrigin,
    preflight,
    authenticated,
  });
  return {
    url,
    findings,
    error: [withOrigin, withSecondOrigin, preflight].some((r) => r?.error || !r?.status) ? 'partial_response' : null,
    baseline: { status: baseline.status },
    withOrigin: { status: withOrigin.status },
    withSecondOrigin: { status: withSecondOrigin.status },
  };
}

/**
 * @param {object} opts
 * @param {Array} opts.probeResults
 * @param {Array} [opts.findings]
 * @param {string} [opts.domain]
 * @param {Function} [opts.log]
 */
export async function runCorsAudit(opts = {}) {
  const { probeResults = [], findings = [], domain = '', log = null, signal = null,
    phaseTimeoutMs = DEFAULT_PHASE_TIMEOUT_MS, requestImpl = rawRequest,
    urlAllowed = null, authenticated = false } = opts;
  const urls = collectCorsProbeUrls({ probeResults, findings, domain });
  if (!urls.length) {
    log?.('[cors-audit] Nenhuma URL para probe', 'info');
    return { findings: [], summary: { skipped: 'sem URLs', probed: 0 } };
  }

  log?.(`[cors-audit] Iniciando em ${urls.length} URL(s)`, 'info');
  const all = [];
  const seen = new Set();
  const results = {};
  const deadline = Date.now() + Math.max(10_000, Number(phaseTimeoutMs) || DEFAULT_PHASE_TIMEOUT_MS);

  for (const url of urls) {
    if (signal?.aborted) throw signal.reason || new Error('CORS audit cancelado');
    if (Date.now() >= deadline) {
      log?.(`[cors-audit] Timeout da fase após ${phaseTimeoutMs}ms; seguindo para o próximo módulo`, 'warn');
      return { findings: all, summary: { total: all.length, probed: Object.keys(results).length, timedOut: true, results } };
    }
    try {
      const r = await probeCorsUrl(url, log, signal, { requestImpl, urlAllowed, authenticated });
      results[url] = { baseline: r.baseline?.status, origin: r.withOrigin?.status, error: r.error || null };
      for (const f of r.findings || []) {
        const key = `${f.type}::${url}`;
        if (seen.has(key)) continue;
        seen.add(key);
        all.push(f);
      }
    } catch (e) {
      if (signal?.aborted || e?.name === 'AbortError') throw signal?.reason || e;
      log?.('[cors-audit] Falha de request; conteúdo externo omitido.', 'warn');
      results[url] = { error: e?.name === 'TimeoutError' ? 'timeout' : 'request_failed' };
    }
  }

  const critical = all.filter((f) => f.score >= 85).length;
  const high = all.filter((f) => f.score >= 70 && f.score < 85).length;
  log?.(`[cors-audit] Concluído: ${all.length} achado(s) — ${critical} crítico(s), ${high} alto(s)`, all.length ? 'warn' : 'info');

  return {
    findings: all,
    summary: { total: all.length, critical, high, probed: Object.keys(results).length, status: Object.values(results).some((r) => r.error) ? 'partial' : 'done', results },
  };
}
