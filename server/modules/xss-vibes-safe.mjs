import crypto from 'node:crypto';

import { readResponseSnippet } from './module-runner.mjs';

export const moduleManifest = Object.freeze({
  id: 'kali_xss_vibes',
  name: 'XSS Contextual Reflection Audit',
  category: 'validation',
  intrusive: true,
  requiresAuth: false,
  requiresKali: false,
  timeoutMs: 60_000,
  concurrency: 1,
  outputs: ['finding', 'metric'],
});

const XSS_PARAM_RE = /^(q|query|search|s|keyword|term|message|comment|title|name|html|content|callback)$/i;

function abortError(signal) {
  const error = signal?.reason instanceof Error
    ? signal.reason
    : new DOMException('The operation was aborted', 'AbortError');
  if (!error.name || error.name === 'Error') error.name = 'AbortError';
  return error;
}

function defaultMarkerFactory(seed) {
  const id = crypto.createHash('sha256').update(String(seed)).digest('hex').slice(0, 12);
  const core = `GRXSS_${id}`;
  return { core, value: `${core}_<>"'&_${core}` };
}

function safeEvidenceUrl(url, param) {
  try {
    const parsed = new URL(url);
    parsed.username = '';
    parsed.password = '';
    for (const key of parsed.searchParams.keys()) parsed.searchParams.set(key, '<redacted>');
    parsed.searchParams.set(param, '<reflection-probe>');
    return parsed.toString();
  } catch {
    return null;
  }
}

export function classifyXssReflection(body, marker) {
  const text = String(body || '');
  const first = text.indexOf(marker.core);
  if (first < 0) return { reflected: false, raw: false, context: 'none' };
  const raw = text.includes(marker.value);
  const before = text.slice(0, first).toLowerCase();
  const lastScriptOpen = before.lastIndexOf('<script');
  const lastScriptClose = before.lastIndexOf('</script');
  const lastTagOpen = before.lastIndexOf('<');
  const lastTagClose = before.lastIndexOf('>');
  const context = lastScriptOpen > lastScriptClose
    ? 'script'
    : lastTagOpen > lastTagClose
      ? 'html_attribute_or_tag'
      : 'html_text_or_data';
  return { reflected: true, raw, context };
}

function collectUrls(urls, maxUrls) {
  const out = [];
  const seen = new Set();
  for (const value of urls || []) {
    if (out.length >= maxUrls) break;
    if (typeof value !== 'string' || !/^https?:\/\//i.test(value)) continue;
    try {
      const parsed = new URL(value);
      if (parsed.username || parsed.password) continue;
      if (![...parsed.searchParams.keys()].some((key) => XSS_PARAM_RE.test(key))) continue;
      if (seen.has(parsed.href)) continue;
      seen.add(parsed.href);
      out.push(parsed.href);
    } catch {
      // Entrada não confiável: ignorar.
    }
  }
  return out;
}

export async function runSafeXssVibesAudit({
  urls = [],
  auth = null,
  signal = null,
  urlAllowed = () => true,
  fetchImpl = fetch,
  identityCtrl = null,
  log = null,
  markerFactory = defaultMarkerFactory,
  maxUrls = 12,
  maxParamsPerUrl = 2,
  maxRequests = 48,
  timeoutMs = 12_000,
} = {}) {
  const findings = [];
  const metrics = { urls: 0, parameters: 0, requests: 0, blockedByScope: 0, requestErrors: 0, timeouts: 0, incompleteComparisons: 0 };

  const request = async (url) => {
    if (signal?.aborted) throw abortError(signal);
    if (urlAllowed(url) !== true) {
      metrics.blockedByScope += 1;
      return null;
    }
    if (metrics.requests >= maxRequests) return null;
    metrics.requests += 1;
    const timeoutSignal = AbortSignal.timeout(Math.max(1_000, Number(timeoutMs) || 12_000));
    const requestSignal = signal ? AbortSignal.any([signal, timeoutSignal]) : timeoutSignal;
    const headers = {
      Accept: 'text/html,application/xhtml+xml,application/json,*/*;q=0.8',
      ...(auth?.headers && typeof auth.headers === 'object' ? auth.headers : {}),
    };
    if (auth?.cookie) headers.Cookie = String(auth.cookie);
    const init = { method: 'GET', redirect: 'manual', signal: requestSignal, headers };
    try {
      const response = identityCtrl?.enabled
        ? await identityCtrl.fetchVerifyGet(url, init)
        : await fetchImpl(url, init);
      return {
        status: response.status,
        text: await readResponseSnippet(response, 192_000),
        contentType: response.headers?.get?.('content-type') || '',
      };
    } catch (error) {
      if (signal?.aborted) throw abortError(signal);
      metrics.requestErrors += 1;
      if (requestSignal.aborted || error?.name === 'TimeoutError') metrics.timeouts += 1;
      return null;
    }
  };

  for (const candidate of collectUrls(urls, Math.max(1, maxUrls))) {
    if (metrics.requests + 2 > maxRequests) break;
    if (urlAllowed(candidate) !== true) {
      metrics.blockedByScope += 1;
      continue;
    }
    metrics.urls += 1;
    const parsed = new URL(candidate);
    const params = [...parsed.searchParams.keys()]
      .filter((key) => XSS_PARAM_RE.test(key))
      .slice(0, Math.max(1, maxParamsPerUrl));
    for (const param of params) {
      if (metrics.requests + 2 > maxRequests) break;
      metrics.parameters += 1;
      const marker = markerFactory(`${parsed.origin}${parsed.pathname}?${param}`);
      const probe = new URL(parsed.href);
      probe.searchParams.set(param, marker.value);
      const first = await request(probe.href);
      if (!first) continue;
      const second = await request(probe.href);
      if (!second) continue;
      if ([first, second].some((row) => row.status < 200 || row.status >= 300)) {
        metrics.incompleteComparisons += 1;
        continue;
      }
      const firstSignal = classifyXssReflection(first.text, marker);
      const secondSignal = classifyXssReflection(second.text, marker);
      if (!firstSignal.reflected || !secondSignal.reflected) continue;

      const htmlResponses = [first, second].every((row) => /^text\/html(?:\s*;|$)/i.test(row.contentType));
      const rawRepeated = firstSignal.raw && secondSignal.raw && htmlResponses;
      const context = firstSignal.context === secondSignal.context
        ? firstSignal.context
        : 'mixed';
      findings.push({
        type: rawRepeated ? 'xss_reflection_candidate' : 'input_reflection_encoded',
        prio: rawRepeated ? 'med' : 'info',
        score: rawRepeated ? 56 : 24,
        value: rawRepeated
          ? `Reflexão contextual repetível em ?${param}= (${context})`
          : `Reflexão de entrada sem contexto HTML executável comprovado em ?${param}=`,
        meta: `scanner=xss_vibes_safe • classification=${rawRepeated ? 'candidate' : 'inventory'} • repeated=yes • context=${context} • non_executable_marker=yes`,
        url: safeEvidenceUrl(candidate, param),
        verification: {
          classification: rawRepeated ? 'candidate' : 'inventory',
          evidence: {
            source: 'xss_vibes_safe',
            url: safeEvidenceUrl(candidate, param),
            method: 'GET',
            parameter: param,
            status: second.status,
            context,
            rawCharactersPreserved: rawRepeated,
            repeated: true,
            htmlContentType: htmlResponses,
            executionVerified: false,
            markerHash: crypto.createHash('sha256').update(marker.core).digest('hex'),
          },
          verifiedAt: new Date().toISOString(),
        },
      });
    }
  }

  log?.(
    `XSS contextual: ${findings.length} reflexão(ões) repetível(is), ${metrics.requests} request(s).`,
    findings.some((finding) => finding.prio === 'med') ? 'warn' : 'info',
  );
  return { findings, metrics, status: metrics.requestErrors || metrics.incompleteComparisons || metrics.blockedByScope ? 'partial' : 'done' };
}
