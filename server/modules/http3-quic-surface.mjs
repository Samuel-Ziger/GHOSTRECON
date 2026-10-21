import { throwIfAborted } from './http-utils.js';

export const moduleManifest = {
  id: 'http3_quic_surface',
  name: 'HTTP/3 / QUIC Surface',
  category: 'surface',
  intrusive: false,
  requiresAuth: false,
  requiresKali: false,
  timeoutMs: 5_000,
  concurrency: 1,
  outputs: ['finding'],
};

const MAX_ALT_SVC_CHARS = 32_768;
const MAX_SURFACE_ROWS = 10_000;
const MAX_ALT_PROTOCOLS = 32;

function metaText(meta) {
  return Object.entries(meta || {})
    .filter(([, v]) => v != null && v !== '')
    .map(([k, v]) => `${k}=${Array.isArray(v) ? v.join(',') : String(v)}`)
    .join(' - ');
}

function headerPairValue(pairs, wanted) {
  const name = String(wanted || '').toLowerCase();
  for (const [k, v] of pairs || []) {
    if (String(k || '').toLowerCase() === name) return String(v || '');
  }
  return '';
}

export function parseAltSvcHttp3(value) {
  const s = String(value || '');
  if (!s || s.length > MAX_ALT_SVC_CHARS) return [];
  const protocols = [];
  const seen = new Set();
  const re = /(?:^|,)\s*(h3(?:-\d+)?)\s*=\s*(?:"([^"]{1,512})"|([^;,\s]{1,512}))([^,]*)/gi;
  let m;
  while ((m = re.exec(s)) !== null && protocols.length < MAX_ALT_PROTOCOLS) {
    const endpoint = String(m[2] || m[3] || '').trim();
    const portMatch = endpoint.match(/:(\d{1,5})$/);
    const port = Number(portMatch?.[1]);
    if (!portMatch || port < 1 || port > 65_535) continue;
    const params = String(m[4] || '');
    const maxAgeMatch = params.match(/(?:^|;)\s*ma\s*=\s*"?(\d+)"?/i);
    const maxAgeSec = maxAgeMatch ? Number(maxAgeMatch[1]) : null;
    // ma=0 invalida o mapeamento armazenado; não é evidência de superfície
    // HTTP/3 persistente no momento da coleta.
    if (maxAgeSec === 0) continue;
    const protocol = m[1].toLowerCase();
    const key = `${protocol}:${endpoint}`;
    if (seen.has(key)) continue;
    seen.add(key);
    protocols.push({ protocol, endpoint, maxAgeSec });
  }
  return protocols;
}

function validHttpObservationUrl(raw) {
  try {
    const parsed = new URL(raw);
    return ['http:', 'https:'].includes(parsed.protocol) && !parsed.username && !parsed.password
      ? parsed
      : null;
  } catch { return null; }
}

function nmapQuicObservation(finding) {
  const value = String(finding?.value || '').slice(0, 2_000);
  const meta = finding?.meta && typeof finding.meta === 'object' ? finding.meta : {};
  const legacyMeta = typeof finding?.meta === 'string' ? finding.meta.slice(0, 2_000) : '';
  const scanKind = String(meta.scanKind || '').toLowerCase();
  const udp443 = scanKind === 'udp' && /(?:^|\D)443(?:\D|$)/.test(value)
    || /\b(?:udp\/443|443\/udp)\b/i.test(value);
  const marker = [value, meta.service, meta.product, meta.note, legacyMeta].join(' ');
  return {
    observed: udp443 && /\b(?:quic|http3|http\/3|h3(?:-\d+)?)\b/i.test(marker),
    value,
    meta: legacyMeta || metaText({
      scan_kind: meta.scanKind,
      service: meta.service,
      product: meta.product,
      evidence_status: meta.evidenceStatus,
    }),
  };
}

export function auditHttp3QuicSurface({ probeResults = [], nmapFindings = [], signal = null } = {}) {
  const findings = [];
  const seen = new Set();

  for (const item of (Array.isArray(probeResults) ? probeResults : []).slice(0, MAX_SURFACE_ROWS)) {
    throwIfAborted(signal);
    const r = item?.r || item;
    if (!r?.ok) continue;
    const sh = r.securityHeaders || {};
    const altSvc = sh.altSvc || headerPairValue(r.responseHeadersFlat, 'alt-svc');
    const protocols = parseAltSvcHttp3(altSvc);
    if (!protocols.length) continue;
    const parsedUrl = validHttpObservationUrl(r.url);
    if (!parsedUrl) continue;
    const host = parsedUrl.hostname;
    const key = `header:${host}:${altSvc}`;
    if (seen.has(key)) continue;
    seen.add(key);
    findings.push({
      type: 'http3',
      prio: 'info',
      score: 18,
      value: `HTTP/3 / QUIC anunciado por Alt-Svc @ ${host}`,
      meta: metaText({
        source: 'http3_quic_surface',
        evidence: 'alt-svc',
        evidence_status: 'advertised_not_negotiated',
        quic_reachability_tested: false,
        protocols: protocols.map((p) => p.protocol),
        alt_svc: altSvc.slice(0, 180),
        server: sh.server || '',
        note: 'Inventário de configuração; Alt-Svc não confirma negociação, alcance ou vulnerabilidade',
      }),
      url: parsedUrl.href,
    });
  }

  for (const f of (Array.isArray(nmapFindings) ? nmapFindings : []).slice(0, MAX_SURFACE_ROWS)) {
    throwIfAborted(signal);
    const observation = nmapQuicObservation(f);
    if (!observation.observed) continue;
    const key = `nmap:${String(f?.url || '')}:${observation.value.slice(0, 240)}`;
    if (seen.has(key)) continue;
    seen.add(key);
    findings.push({
      type: 'http3',
      prio: 'info',
      score: 16,
      value: `Possível anúncio de HTTP/3 / QUIC em inventário Nmap: ${observation.value.slice(0, 120)}`,
      meta: metaText({
        source: 'http3_quic_surface',
        evidence: 'nmap_service',
        evidence_status: 'service_hint_not_negotiated',
        quic_reachability_tested: false,
        original_meta: observation.meta.slice(0, 160),
      }),
      url: f?.url || null,
    });
  }

  return findings;
}
