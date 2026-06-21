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
  const protocols = [];
  const re = /\b(h3(?:-\d+)?)\s*=\s*"?([^";,\s]*)"?/gi;
  let m;
  while ((m = re.exec(s)) !== null) {
    protocols.push({ protocol: m[1], endpoint: m[2] || '' });
  }
  return protocols;
}

export function auditHttp3QuicSurface({ probeResults = [], nmapFindings = [] } = {}) {
  const findings = [];
  const seen = new Set();

  for (const item of probeResults || []) {
    const r = item?.r || item;
    if (!r?.ok) continue;
    const sh = r.securityHeaders || {};
    const altSvc = sh.altSvc || headerPairValue(r.responseHeadersFlat, 'alt-svc');
    const protocols = parseAltSvcHttp3(altSvc);
    if (!protocols.length) continue;
    let host = '';
    try { host = new URL(r.url).hostname; } catch { host = r.url || ''; }
    const key = `header:${host}:${altSvc}`;
    if (seen.has(key)) continue;
    seen.add(key);
    findings.push({
      type: 'http3',
      prio: 'low',
      score: 38,
      value: `HTTP/3 / QUIC anunciado @ ${host}`,
      meta: metaText({
        source: 'http3_quic_surface',
        evidence: 'alt-svc',
        protocols: protocols.map((p) => p.protocol),
        alt_svc: altSvc.slice(0, 180),
        server: sh.server || '',
        note: 'Surface inventory; revisar CVEs e configuracao QUIC conforme stack',
      }),
      url: r.url,
    });
  }

  for (const f of nmapFindings || []) {
    const blob = `${f?.value || ''} ${f?.meta || ''}`;
    if (!/\b(?:udp\/443|443\/udp|quic|http3|http\/3|h3)\b/i.test(blob)) continue;
    const key = `nmap:${String(f?.value || '').slice(0, 120)}`;
    if (seen.has(key)) continue;
    seen.add(key);
    findings.push({
      type: 'http3',
      prio: 'low',
      score: 36,
      value: `Possivel HTTP/3 / QUIC via Nmap: ${String(f?.value || '').slice(0, 120)}`,
      meta: metaText({
        source: 'http3_quic_surface',
        evidence: 'nmap_service',
        original_meta: String(f?.meta || '').slice(0, 160),
      }),
      url: f?.url || null,
    });
  }

  return findings;
}
