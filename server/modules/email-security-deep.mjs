import dns from 'node:dns/promises';
import { limits } from '../config.js';

export const moduleManifest = {
  id: 'email_security_deep',
  name: 'Email Security Deep Audit',
  category: 'surface',
  intrusive: false,
  requiresAuth: false,
  requiresKali: false,
  timeoutMs: 12_000,
  concurrency: 2,
  outputs: ['finding'],
};

const COMMON_DKIM_SELECTORS = ['default', 'google', 'selector1', 'selector2', 'mail', 'smtp', 'mandrill', 'sendgrid', 'k1'];

function joinTxtRecord(txtParts) {
  if (!Array.isArray(txtParts)) return '';
  return txtParts.join('');
}

async function withTimeout(promiseFactory, timeoutMs) {
  return await Promise.race([
    promiseFactory(),
    new Promise((_, reject) => setTimeout(() => reject(new Error('timeout')), Math.max(1, timeoutMs || 5000))),
  ]);
}

async function resolveTxtSafe(hostname, timeoutMs) {
  try {
    const txt = await withTimeout(() => dns.resolveTxt(hostname), timeoutMs);
    return Array.isArray(txt) ? txt.map(joinTxtRecord).filter(Boolean) : [];
  } catch {
    return [];
  }
}

async function resolveMxSafe(hostname, timeoutMs) {
  try {
    const mx = await withTimeout(() => dns.resolveMx(hostname), timeoutMs);
    return Array.isArray(mx) ? mx.filter((x) => x?.exchange).map((x) => ({
      exchange: String(x.exchange).toLowerCase(),
      priority: x.priority,
    })) : [];
  } catch {
    return [];
  }
}

function parseTagRecord(record) {
  const tags = {};
  for (const part of String(record || '').split(';')) {
    const idx = part.indexOf('=');
    if (idx < 0) continue;
    const key = part.slice(0, idx).trim().toLowerCase();
    const value = part.slice(idx + 1).trim();
    if (key) tags[key] = value;
  }
  return tags;
}

export function parseSpfPolicy(record) {
  const raw = String(record || '').trim();
  if (!/^v=spf1\b/i.test(raw)) return null;
  const terms = raw.split(/\s+/).filter(Boolean);
  const all = terms.find((t) => /^[+?~-]?all$/i.test(t)) || '';
  const includeCount = terms.filter((t) => /^include:/i.test(t)).length;
  const redirect = terms.find((t) => /^redirect=/i.test(t)) || '';
  const mx = terms.some((t) => /^[+?~-]?mx(?::|$)/i.test(t));
  const ptr = terms.some((t) => /^[+?~-]?ptr(?::|$)/i.test(t));
  return {
    raw,
    all,
    includeCount,
    redirect,
    mx,
    ptr,
    tooManyDnsLookupsHint: includeCount + (redirect ? 1 : 0) + (mx ? 1 : 0) + (ptr ? 1 : 0) > 9,
  };
}

export function parseDmarcPolicy(record) {
  const raw = String(record || '').trim();
  if (!/^v=DMARC1\b/i.test(raw)) return null;
  const tags = parseTagRecord(raw);
  return {
    raw,
    policy: String(tags.p || '').toLowerCase(),
    subdomainPolicy: String(tags.sp || '').toLowerCase(),
    pct: tags.pct != null ? Number(tags.pct) : 100,
    rua: tags.rua || '',
    ruf: tags.ruf || '',
    adkim: String(tags.adkim || '').toLowerCase(),
    aspf: String(tags.aspf || '').toLowerCase(),
  };
}

function prioFor(score) {
  if (score >= 75) return 'high';
  if (score >= 55) return 'med';
  if (score >= 35) return 'low';
  return 'info';
}

function finding({ issue, score, domain, host = '', meta = [] }) {
  return {
    type: 'email_security',
    prio: prioFor(score),
    score,
    value: `${issue}: ${domain}`,
    meta: ['source=email_security_deep', host ? `host=${host}` : '', ...meta].filter(Boolean).join(' - '),
    url: null,
    owasp: 'A05:2021',
  };
}

export function analyzeEmailSecurityRecords({
  domain,
  mx = [],
  spf = null,
  dmarc = null,
  dkimSelectors = [],
  bimi = null,
  mtaSts = null,
  tlsRpt = null,
} = {}) {
  const findings = [];
  const hasMx = Array.isArray(mx) && mx.length > 0;
  const spfPolicy = parseSpfPolicy(spf);
  const dmarcPolicy = parseDmarcPolicy(dmarc);

  if (hasMx) {
    findings.push(finding({
      issue: 'MX publicado',
      score: 18,
      domain,
      meta: [`mx=${mx.slice(0, 5).map((m) => `${m.exchange}:${m.priority ?? '?'}`).join(',')}`],
    }));
  }

  if (!spfPolicy) {
    findings.push(finding({
      issue: hasMx ? 'SPF ausente em dominio que recebe email' : 'SPF ausente',
      score: hasMx ? 58 : 34,
      domain,
      host: domain,
      meta: ['control=spf'],
    }));
  } else {
    if (/^\+all$/i.test(spfPolicy.all)) {
      findings.push(finding({
        issue: 'SPF permite qualquer remetente (+all)',
        score: 86,
        domain,
        host: domain,
        meta: [`spf=${spfPolicy.raw}`],
      }));
    } else if (/^\?all$/i.test(spfPolicy.all)) {
      findings.push(finding({
        issue: 'SPF neutral (?all)',
        score: 62,
        domain,
        host: domain,
        meta: [`spf=${spfPolicy.raw}`],
      }));
    } else if (!/^-all$|^~all$/i.test(spfPolicy.all)) {
      findings.push(finding({
        issue: 'SPF sem fail/softfail final',
        score: 48,
        domain,
        host: domain,
        meta: [`spf=${spfPolicy.raw}`],
      }));
    }
    if (spfPolicy.tooManyDnsLookupsHint) {
      findings.push(finding({
        issue: 'SPF perto do limite de DNS lookups',
        score: 44,
        domain,
        host: domain,
        meta: [`includes=${spfPolicy.includeCount}`, spfPolicy.redirect ? 'redirect=yes' : ''],
      }));
    }
    if (spfPolicy.ptr) {
      findings.push(finding({
        issue: 'SPF usa mecanismo ptr',
        score: 42,
        domain,
        host: domain,
        meta: ['risk=slow_or_unreliable_spf_evaluation'],
      }));
    }
  }

  if (!dmarcPolicy) {
    findings.push(finding({
      issue: hasMx ? 'DMARC ausente em dominio que recebe email' : 'DMARC ausente',
      score: hasMx ? 64 : 40,
      domain,
      host: `_dmarc.${domain}`,
      meta: ['control=dmarc'],
    }));
  } else {
    if (dmarcPolicy.policy === 'none') {
      findings.push(finding({
        issue: 'DMARC em modo monitoramento (p=none)',
        score: 58,
        domain,
        host: `_dmarc.${domain}`,
        meta: [`dmarc=${dmarcPolicy.raw}`],
      }));
    } else if (!['quarantine', 'reject'].includes(dmarcPolicy.policy)) {
      findings.push(finding({
        issue: 'DMARC sem politica p valida',
        score: 66,
        domain,
        host: `_dmarc.${domain}`,
        meta: [`dmarc=${dmarcPolicy.raw}`],
      }));
    }
    if (Number.isFinite(dmarcPolicy.pct) && dmarcPolicy.pct < 100) {
      findings.push(finding({
        issue: 'DMARC aplicado a menos de 100% das mensagens',
        score: 46,
        domain,
        host: `_dmarc.${domain}`,
        meta: [`pct=${dmarcPolicy.pct}`],
      }));
    }
    if (!dmarcPolicy.rua) {
      findings.push(finding({
        issue: 'DMARC sem rua para relatorios agregados',
        score: 28,
        domain,
        host: `_dmarc.${domain}`,
        meta: ['control=monitoring'],
      }));
    }
    if (dmarcPolicy.policy === 'reject' && dmarcPolicy.subdomainPolicy === 'none') {
      findings.push(finding({
        issue: 'DMARC sp=none enfraquece subdominios',
        score: 42,
        domain,
        host: `_dmarc.${domain}`,
        meta: ['policy=reject', 'subdomain_policy=none'],
      }));
    }
  }

  if (hasMx && !dkimSelectors.length) {
    findings.push(finding({
      issue: 'DKIM nao encontrado em seletores comuns',
      score: 32,
      domain,
      host: `selector._domainkey.${domain}`,
      meta: ['note=heuristic_common_selectors_only'],
    }));
  } else if (dkimSelectors.length) {
    findings.push(finding({
      issue: 'DKIM encontrado em seletor comum',
      score: 20,
      domain,
      host: `${dkimSelectors[0]}._domainkey.${domain}`,
      meta: [`selectors=${dkimSelectors.join(',')}`],
    }));
  }

  const dmarcStrong = dmarcPolicy && ['reject', 'quarantine'].includes(dmarcPolicy.policy);
  if (bimi && !dmarcStrong) {
    findings.push(finding({
      issue: 'BIMI publicado sem DMARC forte',
      score: 38,
      domain,
      host: `default._bimi.${domain}`,
      meta: ['risk=brand_indicator_without_enforcement'],
    }));
  } else if (dmarcStrong && !bimi) {
    findings.push(finding({
      issue: 'BIMI ausente apesar de DMARC forte',
      score: 18,
      domain,
      host: `default._bimi.${domain}`,
      meta: ['opportunity=brand_trust'],
    }));
  }

  if (hasMx && !mtaSts) {
    findings.push(finding({
      issue: 'MTA-STS ausente',
      score: 34,
      domain,
      host: `_mta-sts.${domain}`,
      meta: ['control=smtp_tls_policy'],
    }));
  }
  if (hasMx && !tlsRpt) {
    findings.push(finding({
      issue: 'TLS-RPT ausente',
      score: 24,
      domain,
      host: `_smtp._tls.${domain}`,
      meta: ['control=smtp_tls_reporting'],
    }));
  }

  return findings.sort((a, b) => b.score - a.score);
}

function firstRecord(records, re) {
  return (records || []).find((txt) => re.test(txt)) || null;
}

export async function runEmailSecurityDeep(domain, { timeoutMs = limits.dnsEnrichTimeoutMs || 8000, log = () => {} } = {}) {
  const root = String(domain || '').trim().replace(/^\.+|\.+$/g, '').toLowerCase();
  if (!root) return { findings: [], records: {} };

  const [mx, txtRoot, txtDmarc, txtBimi, txtMtaSts, txtTlsRpt] = await Promise.all([
    resolveMxSafe(root, timeoutMs),
    resolveTxtSafe(root, timeoutMs),
    resolveTxtSafe(`_dmarc.${root}`, timeoutMs),
    resolveTxtSafe(`default._bimi.${root}`, timeoutMs),
    resolveTxtSafe(`_mta-sts.${root}`, timeoutMs),
    resolveTxtSafe(`_smtp._tls.${root}`, timeoutMs),
  ]);

  const dkimRows = await Promise.all(COMMON_DKIM_SELECTORS.map(async (selector) => ({
    selector,
    rows: await resolveTxtSafe(`${selector}._domainkey.${root}`, Math.min(timeoutMs, 3500)),
  })));
  const dkimSelectors = dkimRows
    .filter(({ rows }) => rows.some((r) => /^v=DKIM1\b/i.test(r)))
    .map(({ selector }) => selector)
    .slice(0, 5);

  const records = {
    mx,
    spf: firstRecord(txtRoot, /^v=spf1\b/i),
    dmarc: firstRecord(txtDmarc, /^v=DMARC1\b/i),
    dkimSelectors,
    bimi: firstRecord(txtBimi, /^v=BIMI1\b/i),
    mtaSts: firstRecord(txtMtaSts, /^v=STSv1\b/i),
    tlsRpt: firstRecord(txtTlsRpt, /^v=TLSRPTv1\b/i),
  };
  const findings = analyzeEmailSecurityRecords({ domain: root, ...records });
  log(`Email security deep: MX=${mx.length} DKIM=${dkimSelectors.length} achado(s)=${findings.length}`, findings.some((f) => f.score >= 55) ? 'warn' : 'info');
  return { findings, records };
}
