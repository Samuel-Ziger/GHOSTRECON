import dns from 'node:dns/promises';
import { limits } from '../config.js';
import { combineAbortSignals, throwIfAborted } from './http-utils.js';

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
const MAX_DNS_RECORDS = 100;
const MAX_TXT_RECORD_CHARS = 4_096;

function joinTxtRecord(txtParts) {
  if (!Array.isArray(txtParts)) return '';
  return txtParts.map((part) => String(part)).join('').slice(0, MAX_TXT_RECORD_CHARS);
}

const DNS_ABSENCE_CODES = new Set(['ENODATA', 'ENOTFOUND']);
const DNS_ERROR_CODES = new Set(['ETIMEOUT', 'ESERVFAIL', 'EREFUSED', 'ECONNREFUSED', 'ECANCELLED', 'EFORMERR']);

/** Cada consulta tem seu próprio Resolver; cancel() não afeta outros módulos. */
export async function resolveEmailDns(hostname, kind, {
  timeoutMs = 5000,
  signal = null,
  resolverFactory = () => new dns.Resolver(),
} = {}) {
  throwIfAborted(signal);
  const method = kind === 'MX' ? 'resolveMx' : 'resolveTxt';
  let resolver;
  try {
    resolver = resolverFactory();
  } catch {
    return { state: 'error', records: [], code: 'DNS_RESOLVER_UNAVAILABLE' };
  }
  if (typeof resolver?.[method] !== 'function' || typeof resolver?.cancel !== 'function') {
    return { state: 'error', records: [], code: 'DNS_RESOLVER_UNAVAILABLE' };
  }
  return new Promise((resolve, reject) => {
    let settled = false;
    let timer;
    const finish = (callback, result) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      signal?.removeEventListener('abort', onAbort);
      callback(result);
    };
    const cancel = () => { try { resolver.cancel(); } catch { /* reason is retained below */ } };
    const onAbort = () => {
      cancel();
      finish(reject, signal.reason || new DOMException('DNS cancelado', 'AbortError'));
    };
    signal?.addEventListener('abort', onAbort, { once: true });
    timer = setTimeout(() => {
      cancel();
      finish(resolve, { state: 'timeout', records: [], code: 'ETIMEOUT' });
    }, Math.max(1, Number(timeoutMs) || 5000));
    if (signal?.aborted) { onAbort(); return; }
    Promise.resolve().then(() => settled ? null : resolver[method](hostname)).then((rows) => {
      if (settled) return;
      if (!Array.isArray(rows)) {
        finish(resolve, { state: 'error', records: [], code: 'INVALID_DNS_RESPONSE' });
        return;
      }
      const records = kind === 'MX'
        ? rows.slice(0, MAX_DNS_RECORDS).filter((row) => row && typeof row.exchange === 'string').map((row) => ({
          exchange: row.exchange.toLowerCase().slice(0, 253), priority: row.priority,
        }))
        : rows.slice(0, MAX_DNS_RECORDS).map(joinTxtRecord).filter(Boolean);
      finish(resolve, { state: records.length ? 'ok' : 'absent', records });
    }, (error) => {
      const code = String(error?.code || '');
      finish(resolve, {
        state: DNS_ABSENCE_CODES.has(code) ? 'absent' : code === 'ETIMEOUT' ? 'timeout' : 'error',
        records: [],
        code: DNS_ABSENCE_CODES.has(code) || DNS_ERROR_CODES.has(code) ? code : 'DNS_QUERY_FAILED',
      });
    });
  });
}

function parseTagRecord(record) {
  const tags = Object.create(null);
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
  checks = {},
} = {}) {
  const findings = [];
  const hasMx = Array.isArray(mx) && mx.some((row) => row?.exchange && row.exchange !== '.');
  const spfPolicy = parseSpfPolicy(spf);
  const dmarcPolicy = parseDmarcPolicy(dmarc);
  const checked = {
    root: checks.root !== false,
    mx: checks.mx !== false,
    dmarc: checks.dmarc !== false,
    dkim: checks.dkim !== false,
    bimi: checks.bimi !== false,
    mtaSts: checks.mtaSts !== false,
    tlsRpt: checks.tlsRpt !== false,
  };

  if (checked.mx && hasMx) {
    findings.push(finding({
      issue: 'MX publicado',
      score: 18,
      domain,
      meta: [`mx=${mx.slice(0, 5).map((m) => `${m.exchange}:${m.priority ?? '?'}`).join(',')}`],
    }));
  }

  if (checked.root && !spfPolicy) {
    findings.push(finding({
      issue: hasMx ? 'SPF ausente em dominio que recebe email' : 'SPF ausente',
      score: hasMx ? 58 : 34,
      domain,
      host: domain,
      meta: ['control=spf'],
    }));
  } else if (checked.root) {
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

  if (checked.dmarc && !dmarcPolicy) {
    findings.push(finding({
      issue: hasMx ? 'DMARC ausente em dominio que recebe email' : 'DMARC ausente',
      score: hasMx ? 64 : 40,
      domain,
      host: `_dmarc.${domain}`,
      meta: ['control=dmarc'],
    }));
  } else if (checked.dmarc) {
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

  if (checked.dkim && hasMx && !dkimSelectors.length) {
    findings.push(finding({
      issue: 'DKIM nao encontrado em seletores comuns',
      score: 32,
      domain,
      host: `selector._domainkey.${domain}`,
      meta: ['note=heuristic_common_selectors_only', 'dkim_absence_proven=false'],
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
  if (checked.bimi && checked.dmarc && bimi && !dmarcStrong) {
    findings.push(finding({
      issue: 'BIMI publicado sem DMARC forte',
      score: 38,
      domain,
      host: `default._bimi.${domain}`,
      meta: ['risk=brand_indicator_without_enforcement'],
    }));
  } else if (checked.bimi && dmarcStrong && !bimi) {
    findings.push(finding({
      issue: 'BIMI ausente apesar de DMARC forte',
      score: 18,
      domain,
      host: `default._bimi.${domain}`,
      meta: ['opportunity=brand_trust'],
    }));
  }

  if (checked.mtaSts && hasMx && !mtaSts) {
    findings.push(finding({
      issue: 'MTA-STS ausente',
      score: 34,
      domain,
      host: `_mta-sts.${domain}`,
      meta: ['control=smtp_tls_policy'],
    }));
  }
  if (checked.tlsRpt && hasMx && !tlsRpt) {
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

export async function runEmailSecurityDeep(domain, {
  timeoutMs = limits.dnsEnrichTimeoutMs || 8000,
  log = () => {},
  hostAllowed = () => true,
  signal = null,
  moduleTimeoutMs = moduleManifest.timeoutMs,
  resolverFactory = () => new dns.Resolver(),
} = {}) {
  const moduleSignal = combineAbortSignals(signal, Math.max(1, Number(moduleTimeoutMs) || moduleManifest.timeoutMs));
  throwIfAborted(moduleSignal);
  const root = String(domain || '').trim().replace(/^\.+|\.+$/g, '').toLowerCase();
  if (!root) return { findings: [], records: {}, outcomes: {}, status: 'skipped', reason: 'invalid_domain' };
  if (root.length > 253 || !root.split('.').every((label) => /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/.test(label))) {
    return { findings: [], records: {}, outcomes: {}, status: 'skipped', reason: 'invalid_domain' };
  }
  const hosts = {
    root,
    dmarc: `_dmarc.${root}`,
    bimi: `default._bimi.${root}`,
    mtaSts: `_mta-sts.${root}`,
    tlsRpt: `_smtp._tls.${root}`,
  };
  const lookup = async (hostname, kind = 'TXT', localTimeout = timeoutMs) => {
    throwIfAborted(moduleSignal);
    if (hostAllowed(hostname) !== true) return { state: 'skipped', records: [], code: 'OUT_OF_SCOPE' };
    return resolveEmailDns(hostname, kind, { timeoutMs: localTimeout, signal: moduleSignal, resolverFactory });
  };
  const rows = await Promise.all([
    lookup(root, 'MX'),
    lookup(root),
    lookup(hosts.dmarc),
    lookup(hosts.bimi),
    lookup(hosts.mtaSts),
    lookup(hosts.tlsRpt),
  ]);
  const [mx, txtRoot, txtDmarc, txtBimi, txtMtaSts, txtTlsRpt] = rows.map((row) => row.records);
  const outcomes = Object.fromEntries(['mx', 'root', 'dmarc', 'bimi', 'mtaSts', 'tlsRpt']
    .map((name, index) => [name, { state: rows[index].state, ...(rows[index].code ? { code: rows[index].code } : {}) }]));
  const checked = Object.fromEntries(Object.entries(outcomes).map(([key, row]) => [key, ['ok', 'absent'].includes(row.state)]));

  const dkimRows = await Promise.all(COMMON_DKIM_SELECTORS.map(async (selector) => {
    const hostname = `${selector}._domainkey.${root}`;
    return {
      selector,
      outcome: await lookup(hostname, 'TXT', Math.min(timeoutMs, 3500)),
    };
  }));
  // Se um seletor falhou, o conjunto amostrado é incompleto. Mesmo consultas
  // completas a seletores comuns nunca provam ausência de DKIM no domínio.
  checked.dkim = dkimRows.length > 0
    && dkimRows.every(({ outcome }) => ['ok', 'absent'].includes(outcome.state));
  for (const { selector, outcome } of dkimRows) {
    outcomes[`dkim:${selector}`] = { state: outcome.state, ...(outcome.code ? { code: outcome.code } : {}) };
  }
  const dkimSelectors = dkimRows
    .filter(({ outcome }) => outcome.records.some((r) => /^v=DKIM1\b/i.test(r)))
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
  const findings = analyzeEmailSecurityRecords({
    domain: root,
    ...records,
    checks: checked,
  });
  for (const [check, outcome] of Object.entries(outcomes)) {
    if (!['error', 'timeout'].includes(outcome.state)) continue;
    findings.push({
      type: 'email_security_check', prio: 'info', score: 0,
      value: `Consulta DNS inconclusiva: ${check} @ ${root}`,
      url: null,
      meta: `source=email_security_deep - evidence_status=unavailable - check=${check} - state=${outcome.state} - code=${outcome.code || 'DNS_QUERY_FAILED'}`,
    });
  }
  throwIfAborted(moduleSignal);
  const states = Object.values(outcomes).map((row) => row.state);
  const status = states.every((state) => state === 'skipped') ? 'skipped'
    : states.some((state) => ['error', 'timeout', 'skipped'].includes(state)) ? 'partial' : 'done';
  log(`Email security deep: MX=${mx.length} DKIM=${dkimSelectors.length} achado(s)=${findings.length}`, findings.some((f) => f.score >= 55) ? 'warn' : 'info');
  return { findings, records, outcomes, status };
}
