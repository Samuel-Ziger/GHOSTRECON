/**
 * Phishing infra — recon passivo de domínio canário e comparação de fingerprint
 * contra alvo para exercícios autorizados.
 *
 * NÃO envia phishing, NÃO dispara email, NÃO tenta login. Apenas:
 *   - Consulta DNS (TXT/MX/SPF/DKIM/DMARC) via resolver do sistema
 *   - Valida deliverability (SPF parse, DMARC policy)
 *   - Compara TLS cert + HTTP headers entre dois hosts
 *
 * Uso típico: operador registrou `bank-login-secure.com` para um exercício
 * autorizado e precisa validar antes de mandar emails que:
 *   1. SPF/DKIM/DMARC estão publicados e alinhados
 *   2. Domain age / WHOIS / TLS parecem "suficientemente reais"
 *   3. Fingerprint do canário bate com o fingerprint do alvo (reduz deteção)
 */

import dns from 'node:dns/promises';
import tls from 'node:tls';
import https from 'node:https';

// ============================================================================
// DNS / Email auth (SPF, DKIM selectors, DMARC)
// ============================================================================

async function safeResolve(host, type) {
  try {
    if (type === 'TXT') return await dns.resolveTxt(host);
    if (type === 'MX') return await dns.resolveMx(host);
    if (type === 'NS') return await dns.resolveNs(host);
    if (type === 'A') return await dns.resolve4(host);
    if (type === 'AAAA') return await dns.resolve6(host);
    if (type === 'CNAME') return await dns.resolveCname(host);
  } catch {
    return null;
  }
  return null;
}

export async function auditCampaignDomain(domain) {
  const findings = [];
  const summary = { domain, dns: {} };

  // MX
  const mx = await safeResolve(domain, 'MX');
  summary.dns.mx = mx;
  if (!mx || !mx.length) {
    findings.push({
      severity: 'medium', category: 'phishing-infra',
      title: `Domínio canário sem MX (${domain})`,
      description: 'Sem MX publicado — emails sairão sem reply path válido. Pode cair em spam.',
      evidence: { target: domain, check: 'MX' },
    });
  }

  // SPF
  const txts = (await safeResolve(domain, 'TXT')) || [];
  const flat = txts.map((t) => t.join('').trim());
  summary.dns.txt = flat;
  const spf = flat.find((t) => /^v=spf1\b/i.test(t));
  summary.dns.spf = spf || null;
  if (!spf) {
    findings.push({
      severity: 'medium', category: 'phishing-infra',
      title: `SPF ausente em ${domain}`,
      description: 'Sem registro v=spf1. Providers vão marcar como spam.',
      evidence: { target: domain, check: 'SPF' },
    });
  } else {
    const spfSummary = parseSpf(spf);
    summary.dns.spfParsed = spfSummary;
    if (spfSummary.all === '-all' || spfSummary.all === '~all') {
      // ok
    } else if (spfSummary.all === '+all' || spfSummary.all === '?all') {
      findings.push({
        severity: 'low', category: 'phishing-infra',
        title: `SPF permissivo (${spfSummary.all}) em ${domain}`,
        description: 'Qualifier final `+all`/`?all` permite spoofing a partir de qualquer origem.',
        evidence: { target: domain, spf },
      });
    } else {
      findings.push({
        severity: 'low', category: 'phishing-infra',
        title: `SPF sem qualifier final claro em ${domain}`,
        description: 'Registro SPF não termina com -all/~all — deliverability imprevisível.',
        evidence: { target: domain, spf },
      });
    }
  }

  // DMARC
  const dmarcTxt = (await safeResolve(`_dmarc.${domain}`, 'TXT')) || [];
  const dmarcFlat = dmarcTxt.map((t) => t.join('').trim());
  const dmarc = dmarcFlat.find((t) => /^v=DMARC1\b/i.test(t));
  summary.dns.dmarc = dmarc || null;
  if (!dmarc) {
    findings.push({
      severity: 'medium', category: 'phishing-infra',
      title: `DMARC ausente em ${domain}`,
      description: 'Sem DMARC publicado. Deliverability e reputação degradadas; emails podem ser rejeitados.',
      evidence: { target: domain, check: 'DMARC' },
    });
  } else {
    const pol = /p=(none|quarantine|reject)/i.exec(dmarc);
    summary.dns.dmarcPolicy = pol ? pol[1].toLowerCase() : null;
    if (pol && /reject/i.test(pol[1])) {
      findings.push({
        severity: 'info', category: 'phishing-infra',
        title: `DMARC p=reject em ${domain}`,
        description: 'Policy agressiva — correlato/legítimo, mas spoof via alinhamento SPF/DKIM ainda possível se configurado mal.',
        evidence: { target: domain, dmarc },
      });
    }
  }

  // DKIM selectors comuns
  const selectors = ['default', 'google', 'selector1', 'selector2', 'k1', 'mail', 's1', 's2'];
  const dkimFound = [];
  for (const sel of selectors) {
    const host = `${sel}._domainkey.${domain}`;
    const d = await safeResolve(host, 'TXT');
    if (d && d.length) dkimFound.push({ selector: sel, value: d.map((t) => t.join('')).join(' ') });
  }
  summary.dns.dkim = dkimFound;
  if (!dkimFound.length) {
    findings.push({
      severity: 'low', category: 'phishing-infra',
      title: `DKIM não encontrado em selectors comuns (${domain})`,
      description: `Testados: ${selectors.join(', ')}. Sem DKIM, emails do canário não passam alinhamento.`,
      evidence: { target: domain, testedSelectors: selectors },
    });
  }

  // NS / A — sanity check (domínio existe mesmo?)
  const ns = await safeResolve(domain, 'NS');
  summary.dns.ns = ns;
  if (!ns || !ns.length) {
    findings.push({
      severity: 'high', category: 'phishing-infra',
      title: `Domínio canário sem NS (${domain})`,
      description: 'Domínio não está delegado. Não vai funcionar para email/phishing.',
      evidence: { target: domain },
    });
  }

  return { domain, findings, summary };
}

export function parseSpf(spf) {
  const parts = spf.trim().split(/\s+/);
  const mechanisms = parts.slice(1);
  const all = mechanisms.find((m) => /^[+~?-]?all$/i.test(m)) || null;
  const includes = mechanisms.filter((m) => /^include:/i.test(m)).map((m) => m.slice(8));
  const ip4 = mechanisms.filter((m) => /^ip4:/i.test(m)).map((m) => m.slice(4));
  const ip6 = mechanisms.filter((m) => /^ip6:/i.test(m)).map((m) => m.slice(4));
  return { raw: spf, mechanisms, all, includes, ip4, ip6 };
}

// ============================================================================
// TLS + HTTP headers fingerprint comparison
// ============================================================================

function tlsPeekCert(host, { port = 443, timeoutMs = 8000 } = {}) {
  return new Promise((resolve, reject) => {
    const socket = tls.connect(
      { host, port, servername: host, rejectUnauthorized: false },
      () => {
        const cert = socket.getPeerCertificate(true);
        const cipher = socket.getCipher();
        const protocol = socket.getProtocol();
        socket.end();
        resolve({ cert, cipher, protocol });
      },
    );
    socket.setTimeout(timeoutMs, () => { socket.destroy(new Error('tls timeout')); reject(new Error('tls timeout')); });
    socket.on('error', reject);
  });
}

function httpHeadersHead(host, { path = '/', timeoutMs = 10_000 } = {}) {
  return new Promise((resolve, reject) => {
    const req = https.request(
      { method: 'HEAD', host, port: 443, path, headers: { 'user-agent': 'GHOSTRECON-fingerprint/1.0' }, rejectUnauthorized: false },
      (res) => {
        resolve({ statusCode: res.statusCode, headers: res.headers });
      },
    );
    req.setTimeout(timeoutMs, () => { req.destroy(new Error('http timeout')); reject(new Error('http timeout')); });
    req.on('error', reject);
    req.end();
  });
}

/**
 * Compara 2 hosts (alvo vs canário). Retorna similarity score + diff.
 *
 * O score NÃO é garantia de evasão — é indicador. Alvo real tem muitas
 * variáveis que fingerprint superficial não captura.
 */
export async function compareFingerprints(hostA, hostB, { path = '/' } = {}) {
  const [aTls, bTls, aHeaders, bHeaders] = await Promise.all([
    tlsPeekCert(hostA).catch((e) => ({ error: e.message })),
    tlsPeekCert(hostB).catch((e) => ({ error: e.message })),
    httpHeadersHead(hostA, { path }).catch((e) => ({ error: e.message })),
    httpHeadersHead(hostB, { path }).catch((e) => ({ error: e.message })),
  ]);

  const tlsCompare = compareTls(aTls, bTls);
  const headerCompare = compareHeaders(aHeaders?.headers, bHeaders?.headers);

  // score: 70% TLS, 30% headers
  const score = Math.round((tlsCompare.score * 0.7 + headerCompare.score * 0.3) * 100);

  return {
    hostA, hostB,
    tls: { a: serializeTls(aTls), b: serializeTls(bTls), compare: tlsCompare },
    headers: { a: aHeaders, b: bHeaders, compare: headerCompare },
    score,
    verdict: score >= 80 ? 'high-similarity' : score >= 50 ? 'partial-match' : 'divergent',
  };
}

function serializeTls(t) {
  if (!t || t.error) return { error: t?.error || 'n/a' };
  const c = t.cert || {};
  return {
    subject: c.subject || null, issuer: c.issuer || null,
    valid_from: c.valid_from, valid_to: c.valid_to,
    subjectaltname: c.subjectaltname || null,
    cipher: t.cipher, protocol: t.protocol,
  };
}

function compareTls(a, b) {
  if (!a || a.error || !b || b.error) return { score: 0, diff: ['tls handshake failed'] };
  const diff = [];
  let match = 0, total = 0;
  const fields = ['issuer.O', 'issuer.CN', 'protocol', 'cipher.name'];
  for (const f of fields) {
    total++;
    const av = deepGet(a, f);
    const bv = deepGet(b, f);
    if (av === bv) match++;
    else diff.push({ field: f, a: av, b: bv });
  }
  return { score: total ? match / total : 0, diff };
}

function deepGet(obj, path) {
  return path.split('.').reduce((o, k) => (o ? o[k] : undefined), obj);
}

function compareHeaders(a, b) {
  if (!a || !b) return { score: 0, diff: ['headers unavailable'] };
  const keys = new Set([...Object.keys(a), ...Object.keys(b)]);
  let match = 0; const diff = [];
  for (const k of keys) {
    if (/^(date|expires|content-length|etag|set-cookie)$/i.test(k)) continue; // voláteis
    if (String(a[k] || '') === String(b[k] || '')) match++;
    else diff.push({ header: k, a: a[k], b: b[k] });
  }
  const score = keys.size ? match / Math.max(1, keys.size) : 0;
  return { score, diff: diff.slice(0, 20) };
}
