/**
 * Origin discovery — heurísticas para encontrar IP de origem atrás de
 * Cloudflare/Akamai/etc. Tudo passivo (DNS histórico, CT logs cross-ref,
 * subdomain mismatch). Nada de scan ativo aqui.
 *
 * Caller injeta sources (DNS history fetcher, CT log fetcher, etc.).
 */

import { Resolver } from 'node:dns/promises';

const CDN_RANGES = {
  cloudflare: [/^104\.16\./, /^104\.17\./, /^104\.18\./, /^104\.19\./, /^172\.64\./, /^172\.65\./, /^172\.66\./, /^172\.67\./, /^131\.0\.72\./, /^141\.101\./, /^162\.158\./],
  akamai: [/^23\.32\./, /^23\.40\./, /^23\.46\./, /^23\.48\./, /^96\.6\./, /^104\.64\./, /^184\.24\./, /^184\.50\./],
  fastly: [/^151\.101\./, /^199\.232\./, /^146\.75\./],
  cloudfront: [/^54\.182\./, /^54\.192\./, /^54\.230\./, /^54\.239\./, /^99\.84\./, /^204\.246\./, /^205\.251\./],
};

export function detectCdn(ip) {
  if (!ip) return null;
  for (const [name, ranges] of Object.entries(CDN_RANGES)) {
    if (ranges.some((re) => re.test(ip))) return name;
  }
  return null;
}

/**
 * Compara IPs entre A→host e A→subdomínios candidatos.
 * Subdomínios que apontam para IPs NÃO-CDN são candidatos a origem.
 */
export function detectOriginCandidates({ apex, subdomainIps = {} }) {
  const candidates = [];
  for (const [host, ips] of Object.entries(subdomainIps)) {
    for (const ip of ips || []) {
      const cdn = detectCdn(ip);
      if (!cdn) {
        candidates.push({ host, ip, reason: 'non-cdn-ip' });
      }
    }
  }
  return { apex, candidates };
}

/**
 * Helper: extrai possíveis hostnames "esquecidos" que costumam apontar para
 * origem direta (legacy, dev, mail, etc.)
 */
export const FORGOTTEN_SUBS = [
  'origin', 'origin-www', 'direct', 'real', 'backend',
  'mail', 'smtp', 'mx', 'webmail', 'cpanel', 'whm',
  'staging', 'stage', 'dev', 'qa', 'test', 'beta', 'preview',
  'old', 'legacy', 'v1', 'v2',
  'api-internal', 'internal', 'mgmt', 'admin-direct',
  'ftp', 'sftp',
];

export async function resolveSubsForOrigin(apex, { resolver = new Resolver(), subs = FORGOTTEN_SUBS, timeoutMs = 3000 } = {}) {
  resolver.setServers(['1.1.1.1', '8.8.8.8']);
  const out = {};
  await Promise.all(subs.map(async (s) => {
    const host = `${s}.${apex}`;
    try {
      const ips = await Promise.race([
        resolver.resolve4(host),
        new Promise((_, rej) => setTimeout(() => rej(new Error('timeout')), timeoutMs)),
      ]);
      if (ips?.length) out[host] = ips;
    } catch { /* nx, swallow */ }
  }));
  return out;
}

/**
 * Cross-ref: dado uma lista de subdomínios + IPs (de CT logs/passive DNS),
 * filtra os que são origem-candidate (não-CDN).
 */
export function originDiscoveryToFindings(report, { target } = {}) {
  const findings = [];
  for (const c of report.candidates || []) {
    findings.push({
      severity: 'high', category: 'origin-discovered',
      title: `Possível origem real exposta: ${c.host} → ${c.ip}`,
      description: `Subdomínio ${c.host} resolve para IP ${c.ip} fora de range CDN conhecido. Permite bypass do WAF/CDN se origem aceitar tráfego direto.`,
      evidence: { target: target || report.apex, host: c.host, ip: c.ip, reason: c.reason },
    });
  }
  return findings;
}

/**
 * Validação ativa (passiva-leve): tenta abrir TCP 443 no IP candidato e ver
 * se responde com mesmo CN/SAN do apex — confirmação de origem.
 *
 * Caller injeta `tlsPeek(ip, host)` (igual ao da phishing-infra).
 */
export async function confirmOriginByTls({ candidates = [], apex, tlsPeek }) {
  if (typeof tlsPeek !== 'function') return [];
  const confirmed = [];
  for (const c of candidates) {
    try {
      const peek = await tlsPeek(c.ip, apex);
      const cn = peek?.cert?.subject?.CN || '';
      const san = peek?.cert?.subjectaltname || '';
      const match = cn.includes(apex) || san.includes(apex);
      confirmed.push({ ...c, tlsCn: cn, tlsSan: san, confirmedOrigin: !!match });
    } catch (e) {
      confirmed.push({ ...c, error: e?.message || String(e), confirmedOrigin: false });
    }
  }
  return confirmed;
}
