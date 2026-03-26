import crypto from 'crypto';

export function norm(s) {
  return String(s ?? '')
    .trim()
    .toLowerCase()
    .replace(/\s+/g, ' ');
}

export function fingerprintFinding(target, f) {
  const raw = `${norm(target)}|${norm(f.type)}|${norm(f.value)}|${norm(f.url)}`;
  return crypto.createHash('sha256').update(raw).digest('hex');
}

/**
 * A tabela `findings` deve persistir apenas domínio e subdomínios.
 * Mantém um registro explícito do domínio raiz e deduplica subdomínios.
 */
export function findingsForRunsTable(target, findings) {
  const t = norm(target);
  const out = [
    {
      type: 'domain',
      prio: 'low',
      score: 20,
      value: t,
      meta: 'domínio alvo',
      url: `https://${t}`,
    },
  ];

  const seenSubs = new Set();
  for (const f of findings || []) {
    if (!f || f.type !== 'subdomain') continue;
    const sub = norm(f.value);
    if (!sub || seenSubs.has(sub)) continue;
    seenSubs.add(sub);
    out.push({
      type: 'subdomain',
      prio: f.prio ?? 'med',
      score: f.score ?? 52,
      value: sub,
      meta: f.meta ?? null,
      url: f.url ?? `https://${sub}`,
    });
  }
  return out;
}
