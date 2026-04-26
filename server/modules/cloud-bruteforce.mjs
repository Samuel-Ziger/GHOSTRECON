/**
 * Cloud asset enumeration sem credenciais — gera candidatos de bucket/storage
 * por padrão de nome e (opcionalmente) confirma via HEAD anônimo.
 *
 * Provedores cobertos: AWS S3, Azure Blob, GCP GCS, DigitalOcean Spaces.
 *
 * Tudo sob `--confirm-active` quando confirmação real é executada.
 * Geração de candidatos é offline.
 */

const PERMUTATIONS = [
  '{name}', '{name}-prod', '{name}-staging', '{name}-stage', '{name}-dev', '{name}-qa',
  '{name}-test', '{name}-backup', '{name}-backups', '{name}-archive', '{name}-data',
  '{name}-logs', '{name}-reports', '{name}-assets', '{name}-static', '{name}-public',
  '{name}-private', '{name}-internal', '{name}-uploads', '{name}-files',
  '{name}-images', '{name}-media', '{name}-config', '{name}-secret', '{name}-secrets',
  '{name}-cdn', '{name}-www', '{name}-api', '{name}-app',
  'prod-{name}', 'staging-{name}', 'dev-{name}', 'backup-{name}', 'data-{name}',
  '{name}.{tld}', '{name}-{year}',
];

const TLDS = ['com', 'net', 'io', 'co'];

export function generateCandidates(name, { tldHint = null, year = new Date().getFullYear(), perms = PERMUTATIONS, max = 200 } = {}) {
  if (!name) return [];
  const base = String(name).toLowerCase().replace(/[^a-z0-9-]+/g, '-').replace(/^-+|-+$/g, '');
  const tlds = tldHint ? [tldHint] : TLDS;
  const out = new Set();
  for (const perm of perms) {
    let s = perm.replace('{name}', base).replace('{year}', String(year));
    if (perm.includes('{tld}')) {
      for (const tld of tlds) out.add(s.replace('{tld}', tld));
    } else {
      out.add(s);
    }
    if (out.size > max) break;
  }
  return [...out].slice(0, max);
}

const PROVIDERS = {
  s3: (b) => `https://${b}.s3.amazonaws.com/`,
  's3-region': (b, region = 'us-east-1') => `https://${b}.s3.${region}.amazonaws.com/`,
  azure: (b) => `https://${b}.blob.core.windows.net/`,
  gcs: (b) => `https://storage.googleapis.com/${b}/`,
  do: (b, region = 'nyc3') => `https://${b}.${region}.digitaloceanspaces.com/`,
};

export function buildProbeUrls(candidates, { providers = ['s3', 'azure', 'gcs'] } = {}) {
  const urls = [];
  for (const c of candidates) {
    for (const p of providers) {
      const fn = PROVIDERS[p];
      if (fn) urls.push({ provider: p, candidate: c, url: fn(c) });
    }
  }
  return urls;
}

/**
 * Classifica resposta HEAD anônima:
 *   200 → bucket público (interesting, possivelmente sensível)
 *   403 → bucket existe, listing negado (mas pode ter objects públicos)
 *   404 → não existe
 *   AccessDenied/NoSuchBucket no body → idem
 */
export function classifyProbe(resp, urlMeta) {
  const status = resp?.status || resp?.statusCode || 0;
  const body = String(resp?.body || '').slice(0, 1024);
  if (!status) return { ...urlMeta, status: 0, kind: 'error', error: resp?.error || 'no-response' };
  if (status === 200) return { ...urlMeta, status, kind: 'public-listing' };
  if (status === 403 && /AccessDenied|access denied|insufficient permissions/i.test(body)) {
    return { ...urlMeta, status, kind: 'exists-private' };
  }
  if (status === 403) return { ...urlMeta, status, kind: 'exists-private' };
  if (status === 404 && /NoSuchBucket|does not exist/i.test(body)) {
    return { ...urlMeta, status, kind: 'not-found' };
  }
  if (status === 404) return { ...urlMeta, status, kind: 'not-found' };
  if (status === 301 || status === 302) return { ...urlMeta, status, kind: 'redirect' };
  return { ...urlMeta, status, kind: 'unknown' };
}

/**
 * Pipeline completo: gera + probe via executor + classifica + emite findings.
 */
export async function bruteforceCloud({ name, executor, providers = ['s3', 'azure', 'gcs'], maxConcurrency = 8, target = null }) {
  if (typeof executor !== 'function') throw new Error('bruteforceCloud: executor obrigatório');
  const candidates = generateCandidates(name);
  const urls = buildProbeUrls(candidates, { providers });
  const results = [];
  let i = 0;
  async function worker() {
    while (i < urls.length) {
      const url = urls[i++];
      const resp = await executor({ method: 'HEAD', url: url.url }).catch((e) => ({ error: e?.message || String(e) }));
      results.push(classifyProbe(resp, url));
    }
  }
  await Promise.all(Array.from({ length: Math.min(maxConcurrency, urls.length || 1) }, worker));

  const findings = [];
  for (const r of results) {
    if (r.kind === 'public-listing') {
      findings.push({
        severity: 'high', category: 'cloud-public-bucket',
        title: `Bucket público: ${r.url}`,
        description: `${r.provider} bucket "${r.candidate}" responde 200 anônimo — listing exposto. Validar conteúdo (PII/configs/backups).`,
        evidence: { target: target || name, provider: r.provider, candidate: r.candidate, url: r.url, status: r.status },
      });
    } else if (r.kind === 'exists-private') {
      findings.push({
        severity: 'low', category: 'cloud-bucket-exists',
        title: `Bucket existe (privado): ${r.url}`,
        description: `${r.provider} bucket "${r.candidate}" responde 403 — confirma existência. Tentar paths conhecidos para objects públicos.`,
        evidence: { target: target || name, provider: r.provider, candidate: r.candidate, url: r.url, status: r.status },
      });
    }
  }
  return { findings, results, summary: { candidates: candidates.length, urls: urls.length, public: findings.filter((f) => f.category === 'cloud-public-bucket').length } };
}
