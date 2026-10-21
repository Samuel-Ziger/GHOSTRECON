import { UA } from '../config.js';
import { resolveGithubToken } from './github-token.mjs';
import { readResponseSnippet } from './module-runner.mjs';
import { scanSecrets } from './secrets.js';
import { protectSecretFinding } from './secret-safety.js';

const API_BODY_LIMIT = 2 * 1024 * 1024;
const CODE_BODY_LIMIT = 600_000;

/**
 * Busca passiva na API pública do GitHub (rate limit baixo sem token).
 */
function trimToken(raw) {
  if (raw == null) return resolveGithubToken();
  if (typeof raw !== 'string') return '';
  let t = raw.trim();
  if ((t.startsWith('"') && t.endsWith('"')) || (t.startsWith("'") && t.endsWith("'"))) {
    t = t.slice(1, -1).trim();
  }
  return t;
}

function requestSignal(signal, timeoutMs = 30_000) {
  const timeout = AbortSignal.timeout(Math.max(1_000, Number(timeoutMs) || 30_000));
  return signal ? AbortSignal.any([signal, timeout]) : timeout;
}

async function githubJson(url, token, {
  fetchImpl = globalThis.fetch,
  signal = null,
  accept = 'application/vnd.github+json',
  now = () => new Date(),
} = {}) {
  signal?.throwIfAborted();
  const tok = trimToken(token);
  const headers = { 'User-Agent': UA, Accept: accept };
  if (tok) headers.Authorization = `Bearer ${tok}`;
  const res = await fetchImpl(url, { headers, redirect: 'manual', signal: requestSignal(signal) });
  const text = await readResponseSnippet(res, API_BODY_LIMIT + 1);
  signal?.throwIfAborted();
  let data = null;
  try { data = text ? JSON.parse(text) : null; } catch { /* handled by caller */ }
  const status = Buffer.byteLength(text) > API_BODY_LIMIT ? 'response_too_large' : !data || typeof data !== 'object' || Array.isArray(data) ? 'invalid_response' : 'done';
  return { res, data: status === 'done' ? data : null, status, tokenConfigured: Boolean(tok), retrievedAt: new Date(now()).toISOString() };
}

function githubFailure({ res, data, tokenConfigured }) {
  if (res.status === 403 || res.status === 401) {
    const hint = tokenConfigured
      ? 'Token rejeitado, sem permissão ou rate limit.'
      : 'GITHUB_TOKEN ausente ou rate limit por IP.';
    return `GitHub API ${res.status}: ${hint}`;
  }
  return `HTTP ${res.status}`;
}

export async function githubCodeSearch(domain, token, opts = {}) {
  const q = encodeURIComponent(`${domain} password OR api_key OR secret`);
  const url = `https://api.github.com/search/code?q=${q}&per_page=5`;
  const response = await githubJson(url, token, {
    ...opts,
    accept: 'application/vnd.github.text-match+json, application/vnd.github+json',
  });
  if (!response.res.ok) return { ok: false, note: githubFailure(response) };
  if (response.status !== 'done' || !Array.isArray(response.data?.items)) return { ok: false, status: response.status === 'done' ? 'invalid_response' : response.status, note: 'GitHub: resposta inválida ou excedeu limite' };
  const data = response.data || {};
  const items = data.items || [];
  return {
    ok: true,
    status: data.incomplete_results ? 'partial' : 'done',
    retrievedAt: response.retrievedAt,
    coverage: 'first_page; not_exhaustive',
    total: data.total_count ?? items.length,
    items: items.slice(0, 5).map((it) => ({
      repo: it.repository?.full_name,
      path: it.path,
      html_url: it.html_url,
      api_url: it.url,
      sha: it.sha || null,
    })),
  };
}

export async function githubRepoSearch(domain, token, opts = {}) {
  const perPage = Math.max(1, Math.min(Number(opts.perPage) || 5, 20));
  const q = encodeURIComponent(`${domain} in:name,description,readme`);
  const url = `https://api.github.com/search/repositories?q=${q}&sort=updated&order=desc&per_page=${perPage}`;
  const response = await githubJson(url, token, opts);
  if (!response.res.ok) return { ok: false, note: githubFailure(response) };
  if (response.status !== 'done' || !Array.isArray(response.data?.items)) return { ok: false, status: response.status === 'done' ? 'invalid_response' : response.status, note: 'GitHub: resposta inválida ou excedeu limite' };
  const data = response.data || {};
  const items = data.items || [];
  return {
    ok: true,
    status: data.incomplete_results ? 'partial' : 'done',
    retrievedAt: response.retrievedAt,
    coverage: 'first_page; not_exhaustive',
    total: data.total_count ?? items.length,
    items: items.slice(0, perPage).map((it) => ({
      full_name: it.full_name,
      html_url: it.html_url,
      clone_url: it.clone_url,
      default_branch: it.default_branch || 'main',
      private: Boolean(it.private),
      archived: Boolean(it.archived),
      stargazers_count: Number(it.stargazers_count) || 0,
      updated_at: it.updated_at || null,
      description: it.description || '',
    })),
  };
}

function decodeGithubContent(data) {
  if (!data || data.type === 'dir') return '';
  if (data.encoding === 'base64' && typeof data.content === 'string') {
    try {
      return Buffer.from(data.content.replace(/\s+/g, ''), 'base64').toString('utf8').slice(0, CODE_BODY_LIMIT);
    } catch { return ''; }
  }
  return typeof data.content === 'string' ? data.content.slice(0, CODE_BODY_LIMIT) : '';
}

function targetAppearsInContent(text, target) {
  let domain;
  try { domain = new URL(/^https?:\/\//i.test(target) ? target : `https://${target}`).hostname.toLowerCase(); } catch { return false; }
  if (!domain) return false;
  const content = String(text || '').toLowerCase().replace(/\\u002e/gi, '.');
  const escaped = domain.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  return new RegExp(`(^|[^a-z0-9.-])${escaped}([^a-z0-9.-]|$)`, 'i').test(content);
}

/**
 * Faz download limitado do arquivo retornado pelo Code Search e somente então
 * produz secrets. O resultado de busca isolado continua sendo inventário.
 */
export async function validateGithubCodeHit(hit, {
  target,
  token = null,
  fetchImpl = globalThis.fetch,
  signal = null,
  now = () => new Date(),
} = {}) {
  const apiUrl = String(hit?.api_url || '');
  let parsed;
  try { parsed = new URL(apiUrl); } catch { /* invalid below */ }
  if (!parsed || parsed.origin !== 'https://api.github.com' || parsed.username || parsed.password || parsed.hash || !/^\/repos\/[^/]+\/[^/]+\/contents\//.test(parsed.pathname)) {
    return { findings: [], status: 'invalid_api_url' };
  }
  const response = await githubJson(apiUrl, token, { fetchImpl, signal, now });
  if (!response.res.ok) return { findings: [], status: `http_${response.res.status}` };
  if (response.status !== 'done') return { findings: [], status: response.status };
  if (hit.sha && response.data?.sha && hit.sha !== response.data.sha) return { findings: [], status: 'content_changed_since_search' };
  const text = decodeGithubContent(response.data);
  if (!text) return { findings: [], status: 'content_unavailable' };
  if (!targetAppearsInContent(text, target)) {
    return { findings: [], status: 'target_relation_not_confirmed' };
  }
  const testLike = /(?:^|\/)(?:test|tests|fixtures?|examples?|samples?|docs?)(?:\/|$)/i.test(String(hit?.path || ''));
  const findings = [];
  for (const secret of scanSecrets(text, 2)) {
    const raw = secret.rawMaterial;
    if (!raw) continue;
    findings.push(protectSecretFinding({
      type: 'secret',
      prio: testLike ? 'low' : 'med',
      score: testLike ? 42 : 68,
      value: `[${secret.kind}] ${raw}`,
      url: hit.html_url,
      meta: {
        source: 'github_code_content',
        repository: String(hit.repo || '').slice(0, 180),
        path: String(hit.path || '').slice(0, 400),
        targetRelation: 'content_contains_target',
        context: testLike ? 'test_or_example' : 'unknown_or_production',
        verified: false,
        classification: 'candidate_unverified',
        contentSha: response.data?.sha || hit.sha || null,
        retrievedAt: response.retrievedAt,
        valueFingerprint: secret.correlationFp,
      },
    }));
  }
  return { findings, status: findings.length ? 'classified' : 'no_secret_pattern' };
}
