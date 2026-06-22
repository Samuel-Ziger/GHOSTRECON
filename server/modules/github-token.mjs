/**
 * GITHUB_TOKEN / GH_TOKEN — leitura única para API GitHub e git clone.
 */

export function resolveGithubToken(env = process.env) {
  const raw = env.GITHUB_TOKEN ?? env.GH_TOKEN ?? '';
  if (raw == null || typeof raw !== 'string') return '';
  let t = raw.trim();
  if ((t.startsWith('"') && t.endsWith('"')) || (t.startsWith("'") && t.endsWith("'"))) {
    t = t.slice(1, -1).trim();
  }
  return t;
}

export function githubTokenConfigured(env = process.env) {
  return Boolean(resolveGithubToken(env));
}

/** Preview seguro para logs/UI (ex.: ghp_…a1b2). */
export function githubTokenPreview(token = resolveGithubToken()) {
  const t = String(token || '').trim();
  if (!t) return null;
  if (t.length <= 8) return '***';
  return `${t.slice(0, 4)}…${t.slice(-4)}`;
}

export function githubCapabilities(env = process.env) {
  const token = resolveGithubToken(env);
  return {
    token_configured: Boolean(token),
    token_preview: token ? githubTokenPreview(token) : null,
    clone_auth: Boolean(token) ? 'pat' : 'none',
  };
}
