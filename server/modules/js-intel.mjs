/**
 * JS bundle intel — extrai endpoints, rotas, feature flags e segredos a partir
 * de bundles JavaScript e source maps.
 *
 * Tudo trabalha sobre o conteúdo string (sem rede). O caller decide se baixa
 * via fetch ou Playwright.
 */

const ENDPOINT_REGEX = [
  /(?:fetch|axios(?:\.\w+)?|\.get|\.post|\.put|\.delete|\.patch|\.request)\s*\(\s*[`'"]([^`'"\s]+)[`'"]/g,
  /(?:url|endpoint|baseURL|apiUrl|api_url)\s*[:=]\s*[`'"]([^`'"\s]+)[`'"]/g,
  /new\s+URL\s*\(\s*[`'"]([^`'"\s]+)[`'"]/g,
  /\bhref\s*=\s*[`'"]([^`'"\s]+)[`'"]/g,
];

// Caminhos relativos típicos da SPA
const PATH_HINT_REGEX = /[`'"](\/[a-zA-Z0-9_\-./]{2,200})[`'"]/g;

const SECRET_PATTERNS = [
  { id: 'aws-access-key', re: /\b(AKIA[0-9A-Z]{16})\b/g },
  { id: 'aws-secret', re: /\b([A-Za-z0-9/+=]{40})\b(?=\s*['"]?\s*[,;}\]])/g },
  { id: 'gcp-key', re: /"private_key"\s*:\s*"-----BEGIN PRIVATE KEY-----/g },
  { id: 'github-pat', re: /\b(ghp_[A-Za-z0-9]{36})\b/g },
  { id: 'github-fine', re: /\b(github_pat_[A-Za-z0-9_]{82})\b/g },
  { id: 'slack-token', re: /\b(xox[abprs]-[A-Za-z0-9-]{10,})\b/g },
  { id: 'stripe', re: /\b(sk_(?:live|test)_[A-Za-z0-9]{24,})\b/g },
  { id: 'jwt', re: /\b(eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,})\b/g },
  { id: 'firebase-key', re: /\b(AIza[0-9A-Za-z_-]{35})\b/g },
  { id: 'sendgrid', re: /\b(SG\.[A-Za-z0-9_-]{16,}\.[A-Za-z0-9_-]{16,})\b/g },
  { id: 'private-key-block', re: /-----BEGIN (?:RSA |EC |DSA |OPENSSH |)PRIVATE KEY-----/g },
];

const FEATURE_FLAG_HINTS = /\b(?:isEnabled|featureFlag|launchDarkly|optimizely|growthbook|unleash)\s*\(\s*[`'"]([a-zA-Z0-9._-]+)[`'"]/g;

const INTERESTING_PATH_HINT = /(admin|internal|debug|graphql|swagger|openapi|\/api\/v\d+|impersonate|sudo|legacy|console)/i;

function unique(arr) {
  return [...new Set(arr)];
}

export function extractEndpoints(jsText) {
  if (!jsText || typeof jsText !== 'string') return [];
  const found = [];
  for (const re of ENDPOINT_REGEX) {
    re.lastIndex = 0;
    let m;
    while ((m = re.exec(jsText)) !== null) {
      const u = m[1].trim();
      if (!u || u.startsWith('data:') || u.startsWith('blob:')) continue;
      found.push(u);
      if (found.length > 5000) break;
    }
  }
  return unique(found);
}

export function extractPaths(jsText) {
  if (!jsText || typeof jsText !== 'string') return [];
  const found = [];
  let m;
  PATH_HINT_REGEX.lastIndex = 0;
  while ((m = PATH_HINT_REGEX.exec(jsText)) !== null) {
    const p = m[1];
    if (/\.(svg|png|jpg|jpeg|woff|woff2|ttf|css|map|ico|gif)$/i.test(p)) continue;
    found.push(p);
    if (found.length > 5000) break;
  }
  return unique(found);
}

export function extractSecrets(jsText) {
  if (!jsText || typeof jsText !== 'string') return [];
  const out = [];
  for (const { id, re } of SECRET_PATTERNS) {
    re.lastIndex = 0;
    let m;
    while ((m = re.exec(jsText)) !== null) {
      const value = m[1] || m[0];
      out.push({ id, sample: snippet(jsText, m.index, 40), value: redactValue(id, value) });
      if (out.length > 200) break;
    }
  }
  return out;
}

export function extractFeatureFlags(jsText) {
  if (!jsText || typeof jsText !== 'string') return [];
  const flags = [];
  let m;
  FEATURE_FLAG_HINTS.lastIndex = 0;
  while ((m = FEATURE_FLAG_HINTS.exec(jsText)) !== null) {
    flags.push(m[1]);
    if (flags.length > 500) break;
  }
  return unique(flags);
}

function snippet(text, idx, span = 40) {
  const start = Math.max(0, idx - span);
  const end = Math.min(text.length, idx + span);
  return text.slice(start, end).replace(/\s+/g, ' ').slice(0, 120);
}

function redactValue(id, val) {
  if (id === 'private-key-block') return '<PEM block redacted>';
  if (!val) return val;
  if (val.length <= 12) return val;
  return `${val.slice(0, 6)}…${val.slice(-4)}`;
}

/**
 * Source map handler — quando *.map disponível, recupera lista de fontes
 * (revela paths internos como `webpack:///./src/admin/internal-api.ts`).
 */
export function parseSourceMap(mapText) {
  try {
    const obj = JSON.parse(mapText);
    if (!obj || !Array.isArray(obj.sources)) return { sources: [], internal: [] };
    const sources = obj.sources;
    const internal = sources.filter((s) =>
      /webpack:\/\/|\.\.\/|src\/|admin|internal|secret|debug|legacy|wip/i.test(s),
    );
    return { sources, internal: unique(internal) };
  } catch {
    return { sources: [], internal: [] };
  }
}

/**
 * Aglutina extracts num único bundle de findings, marcando paths/endpoints
 * "interessantes" como severity media e segredos como high/critical.
 */
export function jsBundleToFindings(bundle, { url = null, target = null } = {}) {
  const findings = [];
  const paths = extractPaths(bundle);
  const endpoints = extractEndpoints(bundle);
  const secrets = extractSecrets(bundle);
  const flags = extractFeatureFlags(bundle);

  const interesting = [...paths, ...endpoints].filter((p) => INTERESTING_PATH_HINT.test(p));
  if (interesting.length) {
    findings.push({
      severity: 'medium', category: 'js-bundle',
      title: `JS bundle expõe ${interesting.length} endpoint(s) interessante(s)${url ? ` (${url})` : ''}`,
      description: 'Strings extraídas do bundle apontam para superfícies admin/internal/debug.',
      evidence: { url, target, sample: interesting.slice(0, 30) },
    });
  }
  for (const s of secrets) {
    const sev = ['private-key-block', 'gcp-key', 'aws-access-key', 'github-fine'].includes(s.id) ? 'critical' : 'high';
    findings.push({
      severity: sev, category: 'secrets-leak',
      title: `Segredo (${s.id}) embutido em JS${url ? ` (${url})` : ''}`,
      description: `Padrão ${s.id} encontrado no bundle. Validar se a credencial é válida fora do contexto do cliente.`,
      evidence: { url, target, secretId: s.id, snippet: s.sample, redacted: s.value },
    });
  }
  if (flags.length) {
    findings.push({
      severity: 'low', category: 'js-bundle',
      title: `Feature flags client-side (${flags.length})${url ? ` ${url}` : ''}`,
      description: 'Feature flags client-side podem ser ativadas via override (LD localStorage, cookies). Pode revelar funcionalidades não lançadas.',
      evidence: { url, target, flags: flags.slice(0, 50) },
    });
  }
  return { findings, summary: { paths: paths.length, endpoints: endpoints.length, secrets: secrets.length, flags: flags.length } };
}
