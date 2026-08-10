const REDACTED = '[REDACTED]';

// Âncoras ^/$ evitam falsos positivos como sessionTimeoutMs (política de retomada).
const SENSITIVE_KEY = /^(?:authorization|cookie|api[_-]?key|access[_-]?token|refresh[_-]?token|id[_-]?token|csrf[_-]?token|xsrf[_-]?token|auth[_-]?token|token|secret|password|passwd|passphrase|private[_-]?key|credential|session|sessionid|session[_-]?token|sid)$/i;

const SECRET_PATTERNS = Object.freeze([
  /\bgh[pousr]_[A-Za-z0-9_]{20,}\b/g,
  /\bgithub_pat_[A-Za-z0-9_]{20,}\b/g,
  /\bsk-(?:proj-)?[A-Za-z0-9_-]{16,}\b/g,
  /\bBearer\s+[A-Za-z0-9._~+/=-]{8,}\b/gi,
  /\bBasic\s+[A-Za-z0-9+/=]{8,}\b/gi,
  /\bxox[baprs]-[0-9A-Za-z-]{10,}\b/g,
  /\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{8,}\b/g,
  /\b(?:AKIA|ASIA)[A-Z0-9]{16}\b/g,
  /-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----[\s\S]*?-----END (?:RSA |EC |OPENSSH )?PRIVATE KEY-----/g,
]);

const KEY_VALUE_PATTERN = /(\b(?:authorization|proxy-authorization|cookie|set-cookie|x-api-key|x-auth-token|api[-_]?key|access[-_]?token|refresh[-_]?token|id[-_]?token|csrf[-_]?token|xsrf[-_]?token|auth[-_]?token|token|secret|client[-_]?secret|password|passwd|passphrase|credential|session(?:id|[-_]?token)?|sid)\b\s*[:=]\s*)(?:"[^"\r\n]*"|'[^'\r\n]*'|[^\s,;&\r\n}]+)/gi;
const SENSITIVE_HEADER_PATTERN = /(\b(?:authorization|proxy-authorization|cookie|set-cookie|x-api-key|x-auth-token|x-csrf-token|x-xsrf-token)\s*:\s*)[^\r\n]*/gi;
const QUOTED_KEY_PATTERN = /(["'](?:authorization|proxy[-_]?authorization|cookie|set[-_]?cookie|x[-_]?api[-_]?key|x[-_]?auth[-_]?token|api[-_]?key|access[-_]?token|refresh[-_]?token|id[-_]?token|csrf[-_]?token|xsrf[-_]?token|auth[-_]?token|token|secret|client[-_]?secret|password|passwd|passphrase|private[-_]?key|credential|session(?:id|[-_]?token)?|sid)["']\s*:\s*)(?:"[^"\r\n]*"|'[^'\r\n]*'|[^,}\r\n]+)/gi;
const URL_CREDENTIALS_PATTERN = /([a-z][a-z0-9+.-]*:\/\/)([^/\s:@]+):([^@\s/]+)@/gi;
const SENSITIVE_QUERY_PATTERN = /([?&](?:api[-_]?key|access[-_]?token|refresh[-_]?token|id[-_]?token|csrf[-_]?token|xsrf[-_]?token|auth[-_]?token|token|secret|client[-_]?secret|password|passwd|passphrase|credential|session(?:id|[-_]?token)?|sid|signature|sig)=)[^&#\s]*/gi;
const CURL_SECRET_ARG_PATTERN = /(\B(?:--cookie|-b|--user|-u|--oauth2-bearer)\s+)(?:"[^"\r\n]*"|'[^'\r\n]*'|[^\s\r\n]+)/gi;
const CURL_HEADER_ARG_PATTERN = /(\B(?:--header|-H)\s+)(?:"(?:Authorization|Proxy-Authorization|Cookie|Set-Cookie|X-Api-Key|X-Auth-Token)\s*:[^"\r\n]*"|'(?:Authorization|Proxy-Authorization|Cookie|Set-Cookie|X-Api-Key|X-Auth-Token)\s*:[^'\r\n]*'|(?:Authorization|Proxy-Authorization|Cookie|Set-Cookie|X-Api-Key|X-Auth-Token)\s*:[^\s\r\n]+)/gi;

/** Extra tokens literais (vírgula) via GHOSTRECON_AUTO_REDACT_EXTRA — sem regex do operador. */
export function loadAutoRedactionPolicy(env = process.env) {
  const raw = String(env.GHOSTRECON_AUTO_REDACT_EXTRA || '');
  const extras = [...new Set(
    raw.split(',')
      .map((part) => part.trim())
      .filter((part) => part.length >= 6 && part.length <= 200),
  )].slice(0, 32);
  const cloudRedaction = !/^(0|false|no|off)$/i.test(
    String(env.GHOSTRECON_AUTO_CLOUD_REDACTION ?? '1'),
  );
  return Object.freeze({
    version: 1,
    extras,
    cloudRedaction,
    source: extras.length ? 'env:GHOSTRECON_AUTO_REDACT_EXTRA' : 'builtin',
  });
}

let cachedPolicy = null;
let cachedPolicyKey = '';

function activeRedactionPolicy(env = process.env) {
  const key = `${env.GHOSTRECON_AUTO_REDACT_EXTRA || ''}|${env.GHOSTRECON_AUTO_CLOUD_REDACTION ?? '1'}`;
  if (cachedPolicy && cachedPolicyKey === key) return cachedPolicy;
  cachedPolicyKey = key;
  cachedPolicy = loadAutoRedactionPolicy(env);
  return cachedPolicy;
}

function redactString(value, env = process.env, { cloud = false } = {}) {
  let text = String(value ?? '');
  for (const pattern of SECRET_PATTERNS) text = text.replace(pattern, REDACTED);
  text = text
    .replace(SENSITIVE_HEADER_PATTERN, `$1${REDACTED}`)
    .replace(QUOTED_KEY_PATTERN, `$1"${REDACTED}"`)
    .replace(KEY_VALUE_PATTERN, `$1${REDACTED}`)
    .replace(URL_CREDENTIALS_PATTERN, `$1${REDACTED}:${REDACTED}@`)
    .replace(SENSITIVE_QUERY_PATTERN, `$1${REDACTED}`)
    .replace(CURL_HEADER_ARG_PATTERN, `$1${REDACTED}`)
    .replace(CURL_SECRET_ARG_PATTERN, `$1${REDACTED}`);
  const policy = activeRedactionPolicy(env);
  for (const extra of policy.extras) {
    if (!extra || !text.includes(extra)) continue;
    text = text.split(extra).join(REDACTED);
  }
  // Cloud-only: e-mails/hashes longos em evidência enviada a providers externos.
  // Nunca aplicar em snapshots/checkpoints (catalogHash/planHash são SHA-256).
  if (cloud && policy.cloudRedaction) {
    text = text
      .replace(/\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b/gi, REDACTED)
      .replace(/\b[a-f0-9]{64}\b/gi, REDACTED);
  }
  return text;
}

function redactValue(value, {
  depth = 0,
  maxDepth = 12,
  maxArrayItems = 500,
  maxObjectKeys = 500,
  preserveSensitiveKeys = new Set(),
  cloud = false,
  env = process.env,
  seen = new WeakSet(),
} = {}) {
  if (value == null || typeof value === 'boolean' || typeof value === 'number') return value;
  if (typeof value === 'bigint') return String(value);
  if (typeof value === 'string') return redactString(value, env, { cloud });
  if (typeof value === 'function' || typeof value === 'symbol') return `[${typeof value}]`;
  if (depth >= maxDepth) return '[TRUNCATED_DEPTH]';
  if (typeof value !== 'object') return redactString(value, env, { cloud });
  if (seen.has(value)) return '[CIRCULAR]';
  seen.add(value);
  try {
    if (Array.isArray(value)) {
      const rows = value.slice(0, maxArrayItems).map((item) => redactValue(item, {
        depth: depth + 1, maxDepth, maxArrayItems, maxObjectKeys, preserveSensitiveKeys, cloud, env, seen,
      }));
      if (value.length > maxArrayItems) rows.push(`[TRUNCATED_ITEMS:${value.length - maxArrayItems}]`);
      return rows;
    }
    const out = {};
    const entries = Object.entries(value).slice(0, maxObjectKeys);
    for (const [key, item] of entries) {
      const safeKey = redactString(key, env, { cloud: false }).slice(0, 300);
      out[safeKey] = SENSITIVE_KEY.test(key) && !preserveSensitiveKeys.has(key)
        ? REDACTED
        : redactValue(item, {
            depth: depth + 1,
            maxDepth,
            maxArrayItems,
            maxObjectKeys,
            preserveSensitiveKeys,
            cloud,
            env,
            seen,
          });
    }
    if (Object.keys(value).length > maxObjectKeys) {
      out.__truncatedKeys = Object.keys(value).length - maxObjectKeys;
    }
    return out;
  } finally {
    seen.delete(value);
  }
}

export function redactAutoText(value, env = process.env, options = {}) {
  const cloud = options.cloud !== false;
  if (typeof value === 'string') return redactString(value, env, { cloud });
  try {
    return redactString(JSON.stringify(redactValue(value, { ...options, cloud, env })), env, { cloud });
  } catch {
    return REDACTED;
  }
}

export function redactAutoValue(value, options = {}) {
  // Persistência estrutural: cloud=false por padrão (preserva SHA-256 de plano/checkpoint).
  return redactValue(value, { cloud: false, ...options });
}

export function isSensitiveAutoKey(key) {
  return SENSITIVE_KEY.test(String(key || ''));
}

export const AUTO_REDACTED_VALUE = REDACTED;
