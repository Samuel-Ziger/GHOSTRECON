import { AsyncLocalStorage } from 'node:async_hooks';
import {
  AUTO_REDACTED_VALUE,
  isSensitiveAutoKey,
  redactAutoText,
  redactAutoValue,
} from '../auto-agent/redaction.mjs';

export const reconHttpContext = new AsyncLocalStorage();

const MAX_HISTORY_BODY_CHARS = 8_000;
const MAX_HISTORY_BODY_DEPTH = 12;
const MAX_HISTORY_COLLECTION_ITEMS = 500;

function canonicalHistoryKey(value) {
  return String(value || '').toLowerCase().replace(/[^a-z0-9]/g, '');
}

/**
 * Contextos autenticados não são telemetria. Mesmo campos booleanos como
 * `frameSevenAuth` são omitidos junto com os containers que podem carregar
 * cookies, headers arbitrários, arquivos de sessão ou credenciais inline.
 */
function isPrivateHistoryBodyKey(key) {
  const normalized = canonicalHistoryKey(key);
  if (!normalized) return false;
  if (
    normalized === 'auth'
    || normalized === 'authentication'
    || normalized === 'credential'
    || normalized === 'credentials'
    || normalized === 'storagestate'
    || normalized === 'localstorage'
    || normalized === 'sessionstorage'
    || normalized.startsWith('vigoliumauth')
    || normalized.startsWith('framesevenauth')
    || normalized.startsWith('capturedauth')
    || normalized.startsWith('sharedauth')
  ) {
    return true;
  }
  if (/(?:auth|authentication|session)(?:context|material|secret|state|data|headers?|cookies?|files?|filepaths?)$/.test(normalized)) {
    return true;
  }
  return /^(?:browser|captured|authenticated)?session(?:id|token|context|material|secret|state|data|headers?|cookies?|files?|filepaths?)?$/.test(normalized);
}

function isSensitiveHistoryHeader(name) {
  const normalized = String(name || '').trim().toLowerCase();
  return /(?:^|[-_])(?:authorization|cookie|token|secret|password|passwd|passphrase|key|credential|session|sid|csrf|xsrf)(?:$|[-_])/.test(normalized)
    || /^(?:authorization|proxy-authorization|cookie|set-cookie|x-api-key|x-auth-token)$/i.test(normalized);
}

function isSensitiveHistoryBodyKey(key) {
  return isPrivateHistoryBodyKey(key)
    || isSensitiveAutoKey(key)
    || /(?:auth|session).*(?:file|path)|(?:file|path).*(?:auth|session)/i.test(String(key || ''));
}

function redactHistoryUrlPart(value) {
  const params = new URLSearchParams(String(value || ''));
  const safe = new URLSearchParams();
  for (const [key, child] of params) {
    safe.append(
      key,
      isSensitiveHistoryBodyKey(key) || isSensitiveHistoryHeader(key)
        ? AUTO_REDACTED_VALUE
        : redactAutoText(child),
    );
  }
  return safe.toString();
}

function redactHistoryUrl(value) {
  const raw = String(value || '');
  if (!raw) return '';
  const hashAt = raw.indexOf('#');
  const beforeHash = hashAt >= 0 ? raw.slice(0, hashAt) : raw;
  const fragment = hashAt >= 0 ? raw.slice(hashAt + 1) : '';
  const queryAt = beforeHash.indexOf('?');
  let base = queryAt >= 0 ? beforeHash.slice(0, queryAt) : beforeHash;
  const query = queryAt >= 0 ? beforeHash.slice(queryAt + 1) : '';

  // URL userinfo é autenticação e não pode chegar à telemetria.
  base = base.replace(
    /^([a-z][a-z0-9+.-]*:\/\/)([^/@]+)@/i,
    `$1${AUTO_REDACTED_VALUE}@`,
  );

  const safeQuery = query ? redactHistoryUrlPart(query) : '';
  const safeFragment = fragment
    ? fragment.includes('=')
      ? redactHistoryUrlPart(fragment)
      : redactAutoText(fragment)
    : '';
  return [
    redactAutoText(base),
    queryAt >= 0 ? `?${safeQuery}` : '',
    hashAt >= 0 ? `#${safeFragment}` : '',
  ].join('');
}

function collectStrings(value, out, {
  depth = 0,
  maxDepth = MAX_HISTORY_BODY_DEPTH,
  seen = new WeakSet(),
} = {}) {
  if (value == null || depth > maxDepth) return;
  if (typeof value === 'string') {
    const text = value.trim();
    if (text.length >= 4) {
      out.add(text);
      // `name:Header:value` é o formato inline do Vigolium. O valor do
      // header também deve ser removido caso tenha sido ecoado fora do campo.
      const first = text.indexOf(':');
      const second = first < 0 ? -1 : text.indexOf(':', first + 1);
      const inlineValue = second >= 0 ? text.slice(second + 1).trim() : '';
      if (inlineValue.length >= 4) out.add(inlineValue);
    }
    return;
  }
  if (typeof value !== 'object') return;
  if (seen.has(value)) return;
  seen.add(value);
  try {
    const children = Array.isArray(value) ? value : Object.values(value);
    // A saída persistida continua limitada a 500 itens, porém a coleta de
    // material privado precisa percorrer toda a entrada para que um segredo
    // após esse limite não possa ser ecoado em outro campo.
    for (const child of children) {
      collectStrings(child, out, {
        depth: depth + 1,
        maxDepth,
        seen,
      });
    }
  } finally {
    seen.delete(value);
  }
}

function collectPrivateHistoryMaterial(value, {
  depth = 0,
  out = new Set(),
  seen = new WeakSet(),
} = {}) {
  if (value == null || typeof value !== 'object' || depth > MAX_HISTORY_BODY_DEPTH) return out;
  if (seen.has(value)) return out;
  seen.add(value);
  try {
    if (Array.isArray(value)) {
      for (const item of value) {
        collectPrivateHistoryMaterial(item, { depth: depth + 1, out, seen });
      }
      return out;
    }
    for (const [key, child] of Object.entries(value)) {
      if (isPrivateHistoryBodyKey(key)) {
        collectStrings(child, out);
        continue;
      }
      collectPrivateHistoryMaterial(child, { depth: depth + 1, out, seen });
    }
    return out;
  } finally {
    seen.delete(value);
  }
}

function redactExactHistoryMaterial(value, materials) {
  let safe = String(value ?? '');
  for (const material of materials) {
    safe = safe.split(material).join(AUTO_REDACTED_VALUE);
  }
  return redactAutoText(safe);
}

export function createHttpHistoryStore({
  maxEntries = Number(process.env.GHOSTRECON_HTTP_HISTORY_MAX || 1200),
  responsePreviewMax = Number(process.env.GHOSTRECON_HTTP_HISTORY_RESPONSE_MAX || 120000),
} = {}) {
  const entries = [];
  let seq = 0;

  function redactHttpHeader(name, value) {
    if (isSensitiveHistoryHeader(name)) return '[redacted]';
    return redactAutoText(String(value ?? '')).slice(0, 800);
  }

  function normalizeHeadersForHistory(headers) {
    const out = {};
    try {
      if (!headers) return out;
      if (typeof headers.forEach === 'function') {
        headers.forEach((v, k) => {
          out[String(k).toLowerCase()] = redactHttpHeader(k, v);
        });
        return out;
      }
      for (const [k, v] of Object.entries(headers)) out[String(k).toLowerCase()] = redactHttpHeader(k, v);
    } catch {
      /* best effort */
    }
    return out;
  }

  function safeJsonBodyForHistory(obj) {
    const privateMaterials = [...collectPrivateHistoryMaterial(obj)]
      .sort((left, right) => right.length - left.length);
    const seen = new WeakSet();
    const scrub = (v, key = '', depth = 0) => {
      if (isSensitiveHistoryBodyKey(key)) return AUTO_REDACTED_VALUE;
      if (v == null || typeof v === 'boolean' || typeof v === 'number') return v;
      if (typeof v === 'bigint') return String(v);
      if (typeof v === 'string') return redactExactHistoryMaterial(v, privateMaterials);
      if (typeof v !== 'object') return `[${typeof v}]`;
      if (depth >= MAX_HISTORY_BODY_DEPTH) return '[TRUNCATED_DEPTH]';
      if (seen.has(v)) return '[circular]';
      seen.add(v);
      try {
        if (Array.isArray(v)) {
          return v
            .slice(0, MAX_HISTORY_COLLECTION_ITEMS)
            .map((item) => scrub(item, '', depth + 1));
        }
        const out = {};
        for (const [k, val] of Object.entries(v).slice(0, MAX_HISTORY_COLLECTION_ITEMS)) {
          out[k] = scrub(val, k, depth + 1);
        }
        return out;
      } finally {
        seen.delete(v);
      }
    };
    try {
      return JSON.stringify(
        redactAutoValue(scrub(obj), {
          maxDepth: MAX_HISTORY_BODY_DEPTH,
          maxArrayItems: MAX_HISTORY_COLLECTION_ITEMS,
          maxObjectKeys: MAX_HISTORY_COLLECTION_ITEMS,
        }),
        null,
        2,
      ).slice(0, MAX_HISTORY_BODY_CHARS);
    } catch {
      return '';
    }
  }

  function redactBodyTextForHistory(text) {
    const raw = String(text || '');
    if (!raw) return '';
    const trimmed = raw.trim();
    if ((trimmed.startsWith('{') && trimmed.endsWith('}')) || (trimmed.startsWith('[') && trimmed.endsWith(']'))) {
      try {
        return safeJsonBodyForHistory(JSON.parse(trimmed));
      } catch {
        /* fall through */
      }
    }
    if (/^[^=\s&]+=[\s\S]*$/.test(trimmed) && trimmed.includes('=')) {
      try {
        const params = new URLSearchParams(trimmed);
        const redacted = new URLSearchParams();
        for (const [k, v] of params) {
          redacted.append(
            k,
            isSensitiveHistoryBodyKey(k) ? AUTO_REDACTED_VALUE : redactAutoText(v),
          );
        }
        return redacted.toString().slice(0, MAX_HISTORY_BODY_CHARS);
      } catch {
        /* fall through */
      }
    }
    return redactAutoText(raw)
      .replace(
        /((?:authorization|cookie|token|secret|password|passwd|pwd|api[_-]?key|apikey|x-api-key|auth|authentication|vigoliumAuth(?:Entries|Files?|File)?|session(?:id|token|context|material|secret|state|data|file|path)?)\s*[:=]\s*)(["']?)[^&\s"',}]{1,}/gi,
        `$1$2${AUTO_REDACTED_VALUE}`,
      )
      .slice(0, MAX_HISTORY_BODY_CHARS);
  }

  function bodyPreviewForHistory(body) {
    if (body == null) return '';
    if (typeof body === 'string') return redactBodyTextForHistory(body);
    if (body instanceof URLSearchParams) return redactBodyTextForHistory(body.toString());
    if (Buffer.isBuffer(body)) return redactBodyTextForHistory(body.toString('utf8', 0, Math.min(body.length, 8000)));
    if (body instanceof ArrayBuffer) return redactBodyTextForHistory(Buffer.from(body).toString('utf8', 0, 8000));
    if (ArrayBuffer.isView(body)) {
      const b = Buffer.from(body.buffer, body.byteOffset, body.byteLength);
      return redactBodyTextForHistory(b.toString('utf8', 0, Math.min(b.length, 8000)));
    }
    return `[${Object.prototype.toString.call(body).replace(/^\[object |\]$/g, '')}]`;
  }

  function recordReconHttpHistory(entry) {
    const requestBody = entry.requestBody != null && typeof entry.requestBody === 'object'
      ? safeJsonBodyForHistory(entry.requestBody)
      : redactBodyTextForHistory(entry.requestBody || '');
    const responseBody = entry.responseBody != null && typeof entry.responseBody === 'object'
      ? safeJsonBodyForHistory(entry.responseBody)
      : redactBodyTextForHistory(entry.responseBody || '');
    const row = {
      id: ++seq,
      ts: new Date().toISOString(),
      requestRunId: entry.requestRunId || null,
      target: entry.target ? redactHistoryUrl(entry.target) : null,
      source: redactAutoText(entry.source || 'fetch'),
      method: String(entry.method || 'GET').toUpperCase(),
      url: redactHistoryUrl(entry.url).slice(0, 2000),
      requestHeaders: normalizeHeadersForHistory(entry.requestHeaders),
      requestBody,
      status: entry.status ?? null,
      statusText: redactAutoText(entry.statusText || ''),
      ok: entry.ok ?? null,
      durationMs: entry.durationMs ?? null,
      error: redactAutoText(entry.error || ''),
      responseHeaders: normalizeHeadersForHistory(entry.responseHeaders),
      responseBody,
      mimeType: redactAutoText(entry.mimeType || ''),
      responseSize: entry.responseSize ?? null,
    };
    entries.push(row);
    while (entries.length > maxEntries) entries.shift();
    try {
      if (typeof entry.emit === 'function') entry.emit({ type: 'http_history', entry: row });
    } catch {
      /* ignore stream write races */
    }
    return row;
  }

  return {
    entries,
    responsePreviewMax,
    redactHttpHeader,
    normalizeHeadersForHistory,
    redactBodyTextForHistory,
    bodyPreviewForHistory,
    safeJsonBodyForHistory,
    recordReconHttpHistory,
  };
}
