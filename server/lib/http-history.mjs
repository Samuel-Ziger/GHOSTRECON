import { AsyncLocalStorage } from 'node:async_hooks';

export const reconHttpContext = new AsyncLocalStorage();

export function createHttpHistoryStore({
  maxEntries = Number(process.env.GHOSTRECON_HTTP_HISTORY_MAX || 1200),
  responsePreviewMax = Number(process.env.GHOSTRECON_HTTP_HISTORY_RESPONSE_MAX || 120000),
} = {}) {
  const entries = [];
  let seq = 0;

  function redactHttpHeader(name, value) {
    const n = String(name || '').toLowerCase();
    if (/authorization|cookie|x-api-key|token|secret|password|key/.test(n)) return '[redacted]';
    return String(value ?? '').slice(0, 800);
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
    const seen = new WeakSet();
    const scrub = (v, key = '') => {
      if (/authorization|cookie|token|secret|password|api.?key/i.test(key)) return '[redacted]';
      if (v == null || typeof v !== 'object') return v;
      if (seen.has(v)) return '[circular]';
      seen.add(v);
      if (Array.isArray(v)) return v.map((x) => scrub(x));
      const out = {};
      for (const [k, val] of Object.entries(v)) out[k] = scrub(val, k);
      return out;
    };
    try {
      return JSON.stringify(scrub(obj), null, 2).slice(0, 8000);
    } catch {
      return '';
    }
  }

  function redactBodyTextForHistory(text) {
    const raw = String(text || '');
    if (!raw) return '';
    const keyRe = /authorization|cookie|token|secret|password|passwd|pwd|api[_-]?key|apikey|x-api-key/i;
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
        for (const [k, v] of params) redacted.append(k, keyRe.test(k) ? '[redacted]' : v);
        return redacted.toString().slice(0, 8000);
      } catch {
        /* fall through */
      }
    }
    return raw
      .replace(
        /((?:authorization|cookie|token|secret|password|passwd|pwd|api[_-]?key|apikey|x-api-key)\s*[:=]\s*)(["']?)[^&\s"',}]{4,}/gi,
        '$1$2[redacted]',
      )
      .slice(0, 8000);
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
    const row = {
      id: ++seq,
      ts: new Date().toISOString(),
      requestRunId: entry.requestRunId || null,
      target: entry.target || null,
      source: entry.source || 'fetch',
      method: String(entry.method || 'GET').toUpperCase(),
      url: String(entry.url || '').slice(0, 2000),
      requestHeaders: entry.requestHeaders || {},
      requestBody: redactBodyTextForHistory(entry.requestBody || ''),
      status: entry.status ?? null,
      statusText: entry.statusText || '',
      ok: entry.ok ?? null,
      durationMs: entry.durationMs ?? null,
      error: entry.error || '',
      responseHeaders: entry.responseHeaders || {},
      responseBody: redactBodyTextForHistory(entry.responseBody || ''),
      mimeType: entry.mimeType || '',
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
