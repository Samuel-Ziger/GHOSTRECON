import { createHash } from 'node:crypto';

const RAW_SECRET = Symbol('ghostrecon.raw-secret');
const VALUE_FP_RE = /(?:^|[\s|•])value_fp=([a-f0-9]{64})(?:$|[\s|•])/i;

export function extractSecretMaterial(value) {
  const text = String(value || '').trim();
  const wrapped = text.match(/^\[([^\]]+)\]\s*(.+)$/s);
  if (wrapped) return { kind: wrapped[1].trim() || 'secret', raw: wrapped[2].trim() };
  const bearer = text.match(/^Bearer\s+(.+)$/is);
  if (bearer) return { kind: 'Bearer', raw: bearer[1].trim() };
  return { kind: 'secret', raw: text };
}

export function secretFingerprint(value, kind = null) {
  const extracted = extractSecretMaterial(value);
  const material = extracted.raw;
  return createHash('sha256')
    .update(`v1|${String(kind || extracted.kind || 'secret').trim().toLowerCase()}|${material}`)
    .digest('hex');
}

export function maskSecretMaterial(value) {
  const text = String(value || '');
  if (!text) return '***';
  if (text.includes('***') || text.includes('…')) return text;
  if (text.length <= 8) return '***';
  const edge = text.length >= 32 ? 6 : 4;
  return `${text.slice(0, edge)}…${text.slice(-edge)}`;
}

export function safeSecretReference(value, { fingerprint = null } = {}) {
  const { kind, raw } = extractSecretMaterial(value);
  const fp = fingerprint || secretFingerprint(raw, kind);
  return {
    kind,
    fingerprint: fp,
    masked: maskSecretMaterial(raw),
    ref: `[${kind}] ${maskSecretMaterial(raw)} • fp=${fp.slice(0, 12)}`,
  };
}

function appendFingerprint(meta, fingerprint) {
  if (meta && typeof meta === 'object' && !Array.isArray(meta)) {
    return { ...meta, valueFingerprint: fingerprint };
  }
  const text = String(meta || '').trim();
  if (VALUE_FP_RE.test(text)) return text;
  return [text, `value_fp=${fingerprint}`].filter(Boolean).join(' • ');
}

function redactSerializable(value, raw) {
  if (typeof value === 'string') return redactSecretText(value, raw);
  if (Array.isArray(value)) return value.map((item) => redactSerializable(item, raw));
  if (value && typeof value === 'object') {
    return Object.fromEntries(
      Object.entries(value).map(([key, item]) => [key, redactSerializable(item, raw)]),
    );
  }
  return value;
}

/**
 * Mantém o material cru somente em propriedade Symbol não enumerável. Assim o
 * pipeline ainda pode fazer uma validação explicitamente autorizada, enquanto
 * NDJSON, JSON.stringify, SQLite e relatórios recebem apenas máscara + hash.
 */
export function protectSecretFinding(finding) {
  if (!finding || finding.type !== 'secret') return finding;
  const existing = finding[RAW_SECRET];
  const { kind, raw } = existing
    ? { kind: existing.kind || 'secret', raw: existing.raw || '' }
    : extractSecretMaterial(finding.value);
  const metaFp = String(finding.meta || '').match(VALUE_FP_RE)?.[1] || null;
  const fingerprint = metaFp || secretFingerprint(raw, kind);

  if (!existing) {
    Object.defineProperty(finding, RAW_SECRET, {
      value: Object.freeze({ kind, raw }),
      configurable: false,
      enumerable: false,
      writable: false,
    });
  }
  finding.value = `[${kind}] ${maskSecretMaterial(raw)}`;
  finding.url = redactSecretText(finding.url, raw);
  finding.meta = appendFingerprint(redactSerializable(finding.meta, raw), fingerprint);
  for (const key of Object.keys(finding)) {
    if (['value', 'url', 'meta'].includes(key)) continue;
    finding[key] = redactSerializable(finding[key], raw);
  }
  finding.secretFingerprint = fingerprint;
  return finding;
}

export function rawSecretFromFinding(finding) {
  if (!finding || finding.type !== 'secret') return '';
  return finding[RAW_SECRET]?.raw || extractSecretMaterial(finding.value).raw;
}

export function redactSecretText(value, rawMaterial) {
  let text = String(value ?? '');
  const raw = String(rawMaterial || '');
  if (raw) text = text.split(raw).join(`[REDACTED:${secretFingerprint(raw).slice(0, 12)}]`);
  return text
    .replace(/\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{3,}\b/g, '[REDACTED:JWT]')
    .replace(/\bgh[pousr]_[A-Za-z0-9_]{20,}\b/g, '[REDACTED:GITHUB_TOKEN]')
    .replace(/\bsk-(?:live-|test-)?[A-Za-z0-9_-]{20,}\b/g, '[REDACTED:API_KEY]')
    .replace(/\bxox[baprs]-[0-9A-Za-z-]{10,}\b/g, '[REDACTED:SLACK_TOKEN]');
}
