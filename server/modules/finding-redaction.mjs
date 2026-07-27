import {
  AUTO_REDACTED_VALUE,
  redactAutoText,
  redactAutoValue,
} from '../auto-agent/redaction.mjs';

const MAX_FINDING_DEPTH = 12;
const MAX_TEXT = 24_000;
const MAX_EVIDENCE_TEXT = 4_000;

const RAW_EVIDENCE_KEYS = new Set([
  'raw',
  'rawdata',
  'rawrequest',
  'rawresponse',
  'requestbody',
  'responsebody',
  'body',
  'content',
  'html',
  'curl',
  'curlcommand',
]);

const HTTP_EXCHANGE_KEYS = new Set(['request', 'response']);
const LOCAL_PATH_KEYS = new Set([
  'file',
  'filepath',
  'metadatapath',
  'repopath',
  'path',
  'location',
  'localpath',
  'reportpath',
  'sessiondir',
  'sourcedir',
  'outputdir',
  'root',
  'dir',
  'directory',
  'binary',
  'source',
  'error',
  'reason',
  'message',
]);
const ALWAYS_PRIVATE_PATH_KEYS = new Set([
  'metadatapath',
  'repopath',
  'localpath',
  'reportpath',
  'sessiondir',
  'sourcedir',
  'outputdir',
  'root',
  'directory',
  'binary',
]);
const SAFE_SENSITIVE_NAMED_KEYS = new Set([
  'secretFingerprint',
  'tokenFingerprint',
  'valueFingerprint',
  'evidenceHash',
  'tokenStatus',
]);
const STRUCTURAL_PATH_KEY_NAMES = new Set([
  'file',
  'filePath',
  'filepath',
  'metadataPath',
  'metadatapath',
  'repoPath',
  'repopath',
  'path',
  'location',
  'localPath',
  'localpath',
  'reportPath',
  'reportpath',
  'sessionDir',
  'sessiondir',
  'session_dir',
  'sourceDir',
  'sourcedir',
  'source_dir',
  'outputDir',
  'outputdir',
  'output_dir',
  'root',
  'dir',
  'directory',
  'binary',
  'source',
]);
const STRUCTURAL_KEYS_TO_PRESERVE = new Set([
  ...SAFE_SENSITIVE_NAMED_KEYS,
  ...STRUCTURAL_PATH_KEY_NAMES,
]);

const RAW_ASSIGNMENT_PATTERN =
  /(\b(?:raw(?:request|response|data)?|request|response|requestbody|responsebody|body|content|html|curl(?:-command)?)\b\s*[:=]\s*)[^•\r\n]*/gi;
const LOCAL_PATH_ASSIGNMENT_PATTERN =
  /(\b(?:file|filepath|metadatapath|repopath|path|location|localpath|reportpath|sessiondir|sourcedir|outputdir|root|dir|directory|binary|source)\b\s*[:=]\s*)((?:\/(?:home|Users|tmp|private\/tmp|var\/tmp|root|opt|srv|workspace)\/|[A-Za-z]:[\\/]|\\\\)[^•\r\n]*)/gi;

function canonicalKey(value) {
  return String(value || '').toLowerCase().replace(/[^a-z0-9]/g, '');
}

function escapeRegExp(value) {
  return String(value).replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

export function redactLocalPathsForPublic(value, { paths = [] } = {}) {
  let text = String(value ?? '');
  const knownPaths = [...new Set(
    (Array.isArray(paths) ? paths : [paths])
      .map((item) => String(item || '').trim())
      .filter(Boolean)
      .sort((left, right) => right.length - left.length),
  )];
  for (const knownPath of knownPaths) {
    text = text.replace(new RegExp(escapeRegExp(knownPath), 'g'), '[LOCAL_PATH]');
  }
  return text
    .replace(
      /(?:\/(?:home|Users|tmp|private\/tmp|var\/tmp|root|opt|srv|workspace|builds|etc|usr|mnt|data|run|dev|proc|sys|boot|bin|sbin|lib)\/)[^\r\n"'<>]*/g,
      '[LOCAL_PATH]',
    )
    .replace(/[A-Za-z]:[\\/][^\r\n"'<>]*/g, '[LOCAL_PATH]')
    .replace(/\\\\[^\\\r\n"'<>]+\\[^\r\n"'<>]*/g, '[LOCAL_PATH]');
}

function isAbsoluteLocalPath(value) {
  const text = String(value ?? '').trim();
  return (
    text.startsWith('/')
    || /^[A-Za-z]:[\\/]/.test(text)
    || /^\\\\[^\\]/.test(text)
  );
}

function boundedText(value, max = MAX_TEXT) {
  const clean = redactAutoText(String(value ?? '')).replace(/\0/g, '');
  if (clean.length <= max) return clean;
  return `${clean.slice(0, max)}…[TRUNCATED:${clean.length - max}]`;
}

function redactInlineRawAssignments(value) {
  return boundedText(value)
    .replace(RAW_ASSIGNMENT_PATTERN, `$1${AUTO_REDACTED_VALUE}`)
    .replace(LOCAL_PATH_ASSIGNMENT_PATTERN, '$1[LOCAL_PATH]');
}

function summarizeHttpExchange(value, kind) {
  if (value == null) return value;
  if (value && typeof value === 'object') {
    return sanitizeFindingNode(value, { depth: 1 });
  }

  const text = boundedText(value, MAX_EVIDENCE_TEXT);
  const firstLine = text.split(/\r?\n/, 1)[0]?.trim() || '';
  const marker = kind === 'request' ? '[REDACTED_HTTP_REQUEST]' : '[REDACTED_HTTP_RESPONSE]';
  if (!firstLine) return marker;

  if (kind === 'request') {
    const match = firstLine.match(/^(GET|HEAD|POST|PUT|PATCH|DELETE|OPTIONS|TRACE|CONNECT)\s+(\S+)(?:\s+HTTP\/\d(?:\.\d)?)?/i);
    if (match) return `${marker} ${match[1].toUpperCase()} ${boundedText(match[2], 1_500)}`;
  } else {
    const match = firstLine.match(/^HTTP\/\d(?:\.\d)?\s+(\d{3})(?:\s+([^\r\n]{0,100}))?/i);
    if (match) return `${marker} status=${match[1]}${match[2] ? ` ${boundedText(match[2], 100)}` : ''}`;
  }
  return marker;
}

function sanitizeFindingNode(value, { key = '', depth = 0 } = {}) {
  if (value == null || typeof value === 'boolean' || typeof value === 'number') return value;
  const normalizedKey = canonicalKey(key);

  if (RAW_EVIDENCE_KEYS.has(normalizedKey)) {
    return `[REDACTED_${normalizedKey.toUpperCase()}]`;
  }
  if (HTTP_EXCHANGE_KEYS.has(normalizedKey)) {
    return summarizeHttpExchange(value, normalizedKey);
  }
  if (typeof value === 'string') {
    if (LOCAL_PATH_KEYS.has(normalizedKey)) {
      if (ALWAYS_PRIVATE_PATH_KEYS.has(normalizedKey) && value.trim()) return '[LOCAL_PATH]';
      if (isAbsoluteLocalPath(value)) return '[LOCAL_PATH]';
      return boundedText(redactLocalPathsForPublic(value));
    }
    return normalizedKey === 'meta'
      ? redactInlineRawAssignments(value)
      : boundedText(value, normalizedKey.includes('snippet') ? MAX_EVIDENCE_TEXT : MAX_TEXT);
  }
  if (typeof value === 'bigint') return String(value);
  if (depth >= MAX_FINDING_DEPTH) return '[TRUNCATED_DEPTH]';
  if (Array.isArray(value)) {
    return value.slice(0, 500).map((item) => sanitizeFindingNode(item, { depth: depth + 1 }));
  }
  if (typeof value !== 'object') return boundedText(value);

  const out = {};
  for (const [childKey, child] of Object.entries(value).slice(0, 500)) {
    out[boundedText(childKey, 300)] = sanitizeFindingNode(child, {
      key: childKey,
      depth: depth + 1,
    });
  }
  return out;
}

/**
 * Fronteira pública/persistente de um finding.
 *
 * Mantém classificação, origem, IDs de módulo, URL sanitizada, hashes e demais
 * proveniência. Material HTTP bruto, body, curl e blobs raw são substituídos
 * por marcadores; request/response preservam somente a linha inicial segura ou
 * os metadados estruturados sem segredos.
 */
export function redactFindingForPublic(finding) {
  if (!finding || typeof finding !== 'object') return null;
  const structurallyRedacted = redactAutoValue(finding, {
    maxDepth: MAX_FINDING_DEPTH,
    maxArrayItems: 500,
    maxObjectKeys: 500,
    preserveSensitiveKeys: STRUCTURAL_KEYS_TO_PRESERVE,
  });
  return sanitizeFindingNode(structurallyRedacted);
}

export function redactFindingsForPublic(findings = []) {
  return (Array.isArray(findings) ? findings : [])
    .map((finding) => redactFindingForPublic(finding))
    .filter(Boolean);
}

/**
 * Defesa em profundidade para qualquer chamador da persistência, inclusive
 * caminhos que não passam pelo pipeline principal.
 */
export function redactRunPayloadForPersistence(payload = {}) {
  const findings = redactFindingsForPublic(payload.findings);
  return {
    ...redactAutoValue(payload, {
      preserveSensitiveKeys: new Set(['findings']),
      maxDepth: MAX_FINDING_DEPTH,
      maxArrayItems: 500,
      maxObjectKeys: 500,
    }),
    findings,
  };
}
