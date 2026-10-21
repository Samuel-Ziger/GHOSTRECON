import {
  AUTO_REDACTED_VALUE,
  redactAutoText,
  redactAutoValue,
} from '../auto-agent/redaction.mjs';

const MAX_FINDING_DEPTH = 12;
const MAX_TEXT = 24_000;
const MAX_EVIDENCE_TEXT = 4_000;
const MAX_API_CONTRACT_SNAPSHOT_ARRAY_ITEMS = 5_000;
// O snapshot já foi redigido na coleta e carrega a política na sua
// compatibilidade. Reaplicar extras mutáveis na persistência alteraria o hash.
const BUILTIN_REDACTION_ENV = Object.freeze({
  GHOSTRECON_AUTO_REDACT_EXTRA: '',
  GHOSTRECON_AUTO_CLOUD_REDACTION: '0',
});

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

function boundedText(value, max = MAX_TEXT, env = process.env) {
  // Findings already crossed the structural redaction boundary above. Keep
  // cryptographic evidence/plan fingerprints useful for provenance while the
  // non-cloud policy continues to remove credentials, headers and known token
  // formats. Cloud-bound callers apply their stricter hash policy separately.
  const clean = redactAutoText(String(value ?? ''), env, { cloud: false }).replace(/\0/g, '');
  if (clean.length <= max) return clean;
  return `${clean.slice(0, max)}…[TRUNCATED:${clean.length - max}]`;
}

function redactInlineRawAssignments(value, env = process.env) {
  return boundedText(value, MAX_TEXT, env)
    .replace(RAW_ASSIGNMENT_PATTERN, `$1${AUTO_REDACTED_VALUE}`)
    .replace(LOCAL_PATH_ASSIGNMENT_PATTERN, '$1[LOCAL_PATH]');
}

function summarizeHttpExchange(value, kind, env = process.env) {
  if (value == null) return value;
  if (value && typeof value === 'object') {
    return sanitizeFindingNode(value, { depth: 1, env });
  }

  const text = boundedText(value, MAX_EVIDENCE_TEXT, env);
  const firstLine = text.split(/\r?\n/, 1)[0]?.trim() || '';
  const marker = kind === 'request' ? '[REDACTED_HTTP_REQUEST]' : '[REDACTED_HTTP_RESPONSE]';
  if (!firstLine) return marker;

  if (kind === 'request') {
    const match = firstLine.match(/^(GET|HEAD|POST|PUT|PATCH|DELETE|OPTIONS|TRACE|CONNECT)\s+(\S+)(?:\s+HTTP\/\d(?:\.\d)?)?/i);
    if (match) return `${marker} ${match[1].toUpperCase()} ${boundedText(match[2], 1_500, env)}`;
  } else {
    const match = firstLine.match(/^HTTP\/\d(?:\.\d)?\s+(\d{3})(?:\s+([^\r\n]{0,100}))?/i);
    if (match) return `${marker} status=${match[1]}${match[2] ? ` ${boundedText(match[2], 100, env)}` : ''}`;
  }
  return marker;
}

function sanitizeFindingNode(
  value,
  {
    key = '',
    depth = 0,
    maxArrayItems = 500,
    maxObjectKeys = 500,
    env = process.env,
  } = {},
) {
  if (value == null || typeof value === 'boolean' || typeof value === 'number') return value;
  const normalizedKey = canonicalKey(key);

  if (RAW_EVIDENCE_KEYS.has(normalizedKey)) {
    return `[REDACTED_${normalizedKey.toUpperCase()}]`;
  }
  if (HTTP_EXCHANGE_KEYS.has(normalizedKey)) {
    return summarizeHttpExchange(value, normalizedKey, env);
  }
  if (typeof value === 'string') {
    if (LOCAL_PATH_KEYS.has(normalizedKey)) {
      if (ALWAYS_PRIVATE_PATH_KEYS.has(normalizedKey) && value.trim()) return '[LOCAL_PATH]';
      if (isAbsoluteLocalPath(value)) return '[LOCAL_PATH]';
      return boundedText(redactLocalPathsForPublic(value), MAX_TEXT, env);
    }
    return normalizedKey === 'meta'
      ? redactInlineRawAssignments(value, env)
      : boundedText(value, normalizedKey.includes('snippet') ? MAX_EVIDENCE_TEXT : MAX_TEXT, env);
  }
  if (typeof value === 'bigint') return String(value);
  if (depth >= MAX_FINDING_DEPTH) return '[TRUNCATED_DEPTH]';
  if (Array.isArray(value)) {
    return value.slice(0, maxArrayItems).map((item) => sanitizeFindingNode(item, {
      depth: depth + 1,
      maxArrayItems,
      maxObjectKeys,
      env,
    }));
  }
  if (typeof value !== 'object') return boundedText(value, MAX_TEXT, env);

  const out = {};
  for (const [childKey, child] of Object.entries(value).slice(0, maxObjectKeys)) {
    out[boundedText(childKey, 300, env)] = sanitizeFindingNode(child, {
      key: childKey,
      depth: depth + 1,
      maxArrayItems,
      maxObjectKeys,
      env,
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
  const isApiContractSnapshot = finding.type === 'api_contract_snapshot'
    && finding.verification?.evidence?.apiContractSnapshot?.format
      === 'ghostrecon.api-contract-snapshot';
  const maxArrayItems = isApiContractSnapshot
    ? MAX_API_CONTRACT_SNAPSHOT_ARRAY_ITEMS
    : 500;
  const redactionEnv = isApiContractSnapshot ? BUILTIN_REDACTION_ENV : process.env;
  const structurallyRedacted = redactAutoValue(finding, {
    maxDepth: MAX_FINDING_DEPTH,
    maxArrayItems,
    maxObjectKeys: 500,
    preserveSensitiveKeys: STRUCTURAL_KEYS_TO_PRESERVE,
    env: redactionEnv,
  });
  return sanitizeFindingNode(structurallyRedacted, {
    maxArrayItems,
    maxObjectKeys: 500,
    env: redactionEnv,
  });
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
