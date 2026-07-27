import { sevToPrio, sevToScore } from '../server/lib/severity.mjs';
import {
  redactFindingForPublic,
  redactLocalPathsForPublic,
} from '../server/modules/finding-redaction.mjs';
import { redactAutoValue } from '../server/auto-agent/redaction.mjs';

const MAX_EXTERNAL_DEPTH = 12;
const MAX_EXTERNAL_ITEMS = 500;
const EXTERNAL_PATH_KEYS_TO_PRESERVE = new Set([
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
const ALWAYS_PRIVATE_EXTERNAL_PATH_KEYS = new Set([
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

function isAbsoluteLocalPath(value) {
  const text = String(value ?? '').trim();
  return (
    text.startsWith('/')
    || /^[A-Za-z]:[\\/]/.test(text)
    || /^\\\\[^\\]/.test(text)
  );
}

function exactRedactValue(value, redact, depth = 0, seen = new WeakSet(), key = '') {
  if (value == null || typeof value === 'boolean' || typeof value === 'number') return value;
  if (typeof value === 'bigint') return String(value);
  if (typeof value === 'string') {
    const redacted = typeof redact === 'function' ? redact(value) : value;
    const normalizedKey = String(key).toLowerCase().replace(/[^a-z0-9]/g, '');
    if (
      /^(?:file|filepath|metadatapath|repopath|path|location|localpath|reportpath|sessiondir|sourcedir|outputdir|root|dir|directory|binary|source|error|reason|message)$/i
        .test(normalizedKey)
    ) {
      if (ALWAYS_PRIVATE_EXTERNAL_PATH_KEYS.has(normalizedKey) && redacted.trim()) {
        return '[LOCAL_PATH]';
      }
      return isAbsoluteLocalPath(redacted)
        ? '[LOCAL_PATH]'
        : redactLocalPathsForPublic(redacted);
    }
    return redacted;
  }
  if (typeof value !== 'object') return String(value);
  if (depth >= MAX_EXTERNAL_DEPTH) return '[TRUNCATED_DEPTH]';
  if (seen.has(value)) return '[CIRCULAR]';
  seen.add(value);
  try {
    if (Array.isArray(value)) {
      return value
        .slice(0, MAX_EXTERNAL_ITEMS)
        .map((item) => exactRedactValue(item, redact, depth + 1, seen, key));
    }
    const out = {};
    for (const [key, item] of Object.entries(value).slice(0, MAX_EXTERNAL_ITEMS)) {
      out[key] = exactRedactValue(item, redact, depth + 1, seen, key);
    }
    return out;
  } finally {
    seen.delete(value);
  }
}

/**
 * Fronteira para qualquer JSON emitido pelo processo externo. O redactor do
 * transporte conhece os valores exatos da sessão autenticada; a segunda
 * camada remove padrões sensíveis mesmo quando não pertencem à sessão.
 */
export function redactVigoliumExternalValue(value, { redact } = {}) {
  return redactAutoValue(exactRedactValue(value, redact), {
    preserveSensitiveKeys: EXTERNAL_PATH_KEYS_TO_PRESERVE,
  });
}

function compactJson(value, max = 900) {
  if (value == null) return '';
  try {
    const text = typeof value === 'string' ? value : JSON.stringify(value);
    return text.length > max ? `${text.slice(0, max)}...` : text;
  } catch {
    return String(value).slice(0, max);
  }
}

function firstString(...values) {
  for (const v of values) {
    if (v == null) continue;
    const text = String(v).trim();
    if (text) return text;
  }
  return '';
}

function evidenceFromRow(row) {
  const evidence = {};
  const matched = firstString(row['matched-at'], row.matchedAt, row.matched);
  if (matched) evidence.matchedAt = matched;
  if (row['fuzzing_parameter']) evidence.param = String(row['fuzzing_parameter']);
  if (row['extracted-results']) evidence.extractedResults = compactJson(row['extracted-results'], 1200);
  if (row.extracted_results) evidence.extractedResults = compactJson(row.extracted_results, 1200);
  if (row.request) evidence.request = compactJson(row.request, 4000);
  if (row.response) evidence.response = compactJson(row.response, 4000);
  if (row['curl-command']) evidence.curl = String(row['curl-command']).slice(0, 2000);
  if (!Object.keys(evidence).length) return undefined;
  return redactFindingForPublic({ evidence })?.evidence;
}

/**
 * Converte uma linha JSONL do Vigolium (ResultEvent / Nuclei-compatible) para finding GHOSTRECON.
 * @param {object} row
 * @returns {object|null}
 */
export function vigoliumRowToFinding(row, options = {}) {
  if (!row || typeof row !== 'object') return null;
  row = redactVigoliumExternalValue(row, options);

  const rawModuleId = firstString(row['template-id'], row.templateId, row.module_id, row.moduleId);
  const hasDastShape = Boolean(rawModuleId || row.info || row.url || row.matched || row.host || row['matched-at'] || row.matchedAt);
  if (!hasDastShape) return null;
  const moduleId = rawModuleId || 'vigolium';
  const info = row.info && typeof row.info === 'object' ? row.info : {};
  const name = firstString(info.name, row.module_name, moduleId);
  const severity = String(info.severity || row.severity || 'info').toLowerCase();
  const confidence = String(info.confidence || '').toLowerCase();
  const url = firstString(row.url, row.host);
  const matched = firstString(row['matched-at'], row.matchedAt, row.matched);
  const description = String(info.description || '').trim();
  const tags = Array.isArray(info.tags) ? info.tags.join(',') : '';
  const evidence = evidenceFromRow(row);

  const metaParts = [
    `source=vigolium:${moduleId}`,
    confidence ? `confidence=${confidence}` : '',
    tags ? `tags=${tags}` : '',
    row['fuzzing_parameter'] ? `param=${row['fuzzing_parameter']}` : '',
    evidence ? `evidence=${compactJson(evidence)}` : '',
    row.error ? `error=${String(row.error).slice(0, 200)}` : '',
  ].filter(Boolean);

  const value = matched || name || moduleId;
  const displayUrl = url || (matched && /^https?:\/\//i.test(matched) ? matched : '');

  return redactFindingForPublic({
    type: 'vuln',
    prio: sevToPrio(severity),
    score: sevToScore(severity),
    value: value.slice(0, 500),
    meta: metaParts.join(' • ') + (description ? ` • ${description.slice(0, 280)}` : ''),
    url: displayUrl || undefined,
    owasp: inferOwaspFromTags(tags, moduleId),
    sourceEngine: 'vigolium',
    moduleId,
    moduleName: name,
    confidence: confidence || undefined,
    evidence,
  });
}

function inferOwaspFromTags(tags, moduleId) {
  const hay = `${tags} ${moduleId}`.toLowerCase();
  if (/xss|injection|sqli|ssti|xxe|lfi|rce|command/.test(hay)) return 'A03:2021';
  if (/auth|idor|bola|access/.test(hay)) return 'A01:2021';
  if (/misconfig|header|csp/.test(hay)) return 'A05:2021';
  if (/secret|credential/.test(hay)) return 'A07:2021';
  return undefined;
}

/**
 * @param {string} text — conteúdo JSONL (uma linha = um evento)
 * @returns {object[]}
 */
export function parseVigoliumJsonl(text, options = {}) {
  const findings = [];
  const lines = String(text || '').split(/\r?\n/);
  for (const line of lines) {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith('//')) continue;
    let row;
    try {
      row = JSON.parse(trimmed);
    } catch {
      continue;
    }
    const nestedFindings = Array.isArray(row?.findings)
      ? row.findings
      : Array.isArray(row?.top_findings)
        ? row.top_findings
        : null;
    if (nestedFindings) {
      for (const nested of nestedFindings) {
        const f = vigoliumRowToFinding(nested, options) || auditRowToFinding({
          ...nested,
          agentic_scan_uuid: row.agentic_scan_uuid,
          session_dir: row.session_dir,
        }, options);
        if (f) findings.push(f);
      }
      continue;
    }
    if (row?.type === 'finding' || row?.data?.title) {
      const auditF = auditRowToFinding(row.data || row, options);
      if (auditF) findings.push(auditF);
      continue;
    }
    if (row?.type && row.type !== 'http' && row.type !== 'finding' && !row['template-id']) {
      continue;
    }
    const f = vigoliumRowToFinding(row, options) || auditRowToFinding(row, options);
    if (f) findings.push(f);
  }
  return findings;
}

/**
 * Findings do vigolium-audit / agent (schema mais livre).
 */
export function auditRowToFinding(row, options = {}) {
  if (!row || typeof row !== 'object') return null;
  row = redactVigoliumExternalValue(row, options);
  const title = String(row.title || row.name || row.summary || row.id || '').trim();
  if (!title) return null;
  const severity = String(row.severity || row.priority || 'medium').toLowerCase();
  const file = String(row.file || row.path || row.location || '').trim();
  const description = String(row.description || row.detail || row.rationale || '').trim();

  return redactFindingForPublic({
    type: 'code_audit',
    prio: sevToPrio(severity),
    score: sevToScore(severity),
    value: title.slice(0, 500),
    meta: [
      'source=vigolium:audit',
      file ? `file=${file}` : '',
      row.confidence ? `confidence=${row.confidence}` : '',
    ]
      .filter(Boolean)
      .join(' • ') + (description ? ` • ${description.slice(0, 280)}` : ''),
    url: file || undefined,
    owasp: 'A04:2021',
    sourceEngine: 'vigolium',
    moduleId: 'audit',
    moduleName: 'Vigolium code audit',
    confidence: row.confidence ? String(row.confidence) : undefined,
    evidence: {
      file: file || undefined,
      description: description || undefined,
      raw: compactJson(row, 1200),
    },
  });
}
