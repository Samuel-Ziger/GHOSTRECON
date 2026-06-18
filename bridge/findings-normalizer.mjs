import { sevToPrio, sevToScore } from '../server/lib/severity.mjs';

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
  return Object.keys(evidence).length ? evidence : undefined;
}

/**
 * Converte uma linha JSONL do Vigolium (ResultEvent / Nuclei-compatible) para finding GHOSTRECON.
 * @param {object} row
 * @returns {object|null}
 */
export function vigoliumRowToFinding(row) {
  if (!row || typeof row !== 'object') return null;

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

  return {
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
  };
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
export function parseVigoliumJsonl(text) {
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
        const f = vigoliumRowToFinding(nested) || auditRowToFinding({
          ...nested,
          agentic_scan_uuid: row.agentic_scan_uuid,
          session_dir: row.session_dir,
        });
        if (f) findings.push(f);
      }
      continue;
    }
    if (row?.type === 'finding' || row?.data?.title) {
      const auditF = auditRowToFinding(row.data || row);
      if (auditF) findings.push(auditF);
      continue;
    }
    if (row?.type && row.type !== 'http' && row.type !== 'finding' && !row['template-id']) {
      continue;
    }
    const f = vigoliumRowToFinding(row) || auditRowToFinding(row);
    if (f) findings.push(f);
  }
  return findings;
}

/**
 * Findings do vigolium-audit / agent (schema mais livre).
 */
export function auditRowToFinding(row) {
  if (!row || typeof row !== 'object') return null;
  const title = String(row.title || row.name || row.summary || row.id || '').trim();
  if (!title) return null;
  const severity = String(row.severity || row.priority || 'medium').toLowerCase();
  const file = String(row.file || row.path || row.location || '').trim();
  const description = String(row.description || row.detail || row.rationale || '').trim();

  return {
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
  };
}
