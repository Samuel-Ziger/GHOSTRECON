import { sevToPrio, sevToScore } from '../server/lib/severity.mjs';

/**
 * Converte uma linha JSONL do Vigolium (ResultEvent / Nuclei-compatible) para finding GHOSTRECON.
 * @param {object} row
 * @returns {object|null}
 */
export function vigoliumRowToFinding(row) {
  if (!row || typeof row !== 'object') return null;

  const moduleId = String(row['template-id'] || row.templateId || row.module_id || 'vigolium').trim();
  const info = row.info && typeof row.info === 'object' ? row.info : {};
  const name = String(info.name || moduleId).trim();
  const severity = String(info.severity || row.severity || 'info').toLowerCase();
  const confidence = String(info.confidence || '').toLowerCase();
  const url = String(row.url || row.matched || row.host || '').trim();
  const matched = String(row['matched-at'] || row.matchedAt || '').trim();
  const description = String(info.description || '').trim();
  const tags = Array.isArray(info.tags) ? info.tags.join(',') : '';

  const metaParts = [
    `source=vigolium:${moduleId}`,
    confidence ? `confidence=${confidence}` : '',
    tags ? `tags=${tags}` : '',
    row['fuzzing_parameter'] ? `param=${row['fuzzing_parameter']}` : '',
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
  };
}
