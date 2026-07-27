/**
 * Serialização de findings para persistência (runs.findings_json) e export.
 * Corta campos pesados para caber no limite de bytes.
 */
import { redactFindingForPublic } from './finding-redaction.mjs';

const DEFAULT_MAX_BYTES = 8_000_000;

function truncateStr(s, max) {
  const t = String(s ?? '');
  if (t.length <= max) return t;
  return `${t.slice(0, max)}…[truncated ${t.length - max} chars]`;
}

function slimEvidence(ev, maxSnippet = 4000) {
  if (!ev || typeof ev !== 'object') return ev;
  const o = { ...ev };
  if (typeof o.responseSnippet === 'string') o.responseSnippet = truncateStr(o.responseSnippet, maxSnippet);
  if (typeof o.requestSnippet === 'string') o.requestSnippet = truncateStr(o.requestSnippet, 2000);
  if (Array.isArray(o.decodedExtractions)) {
    o.decodedExtractions = o.decodedExtractions.slice(0, 5).map((d) => ({
      encoding: d.encoding,
      rawSample: truncateStr(d.rawSample, 96),
      decodedUtf8: truncateStr(d.decodedUtf8, 3500),
      decodedBytes: d.decodedBytes,
    }));
  }
  return o;
}

function cloneFindingForSnapshot(f) {
  if (!f || typeof f !== 'object') return f;
  const safe = redactFindingForPublic(f);
  if (!safe) return null;
  const o = {
    type: safe.type,
    prio: safe.prio,
    score: safe.score,
    value: typeof safe.value === 'string' ? truncateStr(safe.value, 24_000) : safe.value,
    meta: typeof safe.meta === 'string' ? truncateStr(safe.meta, 24_000) : safe.meta,
    url: safe.url,
    fingerprint: safe.fingerprint,
    compositeScore: safe.compositeScore,
    attackTier: safe.attackTier,
    bountyProbability: safe.bountyProbability,
    priorityWhy: Array.isArray(safe.priorityWhy) ? safe.priorityWhy.slice(0, 80) : safe.priorityWhy,
    risk: safe.risk,
    provenance: safe.provenance,
    owasp: Array.isArray(safe.owasp) ? safe.owasp : undefined,
    mitre: Array.isArray(safe.mitre) ? safe.mitre : undefined,
  };
  if (safe.verification) {
    o.verification = {
      classification: safe.verification.classification,
      confidenceScore: safe.verification.confidenceScore,
      verifiedAt: safe.verification.verifiedAt,
      evidence: safe.verification.evidence ? slimEvidence(safe.verification.evidence) : undefined,
    };
  }
  return o;
}

/**
 * @param {object[]} findings
 * @param {number} [maxBytes]
 * @returns {string|null} JSON string ou null se vazio
 */
export function serializeFindingsForRunSnapshot(findings, maxBytes = DEFAULT_MAX_BYTES) {
  const lim = Number(process.env.GHOSTRECON_FINDINGS_SNAPSHOT_MAX_BYTES || maxBytes);
  const list = (findings || []).map(cloneFindingForSnapshot).filter(Boolean);
  let payload = {
    schemaVersion: 1,
    savedAt: new Date().toISOString(),
    count: list.length,
    findings: list,
    truncated: false,
    droppedTail: 0,
  };
  let json = JSON.stringify(payload);
  let guard = 0;
  while (Buffer.byteLength(json, 'utf8') > lim && payload.findings.length > 20 && guard < 40) {
    guard += 1;
    const drop = Math.max(1, Math.floor(payload.findings.length * 0.08));
    payload.findings = payload.findings.slice(0, payload.findings.length - drop);
    payload.count = payload.findings.length;
    payload.truncated = true;
    payload.droppedTail += drop;
    json = JSON.stringify(payload);
  }
  if (Buffer.byteLength(json, 'utf8') > lim) {
    payload = {
      schemaVersion: 1,
      savedAt: payload.savedAt,
      truncated: true,
      error: 'snapshot_exceeds_max_bytes_after_trim',
      count: 0,
      findings: [],
    };
    json = JSON.stringify(payload);
  }
  return json;
}

export function parseFindingsSnapshotJson(text) {
  if (!text || typeof text !== 'string') return null;
  try {
    const p = JSON.parse(text);
    if (Array.isArray(p)) return p;
    if (Array.isArray(p.findings)) return p.findings;
    return null;
  } catch {
    return null;
  }
}
