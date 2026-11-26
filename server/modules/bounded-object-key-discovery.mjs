import { createHash } from 'node:crypto';

export const moduleManifest = {
  id: 'bounded_object_key_discovery',
  name: 'Bounded Object Key Discovery',
  category: 'discovery',
  intrusive: false,
  requiresAuth: false,
  requiresKali: false,
  timeoutMs: 5_000,
  concurrency: 1,
  outputs: ['intel', 'metric'],
};

const MAX_INPUT_BYTES = 500_000;
const HARD_MAX_CANDIDATES = 32;
const KEY_ASSIGNMENT_RE = /["']?(?:object[_-]?key|s3[_-]?key|storage[_-]?key|file[_-]?key|download[_-]?key)["']?\s*[:=]\s*["']([^"'\r\n]{1,300})["']/gi;
const PATH_RE = /(?:^|["'\s(=])((?:[A-Za-z0-9_.-]+\/){1,8}[A-Za-z0-9_.-]{1,160}\.(?:json|txt|csv|pdf|zip|png|jpe?g|webp|xml))(?:["'\s)&,]|$)/gi;

function fingerprint(value) {
  return createHash('sha256').update(String(value)).digest('hex');
}

function normalizeObjectKey(value) {
  const text = String(value || '').trim().replace(/^\/+/, '');
  if (!text || text.length > 400 || text.includes('\0') || text.includes('..')) return '';
  if (/^[a-z][a-z0-9+.-]*:\/\//i.test(text)) return '';
  if (!/^[A-Za-z0-9_.@+\/-]+$/.test(text)) return '';
  return text;
}

export function deriveBoundedObjectKeys({
  observations = [],
  knownObjectKeys = [],
  budget = 8,
  signal = null,
} = {}) {
  const limit = Math.min(HARD_MAX_CANDIDATES, Math.max(0, Math.floor(Number(budget) || 0)));
  const knownRows = (Array.isArray(knownObjectKeys) ? knownObjectKeys : []).slice(0, 1_024);
  const observationRows = (Array.isArray(observations) ? observations : []).slice(0, 128);
  const candidates = [];
  const seen = new Set();
  const add = (raw, provenance) => {
    if (candidates.length >= limit) return;
    const key = normalizeObjectKey(raw);
    if (!key || seen.has(key)) return;
    seen.add(key);
    candidates.push({
      key,
      keyFingerprint: fingerprint(key),
      provenance,
      derived: true,
    });
  };

  for (const raw of knownRows) {
    if (signal?.aborted) throw signal.reason || new DOMException('cancelled', 'AbortError');
    add(raw, 'observed_key');
    if (candidates.length >= limit) break;
  }
  for (const observation of observationRows) {
    if (signal?.aborted) throw signal.reason || new DOMException('cancelled', 'AbortError');
    if (candidates.length >= limit) break;
    const text = String(observation?.body ?? observation?.text ?? observation ?? '').slice(0, MAX_INPUT_BYTES);
    for (const pattern of [KEY_ASSIGNMENT_RE, PATH_RE]) {
      pattern.lastIndex = 0;
      let match;
      while (candidates.length < limit && (match = pattern.exec(text)) !== null) add(match[1], 'response_or_javascript');
    }
  }
  return {
    candidates,
    metrics: {
      budget: limit,
      inputsAnalyzed: knownRows.length + observationRows.length,
      candidates: candidates.length,
      truncated: candidates.length >= limit,
      generatedByWordlist: 0,
    },
  };
}

export async function runBoundedObjectKeyDiscovery(ctx = {}) {
  const result = deriveBoundedObjectKeys(ctx);
  return {
    ...result,
    findings: [],
    status: result.metrics.inputsAnalyzed ? 'done' : 'skipped',
    reason: result.metrics.inputsAnalyzed ? undefined : 'no_observations',
  };
}
