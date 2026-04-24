/**
 * Diff engine — pós-processamento sobre o resultado de compareRuns().
 *
 * Responsabilidades (sem tocar em compareRuns nem no DB):
 *   - contagem por severidade
 *   - extração de "new hosts" entre baseline e newer
 *   - filtro por severidade mínima
 *   - seleção de "notable added" (prioritiza high, depois novidade de host/URL)
 *   - fingerprint estável para alerta new-only (hash SHA-1 curto)
 *
 * Usado por:
 *   - ghostrecon diff (CLI)
 *   - ghostrecon schedule (scheduler new-only alert)
 *   - /api/recon/diff-summary (opcional, via main server)
 */

import crypto from 'node:crypto';

const SEVERITY_ORDER = { info: 0, low: 1, medium: 2, high: 3, critical: 4 };

function sev(s) {
  return SEVERITY_ORDER[String(s || '').toLowerCase()] ?? 0;
}

export function normalizeSeverity(s) {
  const x = String(s || '').toLowerCase();
  if (!x) return 'info';
  if (x === 'crit') return 'critical';
  return x;
}

/**
 * `diff` = saída de compareRuns — { added:[], removed:[], target, baselineId, newerId, ... }
 * opts   = { minSeverity, onlyNew }
 */
export function summarizeDiff(diff, { minSeverity = 'low', onlyNew = false } = {}) {
  const added = Array.isArray(diff.added) ? diff.added : [];
  const removed = Array.isArray(diff.removed) ? diff.removed : [];
  const floor = sev(minSeverity);

  const addedFiltered = added.filter((f) => sev(f.severity) >= floor);
  const removedFiltered = removed.filter((f) => sev(f.severity) >= floor);

  const addedBySeverity = countBy(addedFiltered, (f) => normalizeSeverity(f.severity));
  const removedBySeverity = countBy(removedFiltered, (f) => normalizeSeverity(f.severity));

  const hostsBaseline = extractHostsFromFindings(removed.concat(added).filter((f) => !addedFiltered.includes(f)));
  const hostsNewer = extractHostsFromFindings(added);
  const newHosts = [...hostsNewer].filter((h) => !hostsBaseline.has(h)).sort();

  const notableAdded = addedFiltered
    .slice()
    .sort((a, b) => sev(b.severity) - sev(a.severity))
    .slice(0, 30);

  const fingerprint = computeDiffFingerprint(diff.target, addedFiltered);

  return {
    target: diff.target,
    baselineId: diff.baselineId,
    newerId: diff.newerId,
    addedCount: addedFiltered.length,
    removedCount: removedFiltered.length,
    totalAdded: added.length,
    totalRemoved: removed.length,
    addedBySeverity,
    removedBySeverity,
    newHosts,
    notableAdded,
    minSeverity,
    onlyNew,
    fingerprint,
  };
}

/**
 * True quando o diff traz algo que *merece* alertar.
 * Regras:
 *  - onlyNew → só alerta se houver ≥1 finding com severity ≥ minSeverity E fingerprint novo.
 *  - Caso contrário → alerta se addedCount > 0 OU newHosts > 0.
 */
export function shouldAlert(summary, { seenFingerprints = new Set() } = {}) {
  if (!summary) return false;
  if (summary.onlyNew) {
    if (seenFingerprints.has(summary.fingerprint)) return false;
    return summary.addedCount > 0 || summary.newHosts.length > 0;
  }
  return summary.addedCount > 0 || summary.newHosts.length > 0;
}

function countBy(arr, keyFn) {
  const out = {};
  for (const item of arr) {
    const k = keyFn(item);
    out[k] = (out[k] || 0) + 1;
  }
  return out;
}

function extractHostsFromFindings(findings) {
  const out = new Set();
  for (const f of findings || []) {
    const targets = [
      f?.evidence?.target,
      f?.evidence?.host,
      f?.evidence?.url,
      f?.host,
      f?.url,
      f?.target,
    ];
    for (const t of targets) {
      if (!t) continue;
      const host = extractHost(String(t));
      if (host) out.add(host);
    }
  }
  return out;
}

function extractHost(s) {
  try {
    if (s.includes('://')) return new URL(s).hostname.toLowerCase();
    return s.split('/')[0].split(':')[0].trim().toLowerCase();
  } catch {
    return null;
  }
}

function computeDiffFingerprint(target, addedFindings) {
  const parts = [String(target || '')];
  for (const f of addedFindings) {
    parts.push(
      [
        normalizeSeverity(f.severity),
        f.category || f.type || '',
        f.title || '',
        f.evidence?.target || f.url || f.host || '',
      ].join('|'),
    );
  }
  parts.sort();
  return crypto.createHash('sha1').update(parts.join('\n')).digest('hex').slice(0, 16);
}
