import crypto from 'node:crypto';
import {
  createBrainCategory,
  upsertBrainLink,
  upsertManualValidation,
} from '../../modules/db.js';

const CATEGORY_TITLE = 'Artex / GhostIA';
const CATEGORY_DESCRIPTION = 'Achados importados automaticamente do backend Artex. O estado original de triagem é preservado; confirme a evidência antes de reportar.';

function targetHost(raw) {
  const value = String(raw || '').trim().toLowerCase();
  if (!value) return '';
  try {
    const parsed = new URL(/^https?:\/\//i.test(value) ? value : `https://${value}`);
    return parsed.hostname.replace(/^\[|\]$/g, '');
  } catch {
    return value.split('/')[0].split(':')[0];
  }
}

function safeText(value, max = 8_000) {
  return String(value ?? '').replace(/\0/g, '').slice(0, max);
}

function findingFingerprint(target, finding) {
  return crypto.createHash('sha256').update(JSON.stringify({
    source: 'artex',
    target,
    id: finding?.finding_id || finding?.id || '',
    class: finding?.vulnclass || '',
    name: finding?.name || '',
    summary: finding?.summary || '',
  })).digest('hex');
}

export async function syncArtexFindingsToCortex({ target, taskId, findings = [] } = {}) {
  const normalizedTarget = targetHost(target);
  if (!/^[a-z0-9][a-z0-9.-]*[a-z0-9]$/.test(normalizedTarget)) {
    throw new Error('alvo Artex não pode ser normalizado para o Cortex');
  }
  const category = await createBrainCategory(CATEGORY_TITLE, CATEGORY_DESCRIPTION);
  const results = [];
  for (const finding of Array.isArray(findings) ? findings : []) {
    if (!finding || typeof finding !== 'object') continue;
    const fingerprint = findingFingerprint(normalizedTarget, finding);
    const status = safeText(finding.status || 'pending', 40).toLowerCase();
    const snapshot = {
      source: 'artex',
      integration: 'ghostia',
      taskId: safeText(taskId, 80),
      artexFindingId: safeText(finding.finding_id || finding.id, 80),
      triageStatus: status,
      humanValidated: false,
      importedCandidate: !['confirmed', 'resolved', 'fixed'].includes(status),
      type: safeText(finding.vulnclass || 'artex-finding', 120),
      prio: safeText(finding.severity || 'unknown', 30),
      value: safeText(finding.name || finding.summary || finding.vulnclass, 2_000),
      meta: safeText(finding.summary, 4_000),
      evidence: safeText(finding.evidence, 12_000),
      url: safeText(finding.url || '', 1_000),
      observedAt: finding.ts || new Date().toISOString(),
    };
    const notes = [
      `Importado automaticamente do Artex/GhostIA; triagem Artex: ${status}.`,
      snapshot.importedCandidate
        ? 'Candidato pendente: valide a evidência antes de usar em relatório.'
        : 'O Artex marcou este achado como confirmado/resolvido; a validação humana continua recomendada.',
    ].join(' ');
    await upsertManualValidation({ target: normalizedTarget, fingerprint, snapshot, notes });
    await upsertBrainLink({ target: normalizedTarget, fingerprint, categoryId: category.id });
    results.push({ fingerprint, status, artexFindingId: snapshot.artexFindingId });
  }
  return { ok: true, target: normalizedTarget, taskId: String(taskId || ''), category, imported: results.length, items: results };
}
