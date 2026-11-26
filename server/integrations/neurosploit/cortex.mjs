import crypto from 'node:crypto';
import { createBrainCategory, upsertBrainLink, upsertManualValidation } from '../../modules/db.js';
import { redactAutoValue } from '../../auto-agent/redaction.mjs';

const TITLE = 'NeuroSploit';
const DESCRIPTION = 'Achados validados pelo motor NeuroSploit, com evidência e proveniência do engagement preservadas.';

function targetHost(raw) {
  try { return new URL(/^https?:\/\//i.test(raw) ? raw : `https://${raw}`).hostname.toLowerCase(); }
  catch { return String(raw || '').trim().toLowerCase(); }
}

function text(value, max = 8_000) { return String(value ?? '').replace(/\0/g, '').slice(0, max); }

function fingerprint(target, finding) {
  return crypto.createHash('sha256').update(JSON.stringify({
    source: 'neurosploit', target, id: finding.id || '', cwe: finding.cwe || '',
    title: finding.title || '', endpoint: finding.endpoint || '',
  })).digest('hex');
}

export async function syncNeuroSploitFindingsToCortex({ job, findings = [] } = {}) {
  const target = targetHost(job?.target);
  if (!target || !/^[a-z0-9][a-z0-9.:-]*[a-z0-9]$/.test(target)) {
    return { ok: true, skipped: 'target_not_cortex_compatible', imported: 0 };
  }
  const category = await createBrainCategory(TITLE, DESCRIPTION);
  const items = [];
  for (const raw of Array.isArray(findings) ? findings : []) {
    if (!raw || typeof raw !== 'object') continue;
    const finding = redactAutoValue(raw);
    const status = text(finding.review_status || (finding.validated ? 'confirmed' : 'needs-review'), 40).toLowerCase();
    const fp = fingerprint(target, finding);
    const snapshot = {
      source: 'neurosploit',
      integration: 'ghostia',
      jobId: text(job.id, 80),
      runId: text(job.runId, 160),
      engagementId: text(job.engagementId, 120),
      profileId: Number(job.profileId) || null,
      model: text(job.model, 300),
      findingId: text(finding.id, 160),
      agent: text(finding.agent, 160),
      triageStatus: status,
      humanValidated: false,
      importedCandidate: status !== 'confirmed',
      validatedByEngine: finding.validated === true,
      confidence: Number(finding.confidence) || 0,
      votes: text(finding.votes, 120),
      type: text(finding.cwe || 'neurosploit-finding', 120),
      prio: text(finding.severity || 'unknown', 30),
      value: text(finding.title, 2_000),
      meta: text([finding.location, finding.impact, finding.remediation].filter(Boolean).join('\n'), 8_000),
      evidence: text(finding.evidence, 12_000),
      url: text(finding.endpoint, 1_000),
      owasp: text(finding.owasp, 120),
      mitre: text(finding.mitre, 120),
      observedAt: finding.observed_at ? new Date(Number(finding.observed_at) * 1_000).toISOString() : new Date().toISOString(),
    };
    const notes = snapshot.validatedByEngine
      ? 'Importado do NeuroSploit após validação do motor; a confirmação humana continua separada.'
      : 'Candidato do NeuroSploit pendente de revisão humana.';
    await upsertManualValidation({ target, fingerprint: fp, snapshot, notes });
    await upsertBrainLink({ target, fingerprint: fp, categoryId: category.id });
    items.push({ fingerprint: fp, findingId: snapshot.findingId, status });
  }
  return { ok: true, target, category, imported: items.length, items };
}
