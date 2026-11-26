import crypto from 'node:crypto';
import { createBrainCategory, upsertBrainLink, upsertManualValidation } from '../../modules/db.js';
import { redactAutoValue } from '../../auto-agent/redaction.mjs';

const TITLE = 'Mind Skills';
const DESCRIPTION = 'Candidatos produzidos por skills nativas do Mind via Codex/HackBot. Exigem revisão humana antes de qualquer submissão.';

function text(value, max = 8_000) {
  return String(value ?? '').replace(/\0/g, '').slice(0, max);
}

function targetHost(raw) {
  try { return new URL(/^https?:\/\//i.test(raw) ? raw : `https://${raw}`).hostname.toLowerCase(); }
  catch { return String(raw || '').trim().toLowerCase(); }
}

function fingerprint(target, skill, finding) {
  return crypto.createHash('sha256').update(JSON.stringify({
    source: 'mind-skills', target, skill, type: finding.type || finding.cwe || '',
    title: finding.title || finding.value || '', url: finding.url || '',
  })).digest('hex');
}

export async function syncMindResultToCortex({ target, conversationId, plan, result } = {}) {
  const normalizedTarget = targetHost(target);
  if (!normalizedTarget || !/^[a-z0-9][a-z0-9.:-]*[a-z0-9]$/.test(normalizedTarget)) {
    return { ok: true, skipped: 'target_not_cortex_compatible', imported: 0 };
  }
  const safeResult = redactAutoValue(result && typeof result === 'object' ? result : {});
  const findings = Array.isArray(safeResult.findings) ? safeResult.findings : [];
  if (!findings.length) return { ok: true, skipped: 'no_normalized_findings', imported: 0 };
  const category = await createBrainCategory(TITLE, DESCRIPTION);
  const items = [];
  for (const raw of findings.slice(0, 100)) {
    if (!raw || typeof raw !== 'object') continue;
    const skill = text(raw.skill || plan?.skills?.[0] || 'mind', 80);
    const fp = fingerprint(normalizedTarget, skill, raw);
    const snapshot = {
      source: 'mind-skills',
      integration: 'hackbot-codex',
      conversationId: text(conversationId, 80),
      engagementId: text(plan?.engagementId, 120),
      skills: Array.isArray(plan?.skills) ? plan.skills.slice(0, 6) : [],
      skill,
      triageStatus: text(raw.status || 'needs-review', 40).toLowerCase(),
      humanValidated: false,
      importedCandidate: true,
      confidence: Math.max(0, Math.min(1, Number(raw.confidence) || 0)),
      type: text(raw.type || raw.cwe || 'mind-candidate', 120),
      prio: text(raw.severity || raw.prio || 'unknown', 30),
      value: text(raw.title || raw.value || raw.summary, 2_000),
      meta: text([raw.summary, raw.impact, raw.remediation].filter(Boolean).join('\n'), 8_000),
      evidence: text(raw.evidence, 12_000),
      url: text(raw.url || raw.endpoint, 1_000),
      observedAt: new Date().toISOString(),
    };
    await upsertManualValidation({
      target: normalizedTarget,
      fingerprint: fp,
      snapshot,
      notes: 'Candidato importado de uma skill do Mind; valide escopo, reprodução, contraprova e impacto antes de reportar.',
    });
    await upsertBrainLink({ target: normalizedTarget, fingerprint: fp, categoryId: category.id });
    items.push({ fingerprint: fp, skill, status: snapshot.triageStatus });
  }
  return { ok: true, target: normalizedTarget, category, imported: items.length, items };
}
