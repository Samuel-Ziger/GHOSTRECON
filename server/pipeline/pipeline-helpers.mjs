import fs from 'fs';
import { redactFindingsForPublic } from '../modules/finding-redaction.mjs';
import { redactAutoValue } from '../auto-agent/redaction.mjs';

export function aiAutoReportsServerAllowed() {
  const v = String(process.env.GHOSTRECON_AI_AUTO ?? '1').trim().toLowerCase();
  return v !== '0' && v !== 'false' && v !== 'no';
}

/** Mesmo formato que `buildPipelineExportPayload()` na UI — para `runDualAiReports`. */
export function emitIaProximosPassosToLog(aiOut, log) {
  if (!aiOut || typeof log !== 'function') return;
  const parts = [];
  const order = Array.isArray(aiOut._reportCascadeOrder)
    ? aiOut._reportCascadeOrder
    : ['gemini', 'openrouter', 'claude', 'lmstudio'];
  const labels = {
    gemini: 'Gemini — próximos passos',
    openrouter: 'OpenRouter — próximos passos',
    claude: 'Claude (Anthropic) — próximos passos',
    lmstudio: 'LM Studio (local) — próximos passos',
  };
  for (const key of order) {
    const b = aiOut[key];
    if (b?.ok && b.proximosPath && labels[key]) parts.push({ label: labels[key], path: b.proximosPath });
  }
  if (!parts.length) return;
  log('═══ DECISÃO / PRÓXIMOS PASSOS (IA) ═══', 'section');
  for (const { label, path: fpath } of parts) {
    log(`── ${label} ──`, 'section');
    try {
      const text = fs.readFileSync(fpath, 'utf8');
      for (const line of text.split('\n')) {
        const t = line.replace(/\r$/, '');
        if (t.trim() === '') log(' ', 'info');
        else if (t.length > 2400) log(`${t.slice(0, 2400)}…`, 'info');
        else log(t, 'info');
      }
    } catch (e) {
      log(`Não foi possível ler ${fpath}: ${e.message}`, 'warn');
    }
  }
  log('═══ Fim decisão IA — pode seguir para o próximo alvo ═══', 'section');
}

export function buildPipelineExportPayloadForAi({
  target,
  projectName,
  stats,
  findings,
  correlation,
  reportTemplates,
  runId,
  storage,
  intelMerge,
  kaliMode,
  modules,
  bountyContext = null,
  auth = null,
}) {
  const findingsExport = redactFindingsForPublic(findings).map((f) => {
    const ev = f.verification;
    let verificationOut;
    if (ev && typeof ev === 'object') {
      const rsp = ev.evidence?.responseSnippet;
      const req = ev.evidence?.requestSnippet;
      verificationOut = {
        classification: ev.classification,
        confidenceScore: ev.confidenceScore,
        verifiedAt: ev.verifiedAt,
        evidenceHash: ev.evidence?.evidenceHash,
        responseSnippetPreview: typeof rsp === 'string' ? rsp.slice(0, 2000) : undefined,
        requestSnippetPreview: typeof req === 'string' ? req.slice(0, 900) : undefined,
      };
    }
    return {
      type: f.type,
      priority: f.prio,
      score: f.score || 0,
      value: f.value,
      meta: f.meta || '',
      url: f.url || '',
      fingerprint: f.fingerprint || '',
      compositeScore: f.compositeScore,
      attackTier: f.attackTier,
      priorityWhy: f.priorityWhy,
      bountyProbability: f.bountyProbability,
      provenance: f.provenance && (f.provenance.how || f.provenance.relation) ? { ...f.provenance } : undefined,
      verification: verificationOut,
      owasp: Array.isArray(f.owasp) && f.owasp.length ? f.owasp : undefined,
      mitre: Array.isArray(f.mitre) && f.mitre.length ? f.mitre : undefined,
    };
  });
  return {
    schemaVersion: 1,
    source: 'ghostrecon-server-pipeline',
    exportedAt: new Date().toISOString(),
    projectName: projectName || undefined,
    target,
    stats: { ...stats },
    findings: findingsExport,
    correlation,
    reportTemplates: redactAutoValue(reportTemplates),
    runId,
    storage,
    intelMerge,
    kaliMode,
    modules,
    bountyContext: bountyContext || undefined,
    authProfile:
      auth && (auth.cookie || (auth.headers && Object.keys(auth.headers).length))
        ? {
            hasCookie: Boolean(auth.cookie),
            headerKeys: auth.headers ? Object.keys(auth.headers).slice(0, 24) : [],
          }
        : undefined,
  };
}
