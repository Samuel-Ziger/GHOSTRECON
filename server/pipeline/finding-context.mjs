import { createPipelineStageTracker, KALI_SUB_PIPE_STEPS } from '../modules/pipeline-stages.mjs';
import { fingerprintFinding } from '../modules/db.js';
import { captureTokenFinding } from '../modules/token-capture.js';
import { protectSecretFinding } from '../modules/secret-safety.js';
import { redactFindingForPublic } from '../modules/finding-redaction.mjs';
import { redactAutoText, redactAutoValue } from '../auto-agent/redaction.mjs';
import { inferMitreTechniqueIds } from '../modules/mitre-recon.js';
import { inferOwaspTags } from '../modules/owasp-top10.js';

/**
 * Estado partilhado do pipeline: findings, stats, emit helpers e stage tracker.
 */
export function createPipelineContext({
  domain,
  emit,
  captureTokenFindings = false,
  tokenCaptureOptions = null,
}) {
  const findings = [];
  const stats = { subs: 0, endpoints: 0, params: 0, secrets: 0, dorks: 0, high: 0 };
  const emitPublic = (event) => emit(redactAutoValue(event));

  const addFinding = (f, statKey) => {
    if (f?.type === 'secret') protectSecretFinding(f);
    const finding = redactFindingForPublic(f);
    if (!finding) return null;
    try {
      finding.fingerprint = fingerprintFinding(domain, finding);
    } catch {
      /* ignore */
    }
    if (statKey) stats[statKey] = (stats[statKey] || 0) + 1;
    findings.push(finding);
    if (finding.prio === 'high') stats.high += 1;
    emitPublic({
      type: 'finding',
      finding,
      mitreHints: inferMitreTechniqueIds(finding),
      owaspHints: inferOwaspTags(finding),
    });
    emitPublic({ type: 'stats', stats: { ...stats } });
    if (captureTokenFindings === true && finding.type === 'secret' && finding.url) {
      // O material cru, quando existe, permanece somente no Symbol
      // não-enumerável do objeto original. A fronteira pública recebe `finding`.
      captureTokenFinding(f, domain, emitPublic, {
        enabled: true,
        ...(tokenCaptureOptions || {}),
      }).catch(() => {});
    }
    return finding;
  };

  const log = (msg, level = 'info') => emitPublic({
    type: 'log',
    msg: redactAutoText(msg),
    level,
  });
  const stageTracker = createPipelineStageTracker(emitPublic);
  const pipe = (name, state) => stageTracker.pipe(name, state);
  const skipKaliSubPipe = () => stageTracker.skipMany(KALI_SUB_PIPE_STEPS);
  const progress = (p) => stageTracker.progress(p);

  return {
    emit: emitPublic,
    findings,
    stats,
    addFinding,
    log,
    pipe,
    skipKaliSubPipe,
    progress,
    stageTracker,
  };
}
