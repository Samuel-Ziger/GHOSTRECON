import { createPipelineStageTracker, KALI_SUB_PIPE_STEPS } from '../modules/pipeline-stages.mjs';
import { fingerprintFinding } from '../modules/db.js';
import { captureTokenFinding } from '../modules/token-capture.js';
import { inferMitreTechniqueIds } from '../modules/mitre-recon.js';
import { inferOwaspTags } from '../modules/owasp-top10.js';

/**
 * Estado partilhado do pipeline: findings, stats, emit helpers e stage tracker.
 */
export function createPipelineContext({ domain, emit }) {
  const findings = [];
  const stats = { subs: 0, endpoints: 0, params: 0, secrets: 0, dorks: 0, high: 0 };

  const addFinding = (f, statKey) => {
    try {
      f.fingerprint = fingerprintFinding(domain, f);
    } catch {
      /* ignore */
    }
    if (statKey) stats[statKey] = (stats[statKey] || 0) + 1;
    findings.push(f);
    if (f.prio === 'high') stats.high += 1;
    emit({
      type: 'finding',
      finding: f,
      mitreHints: inferMitreTechniqueIds(f),
      owaspHints: inferOwaspTags(f),
    });
    emit({ type: 'stats', stats: { ...stats } });
    if (f.type === 'secret' && f.url) {
      captureTokenFinding(f, domain, emit).catch(() => {});
    }
  };

  const log = (msg, level = 'info') => emit({ type: 'log', msg, level });
  const stageTracker = createPipelineStageTracker(emit);
  const pipe = (name, state) => stageTracker.pipe(name, state);
  const skipKaliSubPipe = () => stageTracker.skipMany(KALI_SUB_PIPE_STEPS);
  const progress = (p) => stageTracker.progress(p);

  return {
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
