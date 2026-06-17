import { createPipelineState } from './pipeline-state.mjs';
import { runInputPhase } from './phases/input.mjs';
import { runFingerprintPhase } from './phases/fingerprint.mjs';
import { runDiscoveryPhase } from './phases/discovery.mjs';
import { runProbePhase } from './phases/probe.mjs';
import { runContentDiscoveryPhase } from './phases/content-discovery.mjs';
import { runGoEnginePhase } from './phases/go-engine.mjs';
import { runGoAgentPhase } from './phases/go-agent.mjs';
import { runValidationPhase } from './phases/validation.mjs';
import { runAggressivePhase } from './phases/aggressive.mjs';
import { runAssetDiscoveryPhase } from './phases/asset-discovery.mjs';
import { runFinalizePhase } from './phases/finalize.mjs';
import { ROOT } from './pipeline-shared.mjs';

export async function runPipeline(ctx) {
  const s = createPipelineState(ctx);
  s.ROOT = ROOT;

  await runInputPhase(s);
  await runFingerprintPhase(s);
  await runDiscoveryPhase(s);
  await runProbePhase(s);
  await runContentDiscoveryPhase(s);
  await runGoEnginePhase(s);
  await runValidationPhase(s);
  await runAggressivePhase(s);
  await runAssetDiscoveryPhase(s);

  await runGoAgentPhase(s);

  await runFinalizePhase({
    domain: s.domain,
    exactMatch: s.exactMatch,
    modules: s.modules,
    emit: s.emit,
    kaliMode: s.kaliMode,
    auth: s.auth,
    bountyCtx: s.bountyCtx,
    findings: s.findings,
    stats: s.stats,
    addFinding: s.addFinding,
    log: s.log,
    pipe: s.pipe,
    progress: s.progress,
    subdomainsAlive: s.subdomainsAlive,
    paramRows: s.paramRows,
    githubClonedItems: s.githubClonedItems,
    projectNameRaw: s.projectNameRaw,
    autoAiReports: s.autoAiReports,
    aiProviderMode: s.aiProviderMode,
    aiUseOpenrouter: s.aiUseOpenrouter,
    aiOpenrouterOnly: s.aiOpenrouterOnly,
    aiPrimaryCloud: s.aiPrimaryCloud,
    shannonSkipDepsVerify: s.shannonSkipDepsVerify,
    pentestgptUrlOverride: s.pentestgptUrlOverride,
    engagementIdRaw: s.engagementIdRaw,
    engagementOperatorRaw: s.engagementOperatorRaw,
    ROOT: s.ROOT,
    reconCoverageSnapshot: s.reconCoverageSnapshot,
    pipelineAiOut: s.pipelineAiOut,
  });
}
