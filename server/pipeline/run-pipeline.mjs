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
import { runActiveDynamicModules } from '../auto-agent/forge/runtime-loader.mjs';
import { runPipelinePhases } from './phase-executor.mjs';

const PIPELINE_PHASES = Object.freeze([
  { name: 'input', run: runInputPhase, recoverable: false },
  { name: 'fingerprint', run: runFingerprintPhase },
  { name: 'discovery', run: runDiscoveryPhase },
  { name: 'probe', run: runProbePhase },
  { name: 'content_discovery', run: runContentDiscoveryPhase },
  { name: 'go_engine', run: runGoEnginePhase },
  { name: 'validation', run: runValidationPhase },
  { name: 'aggressive', run: runAggressivePhase },
  { name: 'asset_discovery', run: runAssetDiscoveryPhase },
  {
    name: 'dynamic_modules',
    run: (state) => runActiveDynamicModules(state, {
      root: state.ROOT,
      isolatedRunner: state.forgeSandboxRunner,
      canaryForgeId: state.forgeCanaryId,
    }),
  },
  { name: 'go_agent', run: runGoAgentPhase },
  { name: 'finalize', run: runFinalizePhase, recoverable: false },
]);

export async function runPipeline(ctx) {
  const s = createPipelineState(ctx);
  s.ROOT = ROOT;

  await runPipelinePhases(s, PIPELINE_PHASES, {
    enabled: ctx.continueOnPhaseError === true || ctx.enablePhaseTimeouts === true,
    continueOnPhaseError: ctx.continueOnPhaseError === true,
    phaseTimeouts: ctx.phaseTimeoutsMs ?? ctx.phaseTimeouts ?? null,
    phaseSettleGraceMs: ctx.phaseSettleGraceMs,
  });
}
