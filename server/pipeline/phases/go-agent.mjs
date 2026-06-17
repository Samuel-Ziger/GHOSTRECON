import { runVigoliumAgent } from '../../../bridge/agent-bridge.mjs';
import {
  resolveVigoliumAgentMode,
  shouldRunGoAgent,
  resolveVigoliumSource,
} from '../../../bridge/vigolium-config.mjs';
import { getVigoliumCapabilities } from '../../../bridge/vigolium-capabilities.mjs';
import { logVigoliumFindingsSummary } from '../../../bridge/vigolium-log.mjs';

/**
 * Fase agent — vigolium-audit / swarm (Codex, Claude Code, etc.).
 * Corre após asset-discovery, antes de finalize.
 */
export async function runGoAgentPhase(s) {
  const { modules, log, pipe, addFinding, progress } = s;
  const agentMode = s.vigoliumAgentMode || resolveVigoliumAgentMode(s);

  if (!shouldRunGoAgent(agentMode, modules)) {
    pipe('vigolium_agent', 'skip');
    pipe('vigolium_audit', 'skip');
    return;
  }

  const cap = await getVigoliumCapabilities({ ghostRoot: s.ROOT });
  if (!cap.installed) {
    log(`Vigolium agent: ${cap.message}`, 'warn');
    pipe('vigolium_agent', 'skip');
    return;
  }

  s.vigoliumSource = resolveVigoliumSource(s);
  if (agentMode === 'audit' && !s.vigoliumSource) {
    log('vigolium_audit: indique caminho do código (vigoliumSource na UI ou GHOSTRECON_VIGOLIUM_SOURCE)', 'warn');
    pipe('vigolium_audit', 'skip');
    pipe('vigolium_agent', 'skip');
    return;
  }

  pipe('vigolium_agent', 'active');
  if (agentMode === 'audit') pipe('vigolium_audit', 'active');
  progress(88);

  try {
    const out = await runVigoliumAgent(s, agentMode);
    if (out.skipped) {
      log(`Vigolium agent: ${out.reason}`, 'warn');
    } else {
      for (const f of out.findings || []) addFinding(f, null);
      logVigoliumFindingsSummary(log, out.findings, {
        label: `Vigolium agent (${out.mode})`,
      });
    }
  } catch (e) {
    log(`Vigolium agent: ${e?.message || e}`, 'warn');
  }

  if (agentMode === 'audit') pipe('vigolium_audit', 'done');
  pipe('vigolium_agent', 'done');
  progress(90);
}
