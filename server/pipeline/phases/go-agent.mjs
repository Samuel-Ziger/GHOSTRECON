import { runVigoliumAgent } from '../../../bridge/agent-bridge.mjs';
import {
  resolveVigoliumAgentMode,
  shouldRunGoAgent,
  resolveVigoliumSource,
} from '../../../bridge/vigolium-config.mjs';
import { getVigoliumCapabilities } from '../../../bridge/vigolium-capabilities.mjs';
import { logVigoliumFindingsSummary } from '../../../bridge/vigolium-log.mjs';
import { rethrowFatalVigoliumExecutionError } from '../../../bridge/vigolium-errors.mjs';

/**
 * Fase agent — vigolium-audit / swarm (Codex, Claude Code, etc.).
 * Corre após asset-discovery, antes de finalize.
 */
export async function runGoAgentPhase(s) {
  s.signal?.throwIfAborted?.();
  const { modules, log, pipe, addFinding, progress } = s;
  const agentMode = s.vigoliumAgentMode || resolveVigoliumAgentMode(s);

  if (!shouldRunGoAgent(agentMode, modules)) {
    pipe('vigolium_agent', 'skip');
    pipe('vigolium_audit', 'skip');
    pipe('vigolium_swarm', 'skip');
    return;
  }

  if (agentMode === 'swarm') {
    const out = await runVigoliumAgent(s, agentMode);
    log(`Vigolium agent: ${out.reason}`, 'warn');
    pipe('vigolium_agent', 'skip');
    pipe('vigolium_audit', 'skip');
    pipe('vigolium_swarm', 'skip');
    progress(92);
    return;
  }

  const cap = await getVigoliumCapabilities({ ghostRoot: s.ROOT });
  if (!cap.installed) {
    log(`Vigolium agent: ${cap.message}`, 'warn');
    pipe('vigolium_agent', 'skip');
    pipe('vigolium_audit', 'skip');
    pipe('vigolium_swarm', 'skip');
    return;
  }

  if (!s.vigoliumRuntimeConfigFrozen) {
    s.vigoliumSource = resolveVigoliumSource(s);
  }
  if (
    !s.vigoliumRuntimeConfigFrozen
    && agentMode === 'audit'
    && !s.vigoliumSource
    && Array.isArray(s.githubClonedItems)
    && s.githubClonedItems.length
  ) {
    s.vigoliumSource = s.githubClonedItems[0].local_path;
    log('vigolium_audit: usando clone GitHub local autorizado', 'info');
  }
  if (agentMode === 'audit' && !s.vigoliumSource) {
    log('vigolium_audit: indique caminho do código (vigoliumSource na UI ou GHOSTRECON_VIGOLIUM_SOURCE)', 'warn');
    pipe('vigolium_audit', 'skip');
    pipe('vigolium_swarm', 'skip');
    pipe('vigolium_agent', 'skip');
    return;
  }
  if (agentMode === 'autopilot' && !s.vigoliumUseCodex) {
    log('vigolium_autopilot: Codex nao foi marcado; o Vigolium pode usar provider externo/indefinido conforme ambiente.', 'warn');
  }
  if (agentMode === 'autopilot' && !s.vigoliumSource) {
    log('vigolium_autopilot: sem vigoliumSource; code review fica limitado/indisponivel.', 'warn');
  }

  pipe('vigolium_agent', 'active');
  if (agentMode === 'audit') pipe('vigolium_audit', 'active');
  else pipe('vigolium_audit', 'skip');
  if (agentMode === 'swarm') pipe('vigolium_swarm', 'active');
  else pipe('vigolium_swarm', 'skip');
  progress(91);

  try {
    const out = await runVigoliumAgent(s, agentMode);
    if (out.skipped) {
      log(`Vigolium agent: ${out.reason}`, 'warn');
      if (agentMode === 'audit') pipe('vigolium_audit', 'skip');
      if (agentMode === 'swarm') pipe('vigolium_swarm', 'skip');
      pipe('vigolium_agent', 'skip');
      progress(92);
      return;
    } else {
      for (const f of out.findings || []) addFinding(f, null);
      logVigoliumFindingsSummary(log, out.findings, {
        label: `Vigolium agent (${out.mode})`,
      });
      if (!out.ok) {
        const state = out.timedOut ? 'timeout' : 'failed';
        log(`Vigolium agent: ${state}; ${out.partial ? 'evidência parcial preservada' : 'sem conclusão válida'}`, 'warn');
        if (agentMode === 'audit') pipe('vigolium_audit', state);
        if (agentMode === 'autopilot') pipe('vigolium_autopilot', state);
        pipe('vigolium_agent', state);
        progress(92);
        return;
      }
      if (out.planOnly) log('Vigolium autopilot: prévia concluída; nenhuma vulnerabilidade foi testada', 'info');
    }
  } catch (e) {
    rethrowFatalVigoliumExecutionError(e, s.signal);
    log(`Vigolium agent: ${e?.message || e}`, 'warn');
    if (agentMode === 'audit') pipe('vigolium_audit', 'failed');
    if (agentMode === 'autopilot') pipe('vigolium_autopilot', 'failed');
    pipe('vigolium_agent', 'failed');
    progress(92);
    return;
  }

  if (agentMode === 'audit') pipe('vigolium_audit', 'done');
  if (agentMode === 'swarm') pipe('vigolium_swarm', 'done');
  pipe('vigolium_agent', 'done');
  progress(92);
}
