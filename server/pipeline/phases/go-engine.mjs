import { runVigoliumScan } from '../../../bridge/vigolium-runner.mjs';
import { shouldRunGoEngine } from '../../../bridge/vigolium-config.mjs';
import { getVigoliumCapabilities } from '../../../bridge/vigolium-capabilities.mjs';
import { logVigoliumFindingsSummary } from '../../../bridge/vigolium-log.mjs';

/**
 * Fase Go — motor Vigolium (DAST). Corre após content-discovery quando engine=go|both
 * ou módulo vigolium_dast activo.
 */
export async function runGoEnginePhase(s) {
  const { modules, log, pipe, addFinding, progress } = s;
  const engineMode = s.engineMode || 'node';

  if (!shouldRunGoEngine(engineMode, modules)) {
    pipe('vigolium_engine', 'skip');
    pipe('vigolium_dast', 'skip');
    return;
  }

  const cap = await getVigoliumCapabilities({ ghostRoot: s.ROOT });
  if (!cap.installed) {
    log(`Motor Vigolium: ${cap.message}`, 'warn');
    pipe('vigolium_engine', 'skip');
    pipe('vigolium_dast', 'skip');
    return;
  }

  pipe('vigolium_engine', 'active');
  pipe('vigolium_dast', 'active');
  progress(72);

  try {
    const out = await runVigoliumScan(s, { log });
    if (out.skipped) {
      log(`Vigolium: ${out.reason}`, 'warn');
      pipe('vigolium_dast', 'skip');
    } else if (!out.ok && !out.findings?.length) {
      log(`Vigolium scan terminou sem findings (exit=${out.exitCode ?? '?'})`, 'info');
    } else {
      for (const f of out.findings || []) {
        addFinding(f, null);
      }
      logVigoliumFindingsSummary(log, out.findings, {
        label: `Vigolium DAST — ${out.target} (${out.strategy})`,
      });
    }
  } catch (e) {
    log(`Vigolium: ${e?.message || e}`, 'warn');
  }

  pipe('vigolium_dast', 'done');
  pipe('vigolium_engine', 'done');
  progress(78);
}
