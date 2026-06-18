import { runProcess } from '../server/modules/module-runner.mjs';
import { parseVigoliumJsonl } from './findings-normalizer.mjs';
import {
  ghostreconRoot,
  resolveVigoliumBinary,
  resolveVigoliumAuthFiles,
  resolveVigoliumModuleTags,
  resolveVigoliumTarget,
  vigoliumAgentTimeoutMs,
} from './vigolium-config.mjs';

export function buildVigoliumAgentArgs(s, mode) {
  const target = resolveVigoliumTarget(s);
  const source = String(s.vigoliumSource || '').trim();
  const authFiles = resolveVigoliumAuthFiles(s);
  const moduleTags = resolveVigoliumModuleTags(s);
  const args = ['agent', mode, '-j', '-F', '--soft-fail'];

  if (mode === 'audit') {
    if (!source) {
      return { skipped: true, reason: 'vigolium_audit requer --source / vigoliumSource', args: [], target, source, authFiles };
    }
    args.push('--source', source);
    const auditMode = String(s.vigoliumAuditMode || process.env.GHOSTRECON_VIGOLIUM_AUDIT_MODE || 'lite').trim();
    if (auditMode) args.push('--mode', auditMode);
  } else if (mode === 'swarm') {
    args.push('-t', target);
    if (source) args.push('--source', source);
    for (const tag of moduleTags) args.push('--module-tag', tag);
    for (const authFile of authFiles) args.push('--auth-file', authFile);
  } else if (mode === 'autopilot') {
    args.push('-t', target);
    if (source) args.push('--source', source);
    for (const tag of moduleTags) args.push('--module-tag', tag);
    for (const authFile of authFiles) args.push('--auth-file', authFile);
  } else if (mode === 'query') {
    const prompt = String(s.vigoliumAgentPrompt || 'security-code-review').trim();
    args.length = 0;
    args.push('agent', 'query', '--prompt-template', prompt, '-j', '--soft-fail');
    if (source) args.push('--source', source);
  }

  return { args, target, source, authFiles, moduleTags, skipped: false };
}

/**
 * @param {object} s — pipeline state
 * @param {'audit'|'swarm'|'query'|'autopilot'} mode
 */
export async function runVigoliumAgent(s, mode) {
  const log = s.log || (() => {});
  const root = s.ROOT || ghostreconRoot();
  const { bin } = await resolveVigoliumBinary(root);
  if (!bin) {
    return { ok: false, skipped: true, reason: 'binário vigolium não encontrado', findings: [] };
  }

  const built = buildVigoliumAgentArgs(s, mode);
  if (built.skipped) {
    return { ok: false, skipped: true, reason: built.reason, findings: [] };
  }
  const { args, target, source } = built;

  log(`Vigolium agent ${mode}: ${mode === 'audit' ? source : target}`, 'info');

  let result;
  try {
    result = await runProcess(bin, args, {
      timeoutMs: vigoliumAgentTimeoutMs(),
      rejectOnError: false,
      rejectOnTimeout: false,
      label: `vigolium agent ${mode}`,
    });
  } catch (e) {
    return { ok: false, skipped: false, reason: e?.message || String(e), findings: [] };
  }

  const raw = result.stdout || '';
  const findings = parseVigoliumJsonl(raw);
  const summary = parseAgentSummary(raw);
  return {
    ok: result.code === 0 || findings.length > 0,
    skipped: false,
    findings,
    summary,
    mode,
    exitCode: result.code,
    timedOut: result.timedOut,
    binary: bin,
  };
}

function parseAgentSummary(raw) {
  const lines = String(raw || '').split(/\r?\n/).map((s) => s.trim()).filter(Boolean);
  for (let i = lines.length - 1; i >= 0; i--) {
    try {
      const row = JSON.parse(lines[i]);
      if (row?.agentic_scan_uuid || row?.session_dir || row?.total_findings != null) return row;
    } catch {
      // ignore non-JSON progress lines
    }
  }
  return null;
}
