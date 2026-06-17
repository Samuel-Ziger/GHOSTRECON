import fs from 'node:fs/promises';
import { mkdtemp, rm } from 'node:fs/promises';
import path from 'node:path';
import { tmpdir } from 'node:os';
import { runProcess } from '../server/modules/module-runner.mjs';
import { parseVigoliumJsonl } from './findings-normalizer.mjs';
import {
  ghostreconRoot,
  resolveVigoliumBinary,
  resolveVigoliumTarget,
  vigoliumAgentTimeoutMs,
} from './vigolium-config.mjs';

/**
 * @param {object} s — pipeline state
 * @param {'audit'|'swarm'|'query'} mode
 */
export async function runVigoliumAgent(s, mode) {
  const log = s.log || (() => {});
  const root = s.ROOT || ghostreconRoot();
  const { bin } = await resolveVigoliumBinary(root);
  if (!bin) {
    return { ok: false, skipped: true, reason: 'binário vigolium não encontrado', findings: [] };
  }

  const tmpDir = await mkdtemp(path.join(tmpdir(), 'ghostrecon-vig-agent-'));
  const outFile = path.join(tmpDir, 'agent.jsonl');
  const target = resolveVigoliumTarget(s);
  const source = String(s.vigoliumSource || '').trim();

  const args = ['agent', mode, '--format', 'jsonl', '-o', outFile, '--ci-output-format', '-F', '--soft-fail'];

  if (mode === 'audit') {
    if (!source) {
      await rm(tmpDir, { recursive: true, force: true }).catch(() => {});
      return { ok: false, skipped: true, reason: 'vigolium_audit requer --source / vigoliumSource', findings: [] };
    }
    args.push('--source', source);
    const auditMode = String(s.vigoliumAuditMode || process.env.GHOSTRECON_VIGOLIUM_AUDIT_MODE || 'lite').trim();
    if (auditMode) args.push('--mode', auditMode);
  } else if (mode === 'swarm') {
    args.push('-t', target);
    if (source) args.push('--source', source);
  } else if (mode === 'query') {
    const prompt = String(s.vigoliumAgentPrompt || 'security-code-review').trim();
    args.length = 0;
    args.push('agent', 'query', '--prompt-template', prompt, '-j', '--soft-fail');
    if (source) args.push('--source', source);
  }

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
    await rm(tmpDir, { recursive: true, force: true }).catch(() => {});
    return { ok: false, skipped: false, reason: e?.message || String(e), findings: [] };
  }

  let raw = '';
  try {
    raw = await fs.readFile(outFile, 'utf8');
  } catch {
    raw = result.stdout || '';
  }
  await rm(tmpDir, { recursive: true, force: true }).catch(() => {});

  const findings = parseVigoliumJsonl(raw);
  return {
    ok: result.code === 0 || findings.length > 0,
    skipped: false,
    findings,
    mode,
    exitCode: result.code,
    timedOut: result.timedOut,
    binary: bin,
  };
}
