import fs from 'node:fs/promises';
import { mkdtemp, rm } from 'node:fs/promises';
import path from 'node:path';
import { tmpdir } from 'node:os';
import { runProcess } from '../server/modules/module-runner.mjs';
import { parseVigoliumJsonl } from './findings-normalizer.mjs';
import {
  ghostreconRoot,
  resolveVigoliumBinary,
  resolveVigoliumStrategy,
  resolveVigoliumModuleFilter,
  resolveVigoliumTarget,
  vigoliumTimeoutMs,
} from './vigolium-config.mjs';

/**
 * Executa `vigolium scan` e devolve findings normalizados.
 * @param {object} s — estado do pipeline
 * @param {{ log?: Function }} hooks
 */
export async function runVigoliumScan(s, hooks = {}) {
  const log = hooks.log || s.log || (() => {});
  const root = s.ROOT || ghostreconRoot();
  const { bin } = await resolveVigoliumBinary(root);
  if (!bin) {
    return {
      ok: false,
      skipped: true,
      reason: 'binário vigolium não encontrado',
      findings: [],
    };
  }

  const target = resolveVigoliumTarget(s);
  const strategy = resolveVigoliumStrategy(s);
  const moduleFilter = resolveVigoliumModuleFilter(s);
  const tmpDir = await mkdtemp(path.join(tmpdir(), 'ghostrecon-vig-'));
  const outFile = path.join(tmpDir, 'findings.jsonl');

  const args = [
    'scan',
    '-t',
    target,
    '--strategy',
    strategy,
    '--format',
    'jsonl',
    '-o',
    outFile,
    '--ci-output-format',
    '-F',
    '--soft-fail',
  ];

  for (const mod of moduleFilter) {
    args.push('-m', mod);
  }

  if (s.auth?.cookie) {
    args.push('--auth', `ghostrecon:Cookie:${s.auth.cookie}`);
  }
  if (s.auth?.headers && typeof s.auth.headers === 'object') {
    for (const [hk, hv] of Object.entries(s.auth.headers)) {
      if (hv != null && String(hv).trim()) {
        args.push('-H', `${hk}: ${hv}`);
      }
    }
  }

  log(`Vigolium scan: ${target} (strategy=${strategy})`, 'info');

  let result;
  try {
    result = await runProcess(bin, args, {
      timeoutMs: vigoliumTimeoutMs(),
      rejectOnError: false,
      rejectOnTimeout: false,
      label: 'vigolium scan',
    });
  } catch (e) {
    await rm(tmpDir, { recursive: true, force: true }).catch(() => {});
    return {
      ok: false,
      skipped: false,
      reason: e?.message || String(e),
      findings: [],
      target,
      strategy,
    };
  }

  let raw = '';
  try {
    raw = await fs.readFile(outFile, 'utf8');
  } catch {
    raw = result.stdout || '';
  }
  await rm(tmpDir, { recursive: true, force: true }).catch(() => {});

  const findings = parseVigoliumJsonl(raw);
  const scanOk = result.code === 0 || findings.length > 0;

  if (!scanOk && result.stderr) {
    log(`Vigolium stderr: ${result.stderr.slice(0, 400)}`, 'warn');
  }

  return {
    ok: scanOk,
    skipped: false,
    findings,
    target,
    strategy,
    exitCode: result.code,
    timedOut: result.timedOut,
    binary: bin,
  };
}
