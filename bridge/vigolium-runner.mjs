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
  resolveVigoliumModuleTags,
  resolveVigoliumAuthFiles,
  resolveVigoliumTarget,
  vigoliumTimeoutMs,
} from './vigolium-config.mjs';

export function buildVigoliumScanArgs(s, { outFile } = {}) {
  const target = resolveVigoliumTarget(s);
  const strategy = resolveVigoliumStrategy(s);
  const moduleFilter = resolveVigoliumModuleFilter(s);
  const moduleTags = resolveVigoliumModuleTags(s);
  const authFiles = resolveVigoliumAuthFiles(s);
  const args = [
    'scan',
    '-t',
    target,
    '--strategy',
    strategy,
    '--format',
    'jsonl',
    '-o',
    outFile || '-',
    '--ci-output-format',
    '-F',
    '--soft-fail',
  ];

  for (const mod of moduleFilter) {
    args.push('-m', mod);
  }
  for (const tag of moduleTags) {
    args.push('--module-tag', tag);
  }
  for (const authFile of authFiles) {
    args.push('--auth-file', authFile);
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

  return { args, target, strategy, moduleFilter, moduleTags, authFiles };
}

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

  const tmpDir = await mkdtemp(path.join(tmpdir(), 'ghostrecon-vig-'));
  const outFile = path.join(tmpDir, 'findings.jsonl');
  const { args, target, strategy } = buildVigoliumScanArgs(s, { outFile });

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
