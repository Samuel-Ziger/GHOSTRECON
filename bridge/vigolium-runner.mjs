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
  resolveVigoliumAuthEntries,
  resolveVigoliumInputFile,
  resolveVigoliumInputType,
  resolveVigoliumOnly,
  resolveVigoliumReportOnly,
  resolveVigoliumTarget,
  shouldPreferVigoliumPath,
  shouldUseVigoliumCodex,
  shouldWriteVigoliumHtmlReport,
  vigoliumTimeoutMs,
} from './vigolium-config.mjs';

function addTargetArgs(args, s) {
  const inputFile = resolveVigoliumInputFile(s);
  const inputType = resolveVigoliumInputType(s);
  if (inputFile) {
    args.push('-T', inputFile);
    if (inputType) args.push('-I', inputType);
    return { target: inputFile, inputFile, inputType };
  }
  const target = resolveVigoliumTarget(s);
  args.push('-t', target);
  return { target, inputFile: null, inputType: null };
}

function addSharedScanArgs(args, s) {
  const moduleFilter = resolveVigoliumModuleFilter(s);
  const moduleTags = resolveVigoliumModuleTags(s);
  const authFiles = resolveVigoliumAuthFiles(s);
  const authEntries = resolveVigoliumAuthEntries(s);

  for (const mod of moduleFilter) {
    args.push('-m', mod);
  }
  for (const tag of moduleTags) {
    args.push('--module-tag', tag);
  }
  for (const authFile of authFiles) {
    args.push('--auth-file', authFile);
  }
  for (const authEntry of authEntries) {
    args.push('--auth', authEntry);
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

  return { moduleFilter, moduleTags, authFiles, authEntries };
}

export function buildVigoliumScanArgs(s, { outFile } = {}) {
  const strategy = resolveVigoliumStrategy(s);
  const only = resolveVigoliumOnly(s);
  const args = [
    'scan',
  ];
  const targetInfo = addTargetArgs(args, s);
  args.push(
    '--strategy',
    strategy,
  );
  if (only) args.push('--only', only);
  args.push(
    '--format',
    'jsonl',
    '-o',
    outFile || '-',
    '--ci-output-format',
    '-F',
    '--soft-fail',
  );
  const shared = addSharedScanArgs(args, s);

  return { args, target: targetInfo.target, strategy, only, ...targetInfo, ...shared };
}

export function buildVigoliumHtmlReportArgs(s, { outFile } = {}) {
  const strategy = resolveVigoliumStrategy(s);
  const reportOnly = resolveVigoliumReportOnly(s);
  const args = ['scan'];
  const targetInfo = addTargetArgs(args, s);
  args.push('--strategy', strategy);
  if (reportOnly) args.push('--only', reportOnly);
  args.push('--format', 'html', '-o', outFile || 'report.html', '-F', '--soft-fail');
  const shared = addSharedScanArgs(args, s);
  return { args, target: targetInfo.target, strategy, reportOnly, ...targetInfo, ...shared };
}

function slugForFile(value) {
  return String(value || 'target')
    .replace(/^https?:\/\//i, '')
    .replace(/[\\/:*?"<>|\s]+/g, '-')
    .replace(/^-+|-+$/g, '')
    .slice(0, 80) || 'target';
}

async function ensureReportFile(s, target) {
  const root = s.ROOT || ghostreconRoot();
  const dir = path.join(root, '.runtime', 'vigolium-reports');
  await fs.mkdir(dir, { recursive: true });
  const stamp = new Date().toISOString().replace(/[:.]/g, '-');
  return path.join(dir, `${stamp}-${slugForFile(target)}.html`);
}

function reportUrlForPath(reportPath) {
  const file = path.basename(String(reportPath || ''));
  return file ? `/api/vigolium/reports/${encodeURIComponent(file)}` : null;
}

function vigoliumProcessEnv(s) {
  if (!shouldUseVigoliumCodex(s)) return process.env;
  return {
    ...process.env,
    GHOSTRECON_VIGOLIUM_USE_CODEX: '1',
    VIGOLIUM_PROVIDER: process.env.VIGOLIUM_PROVIDER || 'openai-codex-oauth',
  };
}

/**
 * Executa `vigolium scan` e devolve findings normalizados.
 * @param {object} s — estado do pipeline
 * @param {{ log?: Function }} hooks
 */
export async function runVigoliumScan(s, hooks = {}) {
  const log = hooks.log || s.log || (() => {});
  const root = s.ROOT || ghostreconRoot();
  const { bin, source } = await resolveVigoliumBinary(root, { preferPath: shouldPreferVigoliumPath(s) });
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

  log(`Vigolium scan: ${target} (strategy=${strategy}, source=${source || 'auto'})`, 'info');

  let result;
  try {
    result = await runProcess(bin, args, {
      timeoutMs: vigoliumTimeoutMs(),
      rejectOnError: false,
      rejectOnTimeout: false,
      spawnOpts: { env: vigoliumProcessEnv(s) },
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
  let htmlReport = null;

  if (shouldWriteVigoliumHtmlReport(s)) {
    const reportPath = await ensureReportFile(s, target);
    const html = buildVigoliumHtmlReportArgs(s, { outFile: reportPath });
    try {
      const reportResult = await runProcess(bin, html.args, {
        timeoutMs: vigoliumTimeoutMs(),
        rejectOnError: false,
        rejectOnTimeout: false,
        spawnOpts: { env: vigoliumProcessEnv(s) },
        label: 'vigolium html report',
      });
      htmlReport = {
        ok: reportResult.code === 0,
        path: reportPath,
        url: reportUrlForPath(reportPath),
        exitCode: reportResult.code,
        timedOut: reportResult.timedOut,
        only: html.reportOnly,
      };
      if (!htmlReport.ok && reportResult.stderr) {
        log(`Vigolium report stderr: ${reportResult.stderr.slice(0, 400)}`, 'warn');
      } else {
        log(`Vigolium HTML report: ${reportPath}`, 'info');
      }
    } catch (e) {
      htmlReport = { ok: false, path: reportPath, url: reportUrlForPath(reportPath), reason: e?.message || String(e) };
      log(`Vigolium HTML report falhou: ${htmlReport.reason}`, 'warn');
    }
  }

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
    binarySource: source,
    htmlReport,
  };
}
