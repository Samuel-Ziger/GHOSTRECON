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
  shouldUseVigoliumVpsProfile,
  shouldWriteVigoliumHtmlReport,
  vigoliumTimeoutMs,
} from './vigolium-config.mjs';
import {
  appendVigoliumVpsScanFlags,
  buildVigoliumOutputBase,
  slugForVigoliumOutput,
  vigoliumArtifactPaths,
  vigoliumReportPublicUrl,
} from './vigolium-vps-profile.mjs';

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

export function buildVigoliumScanArgs(s, { outFile, outBase } = {}) {
  const strategy = resolveVigoliumStrategy(s);
  const only = resolveVigoliumOnly(s);
  const vps = shouldUseVigoliumVpsProfile(s);
  const args = ['scan'];
  const targetInfo = addTargetArgs(args, s);
  args.push('--strategy', strategy);
  if (only) args.push('--only', only);

  if (vps) {
    const base = outBase || (outFile ? String(outFile).replace(/\.(jsonl|html|sqlite)$/i, '') : null) || '-';
    args.push('--format', 'html,sqlite,jsonl', '-o', base, '-F', '--soft-fail');
    appendVigoliumVpsScanFlags(args, s);
  } else {
    args.push('--format', 'jsonl', '-o', outFile || '-', '--ci-output-format', '-F', '--soft-fail');
  }

  const shared = addSharedScanArgs(args, s);
  return { args, target: targetInfo.target, strategy, only, vpsProfile: vps, ...targetInfo, ...shared };
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

function reportUrlForPath(reportPath) {
  const file = path.basename(String(reportPath || ''));
  return file ? `/api/vigolium/reports/${encodeURIComponent(file)}` : null;
}

function hostFromTarget(target) {
  const raw = String(target || '').trim();
  if (!raw) return '';
  try {
    const u = new URL(/^https?:\/\//i.test(raw) ? raw : `https://${raw}`);
    return u.hostname;
  } catch {
    return raw.replace(/^https?:\/\//i, '').split('/')[0];
  }
}

function vigoliumProcessEnv(s) {
  const base = { ...process.env };
  if (shouldUseVigoliumCodex(s)) {
    base.GHOSTRECON_VIGOLIUM_USE_CODEX = '1';
    base.VIGOLIUM_PROVIDER = base.VIGOLIUM_PROVIDER || 'openai-codex-oauth';
  }
  if (shouldUseVigoliumVpsProfile(s)) {
    base.SKIP_EXTERNAL_HARVEST = base.SKIP_EXTERNAL_HARVEST || '1';
    base.VIGOLIUM_STRATEGY = resolveVigoliumStrategy(s);
  }
  return base;
}

async function readFindingsFromSqlite(bin, sqlitePath, host, log) {
  if (!sqlitePath || !host) return [];
  try {
    await fs.access(sqlitePath);
  } catch {
    return [];
  }
  const args = [
    'finding',
    '-j',
    '-S',
    '--db',
    sqlitePath,
    '--host',
    host,
    '--compact',
    '--min-severity',
    'info',
    '--limit',
    '300',
  ];
  const result = await runProcess(bin, args, {
    timeoutMs: Math.min(vigoliumTimeoutMs(), 180_000),
    rejectOnError: false,
    rejectOnTimeout: false,
    label: 'vigolium finding',
  });
  if (result.code !== 0 && typeof log === 'function') {
    log(`Vigolium finding sqlite: exit ${result.code} ${String(result.stderr || '').slice(0, 200)}`, 'warn');
    return [];
  }
  try {
    const parsed = JSON.parse(result.stdout || '{}');
    const rows = Array.isArray(parsed?.findings) ? parsed.findings : [];
    if (!rows.length) return [];
    return parseVigoliumJsonl(rows.map((row) => JSON.stringify(row)).join('\n'));
  } catch (e) {
    if (typeof log === 'function') log(`Vigolium finding sqlite: parse falhou (${e.message})`, 'warn');
    return [];
  }
}

function emitOpenVigoliumReport(s, hooks, htmlReport, log) {
  const emit = hooks.emit || s.emit;
  if (!emit || !htmlReport?.ok) return;
  const url = htmlReport.publicUrl || vigoliumReportPublicUrl(htmlReport.path);
  if (!url) return;
  emit({
    type: 'open_url',
    url,
    label: 'Vigolium — relatório HTML',
    source: 'vigolium',
  });
  log?.(`Vigolium: relatório HTML → ${url}`, 'success');
}

/**
 * Executa `vigolium scan` e devolve findings normalizados.
 * @param {object} s — estado do pipeline
 * @param {{ log?: Function, emit?: Function }} hooks
 */
export async function runVigoliumScan(s, hooks = {}) {
  const log = hooks.log || s.log || (() => {});
  const root = s.ROOT || ghostreconRoot();
  const vps = shouldUseVigoliumVpsProfile(s);
  const { bin, source } = await resolveVigoliumBinary(root, { preferPath: shouldPreferVigoliumPath(s) });
  if (!bin) {
    return {
      ok: false,
      skipped: true,
      reason: 'binário vigolium não encontrado',
      findings: [],
    };
  }

  let tmpDir = null;
  let outBase = null;
  let artifacts = null;
  if (vps) {
    const target = resolveVigoliumTarget(s);
    outBase = buildVigoliumOutputBase(root, target);
    await fs.mkdir(path.dirname(outBase), { recursive: true });
    artifacts = vigoliumArtifactPaths(outBase);
  } else {
    tmpDir = await mkdtemp(path.join(tmpdir(), 'ghostrecon-vig-'));
    artifacts = { jsonl: path.join(tmpDir, 'findings.jsonl'), html: null, sqlite: null };
  }

  const { args, target, strategy } = buildVigoliumScanArgs(s, {
    outFile: artifacts.jsonl,
    outBase,
  });

  const profileLabel = vps ? 'perfil VPS (stateless, strict, skip external-harvest)' : 'perfil legado';
  const codexLabel = shouldUseVigoliumCodex(s) ? 'codex=sim' : 'codex=não';
  log(
    `Vigolium scan [${profileLabel}, ${codexLabel}]: ${target} (strategy=${strategy}, source=${source || 'auto'})`,
    'info',
  );
  log(`Vigolium cmd: ${bin} ${args.join(' ')}`, 'info');

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
    if (tmpDir) await rm(tmpDir, { recursive: true, force: true }).catch(() => {});
    return {
      ok: false,
      skipped: false,
      reason: e?.message || String(e),
      findings: [],
      target,
      strategy,
      vpsProfile: vps,
    };
  }

  let raw = '';
  try {
    raw = await fs.readFile(artifacts.jsonl, 'utf8');
  } catch {
    raw = result.stdout || '';
  }

  let findings = parseVigoliumJsonl(raw);
  if (!findings.length && artifacts.sqlite) {
    const host = hostFromTarget(target);
    const fromDb = await readFindingsFromSqlite(bin, artifacts.sqlite, host, log);
    if (fromDb.length) {
      findings = fromDb;
      log(`Vigolium: ${findings.length} finding(s) importados do SQLite do scan`, 'info');
    }
  }

  const scanOk = result.code === 0 || findings.length > 0;
  let htmlReport = null;

  if (vps && shouldWriteVigoliumHtmlReport(s)) {
    let htmlOk = false;
    try {
      await fs.access(artifacts.html);
      htmlOk = true;
    } catch {
      htmlOk = false;
    }
    htmlReport = {
      ok: htmlOk,
      path: artifacts.html,
      url: reportUrlForPath(artifacts.html),
      publicUrl: vigoliumReportPublicUrl(artifacts.html),
      exitCode: result.code,
      timedOut: result.timedOut,
      inline: true,
      sqlitePath: artifacts.sqlite,
      outputBase: outBase,
    };
    if (htmlOk) {
      log(`Vigolium HTML (inline): ${artifacts.html}`, 'info');
      emitOpenVigoliumReport(s, hooks, htmlReport, log);
    } else {
      log('Vigolium: HTML inline não gerado neste scan', 'warn');
    }
  } else if (!vps && shouldWriteVigoliumHtmlReport(s)) {
    const reportDir = path.join(root, '.runtime', 'vigolium-reports');
    await fs.mkdir(reportDir, { recursive: true });
    const reportPath = path.join(
      reportDir,
      `legacy-${slugForVigoliumOutput(target)}-${Date.now()}.html`,
    );
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
        publicUrl: vigoliumReportPublicUrl(reportPath),
        exitCode: reportResult.code,
        timedOut: reportResult.timedOut,
        only: html.reportOnly,
        inline: false,
      };
      if (!htmlReport.ok && reportResult.stderr) {
        log(`Vigolium report stderr: ${reportResult.stderr.slice(0, 400)}`, 'warn');
      } else {
        log(`Vigolium HTML report: ${reportPath}`, 'info');
        emitOpenVigoliumReport(s, hooks, htmlReport, log);
      }
    } catch (e) {
      htmlReport = {
        ok: false,
        path: reportPath,
        url: reportUrlForPath(reportPath),
        publicUrl: vigoliumReportPublicUrl(reportPath),
        reason: e?.message || String(e),
        inline: false,
      };
      log(`Vigolium HTML report falhou: ${htmlReport.reason}`, 'warn');
    }
  }

  if (!scanOk && result.stderr) {
    log(`Vigolium stderr: ${result.stderr.slice(0, 400)}`, 'warn');
  }

  if (tmpDir) await rm(tmpDir, { recursive: true, force: true }).catch(() => {});

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
    vpsProfile: vps,
    artifacts,
  };
}
