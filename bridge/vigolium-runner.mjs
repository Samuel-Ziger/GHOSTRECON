import fs from 'node:fs/promises';
import { constants as fsConstants } from 'node:fs';
import { mkdtemp, rm } from 'node:fs/promises';
import path from 'node:path';
import { tmpdir } from 'node:os';
import { runProcess } from '../server/modules/module-runner.mjs';
import { parseVigoliumJsonl } from './findings-normalizer.mjs';
import {
  ghostreconRoot,
  buildVigoliumChildEnv,
  resolveVigoliumBinary,
  resolveVigoliumStrategy,
  resolveVigoliumModuleFilter,
  resolveVigoliumModuleTags,
  resolveVigoliumAuthFiles,
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
  createVigoliumAuthTransport,
  vigoliumArgsForLog,
} from './vigolium-auth-transport.mjs';
import { assertVigoliumBinaryIdentity } from './vigolium-binary-integrity.mjs';
import { rethrowFatalVigoliumExecutionError } from './vigolium-errors.mjs';
import { redactAutoText } from '../server/auto-agent/redaction.mjs';
import { redactLocalPathsForPublic } from '../server/modules/finding-redaction.mjs';
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

function addSharedScanArgs(args, s, { authFiles: authFilesOverride } = {}) {
  const moduleFilter = resolveVigoliumModuleFilter(s);
  const moduleTags = resolveVigoliumModuleTags(s);
  const authFiles = Array.isArray(authFilesOverride)
    ? authFilesOverride.map(String).map((value) => value.trim()).filter(Boolean)
    : resolveVigoliumAuthFiles(s);

  for (const mod of moduleFilter) {
    args.push('-m', mod);
  }
  for (const tag of moduleTags) {
    args.push('--module-tag', tag);
  }
  for (const authFile of authFiles) {
    args.push('--auth-file', authFile);
  }

  return { moduleFilter, moduleTags, authFiles };
}

export function buildVigoliumScanArgs(s, { outFile, outBase, authFiles } = {}) {
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

  const shared = addSharedScanArgs(args, s, { authFiles });
  return { args, target: targetInfo.target, strategy, only, vpsProfile: vps, ...targetInfo, ...shared };
}

export function buildVigoliumHtmlReportArgs(s, { outFile, authFiles } = {}) {
  const strategy = resolveVigoliumStrategy(s);
  const reportOnly = resolveVigoliumReportOnly(s);
  const args = ['scan'];
  const targetInfo = addTargetArgs(args, s);
  args.push('--strategy', strategy);
  if (reportOnly) args.push('--only', reportOnly);
  args.push('--format', 'html', '-o', outFile || 'report.html', '-F', '--soft-fail');
  const shared = addSharedScanArgs(args, s, { authFiles });
  return { args, target: targetInfo.target, strategy, reportOnly, ...targetInfo, ...shared };
}

function reportUrlForPath(reportPath) {
  const file = path.basename(String(reportPath || ''));
  return file ? `/api/vigolium/reports/${encodeURIComponent(file)}` : null;
}

const MAX_VIGOLIUM_REPORT_BYTES = 50 * 1024 * 1024;

/**
 * Remove credenciais conhecidas e padrões sensíveis do HTML antes de tornar o
 * artefato acessível pela API. A leitura/escrita usa o mesmo descritor e
 * O_NOFOLLOW para não trocar o alvo entre validação e gravação.
 */
export async function sanitizeVigoliumHtmlReport(reportPath, {
  redact = (value) => String(value ?? ''),
  maxBytes = MAX_VIGOLIUM_REPORT_BYTES,
  paths = [],
} = {}) {
  const noFollow = typeof fsConstants.O_NOFOLLOW === 'number' ? fsConstants.O_NOFOLLOW : 0;
  const handle = await fs.open(
    reportPath,
    fsConstants.O_RDWR | noFollow,
  );
  try {
    const stat = await handle.stat();
    if (!stat.isFile()) throw new Error('Vigolium report não é arquivo regular');
    if (stat.size > maxBytes) throw new Error('Vigolium report excede limite de sanitização');
    const raw = await handle.readFile('utf8');
    const safe = redactLocalPathsForPublic(
      redactAutoText(redact(raw)),
      { paths: [reportPath, ...paths] },
    );
    const buffer = Buffer.from(safe, 'utf8');
    if (buffer.length > maxBytes) throw new Error('Vigolium report sanitizado excede limite');
    await handle.truncate(0);
    let offset = 0;
    while (offset < buffer.length) {
      const { bytesWritten } = await handle.write(
        buffer,
        offset,
        buffer.length - offset,
        offset,
      );
      if (!bytesWritten) throw new Error('falha ao gravar report Vigolium sanitizado');
      offset += bytesWritten;
    }
    await handle.truncate(buffer.length);
    await handle.chmod(0o600);
    await handle.sync();
    return { ok: true, bytes: buffer.length };
  } finally {
    await handle.close();
  }
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

export function assertVigoliumRuntimeTargetBinding(s = {}) {
  const inputFile = resolveVigoliumInputFile(s);
  if (!inputFile) return;
  const error = new Error(
    'Vigolium -T bloqueado: arquivo de entrada arbitrário não está vinculado ao alvo/plano autorizado',
  );
  error.code = 'VIGOLIUM_INPUT_SCOPE_UNSEALED';
  throw error;
}

async function readFindingsFromSqlite(
  bin,
  sqlitePath,
  host,
  log,
  signal = null,
  runProcessImpl = runProcess,
  expectedIdentity = null,
  childEnv = {},
  redact = (value) => String(value ?? ''),
  redactLog = redact,
) {
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
  await assertVigoliumBinaryIdentity(bin, expectedIdentity);
  const result = await runProcessImpl(bin, args, {
    timeoutMs: Math.min(vigoliumTimeoutMs(), 180_000),
    signal,
    rejectOnError: false,
    rejectOnTimeout: false,
    spawnOpts: { env: childEnv },
    label: 'vigolium finding',
  });
  if (result.code !== 0 && typeof log === 'function') {
    log(`Vigolium finding sqlite: exit ${result.code} ${redactLog(result.stderr || '').slice(0, 200)}`, 'warn');
    return [];
  }
  try {
    const parsed = JSON.parse(result.stdout || '{}');
    const rows = Array.isArray(parsed?.findings) ? parsed.findings : [];
    if (!rows.length) return [];
    return parseVigoliumJsonl(
      rows.map((row) => JSON.stringify(row)).join('\n'),
      { redact },
    );
  } catch (e) {
    if (typeof log === 'function') {
      log(`Vigolium finding sqlite: parse falhou (${redactLog(e.message)})`, 'warn');
    }
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
  const runProcessImpl = hooks.runProcessImpl || runProcess;
  s.signal?.throwIfAborted?.();
  assertVigoliumRuntimeTargetBinding(s);
  const root = s.ROOT || ghostreconRoot();
  const vps = shouldUseVigoliumVpsProfile(s);
  const childEnv = buildVigoliumChildEnv(s);
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

  let authTransport = null;
  try {
    authTransport = await createVigoliumAuthTransport(s);
    const redactExternalText = (value) => redactLocalPathsForPublic(
      authTransport.redact(value),
      {
        paths: [
          root,
          tmpDir,
          outBase,
          ...authTransport.authFiles,
        ].filter(Boolean),
      },
    );
    const publicError = (value) => redactAutoText(
      redactExternalText(value?.message || String(value ?? '')),
    );
    const { args, target, strategy } = buildVigoliumScanArgs(s, {
      outFile: artifacts.jsonl,
      outBase,
      authFiles: authTransport.authFiles,
    });

    const profileLabel = vps ? 'perfil VPS (stateless, strict, skip external-harvest)' : 'perfil legado';
    const codexLabel = shouldUseVigoliumCodex(s) ? 'codex=sim' : 'codex=não';
    log(
      `Vigolium scan [${profileLabel}, ${codexLabel}]: ${target} (strategy=${strategy}, source=${source || 'auto'})`,
      'info',
    );
    log(`Vigolium cmd: ${path.basename(bin)} ${vigoliumArgsForLog(args).join(' ')}`, 'info');

    let result;
    try {
      await assertVigoliumBinaryIdentity(bin, s.vigoliumExpectedIdentity);
      result = await runProcessImpl(bin, args, {
        timeoutMs: vigoliumTimeoutMs(),
        signal: s.signal,
        rejectOnError: false,
        rejectOnTimeout: false,
        spawnOpts: { env: childEnv },
        label: 'vigolium scan',
      });
    } catch (e) {
      rethrowFatalVigoliumExecutionError(e, s.signal, publicError(e));
      return {
        ok: false,
        skipped: false,
        reason: publicError(e),
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

  let findings = parseVigoliumJsonl(raw, { redact: redactExternalText });
  if (!findings.length && artifacts.sqlite) {
    const host = hostFromTarget(target);
    const fromDb = await readFindingsFromSqlite(
      bin,
      artifacts.sqlite,
      host,
      log,
      s.signal,
      runProcessImpl,
      s.vigoliumExpectedIdentity,
      childEnv,
      redactExternalText,
      publicError,
    );
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
      await sanitizeVigoliumHtmlReport(artifacts.html, {
        redact: redactExternalText,
        paths: [root, outBase],
      });
      htmlOk = true;
    } catch (error) {
      htmlOk = false;
      log(`Vigolium: HTML inline recusado na sanitização (${publicError(error)})`, 'warn');
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
      log('Vigolium HTML inline sanitizado e disponível pela rota protegida', 'info');
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
    const html = buildVigoliumHtmlReportArgs(s, {
      outFile: reportPath,
      authFiles: authTransport.authFiles,
    });
    try {
      await assertVigoliumBinaryIdentity(bin, s.vigoliumExpectedIdentity);
      const reportResult = await runProcessImpl(bin, html.args, {
        timeoutMs: vigoliumTimeoutMs(),
        signal: s.signal,
        rejectOnError: false,
        rejectOnTimeout: false,
        spawnOpts: { env: childEnv },
        label: 'vigolium html report',
      });
      htmlReport = {
        ok: false,
        path: reportPath,
        url: reportUrlForPath(reportPath),
        publicUrl: vigoliumReportPublicUrl(reportPath),
        exitCode: reportResult.code,
        timedOut: reportResult.timedOut,
        only: html.reportOnly,
        inline: false,
      };
      if (reportResult.code === 0) {
        await sanitizeVigoliumHtmlReport(reportPath, {
          redact: redactExternalText,
          paths: [root],
        });
        htmlReport.ok = true;
      }
      if (!htmlReport.ok && reportResult.stderr) {
        log(`Vigolium report stderr: ${publicError(reportResult.stderr).slice(0, 400)}`, 'warn');
      } else {
        log('Vigolium HTML report sanitizado e disponível pela rota protegida', 'info');
        emitOpenVigoliumReport(s, hooks, htmlReport, log);
      }
    } catch (e) {
      rethrowFatalVigoliumExecutionError(e, s.signal, publicError(e));
      htmlReport = {
        ok: false,
        path: reportPath,
        url: reportUrlForPath(reportPath),
        publicUrl: vigoliumReportPublicUrl(reportPath),
        reason: publicError(e),
        inline: false,
      };
      log(`Vigolium HTML report falhou: ${htmlReport.reason}`, 'warn');
    }
  }

  if (!scanOk && result.stderr) {
    log(`Vigolium stderr: ${publicError(result.stderr).slice(0, 400)}`, 'warn');
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
      vpsProfile: vps,
      artifacts,
    };
  } catch (error) {
    const redactedFailure = authTransport
      ? redactLocalPathsForPublic(
          authTransport.redact(error?.message || String(error)),
          { paths: [root, tmpDir, outBase].filter(Boolean) },
        )
      : 'falha ao preparar autenticação Vigolium';
    rethrowFatalVigoliumExecutionError(error, s.signal, redactAutoText(redactedFailure));
    return {
      ok: false,
      skipped: false,
      reason: redactedFailure,
      findings: [],
      vpsProfile: vps,
    };
  } finally {
    await authTransport?.cleanup?.();
    if (tmpDir) await rm(tmpDir, { recursive: true, force: true }).catch(() => {});
  }
}
