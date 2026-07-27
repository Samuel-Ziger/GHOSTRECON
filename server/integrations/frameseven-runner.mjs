import fs from 'node:fs/promises';
import path from 'node:path';
import { randomUUID } from 'node:crypto';
import {
  frameSevenChildEnv,
  inspectFrameSevenBinaryIdentity,
  redactFrameSevenOutput,
  runFrameSeven,
  resolveFrameSevenBinary,
  validateFrameSevenBinaryIdentity,
} from './frameseven-adapter.mjs';
import { FRAMESEVEN_RECON_TOOLS_ARG_V1 } from './frameseven-policy.mjs';
import { runProcess } from '../modules/module-runner.mjs';
import {
  frameSevenPublicPhysicalFile,
  openFrameSevenRegularFile,
  readAndMergeFrameSevenReport,
  readFrameSevenReportAccessMetadata,
  serializeFrameSevenMergedFindings,
} from './frameseven-report.mjs';

const approvals = new Map();
const DEFAULT_MERGE_TIMEOUT_MS = 60_000;
const DEFAULT_APPROVAL_TIMEOUT_MS = 10 * 60_000;
const MAX_APPROVAL_TIMEOUT_MS = 30 * 60_000;
const FRAMESEVEN_REPORT_FILES = new Set([
  'report.html',
  'report.json',
  'report.md',
]);
const FRAMESEVEN_REPORT_ID_RE = /^[A-Za-z0-9][A-Za-z0-9._-]{0,199}$/;

export function publicFrameSevenReportUrl(root, outputDir) {
  const reportsRoot = path.resolve(root, 'reports');
  const resolvedOutput = path.resolve(String(outputDir || ''));
  const relative = path.relative(reportsRoot, resolvedOutput);
  const parts = relative.split(path.sep);
  if (
    !relative
    || relative.startsWith('..')
    || path.isAbsolute(relative)
    || parts.length !== 1
    || !FRAMESEVEN_REPORT_ID_RE.test(parts[0])
  ) return null;
  return `/api/frameseven/reports/${encodeURIComponent(parts[0])}/report.html`;
}

function safeFrameSevenReportLocation(root, reportId, fileName) {
  const safeReportId = String(reportId || '').trim();
  const safeFileName = String(fileName || '').trim();
  const physicalFileName = frameSevenPublicPhysicalFile(safeFileName);
  if (
    !FRAMESEVEN_REPORT_ID_RE.test(safeReportId)
    || !FRAMESEVEN_REPORT_FILES.has(safeFileName)
    || !physicalFileName
  ) return null;
  const reportsRoot = path.resolve(root, 'reports');
  return {
    reportsRoot,
    reportDir: path.join(reportsRoot, safeReportId),
    filePath: path.join(reportsRoot, safeReportId, physicalFileName),
    fileName: safeFileName,
  };
}

export async function openFrameSevenPublicReport(root, reportId, fileName, {
  maxBytes = 32 * 1024 * 1024,
} = {}) {
  const location = safeFrameSevenReportLocation(root, reportId, fileName);
  if (!location) return null;
  let opened;
  try {
    const realRoot = await fs.realpath(path.resolve(root));
    const reportsRoot = await fs.realpath(location.reportsRoot);
    const reportDirStat = await fs.lstat(location.reportDir);
    if (!reportDirStat.isDirectory() || reportDirStat.isSymbolicLink()) return null;
    const realReportDir = await fs.realpath(location.reportDir);
    const reportsRelative = path.relative(realRoot, reportsRoot);
    const reportRelative = path.relative(reportsRoot, realReportDir);
    if (
      !reportsRelative
      || reportsRelative.startsWith('..')
      || path.isAbsolute(reportsRelative)
      || !reportRelative
      || reportRelative.startsWith('..')
      || path.isAbsolute(reportRelative)
    ) return null;

    opened = await openFrameSevenRegularFile(
      path.join(realReportDir, path.basename(location.filePath)),
      { maxBytes },
    );
    // On Linux, verify the object actually opened by descriptor still belongs
    // to the protected report root. This closes ancestor-symlink races too.
    if (process.platform === 'linux') {
      const openedPath = await fs.realpath(`/proc/self/fd/${opened.handle.fd}`);
      const relative = path.relative(reportsRoot, openedPath);
      if (!relative || relative.startsWith('..') || path.isAbsolute(relative)) {
        await opened.handle.close().catch(() => {});
        return null;
      }
    }
    return {
      ...opened,
      logicalFileName: location.fileName,
      reportId: String(reportId),
    };
  } catch {
    await opened?.handle?.close().catch(() => {});
    return null;
  }
}

export async function readFrameSevenPublicReport(root, reportId, fileName, options = {}) {
  const opened = await openFrameSevenPublicReport(root, reportId, fileName, options);
  if (!opened) return null;
  try {
    const body = await opened.handle.readFile();
    const after = await opened.handle.stat();
    if (
      opened.stat.dev !== after.dev
      || opened.stat.ino !== after.ino
      || opened.stat.size !== after.size
      || opened.stat.mtimeMs !== after.mtimeMs
      || body.byteLength !== opened.size
    ) {
      throw new Error('FrameSeven public report changed while it was being read');
    }
    return {
      body,
      size: body.byteLength,
      logicalFileName: opened.logicalFileName,
      reportId: opened.reportId,
    };
  } finally {
    await opened.handle.close().catch(() => {});
  }
}

/**
 * Compatibility-only path resolver. New routes must use
 * openFrameSevenPublicReport and stream from its already validated descriptor.
 */
export async function resolveFrameSevenReportPath(root, reportId, fileName) {
  const opened = await openFrameSevenPublicReport(root, reportId, fileName);
  if (!opened) return null;
  try {
    return opened.path;
  } finally {
    await opened.handle.close().catch(() => {});
  }
}

export async function readFrameSevenReportAccess(root, reportId) {
  const safeReportId = String(reportId || '').trim();
  if (!FRAMESEVEN_REPORT_ID_RE.test(safeReportId)) return null;
  try {
    const reportsRoot = await fs.realpath(path.resolve(root, 'reports'));
    const reportDir = path.join(reportsRoot, safeReportId);
    const stat = await fs.lstat(reportDir);
    if (!stat.isDirectory() || stat.isSymbolicLink()) return null;
    const realReportDir = await fs.realpath(reportDir);
    const relative = path.relative(reportsRoot, realReportDir);
    if (!relative || relative.startsWith('..') || path.isAbsolute(relative)) return null;
    return await readFrameSevenReportAccessMetadata(realReportDir);
  } catch {
    return null;
  }
}

function settleFrameSevenApproval(id, approved) {
  const key = String(id || '');
  const item = approvals.get(key);
  if (!item) return false;
  approvals.delete(key);
  clearTimeout(item.timer);
  item.signal?.removeEventListener('abort', item.abort);
  item.resolve(approved === true);
  return true;
}

export function requestFrameSevenApproval(id, {
  signal,
  timeoutMs = 10 * 60_000,
  ownerSub = null,
} = {}) {
  const key = String(id || '');
  if (!key || approvals.has(key)) return Promise.resolve(false);
  if (signal?.aborted) return Promise.resolve(false);
  return new Promise((resolve) => {
    const abort = () => settleFrameSevenApproval(key, false);
    const parsed = Number(timeoutMs);
    const limit = Number.isFinite(parsed) && parsed >= 1
      ? Math.min(MAX_APPROVAL_TIMEOUT_MS, Math.floor(parsed))
      : DEFAULT_APPROVAL_TIMEOUT_MS;
    const timer = setTimeout(() => settleFrameSevenApproval(key, false), limit);
    timer.unref?.();
    approvals.set(key, {
      resolve,
      signal,
      abort,
      timer,
      expiresAt: Date.now() + limit,
      ownerSub: String(ownerSub || '').trim() || null,
    });
    signal?.addEventListener('abort', abort, { once: true });
  });
}

export function getFrameSevenApproval(id) {
  const item = approvals.get(String(id));
  if (!item || Date.now() >= item.expiresAt) {
    if (item) settleFrameSevenApproval(id, false);
    return null;
  }
  return {
    approvalId: String(id),
    ownerSub: item.ownerSub,
    expiresAt: item.expiresAt,
  };
}

export function resolveFrameSevenApproval(id, approved, { principal = null } = {}) {
  const item = approvals.get(String(id));
  if (!item || Date.now() >= item.expiresAt) {
    if (item) settleFrameSevenApproval(id, false);
    return false;
  }
  const principalSub = String(principal?.sub || '').trim() || null;
  if (item.ownerSub && item.ownerSub !== principalSub) return false;
  return settleFrameSevenApproval(id, approved);
}

export async function runIntegratedFrameSeven({
  root,
  target,
  authBrowser = false,
  tools = FRAMESEVEN_RECON_TOOLS_ARG_V1,
  offensiveApproved = false,
  requestId,
  pipeline,
  emit = () => {},
  signal,
  env = process.env,
  ownerSub = null,
  engagementId = null,
  expectedBinaryIdentity = null,
  beforeFrameSevenScan = null,
  authCaptureTimeoutMs,
  approvalTimeoutMs,
  beforeScanTimeoutMs,
  runTimeoutMs,
  killGraceMs,
  reapTimeoutMs,
  runFrameSevenImpl = runFrameSeven,
  runProcessImpl = runProcess,
  spawnImpl,
  inspectBinaryIdentityImpl = inspectFrameSevenBinaryIdentity,
} = {}) {
  const binary = resolveFrameSevenBinary(root, env);
  const publicMessage = (value, extraPaths = []) => redactFrameSevenOutput(
    value?.message || String(value || 'FrameSeven integration failed'),
    { paths: [root, binary, ...extraPaths].filter(Boolean) },
  );
  const findings = [];
  const integratedEmit = (event) => { if (event?.type === 'finding' && event.finding) findings.push(event.finding); emit(event); };
  const runGhostAndVigolium = async (auth, stageSignal = signal) => {
    integratedEmit({ type: 'engine_started', engine: 'ghostrecon' });
    try {
      await pipeline(auth, integratedEmit, { signal: stageSignal || signal });
      integratedEmit({ type: 'engine_done', engine: 'ghostrecon' });
    } catch (error) {
      const message = publicMessage(error);
      integratedEmit({ type: 'engine_failed', engine: 'ghostrecon', error: message });
      const wrapped = new Error(message, { cause: error });
      if (error?.name) wrapped.name = error.name;
      if (error?.code) wrapped.code = error.code;
      if (error?.fatal === true) wrapped.fatal = true;
      if (error?.recoverable === false) wrapped.recoverable = false;
      if (error?.unterminated === true) wrapped.unterminated = true;
      throw wrapped;
    }
  };
  if (!await fs.access(binary).then(() => true).catch(() => false)) {
    if (expectedBinaryIdentity) {
      // A binary that existed when the plan was approved must not silently
      // become an optional skip after deletion/replacement.
      await validateFrameSevenBinaryIdentity(binary, expectedBinaryIdentity, {
        inspectImpl: inspectBinaryIdentityImpl,
      });
    }
    integratedEmit({ type: 'engine_unavailable', engine: 'frameseven' });
    integratedEmit({ type: 'engine_skipped', engine: 'frameseven', reason: 'binary_unavailable' });
    await runGhostAndVigolium(null);
    return { skipped: true, status: 'skipped', reason: 'binary_unavailable' };
  }
  await validateFrameSevenBinaryIdentity(binary, expectedBinaryIdentity, {
    inspectImpl: inspectBinaryIdentityImpl,
  });
  let result;
  if (!authBrowser) {
    await runGhostAndVigolium(null);
    if (typeof beforeFrameSevenScan === 'function') {
      await beforeFrameSevenScan({ stage: 'scan', signal });
    }
    result = await runFrameSevenImpl({
      root,
      target,
      authBrowser: false,
      tools,
      offensiveApproved,
      signal,
      emit: integratedEmit,
      env,
      deferDoneEvent: true,
      expectedBinaryIdentity,
      authCaptureTimeoutMs,
      approvalTimeoutMs,
      beforeScanTimeoutMs,
      runTimeoutMs,
      killGraceMs,
      reapTimeoutMs,
      inspectBinaryIdentityImpl,
    });
  }
  else {
    if (typeof beforeFrameSevenScan === 'function') {
      await beforeFrameSevenScan({ stage: 'auth_browser', signal });
    }
    result = await runFrameSevenImpl({
    root,
    target,
    authBrowser: true,
    approvalId: requestId,
    tools,
    offensiveApproved,
    signal,
    emit: integratedEmit,
    env,
      deferDoneEvent: true,
      expectedBinaryIdentity,
      authCaptureTimeoutMs,
      approvalTimeoutMs,
      beforeScanTimeoutMs,
      runTimeoutMs,
      killGraceMs,
      reapTimeoutMs,
      inspectBinaryIdentityImpl,
      waitForAuth: ({ signal: approvalSignal } = {}) => requestFrameSevenApproval(requestId, {
        signal: approvalSignal || signal,
        timeoutMs: approvalTimeoutMs,
        ownerSub,
      }),
      beforeScan: async (auth, { signal: stageSignal } = {}) => {
        const activeSignal = stageSignal || signal;
        await runGhostAndVigolium(auth, activeSignal);
        if (typeof beforeFrameSevenScan === 'function') {
          await beforeFrameSevenScan({ stage: 'authenticated_scan', signal: activeSignal });
        }
      },
    });
  }
  try {
    const merged = await readAndMergeFrameSevenReport({
      outputDir: result.outputDir,
      target,
      existingFindings: findings,
      accessMetadata: {
        ownerSub,
        engagementId,
        authenticated: authBrowser === true,
        privateReport: authBrowser === true,
      },
    });
    for (const finding of merged.newFindings) integratedEmit({ type: 'finding', finding });
    const normalizedPath = path.join(
      result.outputDir,
      `.integrated-findings.${process.pid}.${randomUUID()}.json`,
    );
    try {
      const normalizedHandle = await fs.open(normalizedPath, 'wx', 0o600);
      try {
        await normalizedHandle.writeFile(
          JSON.stringify(serializeFrameSevenMergedFindings(merged.mergedFindings), null, 2),
        );
        await normalizedHandle.sync();
      } finally {
        await normalizedHandle.close().catch(() => {});
      }
      if (process.platform !== 'win32') await fs.chmod(normalizedPath, 0o600);
      // The merge command is a second execution of the approved binary.
      // Revalidate after browser approval/scan and immediately before spawn.
      await validateFrameSevenBinaryIdentity(binary, expectedBinaryIdentity, {
        inspectImpl: inspectBinaryIdentityImpl,
      });
      await runProcessImpl(binary, ['-out', result.outputDir, '-merge-findings', normalizedPath], {
        timeoutMs: Math.min(
          10 * 60_000,
          Math.max(
            1,
            Number(env.GHOSTRECON_FRAMESEVEN_MERGE_TIMEOUT_MS) || DEFAULT_MERGE_TIMEOUT_MS,
          ),
        ),
        signal,
        rejectOnError: true,
        rejectOnTimeout: true,
        label: 'FrameSeven report merge',
        spawnOpts: {
          cwd: root,
          env: frameSevenChildEnv(env),
          stdio: ['ignore', 'pipe', 'pipe'],
        },
        ...(spawnImpl ? { spawnImpl } : {}),
      });
    } finally {
      await fs.rm(normalizedPath, { force: true }).catch(() => {});
    }
    const reportUrl = publicFrameSevenReportUrl(root, result.outputDir);
    integratedEmit({
      type: 'dedupe_summary',
      engines: ['ghostrecon', 'vigolium', 'frameseven'],
      input: merged.inputCount,
      output: merged.outputCount,
      merged: merged.mergedCount,
      ...(reportUrl ? { reportUrl } : {}),
    });
    if (result.status === 'partial' || merged.incomplete) {
      integratedEmit({
        type: 'engine_partial',
        engine: 'frameseven',
        phase: result.status === 'partial' ? 'scan' : 'report',
        recoverable: true,
        code: result.code,
        reportErrors: merged.reportErrors.length,
        ...(reportUrl ? { reportUrl } : {}),
      });
    } else {
      integratedEmit({
        type: 'engine_done',
        engine: 'frameseven',
        code: result.code,
        ...(reportUrl ? { reportUrl } : {}),
      });
    }
    return {
      ...result,
      status: result.status === 'partial' || merged.incomplete ? 'partial' : 'done',
      reportMerge: {
        status: 'done',
        findings: merged.incomingFindings.length,
        output: merged.outputCount,
        reportErrors: merged.reportErrors.length,
      },
    };
  } catch (error) {
    const message = publicMessage(error, [result?.outputDir]);
    if (
      error?.code === 'PROCESS_UNTERMINATED'
      || error?.code === 'FRAMESEVEN_PROCESS_UNTERMINATED'
    ) {
      integratedEmit({
        type: 'engine_failed',
        engine: 'frameseven',
        phase: 'report_merge',
        error: message,
        unterminated: true,
        recoverable: false,
      });
      const fatal = new Error(message, { cause: error });
      fatal.code = error.code;
      fatal.fatal = true;
      fatal.recoverable = false;
      fatal.unterminated = true;
      throw fatal;
    }
    if (signal?.aborted || error?.name === 'AbortError' || error?.code === 'PROCESS_ABORTED') {
      integratedEmit({
        type: 'engine_cancelled',
        engine: 'frameseven',
        phase: 'report_merge',
        error: message,
      });
      const cancellation = new Error(message, { cause: error });
      cancellation.name = 'AbortError';
      cancellation.code = error?.code || 'PROCESS_ABORTED';
      throw cancellation;
    }
    if (error?.code === 'FRAMESEVEN_BINARY_IDENTITY_MISMATCH') {
      integratedEmit({
        type: 'engine_failed',
        engine: 'frameseven',
        phase: 'report_merge',
        error: message,
      });
      const integrityFailure = new Error(message, { cause: error });
      integrityFailure.code = error.code;
      throw integrityFailure;
    }
    integratedEmit({
      type: 'engine_partial',
      engine: 'frameseven',
      phase: 'report_merge',
      error: message,
    });
    integratedEmit({
      type: 'error',
      engine: 'frameseven',
      phase: 'report_merge',
      recoverable: true,
      message,
    });
    integratedEmit({
      type: 'dedupe_summary',
      engines: ['ghostrecon', 'vigolium', 'frameseven'],
      input: findings.length,
      output: findings.length,
      merged: 0,
      reportUnavailable: true,
    });
    return {
      ...result,
      status: 'partial',
      reportMerge: { status: 'failed', error: message },
    };
  }
}
