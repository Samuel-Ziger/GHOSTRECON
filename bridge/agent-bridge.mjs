import { runProcess } from '../server/modules/module-runner.mjs';
import {
  parseVigoliumJsonl,
  redactVigoliumExternalValue,
} from './findings-normalizer.mjs';
import {
  ghostreconRoot,
  buildVigoliumChildEnv,
  resolveVigoliumBinary,
  resolveVigoliumAuthFiles,
  resolveVigoliumModuleTags,
  resolveVigoliumTarget,
  resolveVigoliumAuditMode,
  shouldPreferVigoliumPath,
  vigoliumAgentTimeoutMs,
} from './vigolium-config.mjs';
import { createVigoliumAuthTransport } from './vigolium-auth-transport.mjs';
import { assertVigoliumBinaryIdentity } from './vigolium-binary-integrity.mjs';
import { assertVigoliumSourceIdentity } from './vigolium-source-integrity.mjs';
import { rethrowFatalVigoliumExecutionError } from './vigolium-errors.mjs';
import { redactAutoText } from '../server/auto-agent/redaction.mjs';
import { redactLocalPathsForPublic } from '../server/modules/finding-redaction.mjs';

export function buildVigoliumAgentArgs(s, mode, {
  authFiles: authFilesOverride,
  privateDbPath = null,
} = {}) {
  const target = resolveVigoliumTarget(s);
  const source = String(s.vigoliumSource || '').trim();
  const authFiles = Array.isArray(authFilesOverride)
    ? authFilesOverride.map(String).map((value) => value.trim()).filter(Boolean)
    : resolveVigoliumAuthFiles(s);
  const moduleTags = resolveVigoliumModuleTags(s);
  const args = ['agent', mode, '-j', '-F', '--soft-fail'];

  if (mode === 'audit') {
    if (!source) {
      return { skipped: true, reason: 'vigolium_audit requer --source / vigoliumSource', args: [], target, source, authFiles };
    }
    args.push('--source', source);
    const auditMode = resolveVigoliumAuditMode(s);
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
  if (authFiles.length) {
    if (!privateDbPath || /[\r\n\0]/.test(String(privateDbPath))) {
      return {
        skipped: true,
        reason: 'Vigolium autenticado exige banco temporário isolado',
        args: [],
        target,
        source,
        authFiles,
      };
    }
    args.push('--db', String(privateDbPath));
  }

  return { args, target, source, authFiles, moduleTags, skipped: false };
}

/**
 * @param {object} s — pipeline state
 * @param {'audit'|'swarm'|'query'|'autopilot'} mode
 */
export async function runVigoliumAgent(s, mode, {
  runProcessImpl = runProcess,
  assertVigoliumSourceIdentityImpl = assertVigoliumSourceIdentity,
} = {}) {
  const log = s.log || (() => {});
  s.signal?.throwIfAborted?.();
  const root = s.ROOT || ghostreconRoot();
  const resolvedBinary = s.vigoliumRuntimeConfigFrozen && s.vigoliumBinaryPath
    ? { bin: s.vigoliumBinaryPath, source: s.vigoliumBinarySource || 'approved-plan' }
    : await resolveVigoliumBinary(root, { preferPath: shouldPreferVigoliumPath(s) });
  const { bin, source: binarySource } = resolvedBinary;
  if (!bin) {
    return { ok: false, skipped: true, reason: 'binário vigolium não encontrado', findings: [] };
  }
  let authTransport = null;
  const redactExternalText = (value) => redactLocalPathsForPublic(
    authTransport?.redact(value) || String(value ?? ''),
    { paths: [root, bin, s.vigoliumSource].filter(Boolean) },
  );
  const publicError = (value) => redactAutoText(
    redactExternalText(value?.message || String(value ?? '')),
  );
  try {
    if (mode === 'swarm' || mode === 'autopilot') {
      authTransport = await createVigoliumAuthTransport(s);
    }

    const built = buildVigoliumAgentArgs(s, mode, {
      authFiles: authTransport?.authFiles,
      privateDbPath: authTransport?.privateDbPath,
    });
    if (built.skipped) {
      return { ok: false, skipped: true, reason: built.reason, findings: [] };
    }
    const { args, target, source } = built;

    log(
      `Vigolium agent ${mode}: ${mode === 'audit' ? 'fonte local autorizada' : target}`,
      'info',
    );

    let result;
    try {
      if (source) {
        await assertVigoliumSourceIdentityImpl(
          source,
          s.vigoliumExpectedSourceIdentity,
          {
            allowedRoots: s.vigoliumSourceAllowedRoots,
            signal: s.signal,
            timeoutMs: s.vigoliumAgentTimeoutMs,
          },
        );
      }
      await assertVigoliumBinaryIdentity(bin, s.vigoliumExpectedIdentity);
      result = await runProcessImpl(bin, args, {
        timeoutMs: s.vigoliumRuntimeConfigFrozen && Number.isFinite(s.vigoliumAgentTimeoutMs)
          ? s.vigoliumAgentTimeoutMs
          : vigoliumAgentTimeoutMs(),
        signal: s.signal,
        rejectOnError: false,
        rejectOnTimeout: false,
        spawnOpts: {
          env: s.vigoliumRuntimeConfigFrozen && s.vigoliumChildEnv
            ? { ...s.vigoliumChildEnv }
            : buildVigoliumChildEnv(s),
        },
        label: `vigolium agent ${mode}`,
      });
    } catch (e) {
      rethrowFatalVigoliumExecutionError(e, s.signal, publicError(e));
      return {
        ok: false,
        skipped: false,
        reason: publicError(e),
        findings: [],
      };
    }

    const raw = result.stdout || '';
    const redact = redactExternalText;
    const findings = parseVigoliumJsonl(raw, { redact });
    const summary = parseAgentSummary(raw, { redact });
    return {
      ok: result.code === 0 || findings.length > 0,
      skipped: false,
      findings,
      summary,
      mode,
      exitCode: result.code,
      timedOut: result.timedOut,
      binary: bin,
      binarySource,
    };
  } catch (error) {
    const redactedFailure = authTransport
      ? publicError(error)
      : 'falha ao preparar autenticação Vigolium';
    rethrowFatalVigoliumExecutionError(error, s.signal, redactedFailure);
    return {
      ok: false,
      skipped: false,
      reason: redactedFailure,
      findings: [],
    };
  } finally {
    await authTransport?.cleanup?.();
  }
}

function parseAgentSummary(raw, options = {}) {
  const lines = String(raw || '').split(/\r?\n/).map((s) => s.trim()).filter(Boolean);
  for (let i = lines.length - 1; i >= 0; i--) {
    try {
      const row = JSON.parse(lines[i]);
      if (row?.agentic_scan_uuid || row?.session_dir || row?.total_findings != null) {
        return redactVigoliumExternalValue(row, options);
      }
    } catch {
      // ignore non-JSON progress lines
    }
  }
  return null;
}
