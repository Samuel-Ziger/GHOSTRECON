import fs from 'node:fs/promises';
import path from 'node:path';
import {
  isForgeAbort,
  runForgeCommand,
  throwIfForgeAborted,
} from './process-runner.mjs';
import {
  computeForgeArtifactIntegrity,
  sameForgeArtifactIntegrity,
} from './artifact-integrity.mjs';
import {
  forgeSandboxAttestation,
  runStrongForgeSandboxOperation,
  validateStrongForgeSandboxRunner,
} from './sandbox-policy.mjs';

function safeChildEnv(env) {
  const out = {};
  for (const key of ['PATH', 'HOME', 'LANG', 'LC_ALL', 'TMPDIR', 'TEMP', 'TMP']) {
    if (env[key] != null) out[key] = env[key];
  }
  out.NODE_NO_WARNINGS = '1';
  return out;
}

async function runNode(args, {
  pendingDir,
  env,
  execFileImpl,
  timeoutMs,
  signal,
}) {
  try {
    const result = await runForgeCommand(process.execPath, args, {
      cwd: pendingDir,
      env: safeChildEnv(env),
      timeoutMs,
      maxBuffer: 2 * 1024 * 1024,
      signal,
      execFileImpl,
      label: `Forge syntax ${args.at(-1) || ''}`.trim(),
    });
    return {
      ok: true,
      stdout: String(result?.stdout || '').slice(0, 200000),
      stderr: String(result?.stderr || '').slice(0, 50000),
      code: 0,
    };
  } catch (e) {
    if (isForgeAbort(e, signal)) throw e;
    return {
      ok: false,
      stdout: String(e?.stdout || e?.result?.stdout || '').slice(0, 200000),
      stderr: String(e?.stderr || e?.result?.stderr || e?.message || e).slice(0, 50000),
      code: Number.isInteger(e?.code) ? e.code : null,
      timedOut: e?.code === 'PROCESS_TIMEOUT' || Boolean(e?.killed) || /timed out|timeout/i.test(String(e?.message || '')),
    };
  }
}

function normalizeIsolatedResult(value) {
  if (!value || typeof value !== 'object' || typeof value.ok !== 'boolean') {
    return {
      ok: false,
      skipped: false,
      reason: 'invalid_isolated_runner_result',
      stdout: '',
      stderr: '',
      code: null,
    };
  }
  return {
    ok: value.ok === true,
    skipped: value.skipped === true,
    reason: value.reason ? String(value.reason).slice(0, 500) : null,
    stdout: String(value.stdout || '').slice(0, 200000),
    stderr: String(value.stderr || '').slice(0, 50000),
    code: Number.isInteger(value.code) ? value.code : value.ok === true ? 0 : null,
    timedOut: value.timedOut === true,
  };
}

export async function runForgeTests(pendingDir, {
  env = process.env,
  execFileImpl = null,
  isolatedRunner = null,
  signal = null,
} = {}) {
  throwIfForgeAborted(signal);
  const artifactIntegrity = await computeForgeArtifactIntegrity(pendingDir);
  const timeoutMs = Math.max(
    1000,
    Math.min(120000, Number(env.GHOSTRECON_AUTO_FORGE_TEST_TIMEOUT_MS || 30000)),
  );
  const syntaxModule = await runNode(
    ['--check', 'module.mjs'],
    { pendingDir, env, execFileImpl, timeoutMs, signal },
  );
  const syntaxTest = await runNode(
    ['--check', 'module.test.js'],
    { pendingDir, env, execFileImpl, timeoutMs, signal },
  );
  throwIfForgeAborted(signal);

  const sandbox = validateStrongForgeSandboxRunner(isolatedRunner, 'test');
  let actualIsolation = null;
  let tests = {
    ok: false,
    skipped: true,
    reason: syntaxModule.ok && syntaxTest.ok
      ? sandbox.reason || 'strong_network_sandbox_required'
      : 'syntax_failed',
  };
  if (syntaxModule.ok && syntaxTest.ok && sandbox.ok) {
    try {
      const raw = await runStrongForgeSandboxOperation(
        isolatedRunner,
        'test',
        {
          pendingDir: path.resolve(pendingDir),
          files: Object.freeze(['module.mjs', 'module.test.js']),
        },
        {
          signal,
          timeoutMs,
          label: 'Forge isolated tests',
        },
      );
      throwIfForgeAborted(signal);
      actualIsolation = raw?.sandboxAttestation || null;
      tests = normalizeIsolatedResult(raw);
    } catch (error) {
      if (isForgeAbort(error, signal)) throw error;
      tests = {
        ok: false,
        skipped: false,
        reason: error?.code === 'AUTO_FORGE_TIMEOUT'
          ? 'isolated_runner_timeout'
          : 'isolated_runner_error',
        stdout: String(error?.stdout || '').slice(0, 200000),
        stderr: String(error?.stderr || error?.message || error).slice(0, 50000),
        code: Number.isInteger(error?.code) ? error.code : null,
        timedOut: error?.code === 'AUTO_FORGE_TIMEOUT',
      };
    }
  }

  const finalArtifactIntegrity = await computeForgeArtifactIntegrity(pendingDir);
  const artifactUnchanged = sameForgeArtifactIntegrity(
    artifactIntegrity,
    finalArtifactIntegrity,
  );
  if (!artifactUnchanged) {
    tests = {
      ...tests,
      ok: false,
      reason: 'artifact_changed_during_tests',
    };
  }
  const isolation = forgeSandboxAttestation(sandbox, actualIsolation, {
    operation: 'test',
  });
  const result = {
    schemaVersion: 1,
    ok: syntaxModule.ok
      && syntaxTest.ok
      && isolation.strong === true
      && tests.ok
      && artifactUnchanged,
    checkedAt: new Date().toISOString(),
    artifactIntegrity,
    artifactUnchanged,
    isolation,
    // Node --permission limita filesystem/processos, mas não constitui
    // isolamento de rede. Não o anunciamos como sandbox suficiente.
    nodePermissionModelSufficient: false,
    syntax: { module: syntaxModule, test: syntaxTest },
    tests,
  };
  await fs.writeFile(
    path.join(pendingDir, 'test-results.json'),
    JSON.stringify(result, null, 2),
    'utf8',
  );
  return result;
}
