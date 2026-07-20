import fs from 'node:fs/promises';
import path from 'node:path';
import { execFile as execFileCb } from 'node:child_process';
import { promisify } from 'node:util';

const execFileDefault = promisify(execFileCb);

function safeChildEnv(env) {
  const out = {};
  for (const key of ['PATH', 'HOME', 'LANG', 'LC_ALL', 'TMPDIR', 'TEMP', 'TMP']) if (env[key] != null) out[key] = env[key];
  out.NODE_NO_WARNINGS = '1';
  return out;
}

async function runNode(args, { pendingDir, env, execFileImpl, timeoutMs }) {
  try {
    const result = await execFileImpl(process.execPath, args, {
      cwd: pendingDir,
      env: safeChildEnv(env),
      timeout: timeoutMs,
      maxBuffer: 2 * 1024 * 1024,
      windowsHide: true,
    });
    return { ok: true, stdout: String(result?.stdout || '').slice(0, 200000), stderr: String(result?.stderr || '').slice(0, 50000), code: 0 };
  } catch (e) {
    return {
      ok: false,
      stdout: String(e?.stdout || '').slice(0, 200000),
      stderr: String(e?.stderr || e?.message || e).slice(0, 50000),
      code: Number.isInteger(e?.code) ? e.code : null,
      timedOut: Boolean(e?.killed) || /timed out/i.test(String(e?.message || '')),
    };
  }
}

export async function runForgeTests(pendingDir, { env = process.env, execFileImpl = execFileDefault } = {}) {
  const timeoutMs = Math.max(1000, Math.min(120000, Number(env.GHOSTRECON_AUTO_FORGE_TEST_TIMEOUT_MS || 30000)));
  const allowRead = path.resolve(pendingDir);
  const syntaxModule = await runNode(['--check', 'module.mjs'], { pendingDir, env, execFileImpl, timeoutMs });
  const syntaxTest = await runNode(['--check', 'module.test.js'], { pendingDir, env, execFileImpl, timeoutMs });
  let tests = { ok: false, skipped: true, reason: 'syntax_failed' };
  if (syntaxModule.ok && syntaxTest.ok) {
    tests = await runNode([
      '--permission', `--allow-fs-read=${allowRead}`,
      '--test', '--experimental-test-isolation=none', `--test-timeout=${timeoutMs}`, '--test-concurrency=1', 'module.test.js',
    ], { pendingDir, env, execFileImpl, timeoutMs: timeoutMs + 2000 });
  }
  const result = {
    schemaVersion: 1,
    ok: syntaxModule.ok && syntaxTest.ok && tests.ok,
    checkedAt: new Date().toISOString(),
    permissionModel: true,
    networkAllowed: false,
    childProcessAllowed: false,
    filesystemWriteAllowed: false,
    syntax: { module: syntaxModule, test: syntaxTest },
    tests,
  };
  await fs.writeFile(path.join(pendingDir, 'test-results.json'), JSON.stringify(result, null, 2), 'utf8');
  return result;
}
