import fs from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { constants as fsConstants } from 'node:fs';

import { runProcess } from '../../modules/module-runner.mjs';
import {
  createForgeSandboxOperationAttestation,
  STRONG_FORGE_SANDBOX_CAPABILITIES,
} from './sandbox-policy.mjs';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const DEFAULT_BWRAP = '/usr/bin/bwrap';
const RUNTIME_WORKER = path.join(__dirname, 'runtime-worker.mjs');
const MAX_RUNTIME_INPUT_BYTES = 512 * 1024;

function forgeProcessError(message, code, result = null) {
  const error = new Error(message);
  error.code = code;
  if (result) {
    error.stdout = String(result.stdout || '').slice(0, 200_000);
    error.stderr = String(result.stderr || '').slice(0, 50_000);
    error.result = result;
  }
  return error;
}

function throwIfAborted(signal) {
  if (!signal?.aborted) return;
  if (signal.reason instanceof Error) throw signal.reason;
  throw forgeProcessError(
    signal.reason ? String(signal.reason) : 'Forge cancelado',
    'AUTO_FORGE_CANCELLED',
  );
}

function translateProcessFailure(result, signal, label) {
  throwIfAborted(signal);
  if (result?.cancelled || result?.code === 'PROCESS_ABORTED') {
    throw forgeProcessError(`${label} cancelado`, 'AUTO_FORGE_CANCELLED', result);
  }
  if (result?.timedOut || result?.code === 124) {
    throw forgeProcessError(`${label} excedeu o timeout`, 'AUTO_FORGE_TIMEOUT', result);
  }
  throw forgeProcessError(
    `${label} falhou (exit=${result?.code ?? 'n/d'})`,
    'AUTO_FORGE_SANDBOX_FAILED',
    result,
  );
}

async function optionalReadOnlyBindArgs() {
  const args = [];
  for (const source of ['/lib', '/lib64']) {
    const stat = await fs.stat(source).catch(() => null);
    if (stat?.isDirectory() || stat?.isSymbolicLink()) {
      args.push('--ro-bind', source, source);
    }
  }
  return args;
}

async function baseSandboxArgs() {
  return [
    '--unshare-all',
    // Bubblewrap exige a opção explícita junto de --disable-userns, mesmo
    // quando --unshare-all já inclui o namespace de usuário.
    '--unshare-user',
    '--disable-userns',
    '--die-with-parent',
    '--new-session',
    '--clearenv',
    '--cap-drop', 'ALL',
    '--ro-bind', '/usr', '/usr',
    ...await optionalReadOnlyBindArgs(),
    '--proc', '/proc',
    '--dev', '/dev',
    '--tmpfs', '/tmp',
    '--setenv', 'HOME', '/tmp',
    '--setenv', 'TMPDIR', '/tmp',
    '--setenv', 'PATH', '/usr/bin',
    '--setenv', 'LANG', 'C.UTF-8',
    '--setenv', 'NODE_NO_WARNINGS', '1',
  ];
}

async function assertExecutable(file, label) {
  if (!path.isAbsolute(file)) {
    throw forgeProcessError(
      `${label} deve usar caminho absoluto`,
      'AUTO_FORGE_STRONG_SANDBOX_REQUIRED',
    );
  }
  try {
    await fs.access(file, fsConstants.X_OK);
  } catch {
    throw forgeProcessError(
      `${label} indisponível`,
      'AUTO_FORGE_STRONG_SANDBOX_REQUIRED',
    );
  }
}

/**
 * Cria o runner forte padrão do Forge em Linux. Bubblewrap recebe apenas os
 * artefatos candidatos em leitura, um /tmp efêmero e nenhum namespace de rede
 * do host. Nenhuma variável do ambiente do servidor atravessa `--clearenv`.
 */
export async function createBubblewrapForgeSandboxRunner({
  env = process.env,
  runProcessImpl = runProcess,
  bwrapPath = String(env.GHOSTRECON_AUTO_FORGE_BWRAP_BIN || DEFAULT_BWRAP),
  nodePath = process.execPath,
} = {}) {
  if (process.platform !== 'linux') {
    throw forgeProcessError(
      'Bubblewrap Forge requer Linux',
      'AUTO_FORGE_STRONG_SANDBOX_REQUIRED',
    );
  }
  await Promise.all([
    assertExecutable(bwrapPath, 'Bubblewrap'),
    assertExecutable(nodePath, 'Node.js do sandbox'),
    fs.access(RUNTIME_WORKER, fsConstants.R_OK),
  ]);
  const resolvedNodePath = await fs.realpath(nodePath);
  const nodeIsUnderUsr = resolvedNodePath === '/usr'
    || resolvedNodePath.startsWith('/usr/');
  const sandboxNodePath = nodeIsUnderUsr ? resolvedNodePath : '/runtime/node';

  async function execute(args, {
    timeoutMs,
    signal,
    input = null,
    label,
  }) {
    throwIfAborted(signal);
    const result = await runProcessImpl(bwrapPath, args, {
      timeoutMs,
      signal,
      input,
      stdinMaxBytes: MAX_RUNTIME_INPUT_BYTES,
      label,
      rejectOnError: false,
      rejectOnTimeout: false,
      stdoutMaxBytes: 1_000_000,
      stderrMaxBytes: 200_000,
      spawnOpts: {
        env: {},
        windowsHide: true,
      },
    });
    throwIfAborted(signal);
    return result;
  }

  return Object.freeze({
    capabilities: Object.freeze({ ...STRONG_FORGE_SANDBOX_CAPABILITIES }),

    async runTests({
      pendingDir,
      files = [],
      timeoutMs = 30_000,
      signal = null,
      operationId,
      attestationChallenge,
    } = {}) {
      const resolvedDir = path.resolve(String(pendingDir || ''));
      const expectedFiles = new Set(['module.mjs', 'module.test.js']);
      if (
        files.length !== expectedFiles.size
        || files.some((name) => !expectedFiles.has(name))
      ) {
        return {
          ok: false,
          skipped: false,
          reason: 'invalid_test_file_set',
          stdout: '',
          stderr: '',
          code: null,
        };
      }
      const args = [
        ...await baseSandboxArgs(),
        ...(nodeIsUnderUsr
          ? []
          : ['--dir', '/runtime', '--ro-bind', resolvedNodePath, sandboxNodePath]),
        '--ro-bind', resolvedDir, '/work',
        '--chdir', '/work',
        sandboxNodePath,
        '--max-old-space-size=128',
        '--test-concurrency=1',
        '--test',
        'module.test.js',
      ];
      const result = await execute(args, {
        timeoutMs,
        signal,
        label: 'Forge Bubblewrap tests',
      });
      if (!result?.ok) {
        if (result?.timedOut || result?.cancelled) {
          translateProcessFailure(result, signal, 'Forge Bubblewrap tests');
        }
        return {
          ok: false,
          skipped: false,
          reason: 'isolated_tests_failed',
          stdout: String(result?.stdout || ''),
          stderr: String(result?.stderr || ''),
          code: Number.isInteger(result?.code) ? result.code : null,
        };
      }
      return {
        ok: true,
        skipped: false,
        reason: null,
        stdout: String(result.stdout || ''),
        stderr: String(result.stderr || ''),
        code: 0,
        sandboxAttestation: createForgeSandboxOperationAttestation({
          operation: 'test',
          operationId,
          challenge: attestationChallenge,
          runner: 'bubblewrap',
        }),
      };
    },

    async runModule({
      moduleId,
      source,
      context,
      timeoutMs = 30_000,
      signal = null,
      operationId,
      attestationChallenge,
    } = {}) {
      const input = JSON.stringify({
        moduleId: String(moduleId || '').slice(0, 128),
        source: String(source || ''),
        context: context || {},
        timeoutMs,
      });
      if (Buffer.byteLength(input) > MAX_RUNTIME_INPUT_BYTES) {
        throw forgeProcessError(
          'entrada do runtime Forge excede o limite',
          'AUTO_FORGE_RUNTIME_INPUT_TOO_LARGE',
        );
      }
      const args = [
        ...await baseSandboxArgs(),
        '--dir', '/runtime',
        ...(nodeIsUnderUsr
          ? []
          : ['--ro-bind', resolvedNodePath, sandboxNodePath]),
        '--ro-bind', RUNTIME_WORKER, '/runtime/worker.mjs',
        '--chdir', '/tmp',
        sandboxNodePath,
        '--experimental-vm-modules',
        '--max-old-space-size=128',
        '/runtime/worker.mjs',
      ];
      const result = await execute(args, {
        timeoutMs,
        signal,
        input,
        label: `Forge Bubblewrap runtime ${String(moduleId || '').slice(0, 128)}`,
      });
      if (!result?.ok) {
        translateProcessFailure(result, signal, 'Forge Bubblewrap runtime');
      }
      let wrapper;
      try {
        wrapper = JSON.parse(String(result.stdout || '').trim());
      } catch {
        throw forgeProcessError(
          'runtime Forge retornou JSON inválido',
          'AUTO_FORGE_RUNTIME_INVALID_RESULT',
          result,
        );
      }
      if (
        !wrapper
        || typeof wrapper !== 'object'
        || typeof wrapper.ok !== 'boolean'
      ) {
        throw forgeProcessError(
          'runtime Forge retornou wrapper inválido',
          'AUTO_FORGE_RUNTIME_INVALID_RESULT',
          result,
        );
      }
      if (wrapper.ok !== true) {
        throw forgeProcessError(
          String(wrapper.error || 'runtime Forge rejeitou o módulo').slice(0, 2000),
          'AUTO_FORGE_RUNTIME_FAILED',
          result,
        );
      }
      return {
        ...(wrapper.result && typeof wrapper.result === 'object'
          ? wrapper.result
          : { result: wrapper.result }),
        sandboxAttestation: createForgeSandboxOperationAttestation({
          operation: 'runtime',
          operationId,
          challenge: attestationChallenge,
          runner: 'bubblewrap',
        }),
      };
    },
  });
}
