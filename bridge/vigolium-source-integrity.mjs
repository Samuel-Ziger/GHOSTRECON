import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { runProcess } from '../server/modules/module-runner.mjs';

const SOURCE_IDENTITY_VERSION = 1;
const DEFAULT_TIMEOUT_MS = 15_000;
const MAX_TIMEOUT_MS = 60_000;
const MAX_GIT_OUTPUT_BYTES = 256 * 1024;
const GIT_OBJECT_ID_RE = /^(?:[a-f0-9]{40}|[a-f0-9]{64})$/;
const SOURCE_IDENTITY_KEYS = Object.freeze([
  'version',
  'kind',
  'objectFormat',
  'commit',
  'tree',
  'trackedEntries',
  'dev',
  'ino',
  'mode',
  'uid',
  'gitDirDev',
  'gitDirIno',
]);

function sourceError(code, message, cause = null) {
  const error = new Error(message, cause ? { cause } : undefined);
  error.code = code;
  return error;
}

function samePath(left, right) {
  const normalize = (value) => path.resolve(value);
  return process.platform === 'win32'
    ? normalize(left).toLowerCase() === normalize(right).toLowerCase()
    : normalize(left) === normalize(right);
}

function pathInsideRoot(candidate, root) {
  const relative = path.relative(root, candidate);
  return relative === '' || (
    relative !== '..'
    && !relative.startsWith(`..${path.sep}`)
    && !path.isAbsolute(relative)
  );
}

function isRemoteSource(raw) {
  if (/^[A-Za-z]:[\\/]/.test(raw)) return false;
  return (
    /^[A-Za-z][A-Za-z0-9+.-]*:\/\//.test(raw)
    || /^(?:git|ssh):/i.test(raw)
    || /^[^/\\\s]+@[^/\\\s]+:/.test(raw)
    || /^\\\\/.test(raw)
    || /^\/\//.test(raw)
  );
}

function currentUid() {
  return typeof process.getuid === 'function' ? process.getuid() : null;
}

function assertOwnedDirectory(stat, codePrefix, label) {
  if (!stat.isDirectory()) {
    throw sourceError(`${codePrefix}_NOT_DIRECTORY`, `${label} precisa ser diretório`);
  }
  const uid = currentUid();
  if (uid != null && Number.isFinite(Number(stat.uid)) && Number(stat.uid) !== uid) {
    throw sourceError(`${codePrefix}_OWNER`, `${label} pertence a outro usuário`);
  }
  if (process.platform !== 'win32' && (Number(stat.mode) & 0o022) !== 0) {
    throw sourceError(
      `${codePrefix}_PERMISSIONS`,
      `${label} não pode permitir escrita para grupo/outros`,
    );
  }
}

async function validateDirectoryPath(directory, {
  codePrefix,
  label,
} = {}) {
  const resolved = path.resolve(directory);
  let real;
  try {
    real = await fs.realpath(resolved);
  } catch {
    throw sourceError(`${codePrefix}_UNAVAILABLE`, `${label} não está disponível`);
  }
  if (!samePath(real, resolved)) {
    throw sourceError(
      `${codePrefix}_SYMLINK`,
      `${label} ou diretório ancestral não pode conter symlink`,
    );
  }
  const stat = await fs.lstat(real);
  assertOwnedDirectory(stat, codePrefix, label);
  return { path: real, stat };
}

async function resolveAllowedRoots(allowedRoots) {
  const roots = [...new Set(
    (Array.isArray(allowedRoots) ? allowedRoots : [])
      .map((value) => String(value || '').trim())
      .filter(Boolean)
      .map((value) => path.resolve(value)),
  )];
  if (!roots.length) {
    throw sourceError(
      'VIGOLIUM_SOURCE_ROOT_REQUIRED',
      'raiz permitida para fonte Vigolium não foi configurada',
    );
  }
  const validated = [];
  for (const root of roots) {
    const resolved = await validateDirectoryPath(root, {
      codePrefix: 'VIGOLIUM_SOURCE_ROOT',
      label: 'raiz permitida para fonte Vigolium',
    });
    validated.push(resolved.path);
  }
  return validated;
}

async function validatePathChain(sourcePath, allowedRoot) {
  const relative = path.relative(allowedRoot, sourcePath);
  const parts = relative === '' ? [] : relative.split(path.sep).filter(Boolean);
  let current = allowedRoot;
  for (const part of parts) {
    current = path.join(current, part);
    const resolved = await validateDirectoryPath(current, {
      codePrefix: 'VIGOLIUM_SOURCE',
      label: 'diretório da fonte Vigolium',
    });
    if (!samePath(resolved.path, current)) {
      throw sourceError(
        'VIGOLIUM_SOURCE_SYMLINK',
        'diretório da fonte Vigolium ou ancestral não pode conter symlink',
      );
    }
  }
}

function cleanGitEnv(sourceEnv = process.env) {
  const keys = process.platform === 'win32'
    ? ['PATH', 'PATHEXT', 'SYSTEMROOT', 'WINDIR', 'COMSPEC', 'TEMP', 'TMP']
    : ['PATH', 'TMPDIR', 'TMP', 'TEMP'];
  const env = {};
  for (const key of keys) {
    if (sourceEnv?.[key] != null) env[key] = String(sourceEnv[key]);
  }
  return {
    ...env,
    HOME: os.tmpdir(),
    LANG: 'C',
    LC_ALL: 'C',
    NO_COLOR: '1',
    GIT_CONFIG_NOSYSTEM: '1',
    GIT_CONFIG_GLOBAL: os.devNull,
    GIT_TERMINAL_PROMPT: '0',
    GIT_ASKPASS: '',
    GIT_OPTIONAL_LOCKS: '0',
    GIT_PAGER: 'cat',
  };
}

function normalizeTimeout(value) {
  const parsed = Number(value);
  if (!Number.isFinite(parsed) || parsed <= 0) return DEFAULT_TIMEOUT_MS;
  return Math.max(100, Math.min(MAX_TIMEOUT_MS, Math.floor(parsed)));
}

function rethrowTerminalProcessError(error) {
  if (
    error?.name === 'AbortError'
    || ['PROCESS_ABORTED', 'PROCESS_TIMEOUT', 'PROCESS_UNTERMINATED'].includes(error?.code)
  ) {
    throw error;
  }
}

function parseObjectId(value, label) {
  const normalized = String(value || '').trim().toLowerCase();
  if (!GIT_OBJECT_ID_RE.test(normalized)) {
    throw sourceError(
      'VIGOLIUM_SOURCE_GIT_IDENTITY_INVALID',
      `Git não retornou identidade válida para ${label}`,
    );
  }
  return normalized;
}

function inspectTrackedEntries(raw) {
  const records = String(raw || '').split('\0').filter(Boolean);
  for (const record of records) {
    const tab = record.indexOf('\t');
    const metadata = tab >= 0 ? record.slice(0, tab) : '';
    const [mode, objectId, stage] = metadata.split(/\s+/);
    if (
      !/^[0-7]{6}$/.test(mode || '')
      || !GIT_OBJECT_ID_RE.test(String(objectId || '').toLowerCase())
      || stage !== '0'
    ) {
      throw sourceError(
        'VIGOLIUM_SOURCE_GIT_INDEX_INVALID',
        'índice Git da fonte Vigolium é inválido ou possui conflito',
      );
    }
    if (mode === '120000') {
      throw sourceError(
        'VIGOLIUM_SOURCE_TRACKED_SYMLINK',
        'fonte Vigolium não pode conter symlink rastreado',
      );
    }
    if (mode === '160000') {
      throw sourceError(
        'VIGOLIUM_SOURCE_SUBMODULE',
        'fonte Vigolium com submódulo não é suportada pelo vínculo de identidade',
      );
    }
  }
  return records.length;
}

function sameDirectoryStat(before, after) {
  return ['dev', 'ino', 'mode', 'uid']
    .every((key) => Number(before[key]) === Number(after[key]));
}

function validateExpectedIdentity(expected) {
  if (
    !expected
    || typeof expected !== 'object'
    || Array.isArray(expected)
    || expected.version !== SOURCE_IDENTITY_VERSION
    || expected.kind !== 'git-worktree'
    || !['sha1', 'sha256'].includes(expected.objectFormat)
    || !GIT_OBJECT_ID_RE.test(String(expected.commit || ''))
    || !GIT_OBJECT_ID_RE.test(String(expected.tree || ''))
    || !Number.isSafeInteger(Number(expected.trackedEntries))
    || Number(expected.trackedEntries) < 0
    || ['dev', 'ino', 'mode', 'gitDirDev', 'gitDirIno'].some(
      (key) => !Number.isSafeInteger(Number(expected[key])) || Number(expected[key]) < 0,
    )
    || (
      expected.uid != null
      && (!Number.isSafeInteger(Number(expected.uid)) || Number(expected.uid) < 0)
    )
  ) {
    throw sourceError(
      'VIGOLIUM_SOURCE_IDENTITY_REQUIRED',
      'identidade esperada da fonte Vigolium está ausente ou inválida',
    );
  }
  const expectedLength = expected.objectFormat === 'sha256' ? 64 : 40;
  if (
    String(expected.commit).length !== expectedLength
    || String(expected.tree).length !== expectedLength
  ) {
    throw sourceError(
      'VIGOLIUM_SOURCE_IDENTITY_REQUIRED',
      'formato da identidade esperada da fonte Vigolium é inconsistente',
    );
  }
}

export function assertVigoliumSourceIdentityShape(expected) {
  validateExpectedIdentity(expected);
  return expected;
}

/**
 * Resolve a raiz local permitida para auditoria de código. A rota deve chamar
 * esta função uma vez antes dos gates e persistir a lista no snapshot privado.
 */
export function resolveVigoliumSourceAllowedRoots(
  root,
  sourceEnv = process.env,
) {
  const configured = String(sourceEnv?.GHOSTRECON_VIGOLIUM_SOURCE_ROOT || '').trim();
  const selected = configured || path.join(path.resolve(root), 'clone');
  return Object.freeze([path.resolve(selected)]);
}

/**
 * Inspeciona uma fonte local sem rede e sela a identidade Git do conteúdo.
 *
 * O repositório precisa estar integralmente limpo, inclusive sem arquivos
 * ignorados presentes. Symlinks rastreados e submódulos são recusados porque
 * poderiam apontar para conteúdo não coberto pelo commit/tree aprovado.
 */
export async function inspectVigoliumSourceIdentity(source, {
  allowedRoots,
  signal = null,
  timeoutMs = DEFAULT_TIMEOUT_MS,
  runProcessImpl = runProcess,
  gitBin = 'git',
  env = process.env,
  now = Date.now,
} = {}) {
  signal?.throwIfAborted?.();
  const raw = String(source || '').trim();
  if (!raw || /[\r\n\0]/.test(raw)) {
    throw sourceError('VIGOLIUM_SOURCE_INVALID', 'fonte Vigolium local inválida');
  }
  if (isRemoteSource(raw)) {
    throw sourceError(
      'VIGOLIUM_SOURCE_REMOTE_FORBIDDEN',
      'fonte remota Vigolium não pode ser usada no RUN autenticado/auditado',
    );
  }

  const roots = await resolveAllowedRoots(allowedRoots);
  signal?.throwIfAborted?.();
  const sourceDirectory = await validateDirectoryPath(raw, {
    codePrefix: 'VIGOLIUM_SOURCE',
    label: 'diretório da fonte Vigolium',
  });
  const allowedRoot = roots.find((root) => pathInsideRoot(sourceDirectory.path, root));
  if (!allowedRoot) {
    throw sourceError(
      'VIGOLIUM_SOURCE_OUTSIDE_ROOT',
      'fonte Vigolium está fora da raiz local permitida',
    );
  }
  await validatePathChain(sourceDirectory.path, allowedRoot);

  const gitDirectory = await validateDirectoryPath(path.join(sourceDirectory.path, '.git'), {
    codePrefix: 'VIGOLIUM_SOURCE_GIT_DIR',
    label: 'diretório .git da fonte Vigolium',
  });
  if (!pathInsideRoot(gitDirectory.path, sourceDirectory.path)) {
    throw sourceError(
      'VIGOLIUM_SOURCE_GIT_DIR_OUTSIDE',
      'diretório .git da fonte Vigolium está fora da fonte aprovada',
    );
  }

  const deadline = Number(now()) + normalizeTimeout(timeoutMs);
  const childEnv = cleanGitEnv(env);
  const prefix = [
    '-c',
    'core.fsmonitor=false',
    '-c',
    'core.untrackedCache=false',
    '-C',
    sourceDirectory.path,
  ];
  const git = async (args, label) => {
    signal?.throwIfAborted?.();
    const remaining = Math.max(1, deadline - Number(now()));
    if (remaining <= 1) {
      throw sourceError(
        'PROCESS_TIMEOUT',
        'inspeção da fonte Vigolium excedeu o deadline',
      );
    }
    let result;
    try {
      result = await runProcessImpl(gitBin, [...prefix, ...args], {
        timeoutMs: remaining,
        signal,
        stdoutMaxBytes: MAX_GIT_OUTPUT_BYTES,
        stderrMaxBytes: 32 * 1024,
        rejectOnError: true,
        rejectOnTimeout: true,
        spawnOpts: { env: childEnv },
        label,
      });
    } catch (error) {
      rethrowTerminalProcessError(error);
      throw sourceError(
        'VIGOLIUM_SOURCE_GIT_FAILED',
        'Git não conseguiu validar a fonte Vigolium',
        error,
      );
    }
    if (result?.timedOut || Number(result?.code) !== 0) {
      throw sourceError(
        'VIGOLIUM_SOURCE_GIT_FAILED',
        'Git não conseguiu validar a fonte Vigolium',
      );
    }
    return String(result.stdout || '');
  };

  const statusArgs = [
    'status',
    '--porcelain=v1',
    '-z',
    '--untracked-files=all',
    '--ignored=matching',
  ];
  const statusBefore = await git(statusArgs, 'vigolium source git status');
  if (statusBefore.length > 0) {
    throw sourceError(
      'VIGOLIUM_SOURCE_DIRTY',
      'fonte Vigolium precisa estar limpa, sem arquivos alterados, extras ou ignorados',
    );
  }
  const trackedEntries = inspectTrackedEntries(
    await git(['ls-files', '--stage', '-z'], 'vigolium source git index'),
  );
  const commit = parseObjectId(
    await git(['rev-parse', '--verify', 'HEAD^{commit}'], 'vigolium source git commit'),
    'commit',
  );
  const tree = parseObjectId(
    await git(['rev-parse', '--verify', 'HEAD^{tree}'], 'vigolium source git tree'),
    'tree',
  );
  const statusAfter = await git(statusArgs, 'vigolium source git status final');
  if (statusAfter.length > 0) {
    throw sourceError(
      'VIGOLIUM_SOURCE_CHANGED',
      'fonte Vigolium mudou durante a inspeção',
    );
  }
  signal?.throwIfAborted?.();

  const finalSourcePath = await fs.realpath(sourceDirectory.path);
  const finalGitPath = await fs.realpath(path.join(sourceDirectory.path, '.git'));
  const finalSourceStat = await fs.lstat(finalSourcePath);
  const finalGitStat = await fs.lstat(finalGitPath);
  if (
    !samePath(finalSourcePath, sourceDirectory.path)
    || !samePath(finalGitPath, gitDirectory.path)
    || !sameDirectoryStat(sourceDirectory.stat, finalSourceStat)
    || !sameDirectoryStat(gitDirectory.stat, finalGitStat)
  ) {
    throw sourceError(
      'VIGOLIUM_SOURCE_CHANGED',
      'fonte Vigolium mudou durante a inspeção',
    );
  }

  const objectFormat = commit.length === 64 ? 'sha256' : 'sha1';
  if (tree.length !== commit.length) {
    throw sourceError(
      'VIGOLIUM_SOURCE_GIT_IDENTITY_INVALID',
      'commit e tree Git usam formatos incompatíveis',
    );
  }
  return Object.freeze({
    version: SOURCE_IDENTITY_VERSION,
    kind: 'git-worktree',
    objectFormat,
    commit,
    tree,
    trackedEntries,
    dev: Number(finalSourceStat.dev),
    ino: Number(finalSourceStat.ino),
    mode: Number(finalSourceStat.mode),
    uid: Number.isFinite(Number(finalSourceStat.uid)) ? Number(finalSourceStat.uid) : null,
    gitDirDev: Number(finalGitStat.dev),
    gitDirIno: Number(finalGitStat.ino),
  });
}

/**
 * Revalida imediatamente antes do agente. A identidade esperada é o plano
 * aprovado; este helper nunca promove o estado atual para uma nova aprovação.
 */
export async function assertVigoliumSourceIdentity(source, expected, options = {}) {
  validateExpectedIdentity(expected);
  let actual;
  try {
    actual = await inspectVigoliumSourceIdentity(source, options);
  } catch (error) {
    rethrowTerminalProcessError(error);
    if (String(error?.code || '').startsWith('VIGOLIUM_SOURCE_')) {
      throw sourceError(
        'VIGOLIUM_SOURCE_IDENTITY_MISMATCH',
        'fonte Vigolium diverge do plano aprovado',
        error,
      );
    }
    throw error;
  }
  const matches = SOURCE_IDENTITY_KEYS.every(
    (key) => String(actual[key] ?? '') === String(expected[key] ?? ''),
  );
  if (!matches) {
    throw sourceError(
      'VIGOLIUM_SOURCE_IDENTITY_MISMATCH',
      'fonte Vigolium diverge do plano aprovado',
    );
  }
  return actual;
}
