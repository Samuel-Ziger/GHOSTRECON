import fs from 'fs/promises';
import os from 'os';
import path from 'path';
import { resolveGithubToken } from './github-token.mjs';
import { runProcess } from './module-runner.mjs';

const ONE_DAY_MS = 24 * 60 * 60 * 1000;
const ONE_MONTH_MS = 30 * ONE_DAY_MS;

function parseBool(v, defaultValue = false) {
  if (v == null || String(v).trim() === '') return defaultValue;
  const n = String(v).trim().toLowerCase();
  return n === '1' || n === 'true' || n === 'yes' || n === 'on';
}

export function githubRepoHtmlUrl(repoOrFullName) {
  if (typeof repoOrFullName === 'string') {
    const n = repoOrFullName
      .trim()
      .replace(/^https?:\/\/github\.com\//i, '')
      .replace(/\.git$/i, '')
      .replace(/\/$/, '');
    return n ? `https://github.com/${n}` : '';
  }
  const r = repoOrFullName || {};
  const full = String(r.full_name || '').trim();
  const fromField = String(r.html_url || '').trim();
  if (fromField) return fromField;
  return full ? `https://github.com/${full}` : '';
}

export function githubCloneConfig() {
  const enabled = parseBool(process.env.GHOSTRECON_GITHUB_CLONE_ENABLED, true);
  const cloneDir = String(process.env.GHOSTRECON_CLONE_DIR || 'clone')
    .trim()
    .replace(/\\/g, '/');
  const maxRepos = Math.max(1, Math.min(Number(process.env.GHOSTRECON_CLONE_MAX_REPOS) || 3, 10));
  const cloneTimeoutMs = Math.max(15000, Math.min(Number(process.env.GHOSTRECON_CLONE_TIMEOUT_MS) || 120000, 600000));
  const maxSizeMb = Math.max(50, Math.min(Number(process.env.GHOSTRECON_CLONE_MAX_SIZE_MB) || 200, 4096));
  const retentionDays = Math.max(1, Math.min(Number(process.env.GHOSTRECON_CLONE_RETENTION_DAYS) || 30, 365));
  return {
    enabled,
    cloneDir,
    maxRepos,
    cloneTimeoutMs,
    maxSizeBytes: maxSizeMb * 1024 * 1024,
    retentionMs: retentionDays * ONE_DAY_MS || ONE_MONTH_MS,
  };
}

function safeName(input) {
  return String(input || '')
    .trim()
    .toLowerCase()
    .replace(/[^a-z0-9._-]+/g, '_')
    .replace(/^_+|_+$/g, '')
    .slice(0, 120) || 'repo';
}

function buildRepoCloneDir(baseDir, targetDomain, fullName) {
  const stamp = new Date().toISOString().replace(/[:.]/g, '-');
  const domainPart = safeName(targetDomain);
  const repoPart = safeName(String(fullName || '').replace(/\//g, '__'));
  return path.join(baseDir, `${domainPart}__${repoPart}__${stamp}`);
}

async function dirExists(p) {
  try {
    const st = await fs.stat(p);
    return st.isDirectory();
  } catch {
    return false;
  }
}

async function ensureDir(p) {
  await fs.mkdir(p, { recursive: true });
  return p;
}

/** PAT usado na API GitHub e em `git clone` (GITHUB_TOKEN ou GH_TOKEN). */
export function githubCloneAuthToken() {
  const t = resolveGithubToken();
  return t || null;
}

/** Remove userinfo de URLs HTTP(S); credenciais nunca seguem em argv. */
export function cleanGithubCloneUrl(cloneUrl) {
  const raw = String(cloneUrl || '').trim();
  if (!raw) return raw;
  try {
    const u = new URL(raw);
    if (!/^https?:$/i.test(u.protocol)) return raw;
    u.username = '';
    u.password = '';
    for (const key of [...u.searchParams.keys()]) {
      if (/(?:auth|token|key|password|secret)/i.test(key)) u.searchParams.delete(key);
    }
    u.hash = '';
    return u.toString();
  } catch {
    return raw;
  }
}

/**
 * Compatibilidade com consumidores antigos. O token é deliberadamente
 * ignorado: autenticação de clone usa credential helper temporário.
 */
export function withGithubAuthCloneUrl(cloneUrl, _token = null) {
  return cleanGithubCloneUrl(cloneUrl);
}

/** Remove credenciais de URLs/mensagens antes de logar ou devolver erro. */
export function redactGitCloneSecret(text, secrets = []) {
  let output = String(text || '');
  const values = (Array.isArray(secrets) ? secrets : [secrets])
    .map((value) => String(value || '').trim())
    .filter(Boolean)
    .sort((left, right) => right.length - left.length);
  for (const value of values) output = output.split(value).join('***');
  return output
    .replace(/x-access-token:[^@\s]+@/gi, 'x-access-token:***@')
    .replace(/https:\/\/[^@\s]+@github\.com/gi, 'https://***@github.com')
    .replace(/\b(?:github_pat_|gh[pousr]_)[A-Za-z0-9_]{6,}\b/g, '***');
}

function gitCloneEnv() {
  const env = {
    ...process.env,
    GIT_TERMINAL_PROMPT: '0',
    GCM_INTERACTIVE: 'Never',
  };
  delete env.GITHUB_TOKEN;
  delete env.GH_TOKEN;
  return env;
}

function isGithubHttpsUrl(value) {
  try {
    const url = new URL(String(value || ''));
    return url.protocol === 'https:' && /^github\.com$/i.test(url.hostname);
  } catch {
    return false;
  }
}

function quoteCredentialHelperPath(value) {
  return `'${String(value).replace(/'/g, `'\\''`)}'`;
}

export async function createGitCredentialTransport(token, opts = {}) {
  const secret = String(token || '').trim();
  if (!secret) {
    return { credentialFile: null, helperConfig: null, cleanup: async () => {} };
  }

  const tempRoot = path.resolve(opts.tempRoot || os.tmpdir());
  let dirPath = null;
  try {
    dirPath = await fs.mkdtemp(path.join(tempRoot, 'ghostrecon-git-cred-'));
    await fs.chmod(dirPath, 0o700);
    const credentialFile = path.join(dirPath, 'credentials');
    const credentialUrl = new URL('https://github.com/');
    credentialUrl.username = 'x-access-token';
    credentialUrl.password = secret;
    await fs.writeFile(credentialFile, `${credentialUrl.toString()}\n`, {
      encoding: 'utf8',
      mode: 0o600,
      flag: 'wx',
    });
    await fs.chmod(credentialFile, 0o600);

    let cleaned = false;
    return {
      credentialFile,
      helperConfig: `store --file=${quoteCredentialHelperPath(credentialFile)}`,
      cleanup: async () => {
        if (cleaned) return;
        cleaned = true;
        await fs.rm(dirPath, { recursive: true, force: true }).catch(() => {});
      },
    };
  } catch (error) {
    if (dirPath) await fs.rm(dirPath, { recursive: true, force: true }).catch(() => {});
    throw error;
  }
}

export async function runGitClone(
  cloneUrl,
  targetDir,
  timeoutMs,
  {
    token = githubCloneAuthToken(),
    spawnImpl,
    processRunner = runProcess,
    tempRoot = os.tmpdir(),
    signal = null,
  } = {},
) {
  const cleanUrl = cleanGithubCloneUrl(cloneUrl);
  const credential = await createGitCredentialTransport(
    token && isGithubHttpsUrl(cleanUrl) ? token : null,
    { tempRoot },
  );
  try {
    const args = [
      '-c',
      'credential.helper=',
    ];
    if (credential.helperConfig) {
      args.push('-c', `credential.helper=${credential.helperConfig}`);
    }
    args.push(
      '-c',
      'credential.useHttpPath=false',
      'clone',
      '--depth',
      '1',
      '--filter=blob:none',
      '--no-tags',
      cleanUrl,
      targetDir,
    );

    const secretForms = [token, token ? encodeURIComponent(token) : ''];
    let result;
    try {
      result = await processRunner('git', args, {
        timeoutMs,
        signal,
        spawnImpl,
        spawnOpts: {
          stdio: ['ignore', 'pipe', 'pipe'],
          env: gitCloneEnv(),
        },
        stdoutMaxBytes: 2 * 1024 * 1024,
        stderrMaxBytes: 512 * 1024,
        label: 'git clone',
      });
    } catch (error) {
      if (error?.result) {
        error.result.stdout = redactGitCloneSecret(error.result.stdout, secretForms);
        error.result.stderr = redactGitCloneSecret(error.result.stderr, secretForms);
      }
      error.message = redactGitCloneSecret(error?.message || String(error), secretForms);
      throw error;
    }

    const stdout = redactGitCloneSecret(result.stdout, secretForms);
    const stderr = redactGitCloneSecret(result.stderr, secretForms);
    if (result.code === 0) {
      return { ...result, ok: true, stdout, stderr };
    }

    const mixed = (stderr || stdout || '').slice(0, 400);
    let message = `git clone falhou (${result.code}): ${mixed}`;
    if (
      !token &&
      /authentication failed|could not read username|terminal prompts disabled|403|401/i.test(mixed)
    ) {
      message += ' — define GITHUB_TOKEN no .env (PAT com scope repo) e reinicia o servidor';
    }
    const error = new Error(message);
    error.result = { ...result, stdout, stderr };
    throw error;
  } finally {
    await credential.cleanup();
  }
}

function throwIfAborted(signal, label = 'GitHub clone') {
  if (!signal?.aborted) return;
  const cause = signal.reason instanceof Error ? signal.reason : null;
  const error = new Error(
    `${label} cancelado${cause?.message ? `: ${cause.message}` : ''}`,
    cause ? { cause } : undefined,
  );
  error.name = 'AbortError';
  error.code = 'PROCESS_ABORTED';
  throw error;
}

function isProcessAbort(error) {
  return error?.name === 'AbortError' || error?.code === 'PROCESS_ABORTED';
}

async function calcDirSizeBytes(dirPath, capBytes, signal = null) {
  let total = 0;
  const stack = [dirPath];
  while (stack.length) {
    throwIfAborted(signal);
    const current = stack.pop();
    const entries = await fs.readdir(current, { withFileTypes: true });
    for (const entry of entries) {
      throwIfAborted(signal);
      const full = path.join(current, entry.name);
      if (entry.isSymbolicLink()) continue;
      if (entry.isDirectory()) {
        stack.push(full);
        continue;
      }
      if (!entry.isFile()) continue;
      const st = await fs.stat(full);
      total += st.size || 0;
      if (total > capBytes) return total;
    }
  }
  return total;
}

export async function pruneOldCloneDirs(baseDir, retentionMs, log = null) {
  if (!(await dirExists(baseDir))) return { scanned: 0, removed: 0 };
  const now = Date.now();
  const entries = await fs.readdir(baseDir, { withFileTypes: true });
  let scanned = 0;
  let removed = 0;
  for (const entry of entries) {
    if (!entry.isDirectory()) continue;
    scanned += 1;
    const full = path.join(baseDir, entry.name);
    try {
      const st = await fs.stat(full);
      if (now - st.mtimeMs <= retentionMs) continue;
      await fs.rm(full, { recursive: true, force: true });
      removed += 1;
    } catch (e) {
      if (typeof log === 'function') log(`Clone cleanup falhou em ${entry.name}: ${e.message}`, 'warn');
    }
  }
  return { scanned, removed };
}

export async function cloneGithubReposForTarget({
  targetDomain,
  repos,
  log = null,
  signal = null,
} = {}) {
  throwIfAborted(signal);
  const cfg = githubCloneConfig();
  if (!cfg.enabled) return { ok: true, skipped: true, reason: 'disabled' };
  const baseDir = path.resolve(process.cwd(), cfg.cloneDir);
  await ensureDir(baseDir);
  throwIfAborted(signal);

  const cleanup = await pruneOldCloneDirs(baseDir, cfg.retentionMs, log);
  throwIfAborted(signal);
  if (typeof log === 'function' && cleanup.removed > 0) {
    log(`Clone cleanup: ${cleanup.removed} pasta(s) removida(s) por retenção`, 'info');
  }

  const selected = Array.isArray(repos) ? repos.slice(0, cfg.maxRepos) : [];
  const cloned = [];
  const failed = [];
  const authToken = githubCloneAuthToken();

  if (typeof log === 'function' && selected.length) {
    if (authToken) {
      log('Clone GitHub: credencial configurada por arquivo temporário restrito — git clone sem prompt', 'info');
    } else {
      log(
        'Clone GitHub: GITHUB_TOKEN ausente — repos privados falharão sem abrir prompt interativo.',
        'warn',
      );
    }
  }

  for (const repo of selected) {
    throwIfAborted(signal);
    const fullName = String(repo.full_name || '').trim();
    const cloneUrl = cleanGithubCloneUrl(repo.clone_url);
    if (!fullName || !cloneUrl) continue;
    const repoDir = buildRepoCloneDir(baseDir, targetDomain, fullName);
    try {
      await runGitClone(cloneUrl, repoDir, cfg.cloneTimeoutMs, {
        token: authToken,
        signal,
      });
      const sizeBytes = await calcDirSizeBytes(repoDir, cfg.maxSizeBytes, signal);
      if (sizeBytes > cfg.maxSizeBytes) {
        await fs.rm(repoDir, { recursive: true, force: true });
        throw new Error(`repo acima do limite (${Math.round(sizeBytes / (1024 * 1024))}MB)`);
      }
      cloned.push({
        full_name: fullName,
        clone_url: cloneUrl,
        html_url: githubRepoHtmlUrl(fullName),
        local_path: repoDir,
        size_bytes: sizeBytes,
      });
    } catch (e) {
      try {
        await fs.rm(repoDir, { recursive: true, force: true });
      } catch {
        /* ignore */
      }
      if (isProcessAbort(e)) throw e;
      failed.push({
        full_name: fullName,
        clone_url: cloneUrl,
        html_url: githubRepoHtmlUrl(fullName),
        error: e?.message || String(e),
      });
    }
  }

  return {
    ok: true,
    base_dir: baseDir,
    retention_ms: cfg.retentionMs,
    max_repos: cfg.maxRepos,
    cloned,
    failed,
    selected_count: selected.length,
  };
}
