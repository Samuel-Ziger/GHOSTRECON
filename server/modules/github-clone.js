import fs from 'fs/promises';
import path from 'path';
import { spawn } from 'child_process';
import {
  githubTokenPreview,
  resolveGithubToken,
} from './github-token.mjs';

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

/** Injeta PAT em URLs github.com para clone não-interativo (repos privados / rate limit). */
export function withGithubAuthCloneUrl(cloneUrl, token = githubCloneAuthToken()) {
  const raw = String(cloneUrl || '').trim();
  if (!raw || !token) return raw;
  try {
    const u = new URL(raw);
    if (!/^github\.com$/i.test(u.hostname)) return raw;
    if (u.username || u.password) return raw;
    u.username = 'x-access-token';
    u.password = token;
    return u.toString();
  } catch {
    return raw;
  }
}

/** Remove credenciais de URLs/mensagens antes de logar ou devolver erro. */
export function redactGitCloneSecret(text) {
  return String(text || '')
    .replace(/x-access-token:[^@\s]+@/gi, 'x-access-token:***@')
    .replace(/https:\/\/[^@\s]+@github\.com/gi, 'https://***@github.com');
}

function gitCloneEnv() {
  return {
    ...process.env,
    GIT_TERMINAL_PROMPT: '0',
    GCM_INTERACTIVE: 'Never',
  };
}

function runGitClone(cloneUrl, targetDir, timeoutMs, { token = githubCloneAuthToken() } = {}) {
  const authUrl = withGithubAuthCloneUrl(cloneUrl, token);
  return new Promise((resolve, reject) => {
    const args = [
      '-c',
      'credential.helper=',
      '-c',
      'credential.useHttpPath=false',
      'clone',
      '--depth',
      '1',
      '--filter=blob:none',
      '--no-tags',
      authUrl,
      targetDir,
    ];
    const child = spawn('git', args, { stdio: ['ignore', 'pipe', 'pipe'], env: gitCloneEnv() });
    let stdout = '';
    let stderr = '';
    const timer = setTimeout(() => {
      child.kill('SIGKILL');
      reject(new Error(`timeout no clone (${timeoutMs}ms)`));
    }, timeoutMs);
    child.stdout.on('data', (d) => {
      stdout += String(d || '');
    });
    child.stderr.on('data', (d) => {
      stderr += String(d || '');
    });
    child.on('error', (err) => {
      clearTimeout(timer);
      reject(err);
    });
    child.on('close', (code) => {
      clearTimeout(timer);
      if (code === 0) resolve({ ok: true, stdout, stderr });
      else {
        const mixed = redactGitCloneSecret((stderr || stdout || '').slice(0, 400));
        let msg = `git clone falhou (${code}): ${mixed}`;
        if (
          !token &&
          /authentication failed|could not read username|terminal prompts disabled|403|401/i.test(mixed)
        ) {
          msg += ' — define GITHUB_TOKEN no .env (PAT com scope repo) e reinicia o servidor';
        }
        reject(new Error(msg));
      }
    });
  });
}

async function calcDirSizeBytes(dirPath, capBytes) {
  let total = 0;
  const stack = [dirPath];
  while (stack.length) {
    const current = stack.pop();
    const entries = await fs.readdir(current, { withFileTypes: true });
    for (const entry of entries) {
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

export async function cloneGithubReposForTarget({ targetDomain, repos, log = null } = {}) {
  const cfg = githubCloneConfig();
  if (!cfg.enabled) return { ok: true, skipped: true, reason: 'disabled' };
  const baseDir = path.resolve(process.cwd(), cfg.cloneDir);
  await ensureDir(baseDir);

  const cleanup = await pruneOldCloneDirs(baseDir, cfg.retentionMs, log);
  if (typeof log === 'function' && cleanup.removed > 0) {
    log(`Clone cleanup: ${cleanup.removed} pasta(s) removida(s) por retenção`, 'info');
  }

  const selected = Array.isArray(repos) ? repos.slice(0, cfg.maxRepos) : [];
  const cloned = [];
  const failed = [];
  const authToken = githubCloneAuthToken();

  if (typeof log === 'function' && selected.length) {
    if (authToken) {
      log(`Clone GitHub: PAT carregado (${githubTokenPreview(authToken)}) — git clone sem prompt`, 'info');
    } else {
      log(
        'Clone GitHub: GITHUB_TOKEN ausente no processo Node — git pode pedir user/senha no terminal e travar o recon. Confira .env e reinicie npm start.',
        'warn',
      );
    }
  }

  for (const repo of selected) {
    const fullName = String(repo.full_name || '').trim();
    const cloneUrl = String(repo.clone_url || '').trim();
    if (!fullName || !cloneUrl) continue;
    const repoDir = buildRepoCloneDir(baseDir, targetDomain, fullName);
    try {
      await runGitClone(cloneUrl, repoDir, cfg.cloneTimeoutMs);
      const sizeBytes = await calcDirSizeBytes(repoDir, cfg.maxSizeBytes);
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
