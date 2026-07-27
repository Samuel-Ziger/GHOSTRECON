import test from 'node:test';
import assert from 'node:assert/strict';
import { EventEmitter } from 'node:events';
import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { PassThrough } from 'node:stream';
import {
  cleanGithubCloneUrl,
  createGitCredentialTransport,
  githubCloneAuthToken,
  redactGitCloneSecret,
  runGitClone,
  withGithubAuthCloneUrl,
} from '../modules/github-clone.js';

test('withGithubAuthCloneUrl mantém URL limpa mesmo quando recebe token', () => {
  const url = withGithubAuthCloneUrl('https://github.com/acme/repo.git', 'ghp_testtoken123');
  assert.equal(url, 'https://github.com/acme/repo.git');
});

test('withGithubAuthCloneUrl aceita token com aspas (via resolveGithubToken)', async () => {
  const { resolveGithubToken } = await import('../modules/github-token.mjs');
  const token = resolveGithubToken({ GITHUB_TOKEN: '"ghp_abc123"' });
  const url = withGithubAuthCloneUrl('https://github.com/acme/repo.git', token);
  assert.equal(url, 'https://github.com/acme/repo.git');
});

test('cleanGithubCloneUrl remove userinfo de URL autenticada', () => {
  const already = 'https://user:pass@github.com/a/b.git';
  assert.equal(cleanGithubCloneUrl(already), 'https://github.com/a/b.git');
  assert.equal(
    withGithubAuthCloneUrl('https://gitlab.com/a/b.git', 'ghp_x'),
    'https://gitlab.com/a/b.git',
  );
});

test('withGithubAuthCloneUrl sem token devolve URL original', () => {
  const raw = 'https://github.com/acme/repo.git';
  assert.equal(withGithubAuthCloneUrl(raw, ''), raw);
  assert.equal(withGithubAuthCloneUrl(raw, null), raw);
});

test('redactGitCloneSecret mascara credenciais', () => {
  const dirty =
    'fatal: https://x-access-token:ghp_secret@github.com/o/r.git authentication failed';
  const clean = redactGitCloneSecret(dirty);
  assert.doesNotMatch(clean, /ghp_secret/);
  assert.match(clean, /\*\*\*@github\.com/);
});

test('createGitCredentialTransport cria 0700/0600 e remove no cleanup', async () => {
  const tempRoot = await fs.mkdtemp(path.join(os.tmpdir(), 'ghostrecon-git-credential-test-'));
  const transport = await createGitCredentialTransport('ghp_synthetic_secret', { tempRoot });
  try {
    const value = await fs.readFile(transport.credentialFile, 'utf8');
    assert.match(value, /x-access-token/);
    assert.match(value, /ghp_synthetic_secret/);
    assert.doesNotMatch(transport.helperConfig, /ghp_synthetic_secret/);
    if (process.platform !== 'win32') {
      const dirMode = (await fs.stat(path.dirname(transport.credentialFile))).mode & 0o777;
      const fileMode = (await fs.stat(transport.credentialFile)).mode & 0o777;
      assert.equal(dirMode, 0o700);
      assert.equal(fileMode, 0o600);
    }
  } finally {
    const credentialFile = transport.credentialFile;
    await transport.cleanup();
    await assert.rejects(fs.access(credentialFile));
    await fs.rm(tempRoot, { recursive: true, force: true });
  }
});

test('runGitClone usa URL limpa, helper temporário e ambiente sem PAT', async () => {
  const tempRoot = await fs.mkdtemp(path.join(os.tmpdir(), 'ghostrecon-git-clone-test-'));
  const previousGithub = process.env.GITHUB_TOKEN;
  const previousGh = process.env.GH_TOKEN;
  process.env.GITHUB_TOKEN = 'ghp_parent_env_secret';
  process.env.GH_TOKEN = 'ghp_parent_alt_secret';
  let captured = null;
  const spawnImpl = (command, args, opts) => {
    const child = new EventEmitter();
    child.stdout = new PassThrough();
    child.stderr = new PassThrough();
    child.kill = () => true;
    captured = { command, args, opts };
    queueMicrotask(() => {
      child.stdout.end('remote output ghp_runtime_secret');
      child.emit('close', 0);
    });
    return child;
  };
  try {
    const result = await runGitClone(
      'https://old-user:old-pass@github.com/acme/repo.git',
      path.join(tempRoot, 'repo'),
      5_000,
      { token: 'ghp_runtime_secret', spawnImpl, tempRoot },
    );
    assert.equal(result.ok, true);
    assert.doesNotMatch(result.stdout, /ghp_runtime_secret/);
    assert.equal(captured.command, 'git');
    assert.ok(captured.args.includes('https://github.com/acme/repo.git'));
    assert.doesNotMatch(captured.args.join(' '), /ghp_runtime_secret|old-user|old-pass/);
    assert.equal(captured.opts.env.GITHUB_TOKEN, undefined);
    assert.equal(captured.opts.env.GH_TOKEN, undefined);
    const helper = captured.args.find((value) => String(value).startsWith('credential.helper=store '));
    assert.ok(helper);
    assert.doesNotMatch(helper, /ghp_runtime_secret/);
    const match = helper.match(/--file='([^']+)'/);
    assert.ok(match);
    await assert.rejects(fs.access(match[1]));
  } finally {
    if (previousGithub == null) delete process.env.GITHUB_TOKEN;
    else process.env.GITHUB_TOKEN = previousGithub;
    if (previousGh == null) delete process.env.GH_TOKEN;
    else process.env.GH_TOKEN = previousGh;
    await fs.rm(tempRoot, { recursive: true, force: true });
  }
});

test('runGitClone propaga cancelamento, encerra filho e remove helper temporário', async () => {
  const tempRoot = await fs.mkdtemp(path.join(os.tmpdir(), 'ghostrecon-git-abort-test-'));
  const controller = new AbortController();
  const killSignals = [];
  let helperFile = null;
  let notifySpawn;
  const spawned = new Promise((resolve) => {
    notifySpawn = resolve;
  });
  const spawnImpl = (_command, args) => {
    const child = new EventEmitter();
    child.pid = 4242;
    child.stdout = new PassThrough();
    child.stderr = new PassThrough();
    child.kill = (signal) => {
      killSignals.push(signal);
      queueMicrotask(() => child.emit('close', null, signal));
      return true;
    };
    const helper = args.find((value) => String(value).startsWith('credential.helper=store '));
    helperFile = helper?.match(/--file='([^']+)'/)?.[1] || null;
    notifySpawn();
    return child;
  };

  try {
    const pending = runGitClone(
      'https://github.com/acme/repo.git',
      path.join(tempRoot, 'repo'),
      30_000,
      {
        token: 'ghp_synthetic_abort_secret',
        spawnImpl,
        tempRoot,
        signal: controller.signal,
      },
    );
    await spawned;
    controller.abort(new Error('parar teste'));
    await assert.rejects(
      pending,
      (error) => error?.name === 'AbortError' && error?.code === 'PROCESS_ABORTED',
    );
    assert.ok(killSignals.includes('SIGTERM'));
    assert.ok(helperFile);
    await assert.rejects(fs.access(helperFile));
  } finally {
    await fs.rm(tempRoot, { recursive: true, force: true });
  }
});

test('githubCloneAuthToken le GITHUB_TOKEN ou GH_TOKEN', () => {
  const prevGh = process.env.GITHUB_TOKEN;
  const prevAlt = process.env.GH_TOKEN;
  delete process.env.GITHUB_TOKEN;
  delete process.env.GH_TOKEN;
  assert.equal(githubCloneAuthToken(), null);
  process.env.GH_TOKEN = 'ghp_from_gh';
  assert.equal(githubCloneAuthToken(), 'ghp_from_gh');
  process.env.GITHUB_TOKEN = 'ghp_primary';
  assert.equal(githubCloneAuthToken(), 'ghp_primary');
  if (prevGh === undefined) delete process.env.GITHUB_TOKEN;
  else process.env.GITHUB_TOKEN = prevGh;
  if (prevAlt === undefined) delete process.env.GH_TOKEN;
  else process.env.GH_TOKEN = prevAlt;
});
