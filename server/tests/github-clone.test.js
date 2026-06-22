import test from 'node:test';
import assert from 'node:assert/strict';
import {
  githubCloneAuthToken,
  redactGitCloneSecret,
  withGithubAuthCloneUrl,
} from '../modules/github-clone.js';

test('withGithubAuthCloneUrl injeta x-access-token em github.com', () => {
  const url = withGithubAuthCloneUrl('https://github.com/acme/repo.git', 'ghp_testtoken123');
  assert.equal(url, 'https://x-access-token:ghp_testtoken123@github.com/acme/repo.git');
});

test('withGithubAuthCloneUrl aceita token com aspas (via resolveGithubToken)', async () => {
  const { resolveGithubToken } = await import('../modules/github-token.mjs');
  const token = resolveGithubToken({ GITHUB_TOKEN: '"ghp_abc123"' });
  const url = withGithubAuthCloneUrl('https://github.com/acme/repo.git', token);
  assert.equal(url, 'https://x-access-token:ghp_abc123@github.com/acme/repo.git');
});

test('withGithubAuthCloneUrl nao altera URL ja autenticada ou nao-github', () => {
  const already = 'https://user:pass@github.com/a/b.git';
  assert.equal(withGithubAuthCloneUrl(already, 'ghp_x'), already);
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
