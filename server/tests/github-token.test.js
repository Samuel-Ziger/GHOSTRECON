import test from 'node:test';
import assert from 'node:assert/strict';
import {
  githubCapabilities,
  githubTokenPreview,
  resolveGithubToken,
} from '../modules/github-token.mjs';

test('resolveGithubToken remove aspas e le GH_TOKEN', () => {
  assert.equal(resolveGithubToken({ GITHUB_TOKEN: '"ghp_quoted"' }), 'ghp_quoted');
  assert.equal(resolveGithubToken({ GH_TOKEN: 'ghp_alt' }), 'ghp_alt');
  assert.equal(resolveGithubToken({ GITHUB_TOKEN: '  ' }), '');
});

test('githubTokenPreview mascara token', () => {
  assert.equal(githubTokenPreview('ghp_abcdefghijklmnop'), 'ghp_…mnop');
  assert.equal(githubTokenPreview(''), null);
});

test('githubCapabilities reflete env', () => {
  const cap = githubCapabilities({ GITHUB_TOKEN: 'ghp_test1234567890' });
  assert.equal(cap.token_configured, true);
  assert.equal(cap.clone_auth, 'pat');
  assert.match(cap.token_preview, /ghp_/);
});
