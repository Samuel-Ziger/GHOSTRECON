/**
 * Identity surface — OIDC/OAuth audit + cloud hints.
 */
import test from 'node:test';
import assert from 'node:assert/strict';
import {
  auditOidcMetadata, auditRedirectUris,
  detectCloudSurface, cloudSurfaceToFindings,
} from '../modules/identity-surface.mjs';

test('oidc: PKCE ausente → medium', () => {
  const f = auditOidcMetadata({ issuer: 'https://idp.x.com' }, { host: 'idp.x.com' });
  assert.ok(f.some((x) => /PKCE não declarado/.test(x.title)));
});

test('oidc: PKCE só com plain → low', () => {
  const f = auditOidcMetadata({
    issuer: 'https://idp.x.com',
    code_challenge_methods_supported: ['plain'],
  });
  assert.ok(f.some((x) => /plain/.test(x.title)));
});

test('oidc: PKCE S256 presente → sem finding', () => {
  const f = auditOidcMetadata({
    issuer: 'https://idp.x.com',
    code_challenge_methods_supported: ['S256'],
  });
  assert.ok(!f.some((x) => /PKCE/.test(x.title)));
});

test('oidc: public clients → low', () => {
  const f = auditOidcMetadata({
    issuer: 'https://i',
    code_challenge_methods_supported: ['S256'],
    token_endpoint_auth_methods_supported: ['none', 'client_secret_basic'],
  });
  assert.ok(f.some((x) => /Public clients/.test(x.title)));
});

test('oidc: alg none → high', () => {
  const f = auditOidcMetadata({
    issuer: 'https://i',
    code_challenge_methods_supported: ['S256'],
    id_token_signing_alg_values_supported: ['RS256', 'none'],
  });
  const weak = f.find((x) => /algoritmos/i.test(x.title) || /Algoritmos/.test(x.title));
  assert.ok(weak);
  assert.equal(weak.severity, 'high');
});

test('oidc: scopes admin → medium', () => {
  const f = auditOidcMetadata({
    issuer: 'https://i',
    code_challenge_methods_supported: ['S256'],
    scopes_supported: ['openid', 'admin', 'write:all'],
  });
  assert.ok(f.some((x) => /Scopes potentes/.test(x.title)));
});

test('oauth redirect: wildcard → high', () => {
  const f = auditRedirectUris(['https://acme.com/*'], { host: 'acme.com' });
  assert.equal(f[0].severity, 'high');
  assert.ok(f[0].title.includes('wildcard'));
});

test('oauth redirect: HTTP não-localhost → medium', () => {
  const f = auditRedirectUris(['http://public.com/cb']);
  assert.equal(f[0].severity, 'medium');
});

test('oauth redirect: localhost em prod → info', () => {
  const f = auditRedirectUris(['http://localhost:8080/cb']);
  assert.equal(f[0].severity, 'info');
});

test('cloud: detectCloudSurface S3', () => {
  const hints = detectCloudSurface('https://my-bucket.s3.amazonaws.com/');
  assert.ok(hints.some((h) => h.kind === 's3-bucket'));
});

test('cloud: detectCloudSurface Azure Blob', () => {
  const hints = detectCloudSurface('https://acct.blob.core.windows.net/container');
  assert.ok(hints.some((h) => h.kind === 'blob-storage'));
});

test('cloud: detectCloudSurface GCP GCS', () => {
  const hints = detectCloudSurface('https://storage.googleapis.com/bucket');
  assert.ok(hints.some((h) => h.kind === 'gcs'));
});

test('cloud: takeover candidate', () => {
  const hints = detectCloudSurface('https://acme.github.io');
  assert.ok(hints.some((h) => h.kind === 'takeover-candidate'));
});

test('cloud: IMDS reference', () => {
  const hints = detectCloudSurface('http://169.254.169.254/latest/meta-data/');
  assert.ok(hints.some((h) => h.kind === 'imds-target'));
});

test('cloud: cloudSurfaceToFindings agrega', () => {
  const findings = cloudSurfaceToFindings([
    'https://b.s3.amazonaws.com/', 'https://acme.github.io',
  ], { target: 'acme.com' });
  assert.equal(findings.length, 2);
  assert.ok(findings.find((f) => f.category.startsWith('cloud-')));
});

test('cloud: takeover-candidate gera severity low', () => {
  const fs = cloudSurfaceToFindings(['https://x.herokuapp.com'], { target: 'x' });
  assert.equal(fs[0].severity, 'low');
});
