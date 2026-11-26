import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, writeFile, symlink } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import {
  auditArtifactContent,
  runArtifactSafetyAudit,
} from '../modules/artifact-safety-audit.mjs';

const JWT = 'eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJmaXh0dXJlLXVzZXIifQ.abcdefghijklmnopqrstuvwxyz123456';

test('bloqueia JWT/PAN/CVV/AWS sem reproduzir valores', () => {
  const raw = JSON.stringify({
    authorization: `Bearer ${JWT}`,
    card_number: '4111111111111111',
    cvv: '123',
    AWS_ACCESS_KEY_ID: 'AKIAIOSFODNN7EXAMPLE',
    AWS_SECRET_ACCESS_KEY: 'synthetic-secret-access-key-1234567890',
    AWS_SESSION_TOKEN: 'fixture-session-token-not-real',
  });
  const result = auditArtifactContent(raw);
  assert.equal(result.publicationAllowed, false);
  assert.ok(result.classes.jwt || result.classes.bearer);
  assert.equal(result.classes.pan, 1);
  assert.equal(result.classes.cvv, 1);
  assert.equal(result.classes.aws_access_key, 1);
  assert.equal(result.classes.aws_secret_access_key, 1);
  const serialized = JSON.stringify(result);
  assert.doesNotMatch(serialized, /4111111111111111|fixture-session-token|eyJhbGci/);
});

test('detecta segredo AWS dentro de wrapper base64url', () => {
  const encoded = Buffer.from('AWS_SECRET_ACCESS_KEY=synthetic-secret-access-key-1234567890')
    .toString('base64url');
  const result = auditArtifactContent(JSON.stringify({ raw_b64url: encoded }));
  assert.equal(result.publicationAllowed, false);
  assert.equal(result.classes.aws_secret_access_key, 1);
  assert.ok(result.leaks.some((item) => item.provenance === 'base64_decoded'));
});

test('detecta segredo dentro de campo base64', () => {
  const encoded = Buffer.from(`Authorization: Bearer ${JWT}`).toString('base64');
  const result = auditArtifactContent(JSON.stringify({ raw_b64: encoded }));
  assert.equal(result.publicationAllowed, false);
  assert.ok(result.leaks.some((item) => item.provenance === 'base64_decoded'));
  assert.doesNotMatch(JSON.stringify(result), new RegExp(encoded));
});

test('account/ARN/bucket e order id não são confundidos com segredo', () => {
  const result = auditArtifactContent(JSON.stringify({
    account_id: '123456789012',
    arn: 'arn:aws:lambda:us-east-1:123456789012:function:orders',
    bucket: 'orders-lab-bucket',
    order_id: '4111111111111111',
  }));
  assert.equal(result.safe, true);
});

test('runner restringe paths, recusa symlink e bloqueia publicação', async () => {
  const root = await mkdtemp(path.join(os.tmpdir(), 'ghost-artifact-audit-'));
  const safe = path.join(root, 'safe.json');
  const unsafe = path.join(root, 'unsafe.json');
  const link = path.join(root, 'link.json');
  await writeFile(safe, JSON.stringify({ bucket: 'public-metadata' }));
  await writeFile(unsafe, JSON.stringify({ token: JWT }));
  await symlink(safe, link);
  const result = await runArtifactSafetyAudit({ paths: [safe, unsafe, link], allowedRoot: root });
  assert.equal(result.publicationAllowed, false);
  assert.equal(result.state, 'blocked_sensitive_artifact');
  assert.equal(result.results.find((item) => item.artifact === link)?.error, 'unsupported_file_type');
});
