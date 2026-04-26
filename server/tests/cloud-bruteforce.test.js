import test from 'node:test';
import assert from 'node:assert/strict';
import { generateCandidates, buildProbeUrls, classifyProbe, bruteforceCloud } from '../modules/cloud-bruteforce.mjs';

test('cloud-bf: generateCandidates aplica permutações', () => {
  const c = generateCandidates('acme');
  assert.ok(c.includes('acme-prod'));
  assert.ok(c.includes('acme-backup'));
  assert.ok(c.includes('staging-acme'));
  assert.ok(c.length > 10);
});

test('cloud-bf: generateCandidates respeita max', () => {
  const c = generateCandidates('acme', { max: 5 });
  assert.equal(c.length, 5);
});

test('cloud-bf: buildProbeUrls gera URL por provider', () => {
  const u = buildProbeUrls(['mybucket'], { providers: ['s3', 'azure', 'gcs'] });
  assert.equal(u.length, 3);
  assert.ok(u.find((x) => x.url.includes('s3.amazonaws.com')));
  assert.ok(u.find((x) => x.url.includes('blob.core.windows.net')));
  assert.ok(u.find((x) => x.url.includes('storage.googleapis.com')));
});

test('cloud-bf: classifyProbe → public-listing em 200', () => {
  const r = classifyProbe({ status: 200 }, { provider: 's3', candidate: 'x', url: 'https://x.s3.amazonaws.com/' });
  assert.equal(r.kind, 'public-listing');
});

test('cloud-bf: classifyProbe → exists-private em 403 AccessDenied', () => {
  const r = classifyProbe({ status: 403, body: '<Error><Code>AccessDenied</Code></Error>' }, {});
  assert.equal(r.kind, 'exists-private');
});

test('cloud-bf: classifyProbe → not-found em 404 NoSuchBucket', () => {
  const r = classifyProbe({ status: 404, body: '<Error><Code>NoSuchBucket</Code></Error>' }, {});
  assert.equal(r.kind, 'not-found');
});

test('cloud-bf: bruteforceCloud emite finding pra public bucket', async () => {
  const exec = async ({ url }) => {
    if (url.includes('acme-public')) return { status: 200 };
    return { status: 404, body: '<NoSuchBucket />' };
  };
  const r = await bruteforceCloud({ name: 'acme-public', executor: exec, providers: ['s3'], maxConcurrency: 4 });
  assert.ok(r.findings.length >= 1);
  assert.equal(r.findings[0].category, 'cloud-public-bucket');
});

test('cloud-bf: bruteforceCloud requer executor', async () => {
  await assert.rejects(() => bruteforceCloud({ name: 'x' }), /executor obrigatório/);
});
