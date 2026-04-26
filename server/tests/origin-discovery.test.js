import test from 'node:test';
import assert from 'node:assert/strict';
import { detectCdn, detectOriginCandidates, originDiscoveryToFindings, FORGOTTEN_SUBS } from '../modules/origin-discovery.mjs';

test('origin: detectCdn reconhece Cloudflare', () => {
  assert.equal(detectCdn('104.16.1.1'), 'cloudflare');
  assert.equal(detectCdn('172.67.10.1'), 'cloudflare');
});

test('origin: detectCdn reconhece Akamai/Fastly/CloudFront', () => {
  assert.equal(detectCdn('151.101.1.1'), 'fastly');
  assert.equal(detectCdn('54.230.10.10'), 'cloudfront');
});

test('origin: detectCdn null para IP normal', () => {
  assert.equal(detectCdn('1.2.3.4'), null);
  assert.equal(detectCdn('192.0.2.1'), null);
});

test('origin: detectOriginCandidates separa CDN vs candidates', () => {
  const r = detectOriginCandidates({
    apex: 'acme.com',
    subdomainIps: {
      'origin.acme.com': ['1.2.3.4'],     // candidate
      'www.acme.com': ['104.16.1.1'],     // cloudflare
      'old.acme.com': ['54.230.5.5'],     // cloudfront
      'staging.acme.com': ['198.51.100.1'], // candidate
    },
  });
  assert.equal(r.candidates.length, 2);
  assert.ok(r.candidates.find((c) => c.host === 'origin.acme.com'));
  assert.ok(r.candidates.find((c) => c.host === 'staging.acme.com'));
});

test('origin: originDiscoveryToFindings emite high', () => {
  const report = { apex: 'acme.com', candidates: [{ host: 'old.acme.com', ip: '1.2.3.4', reason: 'non-cdn-ip' }] };
  const f = originDiscoveryToFindings(report);
  assert.equal(f.length, 1);
  assert.equal(f[0].severity, 'high');
});

test('origin: FORGOTTEN_SUBS contém suspects clássicos', () => {
  for (const s of ['origin', 'staging', 'mail', 'old', 'admin-direct']) {
    assert.ok(FORGOTTEN_SUBS.includes(s));
  }
});
