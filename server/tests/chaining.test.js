import test from 'node:test';
import assert from 'node:assert/strict';
import { detectChains, applyChains, summarizeChains, chainsToMarkdown, CHAIN_RULES } from '../modules/chaining.mjs';

const findings = [
  { severity: 'low', category: 'subdomain-takeover', title: 'Subdomain takeover candidate (foo.acme.com)', description: 'CNAME to dangling S3' },
  { severity: 'info', category: 'cookie-scope', title: 'Cookie scope wildcard (.acme.com)', description: 'Set-Cookie domain=.acme.com' },
  { severity: 'medium', category: 'ssrf', title: 'SSRF in /preview' },
  { severity: 'info', category: 'cloud-imds', title: 'IMDS endpoint reference', evidence: { url: 'http://169.254.169.254/latest/meta-data/' } },
  { severity: 'high', category: 'secrets-leak', title: 'AWS access key in JS bundle' },
  { severity: 'low', category: 'cloud-s3-bucket', title: 'S3 bucket exposed' },
];

test('chaining: detecta takeover-to-ato', () => {
  const chains = detectChains(findings);
  assert.ok(chains.find((c) => c.id === 'takeover-to-ato'));
});

test('chaining: detecta ssrf-to-imds', () => {
  const chains = detectChains(findings);
  assert.ok(chains.find((c) => c.id === 'ssrf-to-imds'));
});

test('chaining: detecta leaked-secret-to-cloud-pivot', () => {
  const chains = detectChains(findings);
  assert.ok(chains.find((c) => c.id === 'leaked-secret-to-cloud-pivot'));
});

test('chaining: applyChains preserva findings originais e adiciona chain rows', () => {
  const run = { id: 1, target: 'acme.com', findings };
  const out = applyChains(run);
  assert.equal(out.findings.length >= findings.length + 1, true);
  assert.ok(out.chains.length > 0);
  assert.ok(out.findings.some((f) => f.chain === true));
});

test('chaining: summarizeChains agrega', () => {
  const chains = detectChains(findings);
  const s = summarizeChains(chains);
  assert.ok(s.total > 0);
  assert.ok(['critical', 'high'].includes(s.topSeverity));
});

test('chaining: chainsToMarkdown contém títulos', () => {
  const chains = detectChains(findings);
  const md = chainsToMarkdown(chains);
  assert.ok(md.includes('Attack chains'));
  assert.ok(md.includes('chain id'));
});

test('chaining: zero findings = zero chains', () => {
  assert.equal(detectChains([]).length, 0);
});

test('chaining: CHAIN_RULES tem ids únicos', () => {
  const ids = CHAIN_RULES.map((r) => r.id);
  assert.equal(new Set(ids).size, ids.length);
});
