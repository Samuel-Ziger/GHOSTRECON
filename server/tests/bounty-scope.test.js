import test from 'node:test';
import assert from 'node:assert/strict';
import os from 'node:os';
import path from 'node:path';
import {
  parseHackerOneScope, parseBugcrowdScope, parseIntigritiScope,
  applyScopeFilter, fingerprintFinding, recordSubmission, listSubmissions, dedupeFindings,
} from '../modules/bounty-scope.mjs';

function isolate() {
  const dir = path.join(os.tmpdir(), `gr-bounty-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`);
  process.env.GHOSTRECON_BOUNTY_DIR = dir;
  return dir;
}

test('bounty: parseHackerOneScope normaliza shape', () => {
  const json = { data: [
    { attributes: { asset_identifier: '*.acme.com', asset_type: 'WILDCARD', eligible_for_submission: true } },
    { attributes: { asset_identifier: 'old.acme.com', asset_type: 'URL', eligible_for_submission: false } },
  ]};
  const out = parseHackerOneScope(json);
  assert.equal(out.length, 2);
  assert.equal(out[0].asset, '*.acme.com');
  assert.equal(out[1].eligible, false);
});

test('bounty: parseBugcrowdScope captura in_scope', () => {
  const json = { target_groups: [{ in_scope: [{ uri: '*.acme.com', category: 'website' }] }] };
  const out = parseBugcrowdScope(json);
  assert.equal(out.length, 1);
  assert.equal(out[0].platform, 'bugcrowd');
});

test('bounty: parseIntigritiScope', () => {
  const json = { domains: [{ endpoint: '*.acme.com', tier: 'TIER1' }] };
  const out = parseIntigritiScope(json);
  assert.equal(out[0].asset, '*.acme.com');
  assert.equal(out[0].eligibleForBounty, true);
});

test('bounty: applyScopeFilter filtra in/out por wildcard', () => {
  const scope = [
    { eligible: true, asset: '*.acme.com' },
    { eligible: false, asset: 'old.acme.com' },
  ];
  const findings = [
    { title: 'a', evidence: { target: 'api.acme.com' } },
    { title: 'b', evidence: { target: 'old.acme.com' } },
    { title: 'c', evidence: { target: 'evil.com' } },
  ];
  const r = applyScopeFilter(findings, scope);
  assert.equal(r.inScope.length, 1);
  assert.equal(r.outOfScope.length, 2);
});

test('bounty: fingerprintFinding estável', () => {
  const f1 = { title: 'XSS', category: 'xss', evidence: { target: 'x.com' } };
  const f2 = { title: 'XSS', category: 'xss', evidence: { target: 'x.com' } };
  assert.equal(fingerprintFinding(f1), fingerprintFinding(f2));
});

test('bounty: dedupeFindings detecta duplicates', async () => {
  isolate();
  const f = { title: 'RCE', category: 'rce', evidence: { target: 'a.com' } };
  await recordSubmission({ finding: f, platform: 'h1', reportId: 'XYZ' });
  const dup = await dedupeFindings([f, { title: 'NewBug', category: 'sqli', evidence: { target: 'a.com' } }]);
  assert.equal(dup.duplicate.length, 1);
  assert.equal(dup.fresh.length, 1);
});

test('bounty: listSubmissions devolve histórico', async () => {
  isolate();
  await recordSubmission({ finding: { title: 'A', category: 'x', evidence: { target: 'a' } }, platform: 'h1', payout: 500 });
  const subs = await listSubmissions();
  assert.equal(subs.length, 1);
  assert.equal(subs[0].payout, 500);
});
