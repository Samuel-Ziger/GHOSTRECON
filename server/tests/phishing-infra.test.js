/**
 * Phishing infra — parseSpf determinístico + auditCampaignDomain contra TLD
 * inexistente (tolerante a falhas DNS).
 *
 * compareFingerprints depende de rede — coberto por smoke manual, pulado aqui.
 */
import test from 'node:test';
import assert from 'node:assert/strict';
import { parseSpf, auditCampaignDomain } from '../modules/phishing-infra.mjs';

// ============================================================================
// parseSpf — pure, determinístico
// ============================================================================

test('parseSpf: registro simples com -all', () => {
  const p = parseSpf('v=spf1 ip4:1.2.3.0/24 -all');
  assert.equal(p.all, '-all');
  assert.deepEqual(p.ip4, ['1.2.3.0/24']);
  assert.deepEqual(p.includes, []);
});

test('parseSpf: include + ~all', () => {
  const p = parseSpf('v=spf1 include:_spf.google.com include:mailgun.org ~all');
  assert.deepEqual(p.includes, ['_spf.google.com', 'mailgun.org']);
  assert.equal(p.all, '~all');
});

test('parseSpf: +all permissivo', () => {
  const p = parseSpf('v=spf1 +all');
  assert.equal(p.all, '+all');
});

test('parseSpf: ?all neutral', () => {
  const p = parseSpf('v=spf1 mx ?all');
  assert.equal(p.all, '?all');
});

test('parseSpf: sem qualifier final', () => {
  const p = parseSpf('v=spf1 mx');
  assert.equal(p.all, null);
});

test('parseSpf: ip4 e ip6 coletados', () => {
  const p = parseSpf('v=spf1 ip4:10.0.0.0/8 ip6:2001:db8::/32 -all');
  assert.deepEqual(p.ip4, ['10.0.0.0/8']);
  assert.deepEqual(p.ip6, ['2001:db8::/32']);
});

test('parseSpf: whitespace extra tolerado', () => {
  const p = parseSpf('  v=spf1   mx   -all   ');
  assert.equal(p.all, '-all');
});

test('parseSpf: raw preservado', () => {
  const raw = 'v=spf1 a mx -all';
  const p = parseSpf(raw);
  assert.equal(p.raw, raw);
});

// ============================================================================
// auditCampaignDomain — contra domínio garantido inexistente
// ============================================================================

test('auditCampaignDomain: domínio inexistente produz findings sem throw', async () => {
  // TLD .invalid é reservado (RFC 2606) — resolvers devem falhar
  const r = await auditCampaignDomain('ghostrecon-canary-nope.invalid');
  assert.equal(r.domain, 'ghostrecon-canary-nope.invalid');
  assert.ok(Array.isArray(r.findings));
  assert.ok(r.findings.length > 0, 'domínio inválido deveria produzir pelo menos um finding');
  // sempre deveria mencionar NS ou MX ausente
  assert.ok(r.findings.some((f) => /NS|MX|SPF|DMARC/.test(f.title)));
});

test('auditCampaignDomain: summary tem shape esperado', async () => {
  const r = await auditCampaignDomain('ghostrecon-nope2.invalid');
  assert.ok(r.summary);
  assert.equal(r.summary.domain, 'ghostrecon-nope2.invalid');
  assert.ok('dns' in r.summary);
  assert.ok('dkim' in r.summary.dns || r.summary.dns.dkim === undefined);
});

test('auditCampaignDomain: domínio vazio falha cedo de forma controlada', async () => {
  // não deveria throw — apenas findings com DNS vazio
  const r = await auditCampaignDomain('');
  assert.ok(r);
  assert.ok(Array.isArray(r.findings));
});
