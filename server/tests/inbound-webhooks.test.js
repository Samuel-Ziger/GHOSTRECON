import test from 'node:test';
import assert from 'node:assert/strict';
import { normalizeInboundEvent } from '../modules/inbound-webhooks.js';

test('normalizeInboundEvent: nuclei payload', () => {
  const evt = normalizeInboundEvent('nuclei', {
    'template-id': 'cve-2021-44228-log4shell',
    'matched-at': 'https://api.example.com/hello',
    info: { severity: 'critical', name: 'Log4Shell probe' },
  });
  assert.equal(evt.kind, 'finding');
  assert.equal(evt.severity, 'critical');
  assert.equal(evt.host, 'api.example.com');
  assert.equal(evt.title, 'Log4Shell probe');
});

test('normalizeInboundEvent: subfinder payload', () => {
  const evt = normalizeInboundEvent('subfinder', { host: 'new.example.com' });
  assert.equal(evt.kind, 'subdomain');
  assert.equal(evt.host, 'new.example.com');
  assert.equal(evt.target, 'example.com');
});

test('normalizeInboundEvent: amass payload', () => {
  const evt = normalizeInboundEvent('amass', { name: 'x.example.com', addresses: [] });
  assert.equal(evt.kind, 'subdomain');
  assert.equal(evt.host, 'x.example.com');
});

test('normalizeInboundEvent: custom subdomain', () => {
  const evt = normalizeInboundEvent('custom', { subdomain: 'foo.example.com' });
  assert.equal(evt.kind, 'subdomain');
  assert.equal(evt.host, 'foo.example.com');
});

test('normalizeInboundEvent: custom finding', () => {
  const evt = normalizeInboundEvent('custom', {
    url: 'https://example.com/admin',
    severity: 'high',
    finding: 'exposed admin',
    target: 'example.com',
  });
  assert.equal(evt.kind, 'finding');
  assert.equal(evt.severity, 'high');
  assert.equal(evt.target, 'example.com');
});

test('normalizeInboundEvent: null para input vazio', () => {
  assert.equal(normalizeInboundEvent('x', null), null);
  assert.equal(normalizeInboundEvent('x', {}), null);
  assert.equal(normalizeInboundEvent('x', 'string'), null);
});
