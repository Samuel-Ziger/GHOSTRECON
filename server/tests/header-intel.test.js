import test from 'node:test';
import assert from 'node:assert/strict';
import {
  analyzeSuspiciousResponseHeaders,
  flattenResponseHeaderPairs,
} from '../modules/header-intel.js';

test('X-Powered-By gera achado de stack leak', () => {
  const pairs = [['X-Powered-By', 'PHP/8.2']];
  const hits = analyzeSuspiciousResponseHeaders(pairs, {
    pageUrl: 'https://www.example.com/',
    pageHost: 'www.example.com',
    primaryIpv4: '93.184.216.34',
  });
  assert.ok(hits.some((h) => h.value.includes('X-Powered-By')));
});

test('X-Forwarded-Host alternativo gera sugestão /etc/hosts com IP', () => {
  const pairs = [['X-Forwarded-Host', 'staging.internal.example']];
  const hits = analyzeSuspiciousResponseHeaders(pairs, {
    pageUrl: 'https://www.example.com/',
    pageHost: 'www.example.com',
    primaryIpv4: '93.184.216.34',
  });
  const v = hits.find((h) => h.meta.includes('/etc/hosts'));
  assert.ok(v);
  assert.match(v.meta, /93\.184\.216\.34/);
  assert.match(v.meta, /staging\.internal\.example/);
});

test('flattenResponseHeaderPairs aceita array de pares', () => {
  const flat = flattenResponseHeaderPairs([
    ['Server', 'nginx'],
    ['X-Test', 'a'],
  ]);
  assert.equal(flat.length, 2);
  assert.equal(flat[0][0], 'Server');
});
