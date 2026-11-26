import test from 'node:test';
import assert from 'node:assert/strict';
import { parseReconTarget, hostLiteralForUrl, targetIsIp, isReconTargetStorageKey } from '../modules/recon-target.js';

test('parseReconTarget: IPv4', () => {
  const r = parseReconTarget('192.168.0.1');
  assert.equal(r.ok, true);
  assert.equal(r.target, '192.168.0.1');
  assert.equal(r.explicitUrl, false);
  assert.equal(r.targetUrl, null);
});

test('parseReconTarget: IPv6 URL', () => {
  const r = parseReconTarget('https://[2001:db8::1]/');
  assert.equal(r.ok, true);
  assert.equal(r.target, '2001:db8::1');
  assert.equal(r.origin, 'https://[2001:db8::1]');
  assert.equal(r.port, '443');
});

test('parseReconTarget: bare IPv6', () => {
  const r = parseReconTarget('2001:db8::2');
  assert.equal(r.ok, true);
  assert.equal(r.target, '2001:db8::2');
});

test('parseReconTarget: domain and URL', () => {
  assert.equal(parseReconTarget('Example.COM').target, 'example.com');
  const parsed = parseReconTarget('https://foo.bar/path');
  assert.equal(parsed.target, 'foo.bar');
  assert.equal(parsed.targetUrl, 'https://foo.bar/path');
  assert.equal(parsed.pathname, '/path');
});

test('parseReconTarget: preserva scheme, porta, path e query explícitos', () => {
  const parsed = parseReconTarget('http://147.135.87.82:30472/api/v1?view=full#ignored');
  assert.equal(parsed.ok, true);
  assert.equal(parsed.target, '147.135.87.82');
  assert.equal(parsed.scheme, 'http');
  assert.equal(parsed.port, '30472');
  assert.equal(parsed.authority, '147.135.87.82:30472');
  assert.equal(parsed.origin, 'http://147.135.87.82:30472');
  assert.equal(parsed.pathname, '/api/v1');
  assert.equal(parsed.targetUrl, 'http://147.135.87.82:30472/api/v1?view=full');
});

test('parseReconTarget: porta/path sem scheme falha fechado', () => {
  const parsed = parseReconTarget('example.com:8443/api');
  assert.equal(parsed.ok, false);
  assert.match(parsed.message, /URL HTTP\(S\) completa/);
});

test('parseReconTarget: recusa scheme e credenciais não suportados', () => {
  assert.equal(parseReconTarget('ftp://example.com/file').ok, false);
  assert.equal(parseReconTarget('https://user:pass@example.com/').ok, false);
});

test('hostLiteralForUrl brackets IPv6', () => {
  assert.equal(hostLiteralForUrl('2001:db8::1'), '[2001:db8::1]');
  assert.equal(hostLiteralForUrl('1.2.3.4'), '1.2.3.4');
});

test('targetIsIp', () => {
  assert.equal(targetIsIp('8.8.8.8'), true);
  assert.equal(targetIsIp('example.com'), false);
});

test('isReconTargetStorageKey', () => {
  assert.equal(isReconTargetStorageKey('10.0.0.1'), true);
  assert.equal(isReconTargetStorageKey('2001:db8::1'), true);
  assert.equal(isReconTargetStorageKey('x.example.org'), true);
  assert.equal(isReconTargetStorageKey(''), false);
});
