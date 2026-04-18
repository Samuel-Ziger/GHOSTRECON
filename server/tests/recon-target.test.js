import test from 'node:test';
import assert from 'node:assert/strict';
import { parseReconTarget, hostLiteralForUrl, targetIsIp, isReconTargetStorageKey } from '../modules/recon-target.js';

test('parseReconTarget: IPv4', () => {
  const r = parseReconTarget('192.168.0.1');
  assert.equal(r.ok, true);
  assert.equal(r.target, '192.168.0.1');
});

test('parseReconTarget: IPv6 URL', () => {
  const r = parseReconTarget('https://[2001:db8::1]/');
  assert.equal(r.ok, true);
  assert.equal(r.target, '2001:db8::1');
});

test('parseReconTarget: bare IPv6', () => {
  const r = parseReconTarget('2001:db8::2');
  assert.equal(r.ok, true);
  assert.equal(r.target, '2001:db8::2');
});

test('parseReconTarget: domain and URL', () => {
  assert.equal(parseReconTarget('Example.COM').target, 'example.com');
  assert.equal(parseReconTarget('https://foo.bar/path').target, 'foo.bar');
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
