import test from 'node:test';
import assert from 'node:assert/strict';
import { looksLikeLinuxIdOutput } from '../modules/webshell-probe.js';

test('looksLikeLinuxIdOutput: saída típica de id', () => {
  const body = 'uid=33(www-data) gid=33(www-data) groups=33(www-data)\n';
  assert.equal(looksLikeLinuxIdOutput(body, 'text/plain'), true);
});

test('looksLikeLinuxIdOutput: HTML sem uid rejeita', () => {
  const body = '<!DOCTYPE html><html><body><p>uid reference in css</p></body></html>';
  assert.equal(looksLikeLinuxIdOutput(body, 'text/html'), false);
});

test('looksLikeLinuxIdOutput: HTML com uid= aceita', () => {
  const body = '<pre>uid=0(root) gid=0(root) groups=0(root)</pre>';
  assert.equal(looksLikeLinuxIdOutput(body, 'text/html'), true);
});

test('looksLikeLinuxIdOutput: resposta curta rejeita', () => {
  assert.equal(looksLikeLinuxIdOutput('short', 'text/plain'), false);
});
