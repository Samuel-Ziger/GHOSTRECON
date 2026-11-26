import test from 'node:test';
import assert from 'node:assert/strict';
import { createPipelineState } from '../pipeline/pipeline-state.mjs';
import { buildOriginIndex, buildProbeUrls } from '../pipeline/phases/probe.mjs';
import { resolveVigoliumTarget } from '../../bridge/vigolium-config.mjs';

function stateFor(targetUrl) {
  return createPipelineState({
    domain: '147.135.87.82',
    targetUrl,
    exactMatch: false,
    modules: [],
    emit: () => {},
  });
}

test('pipeline preserva URL explícita e sela scheme/porta do host raiz', () => {
  const state = stateFor('http://147.135.87.82:30472/api');
  assert.equal(state.targetUrl, 'http://147.135.87.82:30472/api');
  assert.equal(state.targetOrigin, 'http://147.135.87.82:30472');
  assert.equal(state.targetPathname, '/api');
  assert.equal(state.targetBasePath, '/api');
  assert.equal(state.urlInScope('http://147.135.87.82:30472/other'), true);
  assert.equal(state.urlInScope('http://147.135.87.82/'), false);
  assert.equal(state.urlInScope('https://147.135.87.82:30472/'), false);
});

test('probe explícito não inventa 80/443 e bare host mantém fallback', () => {
  assert.deepEqual(buildProbeUrls({
    domain: '147.135.87.82',
    hosts: ['147.135.87.82'],
    targetUrl: 'http://147.135.87.82:30472/api',
  }), ['http://147.135.87.82:30472/api']);

  assert.deepEqual(buildProbeUrls({
    domain: 'example.test',
    hosts: ['example.test'],
  }), ['https://example.test/', 'http://example.test/']);
});

test('subdomínio descoberto continua com fallback sem degradar a raiz explícita', () => {
  assert.deepEqual(buildProbeUrls({
    domain: 'example.test',
    hosts: ['example.test', 'api.example.test'],
    targetUrl: 'http://example.test:8080/base',
  }), [
    'http://example.test:8080/base',
    'https://api.example.test/',
    'http://api.example.test/',
  ]);
});

test('origens preservam portas distintas e a base URL explícita', () => {
  const index = buildOriginIndex({
    probeResults: [
      { r: { ok: true, status: 200, url: 'https://example.test:8443/base/api' } },
      { r: { ok: true, status: 200, url: 'https://example.test:9443/' } },
    ],
    hostInScope: () => true,
    targetUrl: 'https://example.test:8443/base/api',
    targetOrigin: 'https://example.test:8443',
  });
  assert.deepEqual([...index.keys()], ['example.test:8443', 'example.test:9443']);
  assert.equal(index.get('example.test:8443').baseUrl, 'https://example.test:8443/base/api');
  assert.equal(index.get('example.test:8443').port, 8443);
  assert.equal(index.get('example.test:9443').port, 9443);
});

test('Vigolium prioriza URL explícita completa', () => {
  assert.equal(resolveVigoliumTarget({
    domain: '147.135.87.82',
    targetUrl: 'http://147.135.87.82:30472/api',
    originByHost: new Map([
      ['147.135.87.82', { origin: 'https://147.135.87.82/' }],
    ]),
  }), 'http://147.135.87.82:30472/api');
});

test('pipeline recusa targetUrl divergente do domain canónico', () => {
  assert.throws(() => createPipelineState({
    domain: 'example.test',
    targetUrl: 'https://other.test/',
    exactMatch: false,
    modules: [],
    emit: () => {},
  }), /não corresponde/);
});
