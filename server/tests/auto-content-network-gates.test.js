import test from 'node:test';
import assert from 'node:assert/strict';

import { shouldFetchTargetJsInContentPhase } from '../pipeline/phases/content-discovery.mjs';

test('RUN manual preserva fetch de JS legado', () => {
  assert.equal(shouldFetchTargetJsInContentPhase({
    autoModeExecution: false,
    modules: [],
  }), true);
});

test('Auto não transforma fontes passivas de URL em fetch implícito ao alvo', () => {
  assert.equal(shouldFetchTargetJsInContentPhase({
    autoModeExecution: true,
    modules: ['wayback', 'common_crawl', 'websocket_recon'],
  }), false);
});

test('Auto permite fetch de JS somente quando análise target-touching foi aprovada', () => {
  for (const moduleId of [
    'client_auth_audit',
    'client_surface_audit',
    'firebase_audit',
    'js_intel',
  ]) {
    assert.equal(shouldFetchTargetJsInContentPhase({
      autoModeExecution: true,
      modules: [moduleId, 'http_probe'],
    }), true, moduleId);
  }
});
