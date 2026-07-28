import assert from 'node:assert/strict';
import test from 'node:test';

import {
  resolveVigoliumEffectiveConfig,
} from '../../bridge/vigolium-config.mjs';
import { createPipelineState } from '../pipeline/pipeline-state.mjs';

function basePipelineContext(vigoliumRuntimeConfig) {
  return {
    domain: 'lab.acme.test',
    exactMatch: false,
    modules: ['vigolium_dast'],
    emit: () => {},
    vigoliumRuntimeConfig,
  };
}

test('snapshot Vigolium congelado preserva vazio/false apesar de ambiente conflitante', (t) => {
  const keys = [
    'GHOSTRECON_ENGINE',
    'GHOSTRECON_VIGOLIUM_MODULES',
    'GHOSTRECON_VIGOLIUM_MODULE_TAGS',
    'GHOSTRECON_VIGOLIUM_AUTH_FILES',
    'GHOSTRECON_VIGOLIUM_AUTHS',
    'GHOSTRECON_VIGOLIUM_USE_CODEX',
    'GHOSTRECON_VIGOLIUM_HTML_REPORT',
  ];
  const previous = Object.fromEntries(keys.map((key) => [key, process.env[key]]));
  t.after(() => {
    for (const key of keys) {
      if (previous[key] == null) delete process.env[key];
      else process.env[key] = previous[key];
    }
  });
  Object.assign(process.env, {
    GHOSTRECON_ENGINE: 'go',
    GHOSTRECON_VIGOLIUM_MODULES: 'must_not_reappear',
    GHOSTRECON_VIGOLIUM_MODULE_TAGS: 'must_not_reappear',
    GHOSTRECON_VIGOLIUM_AUTH_FILES: '/private/must-not-reappear.json',
    GHOSTRECON_VIGOLIUM_AUTHS: 'admin:Cookie:must-not-reappear',
    GHOSTRECON_VIGOLIUM_USE_CODEX: '1',
    GHOSTRECON_VIGOLIUM_HTML_REPORT: '1',
  });

  const effective = resolveVigoliumEffectiveConfig({
    modules: [],
    engine: 'node',
    vigoliumModules: [],
    vigoliumModuleTags: [],
    vigoliumAuthFiles: [],
    vigoliumAuthEntries: [],
    vigoliumUseCodex: false,
    vigoliumHtmlReport: false,
    vigoliumVpsProfile: false,
  }, {
    env: {
      PATH: '/safe/bin',
      GHOSTRECON_ENGINE: 'node',
    },
  });
  const frozen = Object.freeze({
    ...effective,
    vigoliumChildEnv: Object.freeze({ PATH: '/safe/bin' }),
    vigoliumBinaryPath: null,
    vigoliumBinarySource: null,
    vigoliumExpectedIdentity: null,
    vigoliumExpectedSourceIdentity: null,
    vigoliumSourceAllowedRoots: Object.freeze([]),
    vigoliumExpectedAuthFileIdentities: Object.freeze([]),
    vigoliumAuthAllowedRoots: Object.freeze([]),
  });
  const state = createPipelineState(basePipelineContext(frozen));

  assert.equal(state.vigoliumRuntimeConfigFrozen, true);
  assert.equal(state.vigoliumRuntimeConfigVersion, 1);
  assert.equal(state.engineMode, 'node');
  assert.deepEqual(state.vigoliumModules, []);
  assert.deepEqual(state.vigoliumModuleTags, []);
  assert.deepEqual(state.vigoliumAuthFiles, []);
  assert.deepEqual(state.vigoliumAuthEntries, []);
  assert.equal(state.vigoliumUseCodex, false);
  assert.equal(state.vigoliumHtmlReport, false);
  assert.deepEqual(state.vigoliumChildEnv, { PATH: '/safe/bin' });
  assert.equal(state.vigoliumExpectedSourceIdentity, null);
  assert.deepEqual(state.vigoliumSourceAllowedRoots, []);
});

test('snapshot marcado frozen, mas incompleto ou com versão incompatível, falha fechado', () => {
  assert.throws(
    () => createPipelineState(basePipelineContext({
      vigoliumRuntimeConfigFrozen: true,
    })),
    (error) => error?.code === 'VIGOLIUM_RUNTIME_CONFIG_INVALID',
  );

  const effective = resolveVigoliumEffectiveConfig({}, { env: {} });
  assert.throws(
    () => createPipelineState(basePipelineContext({
      ...effective,
      vigoliumRuntimeConfigVersion: 999,
    })),
    (error) => error?.code === 'VIGOLIUM_RUNTIME_CONFIG_INVALID',
  );

  assert.throws(
    () => createPipelineState(basePipelineContext({
      ...resolveVigoliumEffectiveConfig({
        modules: ['vigolium_audit'],
        vigoliumAgent: 'audit',
        vigoliumSource: '/approved/source',
      }, { env: {} }),
      vigoliumChildEnv: {},
      vigoliumExpectedSourceIdentity: null,
      vigoliumSourceAllowedRoots: ['/approved'],
    })),
    (error) => (
      error?.code === 'VIGOLIUM_RUNTIME_CONFIG_INVALID'
      && /identidade da fonte local/.test(error.message)
    ),
  );
});
