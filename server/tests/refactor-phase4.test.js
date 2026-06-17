import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { normalizeModuleId, moduleEnabled } from '../modules/module-ids.mjs';
import {
  getRegistryEntry,
  getModulesForCategory,
  listModuleManifests,
  runModule,
} from '../modules/module-registry.mjs';
import { dispatchRegistryModule } from '../pipeline/dispatcher.mjs';
import { createPipelineContext } from '../pipeline/finding-context.mjs';

describe('refactor phase 4 — registry e dispatcher', () => {
  it('normalizeModuleId converte kebab para snake', () => {
    assert.equal(normalizeModuleId('cookie-session-audit'), 'cookie_session_audit');
    assert.equal(normalizeModuleId('cookie_session_audit'), 'cookie_session_audit');
  });

  it('moduleEnabled aceita aliases', () => {
    assert.equal(moduleEnabled(['csrf-flow-audit'], 'csrf_flow_audit'), true);
    assert.equal(moduleEnabled(['rdap'], 'cookie_session_audit'), false);
  });

  it('registry lote 1 tem run() para módulos com manifest', () => {
    const ids = [
      'cookie_session_audit',
      'csrf_flow_audit',
      'jwt_jwks_audit',
      'hpp_param_pollution',
      'email_security_deep',
      'secrets_context_ranker',
    ];
    for (const id of ids) {
      const e = getRegistryEntry(id);
      assert.ok(e?.manifest?.id, id);
      assert.equal(typeof e.run, 'function', `${id} run`);
    }
    assert.ok(getModulesForCategory('surface').length >= 8);
    assert.ok(listModuleManifests().length >= 10);
  });

  it('dispatchRegistryModule skip quando módulo inactivo', async () => {
    const pipes = [];
    const pctx = createPipelineContext({
      domain: 'example.com',
      emit: (e) => {
        if (e.type === 'pipe') pipes.push(e);
      },
    });
    const s = {
      ...pctx,
      modules: ['rdap'],
      probeResults: [],
      domain: 'example.com',
    };
    const ok = await dispatchRegistryModule(s, 'cookie_session_audit');
    assert.equal(ok, true);
    assert.ok(pipes.some((p) => p.name === 'cookie_session_audit' && p.state === 'skip'));
  });

  it('cookie_session_audit via runModule com probeResults vazio', async () => {
    const pctx = createPipelineContext({ domain: 'example.com', emit: () => {} });
    const s = { ...pctx, domain: 'example.com', modules: ['cookie_session_audit'], probeResults: [] };
    const out = await runModule('cookie_session_audit', s);
    assert.ok(Array.isArray(out.findings));
  });
});
