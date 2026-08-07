import test from 'node:test';
import assert from 'node:assert/strict';
import {
  expandVigoliumEffectiveModules,
  classifyVigoliumModuleRisk,
} from '../../bridge/vigolium-plan-expand.mjs';
import { listFixtureVigoliumModules } from './fixtures/vigolium-auto-catalog.mjs';
import {
  assertEngineScopeEnforcementAvailable,
  sealEngineScopePolicy,
} from '../modules/engine-scope-policy.mjs';

test('expansão Vigolium falha fechado em seleção vazia (nunca all)', async () => {
  await assert.rejects(
    expandVigoliumEffectiveModules({
      modules: [],
      moduleTags: [],
      only: null,
      listModulesImpl: listFixtureVigoliumModules,
    }),
    (error) => error?.code === 'VIGOLIUM_EMPTY_SELECTION',
  );
});

test('expansão Vigolium resolve IDs concretos e bloqueia write/credential no Auto', async () => {
  const ok = await expandVigoliumEffectiveModules({
    modules: ['headers', 'audit'],
    listModulesImpl: listFixtureVigoliumModules,
  });
  assert.deepEqual(ok.moduleIds, ['audit', 'headers']);
  assert.equal(classifyVigoliumModuleRisk({ id: 'upload_probe', tags: ['upload'] }), 'write');

  await assert.rejects(
    expandVigoliumEffectiveModules({
      modules: ['upload_probe'],
      listModulesImpl: listFixtureVigoliumModules,
    }),
    (error) => error?.code === 'VIGOLIUM_AUTO_BLOCKED_MODULES',
  );
  await assert.rejects(
    expandVigoliumEffectiveModules({
      modules: ['credential_spray'],
      listModulesImpl: listFixtureVigoliumModules,
    }),
    (error) => error?.code === 'VIGOLIUM_AUTO_BLOCKED_MODULES',
  );
});

test('tag inexistente e all são fail-closed', async () => {
  await assert.rejects(
    expandVigoliumEffectiveModules({
      moduleTags: ['tag-que-nao-existe'],
      listModulesImpl: listFixtureVigoliumModules,
    }),
    (error) => error?.code === 'VIGOLIUM_TAG_MISSING',
  );
  await assert.rejects(
    expandVigoliumEffectiveModules({
      modules: ['all'],
      listModulesImpl: listFixtureVigoliumModules,
    }),
    (error) => error?.code === 'VIGOLIUM_FILTER_ALL_FORBIDDEN',
  );
});

test('scopePolicy selada exige suporte declarado do engine', () => {
  const sealed = sealEngineScopePolicy({
    schemaVersion: 1,
    rootDomain: 'example.com',
    engagementId: 'ENG-1',
    authorizationBinding: 'a'.repeat(64),
    scopeDomains: ['example.com'],
    scopeIps: [],
    exclusions: [],
  });
  assert.match(sealed.policyHash, /^[a-f0-9]{64}$/);
  assert.throws(
    () => assertEngineScopeEnforcementAvailable({
      engine: 'vigolium',
      sealedPolicy: sealed,
      env: {},
      engineDeclaresSupport: false,
    }),
    (error) => error?.code === 'ENGINE_SCOPE_UNSUPPORTED',
  );
  assert.doesNotThrow(() => assertEngineScopeEnforcementAvailable({
    engine: 'vigolium',
    sealedPolicy: sealed,
    env: { GHOSTRECON_ENGINE_SCOPE_SUPPORT: '1' },
  }));
});
