import assert from 'node:assert/strict';
import test from 'node:test';

import {
  RETIRED_MODULE_IDS,
  assertNoRetiredModules,
  createRetiredModulesError,
  findRetiredModuleIds,
} from '../modules/retired-modules.mjs';
import { registerAiRoutes } from '../routes/ai.mjs';

test('tombstones reconhecem IDs canónicos e aliases kebab-case', () => {
  assert.deepEqual(RETIRED_MODULE_IDS, ['shannon_whitebox', 'pentestgpt_validate']);
  assert.deepEqual(
    findRetiredModuleIds([
      'http_probe',
      'shannon-whitebox',
      'pentestgpt_validate',
      'SHANNON_WHITEBOX',
    ]),
    ['shannon_whitebox', 'pentestgpt_validate'],
  );
});

test('módulo aposentado falha explicitamente com 410 MODULE_RETIRED', () => {
  const error = createRetiredModulesError(['pentestgpt-validate']);
  assert.equal(error?.code, 'MODULE_RETIRED');
  assert.equal(error?.statusCode, 410);
  assert.deepEqual(error?.retiredModules, ['pentestgpt_validate']);
  assert.throws(
    () => assertNoRetiredModules(['shannon_whitebox']),
    (caught) => caught?.code === 'MODULE_RETIRED'
      && caught?.statusCode === 410
      && caught?.retiredModules?.[0] === 'shannon_whitebox',
  );
});

test('módulos ativos atravessam o gate sem alteração', () => {
  const modules = ['http_probe', 'github'];
  assert.equal(assertNoRetiredModules(modules), modules);
  assert.deepEqual(findRetiredModuleIds(modules), []);
});

test('rotas operacionais removidas não são mais registradas', () => {
  const paths = [];
  const app = {
    post(pathname) { paths.push(`POST ${pathname}`); },
    get(pathname) { paths.push(`GET ${pathname}`); },
  };
  registerAiRoutes(app, { validateCsrfToken: () => true });
  assert.ok(paths.includes('POST /api/ai-reports'));
  assert.equal(paths.includes('POST /api/shannon/prep'), false);
  assert.equal(paths.includes('POST /api/pentestgpt-ping'), false);
});
