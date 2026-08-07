import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs/promises';

import {
  sealEngineScopePolicy,
  scopePolicyEnvBindings,
  writeSealedScopePolicyFile,
} from '../modules/engine-scope-policy.mjs';
import { frameSevenChildEnv } from '../integrations/frameseven-adapter.mjs';

test('writeSealedScopePolicyFile cria arquivo 0600 e bindings sem authorizationBinding', async () => {
  const sealed = sealEngineScopePolicy({
    schemaVersion: 1,
    rootDomain: 'example.test',
    engagementId: 'ENG-1',
    authorizationBinding: 'binding-secret',
    scopeDomains: ['example.test'],
    scopeIps: [],
    exclusions: ['out.example.test'],
  });
  const resource = await writeSealedScopePolicyFile(sealed);
  try {
    const text = await fs.readFile(resource.filePath, 'utf8');
    assert.match(text, /example\.test/);
    assert.doesNotMatch(text, /binding-secret/);
    const env = scopePolicyEnvBindings(sealed, { policyFile: resource.filePath });
    assert.equal(env.GHOSTRECON_SCOPE_POLICY_HASH, sealed.policyHash);
    assert.equal(env.GHOSTRECON_SCOPE_POLICY_FILE, resource.filePath);
    assert.doesNotMatch(env.GHOSTRECON_SCOPE_POLICY_JSON, /binding-secret/);
    const child = frameSevenChildEnv({
      PATH: '/bin',
      GITHUB_TOKEN: 'secret',
      ...env,
    });
    assert.equal(child.PATH, '/bin');
    assert.equal(child.GHOSTRECON_SCOPE_POLICY_HASH, sealed.policyHash);
    assert.equal(child.GITHUB_TOKEN, undefined);
  } finally {
    await resource.close();
  }
});
