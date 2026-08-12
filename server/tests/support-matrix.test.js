import test from 'node:test';
import assert from 'node:assert/strict';

import {
  buildSupportMatrix,
  listDeclaredSupportComponents,
  SUPPORT_MATRIX_SCHEMA_VERSION,
} from '../app/support-matrix.mjs';

test('matriz de suporte tem IDs únicos, níveis e políticas tipados', () => {
  const declared = listDeclaredSupportComponents();
  assert.equal(new Set(declared.map((item) => item.id)).size, declared.length);
  assert.ok(declared.every((item) => ['stable', 'beta', 'experimental', 'external'].includes(item.level)));
  assert.ok(declared.every((item) => ['enabled', 'opt_in', 'disabled'].includes(item.policy)));
});

test('matriz mantém recursos intrusivos experimentais desabilitados por política', () => {
  const matrix = buildSupportMatrix();
  assert.equal(matrix.schemaVersion, SUPPORT_MATRIX_SCHEMA_VERSION);
  assert.match(matrix.policyNotice, /não concede autorização/);
  assert.equal(matrix.components.find((item) => item.id === 'core')?.readiness.state, 'available');
  assert.equal(matrix.components.find((item) => item.id === 'auto_authorized')?.policy, 'disabled');
  assert.equal(matrix.components.find((item) => item.id === 'forge')?.policy, 'disabled');
});

test('readiness observada é informativa e preserva a política declarada', () => {
  const matrix = buildSupportMatrix({
    observed: {
      vigolium: { installed: true, reachable: false },
      hexstrike: { ok: false, message: 'offline' },
    },
  });
  const vigolium = matrix.components.find((item) => item.id === 'vigolium');
  const hexstrike = matrix.components.find((item) => item.id === 'hexstrike');
  assert.deepEqual(vigolium.readiness, { state: 'degraded', reason: 'installed_not_reachable' });
  assert.equal(vigolium.policy, 'opt_in');
  assert.deepEqual(hexstrike.readiness, { state: 'unavailable', reason: 'offline' });
  assert.equal(hexstrike.policy, 'opt_in');
});
