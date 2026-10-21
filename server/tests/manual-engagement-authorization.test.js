import test from 'node:test';
import assert from 'node:assert/strict';

import {
  buildManualAuthorizationEngagement,
  preRunChecklist,
} from '../modules/engagement.mjs';

const NOW = new Date('2026-08-22T12:00:00.000Z');

test('autorização manual fica curta, assinada e vinculada ao domínio declarado', () => {
  const engagement = buildManualAuthorizationEngagement({
    id: 'MANUAL-TEST-DOMAIN',
    target: 'https://Portal.Example.com/login',
    authorizationConfirmed: true,
    basis: 'explicit',
    includeSubdomains: true,
    exclusions: 'admin.portal.example.com, blocked.portal.example.com',
    operator: 'tester',
    now: NOW,
  });

  assert.equal(engagement.status, 'active');
  assert.equal(engagement.roeSigned, true);
  assert.deepEqual(engagement.scopeDomains, [
    'portal.example.com',
    '*.portal.example.com',
  ]);
  assert.deepEqual(engagement.scopeIps, []);
  assert.deepEqual(engagement.exclusions, [
    'admin.portal.example.com',
    'blocked.portal.example.com',
  ]);
  assert.equal(
    new Date(engagement.window.endsAt).getTime() - NOW.getTime(),
    8 * 60 * 60_000,
  );

  assert.equal(preRunChecklist({
    engagement,
    target: 'api.portal.example.com',
    modules: ['sqlmap'],
    intrusiveModules: ['sqlmap'],
    requireFormalAuthorization: true,
    now: NOW,
  }).ok, true);
  assert.equal(preRunChecklist({
    engagement,
    target: 'admin.portal.example.com',
    modules: ['sqlmap'],
    intrusiveModules: ['sqlmap'],
    requireFormalAuthorization: true,
    now: NOW,
  }).ok, false);
});

test('autorização manual de IP nunca cria wildcard e limita duração a 24 horas', () => {
  const engagement = buildManualAuthorizationEngagement({
    id: 'MANUAL-TEST-IP',
    target: '192.0.2.20',
    authorizationConfirmed: true,
    basis: 'lab',
    includeSubdomains: true,
    durationMs: 7 * 24 * 60 * 60_000,
    now: NOW,
  });

  assert.deepEqual(engagement.scopeDomains, []);
  assert.deepEqual(engagement.scopeIps, ['192.0.2.20']);
  assert.equal(
    new Date(engagement.window.endsAt).getTime() - NOW.getTime(),
    24 * 60 * 60_000,
  );
});

test('autorização manual falha sem declaração, base válida ou alvo válido', () => {
  assert.throws(
    () => buildManualAuthorizationEngagement({
      target: 'example.com',
      authorizationConfirmed: false,
      basis: 'owned',
    }),
    /confirmação explícita/,
  );
  assert.throws(
    () => buildManualAuthorizationEngagement({
      target: 'example.com',
      authorizationConfirmed: true,
      basis: 'unknown',
    }),
    /base de autorização inválida/,
  );
  assert.throws(
    () => buildManualAuthorizationEngagement({
      target: 'not a target',
      authorizationConfirmed: true,
      basis: 'owned',
    }),
    /inválido/,
  );
});
