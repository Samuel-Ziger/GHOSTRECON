import test from 'node:test';
import assert from 'node:assert/strict';

import { validateToken } from '../modules/token-validator.js';

function jwt(payload) {
  const header = Buffer.from(JSON.stringify({ alg: 'HS256', typ: 'JWT' })).toString('base64url');
  const body = Buffer.from(JSON.stringify(payload)).toString('base64url');
  return `${header}.${body}.fixturesignature`;
}

test('secret-validation: API key genérica não é enviada por headers adivinhados', async () => {
  let calls = 0;
  const result = await validateToken('generic_api_key_fixture_123456789', 'https://api.example.test/data', {
    network: true,
    probeImpl: async () => {
      calls += 1;
      return { status: 200 };
    },
    urlAllowed: () => true,
  });
  assert.equal(calls, 0);
  assert.equal(result.status, 'unknown');
});

test('secret-validation: anon key Supabase é configuração pública, não segredo vivo', async () => {
  let calls = 0;
  const token = jwt({ role: 'anon', iss: 'https://project.example.test/auth/v1' });
  const result = await validateToken(token, 'https://project.example.test/app.js', {
    network: true,
    probeImpl: async () => {
      calls += 1;
      return { status: 200 };
    },
    urlAllowed: () => true,
  });
  assert.equal(calls, 0);
  assert.equal(result.status, 'public_configuration');
});

test('secret-validation: HTTP 403 não confirma token autenticado', async () => {
  const token = jwt({ role: 'authenticated', iss: 'https://project.supabase.co/auth/v1' });
  const result = await validateToken(token, 'https://project.example.test/app.js', {
    network: true,
    probeImpl: async () => ({ status: 403 }),
    urlAllowed: () => true,
  });
  assert.equal(result.status, 'probable');
  assert.equal(result.probes.length, 1);
});

test('secret-validation: /auth/v1/user HTTP 200 confirma JWT de usuário', async () => {
  const token = jwt({ role: 'authenticated', iss: 'https://project.supabase.co/auth/v1' });
  const result = await validateToken(token, 'https://project.example.test/app.js', {
    network: true,
    probeImpl: async (url) => ({ status: url.endsWith('/auth/v1/user') ? 200 : 500 }),
    urlAllowed: () => true,
  });
  assert.equal(result.status, 'valid');
  assert.equal(result.probes.length, 1);
});
