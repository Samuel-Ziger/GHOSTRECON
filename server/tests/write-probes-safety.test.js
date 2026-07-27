import test from 'node:test';
import assert from 'node:assert/strict';

import { runFirebaseAudit } from '../modules/firebase-audit.mjs';
import { runSupabaseAudit } from '../modules/supabase-audit.mjs';
import {
  probeRlsWriteTables,
  probeRpcExposure,
  resolveSupabaseAuthToken,
} from '../modules/supabase-rls-audit.mjs';

function fakeResponse(status = 403, body = '{}', headers = {}) {
  return { status, body, headers, error: null };
}

test('Supabase não cria sessão/conta nem usa service_role com writeProbes=false', async () => {
  const servicePayload = Buffer.from(JSON.stringify({
    role: 'service_role',
    iss: 'https://project.supabase.co/auth/v1',
  })).toString('base64url');
  const serviceJwt = `eyJhbGciOiJIUzI1NiJ9.${servicePayload}.signature`;
  const calls = [];

  const result = await resolveSupabaseAuthToken(
    'https://project.supabase.co',
    'anon-key',
    {
      bundleText: `const key = "${serviceJwt}"`,
      writeProbes: false,
      allowServiceRole: true,
      requestImpl: async (url, options = {}) => {
        calls.push({ url, method: options.method || 'GET' });
        return fakeResponse();
      },
    },
  );

  assert.equal(result.authToken, null);
  assert.equal(result.source, null);
  assert.equal(calls.some((call) => call.url.includes('/signup')), false);
});

test('helpers Supabase mutáveis falham fechados sem gate explícito', async () => {
  assert.deepEqual(
    await probeRlsWriteTables(
      'https://project.supabase.co',
      'anon-key',
      null,
      [{ table: 'profiles' }],
    ),
    [],
  );
  assert.deepEqual(
    await probeRpcExposure('https://project.supabase.co', 'anon-key', null),
    [],
  );
});

test('Supabase ignora env de write e mantém todos os caminhos mutáveis desligados', async () => {
  const previous = process.env.GHOSTRECON_SUPABASE_WRITE_PROBES;
  process.env.GHOSTRECON_SUPABASE_WRITE_PROBES = '1';
  const calls = [];

  try {
    const result = await runSupabaseAudit(
      {
        supabaseUrl: 'https://project.supabase.co',
        anonKey: 'anon-key',
        bundleText: '',
      },
      {
        authToken: 'header.payload.signature',
        writeProbes: false,
        requestImpl: async (url, options = {}) => {
          const method = options.method || 'GET';
          calls.push({ url, method, body: options.body || '' });
          if (url.includes('/auth/v1/token')) return fakeResponse(429);
          if (url.endsWith('/auth/v1/settings')) {
            return fakeResponse(200, JSON.stringify({
              disable_signup: false,
              external: { email: true },
            }));
          }
          return fakeResponse();
        },
      },
    );

    const forbidden = calls.filter(({ url, method }) =>
      url.includes('/auth/v1/signup')
      || url.includes('/auth/v1/recover')
      || url.includes('/rest/v1/rpc/')
      || ['PUT', 'PATCH', 'DELETE'].includes(method)
      || (method === 'POST' && /study_records|user_plans/.test(url)),
    );
    assert.deepEqual(forbidden, []);
    assert.equal(result.summary.writeProbes, false);
    assert.equal(result.summary.probeResults.writeProbes, 'disabled');
    assert.ok(result.findings.some((finding) =>
      finding.type === 'supabase_open_signup'
      && finding.meta?.verifiedByWriteProbe === false,
    ));
  } finally {
    if (previous === undefined) delete process.env.GHOSTRECON_SUPABASE_WRITE_PROBES;
    else process.env.GHOSTRECON_SUPABASE_WRITE_PROBES = previous;
  }
});

test('Firebase ignora env de write e não faz signup/PUT/PATCH/DELETE por padrão', async () => {
  const previous = process.env.GHOSTRECON_FIREBASE_WRITE_PROBES;
  process.env.GHOSTRECON_FIREBASE_WRITE_PROBES = '1';
  const calls = [];

  try {
    const result = await runFirebaseAudit(
      {
        apiKey: 'AIza' + 'A'.repeat(35),
        projectId: 'ghostrecon-test',
        targetOrigin: 'https://app.example.test',
      },
      {
        requestImpl: async (url, options = {}) => {
          calls.push({ url, method: options.method || 'GET' });
          return fakeResponse();
        },
      },
    );

    assert.equal(calls.some(({ url }) => url.includes('accounts:signUp')), false);
    assert.equal(calls.some(({ method }) => ['POST', 'PUT', 'PATCH', 'DELETE'].includes(method)), false);
    assert.equal(result.summary.writeProbes, false);
    assert.equal(result.summary.results.writeProbes, 'disabled');
  } finally {
    if (previous === undefined) delete process.env.GHOSTRECON_FIREBASE_WRITE_PROBES;
    else process.env.GHOSTRECON_FIREBASE_WRITE_PROBES = previous;
  }
});
