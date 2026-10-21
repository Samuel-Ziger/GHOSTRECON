import test from 'node:test';
import assert from 'node:assert/strict';
import {
  detectServiceRoleExposure,
  analyzeAnonKeyLifetime,
  probeRealtimeHints,
  SUPABASE_VULN_TAXONOMY,
  extractSupabaseCredentials,
  resolveSupabaseAuthToken,
  runSupabaseRlsAudit,
  validateSupabasePublicApiKey,
  validateSupabaseUserToken,
} from '../modules/supabase-rls-audit.mjs';
import { runSupabaseAudit } from '../modules/supabase-audit.mjs';
import {
  fingerprintLovable,
  _internals as lovableInternals,
} from '../modules/lovable-fingerprint.js';

const fakeAnonPayload = Buffer.from(JSON.stringify({ iss: 'supabase', role: 'anon', ref: 'abcdefghijklmnop' })).toString('base64url');
const fakeAnonJwt = `eyJhbGciOiJIUzI1NiJ9.${fakeAnonPayload}.sig`;
const fakeServiceJwt = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJvbGUiOiJzZXJ2aWNlX3JvbGUiLCJpYXQiOjE2MDAwMDAwMDAsImV4cCI6OTk5OTk5OTk5OTk5fQ.sig';
const fakeAuthPayload = Buffer.from(JSON.stringify({ iss: 'supabase', role: 'authenticated', sub: 'user-123', exp: 9999999999 })).toString('base64url');
const fakeAuthJwt = `eyJhbGciOiJIUzI1NiJ9.${fakeAuthPayload}.sig`;
const fakePublishableKey = 'sb_publishable_fixture_public_key_1234567890';

function userTokenFor(projectUrl = 'https://project.example.test') {
  const payload = Buffer.from(JSON.stringify({
    iss: `${projectUrl}/auth/v1`,
    role: 'authenticated',
    sub: 'fixture-user',
    exp: 9_999_999_999,
  })).toString('base64url');
  return `eyJhbGciOiJIUzI1NiJ9.${payload}.sig`;
}

test('supabase: extractSupabaseCredentials encontra URL e anon key no bundle', () => {
  const text = `const url = "https://abcdefghijklmnop.supabase.co"; const key = "${fakeAnonJwt}";`;
  const creds = extractSupabaseCredentials(text);
  assert.equal(creds.supabaseUrl, 'https://abcdefghijklmnop.supabase.co');
  assert.equal(creds.anonKey, fakeAnonJwt);
});

test('supabase: extractSupabaseCredentials deriva URL do ref no JWT', () => {
  const creds = extractSupabaseCredentials(`const key = "${fakeAnonJwt}";`);
  assert.equal(creds.supabaseUrl, 'https://abcdefghijklmnop.supabase.co');
  assert.equal(creds.anonKey, fakeAnonJwt);
});

test('supabase: extractSupabaseCredentials separa auth e service_role', () => {
  const text = `${fakeAnonJwt} ${fakeAuthJwt} ${fakeServiceJwt}`;
  const creds = extractSupabaseCredentials(text);
  assert.equal(creds.serviceRoleKey, null);
  assert.deepEqual(creds.authTokens, []);
  assert.equal(creds.authenticatedTokenCandidates, 1);
  assert.equal(creds.serviceRoleCandidates, 1);
});

test('supabase: chave operacional aceita somente publishable ou JWT legado role=anon', () => {
  assert.equal(
    validateSupabasePublicApiKey(fakePublishableKey, 'https://abcdefghijklmnop.supabase.co').ok,
    true,
  );
  assert.equal(
    validateSupabasePublicApiKey(fakeAnonJwt, 'https://abcdefghijklmnop.supabase.co').ok,
    true,
  );
  assert.equal(
    validateSupabasePublicApiKey(fakeAnonJwt, 'https://otherprojectref.supabase.co').reason,
    'anon_key_project_mismatch',
  );
  assert.equal(
    validateSupabasePublicApiKey(fakeServiceJwt, 'https://abcdefghijklmnop.supabase.co').reason,
    'service_role_refused',
  );
  assert.equal(
    validateSupabasePublicApiKey(fakeAuthJwt, 'https://abcdefghijklmnop.supabase.co').reason,
    'non_anon_jwt_refused',
  );
  assert.equal(
    validateSupabasePublicApiKey('sb_secret_fixture_privileged_123456', 'https://abcdefghijklmnop.supabase.co').reason,
    'secret_key_refused',
  );
});

test('supabase: extração reconhece publishable e nunca promove JWT privilegiado a anon key', () => {
  const modern = extractSupabaseCredentials(
    `const url="https://abcdefghijklmnop.supabase.co"; const key="${fakePublishableKey}";`,
  );
  assert.equal(modern.anonKey, fakePublishableKey);

  const privilegedOnly = extractSupabaseCredentials(
    `const url="https://abcdefghijklmnop.supabase.co"; ${fakeServiceJwt} ${fakeAuthJwt}`,
  );
  assert.equal(privilegedOnly.anonKey, null);
  assert.equal(privilegedOnly.serviceRoleCandidates, 1);
  assert.equal(privilegedOnly.authenticatedTokenCandidates, 1);
});

test('Lovable reporta service_role estático, mas não o reutiliza em requests', async () => {
  const servicePayload = Buffer.from(JSON.stringify({
    iss: 'supabase',
    role: 'service_role',
    ref: 'abcdefghijklmnop',
  })).toString('base64url');
  const serviceToken = `eyJhbGciOiJIUzI1NiJ9.${servicePayload}.${'s'.repeat(32)}`;
  const html = `<html><meta name="lovable"><script>
    const url="https://abcdefghijklmnop.supabase.co";
    const key="${serviceToken}";
  </script></html>`;
  const calls = [];
  const result = await fingerprintLovable('https://app.example.test/', {
    fetch: async (url) => {
      calls.push(String(url));
      return new Response(html, { status: 200, headers: { 'content-type': 'text/html' } });
    },
    probeMisconfig: false,
  });

  assert.equal(result.context.anonKey, null);
  assert.equal(calls.some((url) => url.includes('.supabase.co/')), false);
  assert.ok(result.findings.some((finding) => finding.type === 'supabase_service_role_exposed'));
});

test('runners Supabase recusam context.anonKey privilegiada antes de qualquer rede', async () => {
  for (const run of [
    () => runSupabaseAudit({
      supabaseUrl: 'https://abcdefghijklmnop.supabase.co',
      anonKey: fakeServiceJwt,
      bundleText: '',
    }, {
      urlAllowed: () => true,
      requestImpl: async () => { throw new Error('rede não deveria executar'); },
    }),
    () => runSupabaseRlsAudit({
      supabaseUrl: 'https://abcdefghijklmnop.supabase.co',
      anonKey: 'sb_secret_fixture_privileged_123456',
      bundleText: '',
    }, {
      urlAllowed: () => true,
      requestImpl: async () => { throw new Error('rede não deveria executar'); },
    }),
  ]) {
    const result = await run();
    assert.equal(result.summary.skipped, 'unsafe_or_invalid_public_api_key');
    assert.match(result.summary.apiKeyRejectedReason, /service_role|secret_key/);
  }
});

test('supabase: detectServiceRoleExposure encontra service_role JWT', () => {
  const findings = detectServiceRoleExposure(`const key = "${fakeServiceJwt}";`);
  assert.ok(findings.find((f) => f.type === 'supabase_service_role_exposed'));
  assert.equal(findings[0].score, 48);
  assert.equal(findings[0].meta.evidenceStatus, 'static_credential_candidate');
  assert.equal(findings[0].meta.credentialValidated, false);
  assert.equal(findings[0].cvss, null);
});

test('supabase: detectServiceRoleExposure ignora anon key conhecida', () => {
  const anon = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJvbGUiOiJhbm9uIn0.x';
  const findings = detectServiceRoleExposure(anon, { anonKey: anon });
  assert.equal(findings.length, 0);
});

test('supabase: detectServiceRoleExposure literal SUPABASE_SERVICE_ROLE', () => {
  const findings = detectServiceRoleExposure('const k = process.env.SUPABASE_SERVICE_ROLE_KEY = "sb_secret_abc123";');
  assert.ok(findings.length >= 1);
});

test('supabase: probeRealtimeHints detecta channel', () => {
  const findings = probeRealtimeHints('supabase.channel("public").on("postgres_changes", handler).subscribe();');
  assert.ok(findings.find((f) => f.type === 'supabase_realtime_hint'));
});

test('supabase: analyzeAnonKeyLifetime flag exp longa', () => {
  const exp = Math.floor(Date.now() / 1000) + 86400 * 365 * 20;
  const payload = Buffer.from(JSON.stringify({ role: 'anon', exp })).toString('base64url');
  const jwt = `header.${payload}.sig`;
  const f = analyzeAnonKeyLifetime(jwt);
  assert.ok(f);
  assert.equal(f.type, 'supabase_jwt_long_lived');
});

test('supabase: VULN_TAXONOMY mapeia RLS', () => {
  assert.ok(SUPABASE_VULN_TAXONOMY.supabase_rls_disabled_read.includes('Política de acesso não verificada'));
  assert.ok(SUPABASE_VULN_TAXONOMY.supabase_service_role_exposed.includes('Candidato a credencial Service Role'));
  assert.doesNotMatch(
    JSON.stringify(SUPABASE_VULN_TAXONOMY),
    /Signup Aberto Indevidamente|GraphQL sem Controle de Acesso|Edge Function sem autenticação/,
  );
});

test('supabase: tabela vazia com HTTP 200 não vira falha de RLS', async () => {
  const result = await runSupabaseRlsAudit(
    { supabaseUrl: 'https://project.example.test', anonKey: fakePublishableKey, bundleText: '' },
    {
      tables: ['profiles'],
      requestImpl: async (url) => {
        if (url.includes('/rest/v1/profiles')) return { status: 200, body: '[]', headers: {}, error: null };
        return { status: 403, body: '{}', headers: {}, error: null };
      },
      urlAllowed: () => true,
    },
  );
  assert.equal(result.findings.some((f) => f.type === 'supabase_rls_disabled_read'), false);
});

test('supabase: linhas reais com coluna sensível geram evidência observada', async () => {
  const result = await runSupabaseRlsAudit(
    { supabaseUrl: 'https://project.example.test', anonKey: fakePublishableKey, bundleText: '' },
    {
      tables: ['profiles'],
      requestImpl: async (url) => {
        if (url.includes('/rest/v1/profiles')) {
          return { status: 200, body: '[{"id":1,"email":"fixture@example.test"}]', headers: {}, error: null };
        }
        return { status: 403, body: '{}', headers: {}, error: null };
      },
      urlAllowed: () => true,
    },
  );
  const hit = result.findings.find((f) => f.type === 'supabase_rls_disabled_read');
  assert.ok(hit);
  assert.equal(hit.meta.evidenceStatus, 'observed_rows');
});

test('supabase: service_role explícito é recusado e token de usuário exige issuer do projeto', async () => {
  const service = await resolveSupabaseAuthToken(
    'https://project.example.test',
    'anon-key',
    { envToken: fakeServiceJwt },
  );
  assert.equal(service.authToken, null);
  assert.equal(service.rejectedReason, 'service_role_refused');

  const otherProject = await resolveSupabaseAuthToken(
    'https://project.example.test',
    'anon-key',
    { envToken: userTokenFor('https://other.example.test') },
  );
  assert.equal(otherProject.authToken, null);
  assert.equal(otherProject.rejectedReason, 'issuer_project_mismatch');
});

test('supabase: token de usuário exige exp numérico futuro', () => {
  const tokenWith = (extraClaims) => {
    const payload = Buffer.from(JSON.stringify({
      iss: 'https://project.example.test/auth/v1',
      role: 'authenticated',
      sub: 'fixture-user',
      ...extraClaims,
    })).toString('base64url');
    return `eyJhbGciOiJIUzI1NiJ9.${payload}.sig`;
  };
  assert.equal(
    validateSupabaseUserToken(tokenWith({}), 'https://project.example.test').reason,
    'token_exp_missing_or_invalid',
  );
  assert.equal(
    validateSupabaseUserToken(tokenWith({ exp: '9999999999' }), 'https://project.example.test').reason,
    'token_exp_missing_or_invalid',
  );
  assert.equal(
    validateSupabaseUserToken(
      tokenWith({ exp: 1_700_000_100 }),
      'https://project.example.test',
      { now: () => 1_700_000_000_000 },
    ).ok,
    true,
  );
});

test('supabase: token de usuário explícito é usado somente no passe read-only autenticado', async () => {
  const authToken = userTokenFor();
  const calls = [];
  const result = await runSupabaseAudit(
    {
      supabaseUrl: 'https://project.example.test',
      anonKey: fakePublishableKey,
      bundleText: '',
    },
    {
      authToken,
      tables: ['profiles'],
      urlAllowed: () => true,
      requestImpl: async (url, options = {}) => {
        calls.push({ url, authorization: options.headers?.Authorization || '' });
        if (url.includes('/rest/v1/profiles')) {
          return { status: 200, body: '[]', headers: {}, error: null };
        }
        if (url.endsWith('/auth/v1/settings')) {
          return { status: 200, body: '{}', headers: {}, error: null };
        }
        return { status: 403, body: '{}', headers: {}, error: null };
      },
    },
  );

  const tableCalls = calls.filter((call) => call.url.includes('/rest/v1/profiles'));
  assert.equal(tableCalls.some((call) => call.authorization === `Bearer ${fakePublishableKey}`), true);
  assert.equal(tableCalls.some((call) => call.authorization === `Bearer ${authToken}`), true);
  assert.equal(result.summary.authTokenPresent, true);
  assert.equal(result.summary.authTokenSource, 'operator_config');
  assert.equal(result.summary.probeResults.rlsAudit.rlsReadOutcomes[0].accessContext, 'anonymous');
  assert.equal(result.summary.probeResults.rlsAudit.rlsReadAuthenticatedOutcomes[0].accessContext, 'authenticated');
  assert.equal(result.findings.some((finding) => finding.type === 'supabase_open_signup'), false);
});

test('supabase: settings vazio não implica signup aberto', async () => {
  const findings = await (async () => {
    const result = await runSupabaseRlsAudit(
      { supabaseUrl: 'https://project.example.test', anonKey: fakePublishableKey },
      {
        tables: [],
        urlAllowed: () => true,
        requestImpl: async (url) => ({
          status: url.endsWith('/auth/v1/settings') ? 200 : 403,
          body: url.endsWith('/auth/v1/settings') ? '{}' : '{}',
          headers: {},
          error: null,
        }),
      },
    );
    return result.findings;
  })();
  assert.equal(findings.some((finding) => finding.type === 'supabase_open_signup'), false);
});

test('Lovable limita e valida nomes de tabelas antes do probe RLS', async () => {
  const calls = [];
  const tables = [
    ...Array.from({ length: 50 }, (_unused, index) => `table_${index}`),
    '../escape',
    'users?select=*',
    'bad/name',
    '',
  ];
  const rows = await lovableInternals.probeSupabaseTables({
    supabaseUrl: 'https://abcdefghijklmnop.supabase.co',
    anonKey: fakePublishableKey,
    tables,
    urlAllowed: () => true,
    fetchImpl: async (url) => {
      calls.push(String(url));
      return new Response('[{"id":1}]', {
        status: 200,
        headers: { 'content-type': 'application/json' },
      });
    },
  });
  assert.equal(calls.length, 40);
  assert.equal(rows.length, 40);
  assert.ok(calls.every((url) => /\/rest\/v1\/table_\d+\?select=/.test(url)));
  assert.ok(calls.every((url) => !/escape|users%3F|bad%2F/.test(url)));
});
