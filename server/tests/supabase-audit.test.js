import test from 'node:test';
import assert from 'node:assert/strict';
import {
  detectServiceRoleExposure,
  analyzeAnonKeyLifetime,
  probeRealtimeHints,
  SUPABASE_VULN_TAXONOMY,
  extractSupabaseCredentials,
} from '../modules/supabase-rls-audit.mjs';

const fakeAnonPayload = Buffer.from(JSON.stringify({ iss: 'supabase', role: 'anon', ref: 'abcdefghijklmnop' })).toString('base64url');
const fakeAnonJwt = `eyJhbGciOiJIUzI1NiJ9.${fakeAnonPayload}.sig`;
const fakeServiceJwt = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJvbGUiOiJzZXJ2aWNlX3JvbGUiLCJpYXQiOjE2MDAwMDAwMDAsImV4cCI6OTk5OTk5OTk5OTk5fQ.sig';
const fakeAuthPayload = Buffer.from(JSON.stringify({ iss: 'supabase', role: 'authenticated', sub: 'user-123', exp: 9999999999 })).toString('base64url');
const fakeAuthJwt = `eyJhbGciOiJIUzI1NiJ9.${fakeAuthPayload}.sig`;

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
  assert.equal(creds.serviceRoleKey, fakeServiceJwt);
  assert.equal(creds.authTokens.length, 1);
  assert.equal(creds.authTokens[0].sub, 'user-123');
});

test('supabase: detectServiceRoleExposure encontra service_role JWT', () => {
  const findings = detectServiceRoleExposure(`const key = "${fakeServiceJwt}";`);
  assert.ok(findings.find((f) => f.type === 'supabase_service_role_exposed'));
  assert.ok(findings[0].score >= 95);
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
  assert.ok(SUPABASE_VULN_TAXONOMY.supabase_rls_disabled_read.includes('RLS Desabilitado'));
  assert.ok(SUPABASE_VULN_TAXONOMY.supabase_service_role_exposed.includes('Exposição da chave Service Role'));
});
