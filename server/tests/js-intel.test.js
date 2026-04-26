import test from 'node:test';
import assert from 'node:assert/strict';
import {
  extractEndpoints, extractPaths, extractSecrets, extractFeatureFlags,
  parseSourceMap, jsBundleToFindings,
} from '../modules/js-intel.mjs';

const sampleBundle = `
  const api = "https://api.acme.com/v2";
  fetch("/api/v1/users/123", { method: "GET" });
  axios.post("/admin/internal/users", body);
  const debugRoute = "/internal/debug/dump";
  const url = "/static.css";
  const KEY = "AKIAABCDEFGHIJKL1234";
  const ghpat = "ghp_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
  if (isEnabled("new-checkout-flow")) {}
  if (featureFlag("admin-tools-v2")) {}
`;

test('js-intel: extractEndpoints captura URLs de fetch/axios', () => {
  const e = extractEndpoints(sampleBundle);
  assert.ok(e.includes('/api/v1/users/123'));
  assert.ok(e.includes('/admin/internal/users'));
});

test('js-intel: extractPaths captura paths string mas pula assets', () => {
  const p = extractPaths(sampleBundle);
  assert.ok(p.includes('/internal/debug/dump'));
  assert.ok(!p.includes('/static.css'));
});

test('js-intel: extractSecrets detecta AWS access key + GitHub PAT', () => {
  const s = extractSecrets(sampleBundle);
  assert.ok(s.find((x) => x.id === 'aws-access-key'));
  assert.ok(s.find((x) => x.id === 'github-pat'));
});

test('js-intel: extractFeatureFlags captura nomes', () => {
  const flags = extractFeatureFlags(sampleBundle);
  assert.ok(flags.includes('new-checkout-flow'));
  assert.ok(flags.includes('admin-tools-v2'));
});

test('js-intel: parseSourceMap retorna sources internas', () => {
  const map = JSON.stringify({ version: 3, sources: ['webpack:///./src/admin/internal-api.ts', 'webpack:///./src/public.js'] });
  const out = parseSourceMap(map);
  assert.equal(out.sources.length, 2);
  assert.ok(out.internal.length >= 1);
});

test('js-intel: jsBundleToFindings emite secret + bundle finding', () => {
  const r = jsBundleToFindings(sampleBundle, { url: 'https://app.acme.com/main.js', target: 'acme.com' });
  assert.ok(r.findings.find((f) => f.category === 'secrets-leak'));
  assert.ok(r.findings.find((f) => f.category === 'js-bundle'));
  assert.ok(r.summary.secrets >= 2);
});

test('js-intel: bundle vazio devolve summary zerado', () => {
  const r = jsBundleToFindings('', {});
  assert.equal(r.findings.length, 0);
});
