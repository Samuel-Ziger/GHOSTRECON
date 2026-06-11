import test from 'node:test';
import assert from 'node:assert/strict';

import {
  auditCookieHeaders,
  parseSetCookie,
  splitSetCookieHeader,
} from '../modules/cookie-session-audit.mjs';
import { auditCsrfHtml, extractForms } from '../modules/csrf-flow-audit.mjs';
import { auditJwks } from '../modules/jwt-jwks-audit.mjs';
import {
  auditServiceWorkerScript,
  findServiceWorkerRegistrations,
} from '../modules/service-worker-audit.mjs';
import {
  collectOpenApiSummary,
  diffOpenApiSummaries,
} from '../modules/api-contract-diff.mjs';
import { listModuleManifests } from '../modules/module-registry.mjs';

test('cookie audit preserva Expires ao dividir Set-Cookie combinado', () => {
  const parts = splitSetCookieHeader('sid=abc; Expires=Wed, 21 Oct 2030 07:28:00 GMT; Path=/, theme=dark; Path=/');
  assert.equal(parts.length, 2);
  assert.equal(parseSetCookie(parts[0]).name, 'sid');
  assert.equal(parseSetCookie(parts[1]).name, 'theme');
});

test('cookie audit detecta sessao sem HttpOnly/Secure/SameSite', () => {
  const findings = auditCookieHeaders(['sessionid=abc; Path=/'], { url: 'https://app.example.com/' });
  assert.ok(findings.some((f) => /HttpOnly/.test(f.value)));
  assert.ok(findings.some((f) => /Secure/.test(f.value)));
  assert.ok(findings.some((f) => /SameSite/.test(f.value)));
});

test('csrf audit detecta form POST sem token', () => {
  const html = '<form method="post" action="/profile"><input name="email"></form>';
  const forms = extractForms(html, { url: 'https://app.example.com/settings' });
  assert.equal(forms[0].effectiveMethod, 'POST');
  const findings = auditCsrfHtml(html, { url: 'https://app.example.com/settings', hasSessionCookie: true });
  assert.equal(findings.length, 1);
  assert.equal(findings[0].type, 'csrf_flow');
});

test('csrf audit ignora form POST com token', () => {
  const html = '<form method="post"><input name="csrf_token"><input name="email"></form>';
  assert.equal(auditCsrfHtml(html, { url: 'https://app.example.com/' }).length, 0);
});

test('jwks audit detecta kid duplicado e chave simetrica publica', () => {
  const jwks = {
    keys: [
      { kty: 'oct', kid: 'shared', alg: 'HS256', k: 'abc' },
      { kty: 'RSA', kid: 'shared', n: 'AQAB', e: 'AQAB' },
    ],
  };
  const findings = auditJwks(jwks, { url: 'https://idp.example.com/jwks.json' });
  assert.ok(findings.some((f) => /kid duplicado/.test(f.value)));
  assert.ok(findings.some((f) => /simetrica/.test(f.value)));
  assert.ok(findings.some((f) => /HS256/.test(f.value)));
});

test('service worker audit encontra register e cache sensivel', () => {
  const regs = findServiceWorkerRegistrations(
    'navigator.serviceWorker.register("/sw.js", { scope: "/" })',
    { baseUrl: 'https://app.example.com/' },
  );
  assert.equal(regs[0].scriptUrl, 'https://app.example.com/sw.js');
  const findings = auditServiceWorkerScript(
    "self.addEventListener('fetch', e => e.respondWith(caches.open('v1').then(c => c.match('/api/me')))); self.skipWaiting(); clients.claim();",
    { url: regs[0].scriptUrl, registration: regs[0] },
  );
  assert.ok(findings.some((f) => /cachear respostas sensiveis/.test(f.value)));
  assert.ok(findings.some((f) => /controle imediatamente/.test(f.value)));
});

test('api contract diff resume e compara operacoes', () => {
  const prev = collectOpenApiSummary({
    openapi: '3.0.0',
    paths: {
      '/users': { get: { responses: { 200: {} }, security: [{ bearer: [] }] } },
      '/admin': { delete: { responses: { 204: {} }, security: [{ bearer: [] }] } },
    },
    components: { securitySchemes: { bearer: { type: 'http', scheme: 'bearer' } } },
  }, { url: 'https://api.example.com/openapi.json' });
  const cur = collectOpenApiSummary({
    openapi: '3.0.0',
    paths: {
      '/users': { get: { responses: { 200: {} }, security: [{ bearer: [] }] } },
      '/orders': { post: { responses: { 201: {} }, security: [] } },
    },
    components: { securitySchemes: {} },
  }, { url: 'https://api.example.com/openapi.json' });
  const diff = diffOpenApiSummaries(prev, cur);
  assert.equal(diff.changed, true);
  assert.deepEqual(diff.removedOperations, ['DELETE /admin']);
  assert.deepEqual(diff.addedOperations, ['POST /orders']);
  assert.deepEqual(diff.removedSecuritySchemes, ['bearer']);
  assert.equal(diff.operationsWithoutSecurityDelta, 1);
});

test('module registry lista primeiro lote', () => {
  const ids = listModuleManifests().map((m) => m.id).sort();
  assert.deepEqual(ids, [
    'api_contract_diff',
    'cookie_session_audit',
    'csrf_flow_audit',
    'jwt_jwks_audit',
    'service_worker_audit',
  ]);
});
