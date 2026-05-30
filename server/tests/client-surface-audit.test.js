import test from 'node:test';
import assert from 'node:assert/strict';
import {
  auditJsSurface,
  auditHtmlSurface,
  auditHeaderSurface,
  mergeClientSurfaceFindings,
  VULN_TAXONOMY,
} from '../modules/client-surface-audit.mjs';
import { analyzeCspWeaknesses } from '../modules/security-headers.js';

test('client-surface: detecta sink innerHTML', () => {
  const { findings } = auditJsSurface('el.innerHTML = userInput + data;');
  assert.ok(findings.find((f) => f.type === 'client_dom_xss_sink'));
});

test('client-surface: detecta postMessage sem origin check', () => {
  const js = `window.addEventListener('message', function(e) { doAuth(e.data); });`;
  const { findings } = auditJsSurface(js);
  assert.ok(findings.find((f) => f.type === 'client_postmessage_no_origin'));
});

test('client-surface: detecta prototype pollution patterns', () => {
  const { findings } = auditJsSurface('Object.assign({}, JSON.parse(input)); obj.__proto__ = x;');
  assert.ok(findings.find((f) => f.type === 'client_prototype_pollution'));
});

test('client-surface: detecta JWT em localStorage', () => {
  const { findings } = auditJsSurface(`localStorage.setItem('access_token', token);`);
  assert.ok(findings.find((f) => f.type === 'client_jwt_in_storage'));
});

test('client-surface: HTML sem SRI em script externo', () => {
  const html = '<script src="https://cdn.example.com/lib.js"></script>';
  const { findings } = auditHtmlSurface(html, { url: 'https://app.example.com/', isHttps: true });
  assert.ok(findings.find((f) => f.type === 'client_sri_missing'));
});

test('client-surface: tabnabbing target=_blank sem noopener', () => {
  const html = '<a href="https://evil.com" target="_blank">x</a>';
  const { findings } = auditHtmlSurface(html);
  assert.ok(findings.find((f) => f.type === 'client_tabnabbing'));
});

test('client-surface: CSP unsafe-inline', () => {
  const { findings } = auditHeaderSurface({
    contentSecurityPolicy: "default-src 'self'; script-src 'self' 'unsafe-inline'",
  });
  assert.ok(findings.find((f) => f.type === 'client_csp_weak'));
});

test('security-headers: analyzeCspWeaknesses unsafe-eval', () => {
  const w = analyzeCspWeaknesses("script-src 'self' 'unsafe-eval'");
  assert.ok(w.some((x) => x.issue === 'unsafe-eval'));
});

test('client-surface: VULN_TAXONOMY mapeia categorias', () => {
  assert.ok(VULN_TAXONOMY.client_dom_xss_sink.includes('DOM XSS'));
  assert.ok(VULN_TAXONOMY.client_sri_missing.includes('Missing Subresource Integrity'));
});

test('client-surface: mergeClientSurfaceFindings deduplica', () => {
  const a = auditJsSurface('el.innerHTML=x');
  const b = auditJsSurface('el.innerHTML=y');
  const m = mergeClientSurfaceFindings([a, b]);
  assert.equal(m.filter((f) => f.type === 'client_dom_xss_sink').length, 1);
});
