import test from 'node:test';
import assert from 'node:assert/strict';
import {
  analyzeCorsResponses,
  collectCorsProbeUrls,
  EVIL_ORIGIN,
} from '../modules/cors-audit.mjs';
import { summarizeSecurityHeaderGaps } from '../modules/security-headers.js';
import { analyzeSuspiciousResponseHeaders } from '../modules/header-intel.js';

test('cors-audit: Origin maliciosa com HTTP 500 gera achado crítico', () => {
  const findings = analyzeCorsResponses({
    url: 'https://api.example.com/health',
    baseline: {
      status: 200,
      headers: {
        'access-control-allow-credentials': 'true',
        vary: 'Origin',
      },
      body: 'ok',
    },
    withOrigin: {
      status: 500,
      headers: { vary: 'Origin' },
      body: 'Internal Server Error',
    },
  });
  const hit = findings.find((f) => f.type === 'cors_origin_server_error');
  assert.ok(hit);
  assert.ok(hit.score >= 85);
});

test('cors-audit: wildcard ACAO gera achado alto', () => {
  const findings = analyzeCorsResponses({
    url: 'https://www.example.com/',
    baseline: { status: 200, headers: { 'access-control-allow-origin': '*' }, body: '<html/>' },
    withOrigin: { status: 200, headers: { 'access-control-allow-origin': '*' }, body: '<html/>' },
  });
  assert.ok(findings.find((f) => f.type === 'cors_wildcard'));
});

test('cors-audit: credenciais + Origin refletida', () => {
  const findings = analyzeCorsResponses({
    url: 'https://api.example.com/data',
    baseline: { status: 200, headers: {}, body: '{}' },
    withOrigin: {
      status: 200,
      headers: {
        'access-control-allow-origin': EVIL_ORIGIN,
        'access-control-allow-credentials': 'true',
      },
      body: '{}',
    },
  });
  assert.ok(findings.find((f) => f.type === 'cors_credentials_reflected'));
});

test('cors-audit: collectCorsProbeUrls inclui /health nos origins', () => {
  const urls = collectCorsProbeUrls({
    probeResults: [{ r: { ok: true, url: 'https://api.example.com/', status: 200 } }],
    domain: 'example.com',
  });
  assert.ok(urls.some((u) => u.includes('/health')));
});

test('security-headers: summarizeSecurityHeaderGaps com 3+ ausentes', () => {
  const gap = summarizeSecurityHeaderGaps('https://www.example.com/', {
    contentSecurityPolicy: '',
    xFrameOptions: '',
    xContentTypeOptions: '',
    referrerPolicy: '',
    strictTransportSecurity: 'max-age=31536000',
  });
  assert.ok(gap);
  assert.ok(gap.missing.length >= 3);
  assert.equal(gap.clickjackingRisk, true);
  assert.ok(gap.score >= 70);
});

test('header-intel: nginx com versão e SO é médio', () => {
  const hits = analyzeSuspiciousResponseHeaders(
    [['Server', 'nginx/1.24.0 (Ubuntu)']],
    { pageUrl: 'https://api.example.com/', pageHost: 'api.example.com' },
  );
  const v = hits.find((h) => h.value.includes('Versão do servidor'));
  assert.ok(v);
  assert.equal(v.prio, 'med');
  assert.ok(v.score >= 50);
});
