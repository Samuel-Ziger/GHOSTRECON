import test from 'node:test';
import assert from 'node:assert/strict';
import {
  analyzeCorsResponses,
  collectCorsProbeUrls,
  EVIL_ORIGIN,
  SECOND_EVIL_ORIGIN,
  runCorsAudit,
} from '../modules/cors-audit.mjs';
import { summarizeSecurityHeaderGaps } from '../modules/security-headers.js';
import { analyzeSuspiciousResponseHeaders } from '../modules/header-intel.js';

test('cors-audit: HTTP 500 por Origin é erro operacional, não vulnerabilidade crítica', () => {
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
  assert.ok(hit.score < 30);
  assert.equal(hit.meta.evidenceStatus, 'operational_error');
});

test('cors-audit: wildcard ACAO gera inventário informativo', () => {
  const findings = analyzeCorsResponses({
    url: 'https://www.example.com/',
    baseline: { status: 200, headers: { 'access-control-allow-origin': '*' }, body: '<html/>' },
    withOrigin: { status: 200, headers: { 'access-control-allow-origin': '*' }, body: '<html/>' },
  });
  const hit = findings.find((f) => f.type === 'cors_wildcard');
  assert.ok(hit);
  assert.equal(hit.prio, 'info');
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
    withSecondOrigin: {
      status: 200,
      headers: {
        'access-control-allow-origin': SECOND_EVIL_ORIGIN,
        'access-control-allow-credentials': 'true',
      },
      body: '{}',
    },
  });
  assert.ok(findings.find((f) => f.type === 'cors_credentials_reflected'));
});

test('cors-audit: uma única reflexão não basta para acusar CORS arbitrário', () => {
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
  assert.equal(findings.some((f) => f.type === 'cors_credentials_reflected'), false);
});

test('cors-audit: collectCorsProbeUrls inclui /health nos origins', () => {
  const urls = collectCorsProbeUrls({
    probeResults: [{ r: { ok: true, url: 'https://api.example.com/', status: 200 } }],
    domain: 'example.com',
  });
  assert.ok(urls.some((u) => u.includes('/health')));
});

test('cors-audit: respeita cancelamento antes do primeiro probe', async () => {
  const controller = new AbortController();
  controller.abort(new Error('operator_cancelled'));
  await assert.rejects(() => runCorsAudit({
    probeResults: [{ r: { ok: true, url: 'https://api.example.com/', status: 200 } }],
    domain: 'example.com',
    signal: controller.signal,
  }), /operator_cancelled/);
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
  assert.equal(gap.clickjackingProtectionGap, true);
  assert.equal(gap.clickjackingRisk, false);
  assert.equal(gap.evidenceStatus, 'configuration_observation');
  assert.ok(gap.score <= 32);
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
