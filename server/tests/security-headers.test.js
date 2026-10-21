import test from 'node:test';
import assert from 'node:assert/strict';
import {
  analyzeCspWeaknesses,
  analyzePermissionsPolicyGaps,
  analyzeSecurityHeaders,
  summarizeSecurityHeaderGaps,
} from '../modules/security-headers.js';
import { snapshotSecurityHeaders } from '../modules/probe.js';

test('HTTPS sem HSTS gera achado', () => {
  const snap = {
    strictTransportSecurity: '',
    contentSecurityPolicy: 'default-src self',
    xFrameOptions: 'DENY',
    xContentTypeOptions: 'nosniff',
    referrerPolicy: 'no-referrer',
    permissionsPolicy: '',
    crossOriginOpenerPolicy: '',
    crossOriginEmbedderPolicy: '',
    server: 'nginx',
    setCookieSample: [],
  };
  const issues = analyzeSecurityHeaders('https://exemplo.com/', snap);
  assert.ok(issues.some((i) => i.text.includes('HSTS')));
});

test('HTTP não exige HSTS', () => {
  const snap = {
    strictTransportSecurity: '',
    contentSecurityPolicy: '',
    xFrameOptions: '',
    xContentTypeOptions: '',
    referrerPolicy: '',
    permissionsPolicy: '',
    crossOriginOpenerPolicy: '',
    crossOriginEmbedderPolicy: '',
    server: '',
    setCookieSample: [],
  };
  const issues = analyzeSecurityHeaders('http://exemplo.com/', snap);
  assert.ok(!issues.some((i) => i.text.includes('HSTS')));
});

test('security_headers não duplica a auditoria especializada de Set-Cookie', () => {
  const issues = analyzeSecurityHeaders('https://exemplo.com/', {
    strictTransportSecurity: 'max-age=31536000',
    contentSecurityPolicy: "default-src 'self'; frame-ancestors 'none'",
    xFrameOptions: 'DENY',
    xContentTypeOptions: 'nosniff',
    referrerPolicy: 'no-referrer',
    setCookieSample: ['session=opaque; Path=/'],
  });
  assert.equal(issues.some((issue) => issue.header === 'Set-Cookie'), false);
});

test('summarizeSecurityHeaderGaps emite composto com 3+ ausentes', () => {
  const gap = summarizeSecurityHeaderGaps('https://www.exemplo.com/', {
    contentSecurityPolicy: '',
    xFrameOptions: '',
    xContentTypeOptions: '',
    referrerPolicy: '',
    strictTransportSecurity: 'max-age=63072000',
  });
  assert.ok(gap);
  assert.ok(gap.missing.length >= 3);
  assert.ok(gap.score <= 32);
  assert.equal(gap.evidenceStatus, 'configuration_observation');
  assert.equal(gap.clickjackingProtectionGap, true);
  assert.equal(gap.clickjackingRisk, false);
});

test('snapshot preserva CSP aplicada, Report-Only e ocorrências oferecidas pelo adapter', () => {
  const raw = {
    'content-security-policy': ["default-src 'self'", "frame-ancestors 'none'"],
    'content-security-policy-report-only': ["script-src 'unsafe-eval'"],
    'x-frame-options': ['DENY', 'SAMEORIGIN'],
  };
  const headers = {
    get(name) { return (raw[name] || []).join(', '); },
    raw() { return raw; },
  };
  const snap = snapshotSecurityHeaders(headers);
  assert.deepEqual(snap.contentSecurityPolicies, raw['content-security-policy']);
  assert.deepEqual(snap.contentSecurityPolicyReportOnlyPolicies, raw['content-security-policy-report-only']);
  assert.deepEqual(snap.xFrameOptionsValues, raw['x-frame-options']);
  assert.equal(snap.contentSecurityPolicyReportOnly, "script-src 'unsafe-eval'");
});

test('CSP Report-Only não é contada como política aplicada nem proteção de frame', () => {
  const issues = analyzeSecurityHeaders('https://example.test/', {
    strictTransportSecurity: 'max-age=31536000',
    contentSecurityPolicy: '',
    contentSecurityPolicyReportOnly: "default-src 'self'; frame-ancestors 'none'",
    xFrameOptions: '',
    xContentTypeOptions: 'nosniff',
    referrerPolicy: 'no-referrer',
  });
  assert.ok(issues.some((issue) => issue.diagnosticCode === 'csp_report_only_without_enforced_policy'));
  assert.ok(issues.some((issue) => issue.diagnosticCode === 'frame_protection_not_observed'));
  assert.ok(issues.every((issue) => issue.provenance?.browserBehaviorVerified === false));
});

test('frame-ancestors wildcard ou apenas esquema não é tratado como proteção efetiva', () => {
  for (const policy of ['frame-ancestors *', 'frame-ancestors https:']) {
    const issues = analyzeSecurityHeaders('https://example.test/', {
      strictTransportSecurity: 'max-age=31536000',
      contentSecurityPolicy: policy,
      xFrameOptions: '',
      xContentTypeOptions: 'nosniff',
      referrerPolicy: 'no-referrer',
    });
    assert.ok(issues.some((issue) => issue.diagnosticCode === 'frame_protection_not_observed'), policy);
  }
});

test('fraquezas Report-Only ficam marcadas como não aplicadas e com score informativo', () => {
  const issues = analyzeCspWeaknesses({
    contentSecurityPolicy: "default-src 'self'; frame-ancestors 'none'",
    contentSecurityPolicyReportOnly: "script-src 'unsafe-eval'; frame-ancestors 'none'",
  });
  const reportOnly = issues.find((issue) => issue.issue === 'unsafe-eval' && issue.disposition === 'report-only');
  assert.ok(reportOnly);
  assert.equal(reportOnly.enforced, false);
  assert.ok(reportOnly.score <= 18);
  assert.equal(reportOnly.effectAssessment, 'not_inferred_from_header_observation');
});

test('múltiplas CSP aplicadas são camadas separadas e preservam policyIndex', () => {
  const snap = {
    contentSecurityPolicies: [
      "default-src 'self'; frame-ancestors 'none'",
      "script-src https://cdn.example.test 'unsafe-eval'",
    ],
    xFrameOptions: '',
    xContentTypeOptions: 'nosniff',
    referrerPolicy: 'no-referrer',
  };
  const base = analyzeSecurityHeaders('https://example.test/', snap);
  assert.equal(base.some((issue) => issue.diagnosticCode === 'csp_enforced_policy_not_observed'), false);
  assert.equal(base.some((issue) => issue.diagnosticCode === 'frame_protection_not_observed'), false);

  const weakness = analyzeCspWeaknesses(snap).find((issue) => issue.issue === 'unsafe-eval');
  assert.ok(weakness);
  assert.equal(weakness.policyIndex, 1);
  assert.equal(weakness.sourceDirective, 'script-src');
  assert.equal(weakness.enforced, true);
});

test('lista CSP achatada por Headers é separada em políticas cumulativas', () => {
  const issues = analyzeCspWeaknesses(
    "default-src 'self'; frame-ancestors 'none', script-src 'self' 'unsafe-eval'",
  );
  const unsafeEval = issues.find((issue) => issue.issue === 'unsafe-eval');
  assert.ok(unsafeEval);
  assert.equal(unsafeEval.policyIndex, 1);
  assert.equal(issues.some((issue) => issue.issue === 'no-frame-ancestors'), false);
});

test('diretiva CSP duplicada usa a primeira e gera diagnóstico sem falso positivo', () => {
  const issues = analyzeCspWeaknesses(
    "script-src 'self'; script-src * 'unsafe-eval'; frame-ancestors 'none'",
  );
  assert.ok(issues.some((issue) => issue.issue === 'duplicate-directive'));
  assert.equal(issues.some((issue) => issue.issue === 'unsafe-eval'), false);
  assert.equal(issues.some((issue) => issue.issue === 'wildcard-src'), false);
});

test('parser diferencia diretivas de script e tokens exatos', () => {
  const styleOnly = analyzeCspWeaknesses("style-src 'unsafe-inline'; frame-ancestors 'none'");
  assert.equal(styleOnly.some((issue) => issue.issue === 'unsafe-inline'), false);

  const unquoted = analyzeCspWeaknesses('script-src unsafe-inline; frame-ancestors self');
  assert.equal(unquoted.some((issue) => issue.issue === 'unsafe-inline'), false);

  const element = analyzeCspWeaknesses("script-src-elem data:; frame-ancestors 'self'");
  assert.ok(element.some((issue) => issue.issue === 'data-script'));
});

test('CSP acima do limite falha fechada como parcial, sem inventar ausência', () => {
  const issues = analyzeSecurityHeaders('https://example.test/', {
    strictTransportSecurity: 'max-age=31536000',
    contentSecurityPolicy: 'a'.repeat(32_769),
    xFrameOptions: '',
    xContentTypeOptions: '',
    referrerPolicy: '',
  });
  assert.ok(issues.some((issue) => issue.diagnosticCode === 'csp_analysis_incomplete'));
  assert.ok(issues.some((issue) => issue.diagnosticCode === 'frame_protection_analysis_incomplete'));
  assert.equal(issues.some((issue) => issue.diagnosticCode === 'csp_enforced_policy_not_observed'), false);
  assert.equal(summarizeSecurityHeaderGaps('https://example.test/', {
    contentSecurityPolicy: 'a'.repeat(32_769),
    xFrameOptions: '',
    xContentTypeOptions: '',
    referrerPolicy: '',
  }), null);
});

test('headers singleton duplicados ficam ambíguos em vez de serem tratados como efetivos', () => {
  const issues = analyzeSecurityHeaders('https://example.test/', {
    strictTransportSecurityValues: ['max-age=31536000', 'max-age=0'],
    contentSecurityPolicy: "frame-ancestors 'none'",
    xFrameOptionsValues: ['DENY', 'SAMEORIGIN'],
    xContentTypeOptionsValues: ['nosniff', 'nosniff'],
    referrerPolicy: 'invalid, strict-origin, future-policy',
  });
  assert.ok(issues.some((issue) => issue.diagnosticCode === 'hsts_analysis_incomplete'));
  assert.ok(issues.some((issue) => issue.diagnosticCode === 'nosniff_analysis_incomplete'));
  // O último token reconhecido continua sendo strict-origin; desconhecidos são ignorados.
  assert.equal(issues.some((issue) => issue.diagnosticCode === 'referrer_policy_not_observed'), false);
});

test('sintaxe CSP inválida e limite de políticas geram diagnóstico limitado', () => {
  const malformed = analyzeCspWeaknesses("default-src 'self'; !!! bad");
  assert.ok(malformed.some((issue) => issue.issue === 'malformed-directive'));

  const many = analyzeCspWeaknesses(Array.from({ length: 30 }, () => "default-src 'self'"));
  assert.ok(many.some((issue) => issue.issue === 'analysis-incomplete'));
  assert.ok(many.length <= 48);
});

test('Permissions-Policy oversized vira análise parcial, não ausência', () => {
  const issues = analyzePermissionsPolicyGaps({ permissionsPolicy: 'x'.repeat(32_769) });
  assert.equal(issues.length, 1);
  assert.equal(issues[0].diagnosticCode, 'permissions_policy_analysis_incomplete');
  assert.equal(issues[0].analysisStatus, 'partial');
  assert.equal('missing' in issues[0], false);
});
