import test from 'node:test';
import assert from 'node:assert/strict';

import {
  collectOpenApiSummary,
  createApiContractSnapshot,
  findPreviousApiContractSnapshots,
  previousApiContractSnapshotFor,
  runApiContractDiff,
} from '../modules/api-contract-diff.mjs';
import {
  auditCookieHeaders,
  splitSetCookieHeader,
} from '../modules/cookie-session-audit.mjs';
import {
  resolveEmailDns,
  runEmailSecurityDeep,
} from '../modules/email-security-deep.mjs';
import {
  auditHttp3QuicSurface,
  parseAltSvcHttp3,
} from '../modules/http3-quic-surface.mjs';
import {
  analyzeCspWeaknesses,
  analyzeSecurityHeaders,
  summarizeSecurityHeaderGaps,
} from '../modules/security-headers.js';

function apiSummary(url, path = '/health') {
  return collectOpenApiSummary({
    openapi: '3.0.3',
    paths: { [path]: { get: { responses: { 200: {} } } } },
  }, { url });
}

function snapshotRun(id, target, summary) {
  return {
    id,
    target,
    created_at: `2026-09-0${id}T00:00:00.000Z`,
    findings: [{
      type: 'api_contract_snapshot',
      verification: {
        evidence: { apiContractSnapshot: createApiContractSnapshot(summary) },
      },
    }],
  };
}

test('API contract procura baseline exato em runs anteriores, sem fallback por origem', async () => {
  const a = apiSummary('https://api.example.test/openapi.json');
  const b = apiSummary('https://api.example.test/v2/api-docs', '/v2/health');
  const runs = [snapshotRun(2, 'example.test', b), snapshotRun(1, 'example.test', a)];
  const snapshots = await findPreviousApiContractSnapshots({
    target: 'example.test',
    listRunsFn: async () => runs.map(({ id, target }) => ({ id, target })),
    getRunByIdFn: async (id) => runs.find((run) => run.id === id),
  });
  assert.equal(snapshots.length, 2);
  assert.equal(previousApiContractSnapshotFor(a, snapshots)?.summary.url, a.url);
  assert.equal(previousApiContractSnapshotFor(
    apiSummary('https://api.example.test/swagger.json'),
    snapshots,
  ), null);
});

test('API contract propaga cancelamento sem iniciar fetch', async () => {
  const controller = new AbortController();
  controller.abort(new Error('operator_cancelled'));
  let called = false;
  await assert.rejects(runApiContractDiff({
    origins: ['https://api.example.test'],
    domain: 'example.test',
    signal: controller.signal,
    fetchImpl: async () => { called = true; throw new Error('unexpected'); },
  }), /operator_cancelled/);
  assert.equal(called, false);
});

test('cookie parser limita entrada e não infere sessão por substring comum', () => {
  assert.deepEqual(splitSetCookieHeader('x'.repeat(65_537)), []);
  const findings = auditCookieHeaders(['accessibility=on; Path=/'], {
    url: 'https://app.example.test/',
  });
  assert.equal(findings.some((finding) => /HttpOnly|SameSite/.test(finding.value)), false);
});

test('cookie removido não é relatado como sessão exposta', () => {
  const findings = auditCookieHeaders(['sessionid=gone; Max-Age=0; Path=/'], {
    url: 'https://app.example.test/',
    now: () => Date.UTC(2026, 8, 6),
  });
  assert.deepEqual(findings, []);
});

function dnsError(code) {
  return Object.assign(new Error(code), { code });
}

test('DNS distingue ausência de falha e limita quantidade/tamanho dos TXT', async () => {
  const absent = await resolveEmailDns('_dmarc.example.test', 'TXT', {
    resolverFactory: () => ({ cancel() {}, resolveTxt: async () => { throw dnsError('ENODATA'); } }),
  });
  assert.equal(absent.state, 'absent');

  const failed = await resolveEmailDns('_dmarc.example.test', 'TXT', {
    resolverFactory: () => ({ cancel() {}, resolveTxt: async () => { throw dnsError('ESERVFAIL'); } }),
  });
  assert.equal(failed.state, 'error');

  const bounded = await resolveEmailDns('example.test', 'TXT', {
    resolverFactory: () => ({
      cancel() {},
      resolveTxt: async () => Array.from({ length: 150 }, () => ['x'.repeat(5_000)]),
    }),
  });
  assert.equal(bounded.records.length, 100);
  assert.ok(bounded.records.every((record) => record.length === 4_096));
});

test('DNS timeout cancela resolver e cancelamento do operador é propagado', async () => {
  let cancelled = 0;
  const timeout = await resolveEmailDns('example.test', 'TXT', {
    timeoutMs: 5,
    resolverFactory: () => ({
      cancel() { cancelled += 1; },
      resolveTxt: async () => new Promise(() => {}),
    }),
  });
  assert.equal(timeout.state, 'timeout');
  assert.equal(cancelled, 1);

  const controller = new AbortController();
  controller.abort(new Error('operator_cancelled'));
  await assert.rejects(resolveEmailDns('example.test', 'TXT', {
    signal: controller.signal,
    resolverFactory: () => { throw new Error('must_not_run'); },
  }), /operator_cancelled/);
});

test('DKIM parcial não produz alegação de ausência nos seletores comuns', async () => {
  const { findings, status, outcomes } = await runEmailSecurityDeep('example.test', {
    hostAllowed: () => true,
    resolverFactory: () => ({
      cancel() {},
      resolveMx: async () => [{ exchange: 'mail.example.test', priority: 10 }],
      resolveTxt: async (hostname) => {
        if (hostname === 'example.test') return [['v=spf1 -all']];
        if (hostname === '_dmarc.example.test') return [['v=DMARC1; p=reject; rua=mailto:d@example.test']];
        if (hostname === 'default._domainkey.example.test') throw dnsError('ESERVFAIL');
        throw dnsError('ENODATA');
      },
    }),
  });
  assert.equal(status, 'partial');
  assert.equal(outcomes['dkim:default'].state, 'error');
  assert.equal(findings.some((finding) => /DKIM nao encontrado/.test(finding.value)), false);
  assert.ok(findings.some((finding) => finding.type === 'email_security_check'));
});

test('HTTP/3 diferencia anúncio de negociação e exige UDP/443 no legado Nmap', () => {
  assert.deepEqual(parseAltSvcHttp3('h3=":443"; ma=0'), []);
  const advertised = auditHttp3QuicSurface({
    probeResults: [{ r: {
      ok: true,
      url: 'https://example.test/',
      securityHeaders: { altSvc: 'h3=":443"; ma=3600' },
    } }],
  });
  assert.equal(advertised.length, 1);
  assert.equal(advertised[0].prio, 'info');
  assert.match(advertised[0].meta, /advertised_not_negotiated/);

  const notUdp443 = auditHttp3QuicSurface({
    nmapFindings: [{ type: 'nmap', value: 'tcp/443 host — quic', meta: 'quic' }],
  });
  assert.deepEqual(notUdp443, []);
});

test('HTTP/3 respeita cancelamento antes de percorrer evidências', () => {
  const controller = new AbortController();
  controller.abort(new Error('operator_cancelled'));
  assert.throws(() => auditHttp3QuicSurface({
    probeResults: [{ r: { ok: true, url: 'https://example.test/' } }],
    signal: controller.signal,
  }), /operator_cancelled/);
});

test('headers são observações de configuração, com diretivas e atributos exatos', () => {
  const issues = analyzeSecurityHeaders('https://example.test/', {
    strictTransportSecurity: 'max-age=0',
    contentSecurityPolicy: "default-src 'none' https://frame-ancestors.example",
    xFrameOptions: 'ALLOWALL',
    xContentTypeOptions: 'almost-nosniff',
    referrerPolicy: 'invalid',
    setCookieSample: ['secureid=x; Path=/'],
  });
  assert.ok(issues.length >= 4);
  assert.ok(issues.every((issue) => issue.score <= 34));
  assert.ok(issues.every((issue) => issue.evidenceStatus === 'configuration_observation'));
  assert.equal(issues.some((issue) => issue.header === 'Set-Cookie'), false);

  const csp = analyzeCspWeaknesses("default-src 'none'; style-src 'unsafe-inline'");
  assert.equal(csp.some((issue) => issue.issue === 'unsafe-inline'), false);
  assert.ok(csp.some((issue) => issue.issue === 'no-frame-ancestors'));

  const bundle = summarizeSecurityHeaderGaps('https://example.test/', {
    contentSecurityPolicy: '', xFrameOptions: '', xContentTypeOptions: '', referrerPolicy: '',
  });
  assert.equal(bundle.clickjackingRisk, false);
  assert.equal(bundle.clickjackingProtectionGap, true);
  assert.equal(bundle.evidenceStatus, 'configuration_observation');
});
