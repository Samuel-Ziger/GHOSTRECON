import test from 'node:test';
import assert from 'node:assert/strict';

import {
  auditWebSocketUrls,
  extractWebSocketUrlsFromText,
} from '../modules/websocket-recon.mjs';
import {
  auditHppParamPollution,
  duplicateQueryParams,
} from '../modules/hpp-param-pollution.mjs';
import {
  auditDomClobberingHtml,
  auditDomClobberingJs,
} from '../modules/dom-clobbering-audit.mjs';
import {
  analyzeEmailSecurityRecords,
  parseDmarcPolicy,
  parseSpfPolicy,
} from '../modules/email-security-deep.mjs';
import {
  rankSecretFindings,
  scoreSecretContext,
} from '../modules/secrets-context-ranker.mjs';

test('websocket recon extrai endpoints e prioriza token em query/ws claro', () => {
  const urls = extractWebSocketUrlsFromText(
    'const s = new WebSocket("ws://api.example.com/admin/socket?token=abc");',
    { baseUrl: 'https://app.example.com/' },
  );
  assert.deepEqual(urls, ['ws://api.example.com/admin/socket?token=abc']);
  const findings = auditWebSocketUrls(urls, { target: 'example.com' });
  assert.ok(findings.some((f) => /sem TLS/.test(f.value)));
  assert.ok(findings.some((f) => /Token em query/.test(f.value)));
});

test('hpp audit detecta parametro duplicado e parametros sensiveis multi-contexto', () => {
  const dup = duplicateQueryParams('https://app.example.com/cb?next=/a&next=/b&id=1');
  assert.equal(dup[0].name, 'next');
  assert.equal(dup[0].count, 2);

  const findings = auditHppParamPollution([
    'https://app.example.com/cb?next=/a&next=/b',
    'https://app.example.com/login?redirect=/home',
    'https://app.example.com/logout?redirect=/bye',
  ]);
  assert.ok(findings.some((f) => /Parametro repetido/.test(f.value)));
  assert.ok(findings.some((f) => /redirect/.test(f.value)));
});

test('dom clobbering audit detecta id/name perigosos e acesso dinamico', () => {
  const htmlFindings = auditDomClobberingHtml(
    '<form id="constructor" name="location"></form><div id="constructor"></div>',
    { url: 'https://app.example.com/' },
  );
  assert.ok(htmlFindings.some((f) => /constructor/.test(f.value)));
  assert.ok(htmlFindings.some((f) => /location/.test(f.value)));

  const jsFindings = auditDomClobberingJs('const x = document[location.hash.slice(1)];', {
    url: 'https://app.example.com/app.js',
  });
  assert.ok(jsFindings.some((f) => /document/.test(f.value)));
});

test('email security deep analisa SPF e DMARC fracos sem DNS real', () => {
  const spf = parseSpfPolicy('v=spf1 include:_spf.example.net +all');
  assert.equal(spf.all, '+all');
  const dmarc = parseDmarcPolicy('v=DMARC1; p=none; pct=50');
  assert.equal(dmarc.policy, 'none');
  assert.equal(dmarc.pct, 50);

  const findings = analyzeEmailSecurityRecords({
    domain: 'example.com',
    mx: [{ exchange: 'mail.example.com', priority: 10 }],
    spf: spf.raw,
    dmarc: dmarc.raw,
    dkimSelectors: [],
  });
  assert.ok(findings.some((f) => /SPF permite qualquer/.test(f.value)));
  assert.ok(findings.some((f) => /DMARC em modo/.test(f.value)));
  assert.ok(findings.some((f) => /DKIM nao encontrado/.test(f.value)));
});

test('secrets context ranker prioriza segredo de alto valor em contexto prod', () => {
  const secret = {
    type: 'secret',
    prio: 'high',
    score: 92,
    value: '[github_token] ghp_masked',
    meta: 'Possivel segredo em JS - value_fp=abc123',
    url: 'https://app.acme.com/static/prod-admin.js',
  };
  const score = scoreSecretContext(secret);
  assert.equal(score.prio, 'high');
  assert.ok(score.reasons.includes('high_value_kind'));

  const ranked = rankSecretFindings([
    secret,
    {
      type: 'secret',
      prio: 'high',
      value: '[captcha_public] masked',
      meta: 'fixture',
      url: 'https://app.example.com/test/example.js',
    },
  ]);
  assert.equal(ranked[0].type, 'secret_context');
  assert.match(ranked[0].value, /github_token/);
});
