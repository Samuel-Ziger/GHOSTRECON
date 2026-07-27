import test from 'node:test';
import assert from 'node:assert/strict';

import {
  redactFindingForPublic,
  redactRunPayloadForPersistence,
} from '../modules/finding-redaction.mjs';
import { serializeFindingsForRunSnapshot } from '../modules/finding-serialize.js';
import { sanitizeRunPayloadForPersistence } from '../modules/db.js';
import { createPipelineContext } from '../pipeline/finding-context.mjs';
import { buildPipelineExportPayloadForAi } from '../pipeline/pipeline-helpers.mjs';
import {
  parseVigoliumJsonl,
  vigoliumRowToFinding,
} from '../../bridge/findings-normalizer.mjs';
import { createVigoliumAuthTransport } from '../../bridge/vigolium-auth-transport.mjs';

const AUTH_SECRET = 'opaque-auth-fixture-7f2d';
const COOKIE_SECRET = 'opaque-cookie-fixture-8a3e';
const BODY_SECRET = `ghp_${'AbCd1234'.repeat(4)}`;

function assertNoFixtureSecrets(value, label = 'payload') {
  const serialized = typeof value === 'string' ? value : JSON.stringify(value);
  assert.equal(serialized.includes(AUTH_SECRET), false, `${label}: authorization`);
  assert.equal(serialized.includes(COOKIE_SECRET), false, `${label}: cookie`);
  assert.equal(serialized.includes(BODY_SECRET), false, `${label}: token`);
}

function authenticatedFinding() {
  return {
    type: 'vuln',
    prio: 'high',
    score: 88,
    value: 'Authenticated fixture',
    meta: `source=vigolium:fixture • request=Cookie: sid=${COOKIE_SECRET} • confidence=high`,
    url: `https://example.test/private?token=${AUTH_SECRET}`,
    sourceEngine: 'vigolium',
    moduleId: 'fixture-auth',
    moduleName: 'Authenticated fixture',
    provenance: {
      engine: 'vigolium',
      relation: 'authenticated-validation',
      sessionDir: '/tmp/private-auth-session',
      repoPath: '/mnt/runner/private/repository',
    },
    evidence: {
      request: [
        `GET /private?token=${AUTH_SECRET} HTTP/1.1`,
        'Host: example.test',
        `Authorization: Bearer ${AUTH_SECRET}`,
        `Cookie: sid=${COOKIE_SECRET}`,
        '',
        `token=${BODY_SECRET}`,
      ].join('\r\n'),
      response: [
        'HTTP/1.1 200 OK',
        `Set-Cookie: sid=${COOKIE_SECRET}`,
        '',
        `{"access_token":"${AUTH_SECRET}","github":"${BODY_SECRET}"}`,
      ].join('\r\n'),
      curl: `curl -H 'Authorization: Bearer ${AUTH_SECRET}' --cookie 'sid=${COOKIE_SECRET}' https://example.test/private`,
      raw: { auth: AUTH_SECRET, body: BODY_SECRET },
      headers: {
        Authorization: `Bearer ${AUTH_SECRET}`,
        Cookie: `sid=${COOKIE_SECRET}`,
        'Content-Type': 'application/json',
      },
      evidenceHash: 'a'.repeat(64),
    },
    verification: {
      classification: 'probable',
      confidenceScore: 82,
      evidence: {
        requestSnippet: `GET /private Authorization: Bearer ${AUTH_SECRET}`,
        responseSnippet: `Set-Cookie: sid=${COOKIE_SECRET} token=${BODY_SECRET}`,
        evidenceHash: 'b'.repeat(64),
      },
    },
  };
}

test('redação de finding remove material HTTP autenticado e preserva proveniência', () => {
  const safe = redactFindingForPublic(authenticatedFinding());
  assertNoFixtureSecrets(safe);
  assert.equal(safe.sourceEngine, 'vigolium');
  assert.equal(safe.moduleId, 'fixture-auth');
  assert.equal(safe.provenance.relation, 'authenticated-validation');
  assert.equal(safe.provenance.sessionDir, '[LOCAL_PATH]');
  assert.equal(safe.provenance.repoPath, '[LOCAL_PATH]');
  assert.equal(safe.evidence.evidenceHash, 'a'.repeat(64));
  assert.match(safe.url, /token=\[REDACTED\]/i);
  assert.match(safe.evidence.request, /^\[REDACTED_HTTP_REQUEST\] GET /);
  assert.match(safe.evidence.response, /^\[REDACTED_HTTP_RESPONSE\] status=200/);
  assert.equal(safe.evidence.curl, '[REDACTED_CURL]');
  assert.equal(safe.evidence.raw, '[REDACTED_RAW]');
  assert.equal(safe.evidence.headers.Authorization, '[REDACTED]');
  assert.equal(safe.evidence.headers.Cookie, '[REDACTED]');
  assert.equal(safe.evidence.headers['Content-Type'], 'application/json');
  assert.doesNotMatch(JSON.stringify(safe), /\/tmp\/private-auth-session/);
});

test('fronteiras NDJSON, snapshot, DB e relatório IA recebem somente finding redigido', () => {
  const events = [];
  const ctx = createPipelineContext({
    domain: 'example.test',
    emit: (event) => events.push(event),
  });
  ctx.addFinding(authenticatedFinding());
  ctx.log(`Authorization: Bearer ${AUTH_SECRET}\nCookie: sid=${COOKIE_SECRET}`, 'warn');

  assertNoFixtureSecrets(events, 'NDJSON');
  assertNoFixtureSecrets(ctx.findings, 'pipeline findings');
  assert.equal(ctx.findings[0].sourceEngine, 'vigolium');

  const snapshot = serializeFindingsForRunSnapshot([authenticatedFinding()]);
  assertNoFixtureSecrets(snapshot, 'SQLite snapshot');

  const dbPayload = sanitizeRunPayloadForPersistence({
    target: 'example.test',
    exactMatch: false,
    modules: ['vigolium_dast'],
    stats: {},
    correlation: null,
    findings: [authenticatedFinding()],
    findingsJson: JSON.stringify({ findings: [authenticatedFinding()] }),
  });
  assertNoFixtureSecrets(dbPayload, 'DB payload');
  assert.equal(dbPayload.findings[0].moduleId, 'fixture-auth');
  assertNoFixtureSecrets(JSON.parse(dbPayload.findingsJson), 'rebuilt DB snapshot');

  const genericPersistence = redactRunPayloadForPersistence({
    target: 'example.test',
    findings: [authenticatedFinding()],
  });
  assertNoFixtureSecrets(genericPersistence, 'generic persistence boundary');

  const aiReport = buildPipelineExportPayloadForAi({
    target: 'example.test',
    projectName: 'fixture',
    stats: {},
    findings: [authenticatedFinding()],
    correlation: null,
    reportTemplates: [],
    runId: 1,
    storage: 'fixture',
    intelMerge: null,
    kaliMode: false,
    modules: ['vigolium_dast'],
    auth: {
      cookie: `sid=${COOKIE_SECRET}`,
      headers: { Authorization: `Bearer ${AUTH_SECRET}` },
    },
  });
  assertNoFixtureSecrets(aiReport, 'AI/report payload');
  assert.deepEqual(aiReport.authProfile.headerKeys, ['Authorization']);
});

test('normalizador Vigolium nunca propaga request, response ou curl autenticado em claro', () => {
  const finding = vigoliumRowToFinding({
    'template-id': 'fixture-auth',
    url: `https://example.test/private?access_token=${AUTH_SECRET}`,
    info: {
      name: 'Authenticated validation',
      severity: 'high',
      confidence: 'high',
      tags: ['auth', 'fixture'],
      description: `Authorization: Bearer ${AUTH_SECRET}`,
    },
    request: `GET /private HTTP/1.1\r\nAuthorization: Bearer ${AUTH_SECRET}\r\nCookie: sid=${COOKIE_SECRET}`,
    response: `HTTP/1.1 200 OK\r\nSet-Cookie: sid=${COOKIE_SECRET}\r\n\r\n${BODY_SECRET}`,
    'curl-command': `curl -H 'Authorization: Bearer ${AUTH_SECRET}' --cookie sid=${COOKIE_SECRET} https://example.test/private`,
  });

  assert.ok(finding);
  assertNoFixtureSecrets(finding, 'Vigolium normalizer');
  assert.equal(finding.sourceEngine, 'vigolium');
  assert.equal(finding.moduleId, 'fixture-auth');
  assert.match(finding.evidence.request, /^\[REDACTED_HTTP_REQUEST\]/);
  assert.match(finding.evidence.response, /^\[REDACTED_HTTP_RESPONSE\]/);
  assert.equal(finding.evidence.curl, '[REDACTED_CURL]');
});

test('redactor exato da sessão remove segredo opaco mesmo fora de um campo nomeado', async () => {
  const opaqueSecret = 'opaque-session-value-fixture-4f8d';
  const transport = await createVigoliumAuthTransport({
    auth: {
      cookie: `sid=${opaqueSecret}`,
      headers: { Authorization: `Bearer ${opaqueSecret}` },
    },
  });
  try {
    const rows = parseVigoliumJsonl(JSON.stringify({
      'template-id': 'opaque-auth-output',
      url: `https://example.test/private?opaque=${encodeURIComponent(opaqueSecret)}`,
      'matched-at': `authenticated marker ${opaqueSecret}`,
      info: {
        name: `Session marker ${opaqueSecret}`,
        severity: 'medium',
        description: `standalone evidence ${opaqueSecret}`,
      },
    }), { redact: transport.redact });
    assert.equal(rows.length, 1);
    assertNoFixtureSecrets(rows);
    assert.equal(JSON.stringify(rows).includes(opaqueSecret), false);
    assert.match(JSON.stringify(rows), /redacted/i);
  } finally {
    await transport.cleanup();
  }
});
