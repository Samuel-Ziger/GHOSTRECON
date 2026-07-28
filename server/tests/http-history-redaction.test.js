import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import { createHttpHistoryStore } from '../lib/http-history.mjs';

const SESSION_SECRET = 'synthetic-x-session-id-secret';
const INLINE_SECRET = 'synthetic-vigolium-inline-secret';
const AUTH_FILE = '/tmp/ghostrecon-private/session-auth.json';

function authenticatedBodyFixture() {
  return {
    domain: 'example.test',
    auth: {
      headers: {
        // O nome é deliberadamente arbitrário: a proteção vem do container
        // `auth`, não de uma allow/denylist limitada de nomes de header.
        'X-Session-ID': SESSION_SECRET,
        'X-Workspace-Context': 'synthetic-custom-header-secret',
      },
      profile: {
        storageState: {
          localStorage: [{ name: 'opaque', value: 'synthetic-browser-storage-secret' }],
        },
      },
    },
    vigoliumAuthEntries: [`operator:X-Session-ID:${INLINE_SECRET}`],
    vigoliumAuthFiles: [AUTH_FILE],
    vigoliumAuthFile: AUTH_FILE,
    harmless: 'preserve-me',
    echoedSessionMaterial: SESSION_SECRET,
    echoedInlineMaterial: INLINE_SECRET,
  };
}

describe('HTTP history redaction boundary', () => {
  it('omite auth, headers arbitrários, Vigolium auth e paths antes de persistir ou emitir NDJSON', () => {
    const history = createHttpHistoryStore();
    const emitted = [];
    const body = authenticatedBodyFixture();

    const row = history.recordReconHttpHistory({
      requestRunId: 'run-fixture',
      target: 'example.test',
      source: 'browser',
      method: 'POST',
      url: '/api/recon/stream',
      requestHeaders: {
        'X-Session-ID': SESSION_SECRET,
        'X-Harmless': 'visible-header',
      },
      // Passa o objeto bruto para provar que a fronteira final não depende de
      // o chamador ter usado safeJsonBodyForHistory anteriormente.
      requestBody: body,
      responseHeaders: {
        'Set-Cookie': `sid=${SESSION_SECRET}`,
      },
      responseBody: {
        auth: body.auth,
        ok: true,
      },
      emit: (event) => emitted.push(event),
    });

    const persisted = JSON.stringify(history.entries);
    const streamed = JSON.stringify(emitted);
    for (const serialized of [persisted, streamed]) {
      assert.doesNotMatch(serialized, new RegExp(SESSION_SECRET));
      assert.doesNotMatch(serialized, new RegExp(INLINE_SECRET));
      assert.doesNotMatch(serialized, /synthetic-custom-header-secret/);
      assert.doesNotMatch(serialized, /synthetic-browser-storage-secret/);
      assert.equal(serialized.includes(AUTH_FILE), false);
      assert.doesNotMatch(serialized, /session-auth\.json/);
      assert.doesNotMatch(serialized, /ghostrecon-private/);
      assert.match(serialized, /REDACTED/i);
    }

    assert.equal(row.requestHeaders['x-session-id'], '[redacted]');
    assert.equal(row.requestHeaders['x-harmless'], 'visible-header');
    assert.equal(row.responseHeaders['set-cookie'], '[redacted]');
    assert.match(row.requestBody, /preserve-me/);
  });

  it('redige o mesmo material quando o body chega como JSON ou form-urlencoded', () => {
    const history = createHttpHistoryStore();
    const body = authenticatedBodyFixture();

    const json = history.redactBodyTextForHistory(JSON.stringify(body));
    const form = history.redactBodyTextForHistory(new URLSearchParams({
      domain: 'example.test',
      auth: SESSION_SECRET,
      vigoliumAuthEntries: `operator:X-Session-ID:${INLINE_SECRET}`,
      vigoliumAuthFiles: AUTH_FILE,
    }).toString());

    for (const safe of [json, form]) {
      assert.doesNotMatch(safe, new RegExp(SESSION_SECRET));
      assert.doesNotMatch(safe, new RegExp(INLINE_SECRET));
      assert.equal(safe.includes(AUTH_FILE), false);
      assert.doesNotMatch(safe, /session-auth\.json/);
      assert.match(safe, /REDACTED/i);
    }
  });

  it('redige credenciais, query e fragmento sensíveis da URL antes de persistir ou emitir', () => {
    const history = createHttpHistoryStore();
    const events = [];
    const row = history.recordReconHttpHistory({
      target: `https://example.test/?x-session-id=${SESSION_SECRET}`,
      url:
        `https://operator:password@example.test/path?x-session-id=${SESSION_SECRET}`
        + `&safe=visible#authorization=${INLINE_SECRET}`,
      requestHeaders: {},
      responseHeaders: {},
      emit: (event) => events.push(event),
    });
    const serialized = JSON.stringify({ row, entries: history.entries, events });
    assert.equal(serialized.includes(SESSION_SECRET), false);
    assert.equal(serialized.includes(INLINE_SECRET), false);
    assert.equal(serialized.includes('operator:password'), false);
    assert.match(decodeURIComponent(row.url), /x-session-id=\[REDACTED\]/);
    assert.match(decodeURIComponent(row.url), /authorization=\[REDACTED\]/);
    assert.match(row.url, /safe=visible/);
  });

  it('coleta material privado além do limite de saída antes de redigir ecos', () => {
    const history = createHttpHistoryStore();
    const lateSecret = 'synthetic-secret-after-item-500';
    const headers = Object.fromEntries(
      Array.from({ length: 501 }, (_, index) => [
        `X-Private-${index}`,
        index === 500 ? lateSecret : `synthetic-private-${index}`,
      ]),
    );
    const row = history.recordReconHttpHistory({
      target: 'example.test',
      url: '/api/recon/stream',
      requestHeaders: {},
      responseHeaders: {},
      requestBody: {
        auth: { headers },
        echoedOutsidePrivateContainer: lateSecret,
      },
    });
    assert.equal(JSON.stringify(row).includes(lateSecret), false);
    assert.match(row.requestBody, /REDACTED/i);
  });
});
