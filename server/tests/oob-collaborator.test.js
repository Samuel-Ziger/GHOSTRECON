import test from 'node:test';
import assert from 'node:assert/strict';
import { parseDnsQuery, buildOobPayloads, startCatcher } from '../modules/oob-collaborator.mjs';

test('oob: parseDnsQuery parseia nome simples', () => {
  // header (12 bytes) + label "abc" (3) + label "com" (3) + null + qtype (2) + qclass (2)
  const buf = Buffer.from([
    0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x03, 0x61, 0x62, 0x63, 0x03, 0x63, 0x6f, 0x6d, 0x00,
    0x00, 0x01, 0x00, 0x01,
  ]);
  const q = parseDnsQuery(buf);
  assert.equal(q.id, 0x1234);
  assert.equal(q.name, 'abc.com');
});

test('oob: buildOobPayloads gera URLs e payloads canônicos', () => {
  const p = buildOobPayloads({ token: 'abcdef0123456789', host: 'oob.lab', httpPort: 8054 });
  assert.ok(p.ssrf.some((u) => u.includes('abcdef0123456789')));
  assert.ok(p.xxe.some((s) => s.includes('SYSTEM')));
  assert.ok(p.rceShell.some((s) => /curl/.test(s)));
  assert.ok(p.logInjection.some((s) => /jndi/.test(s)));
});

test('oob: catcher mintToken e waitForToken (HTTP)', async () => {
  const cat = await startCatcher({ port: 0, httpPort: 0, host: '127.0.0.1', startDns: false });
  const t = cat.mintToken({ note: 'test' });
  // Disparar request manual
  const port = cat.httpPort;
  const http = await import('node:http');
  await new Promise((res) => {
    http.get({ host: '127.0.0.1', port, path: `/?t=${t.token}` }, (r) => {
      r.on('data', () => {});
      r.on('end', res);
    });
  });
  const hits = await cat.waitForToken(t.token, { timeoutMs: 2000 });
  assert.ok(hits.length >= 1);
  assert.equal(hits[0].kind, 'http');
  await cat.stop();
});

test('oob: catcher start sem dns/http é no-op seguro', async () => {
  const cat = await startCatcher({ startDns: false, startHttp: false });
  await cat.stop();
});
