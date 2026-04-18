import test from 'node:test';
import assert from 'node:assert/strict';
import {
  sniffDecodeBase64Base32,
  tryDecodeBase64Chunk,
  tryDecodeBase32Rfc4648,
} from '../modules/encoding-sniff.js';

test('tryDecodeBase64Chunk: passwd line', () => {
  const line = 'root:x:0:0:root:/root:/bin/bash\n';
  const b64 = Buffer.from(line, 'utf8').toString('base64');
  const buf = tryDecodeBase64Chunk(b64);
  assert.ok(buf);
  assert.match(buf.toString('utf8'), /root:x:0:0/);
});

test('tryDecodeBase32Rfc4648: RFC vector', () => {
  const buf = tryDecodeBase32Rfc4648('NBSWY3DPEB3W64TMMQ======');
  assert.ok(buf);
  assert.match(buf.toString('utf8'), /hello world/i);
});

test('sniffDecodeBase64Base32 finds both in HTML', () => {
  const b64 = Buffer.from('SECRET_TOKEN_ABC', 'utf8').toString('base64');
  const b32 = 'NBSWY3DPEB3W64TMMQ======';
  const html = `<div data-x="${b64}">x</div><span>${b32}</span>`;
  const hits = sniffDecodeBase64Base32(html, { maxPerKind: 2, maxUtf8: 2000 });
  assert.ok(hits.some((h) => h.encoding === 'base64' && h.decodedUtf8.includes('SECRET')));
  assert.ok(hits.some((h) => h.encoding === 'base32' && /hello world/i.test(h.decodedUtf8)));
});
