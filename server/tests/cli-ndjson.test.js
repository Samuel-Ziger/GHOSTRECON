/**
 * Parser NDJSON do CLI — corner cases: chunks parciais, CRLF, linhas em branco,
 * JSON malformado, trailing sem newline.
 */
import test from 'node:test';
import assert from 'node:assert/strict';
import { createNdjsonParser } from '../modules/cli/client.mjs';

test('ndjson: linhas completas em um chunk', () => {
  const seen = [];
  const p = createNdjsonParser((e) => seen.push(e));
  p.feed('{"a":1}\n{"b":2}\n');
  const res = p.end();
  assert.equal(res.lines, 2);
  assert.deepEqual(seen, [{ a: 1 }, { b: 2 }]);
});

test('ndjson: linha quebrada entre chunks', () => {
  const seen = [];
  const p = createNdjsonParser((e) => seen.push(e));
  p.feed('{"type":"pro');
  p.feed('gress","step":"dns"}\n');
  const res = p.end();
  assert.equal(res.lines, 1);
  assert.deepEqual(seen, [{ type: 'progress', step: 'dns' }]);
});

test('ndjson: CRLF (Windows streams)', () => {
  const seen = [];
  const p = createNdjsonParser((e) => seen.push(e));
  p.feed('{"x":1}\r\n{"x":2}\r\n');
  p.end();
  assert.deepEqual(seen, [{ x: 1 }, { x: 2 }]);
});

test('ndjson: linhas em branco são ignoradas', () => {
  const seen = [];
  const p = createNdjsonParser((e) => seen.push(e));
  p.feed('\n\n{"ok":true}\n\n\n');
  p.end();
  assert.equal(seen.length, 1);
  assert.deepEqual(seen[0], { ok: true });
});

test('ndjson: JSON malformado produz evento parse-error, não lança', () => {
  const seen = [];
  const p = createNdjsonParser((e) => seen.push(e));
  p.feed('{oops\n{"ok":1}\n');
  p.end();
  assert.equal(seen.length, 2);
  assert.equal(seen[0].type, 'parse-error');
  assert.equal(seen[0].raw, '{oops');
  assert.deepEqual(seen[1], { ok: 1 });
});

test('ndjson: trailing sem newline é emitido no end()', () => {
  const seen = [];
  const p = createNdjsonParser((e) => seen.push(e));
  p.feed('{"a":1}\n{"b":2}'); // sem \n final
  const res = p.end();
  assert.equal(res.lines, 2);
  assert.deepEqual(seen, [{ a: 1 }, { b: 2 }]);
});

test('ndjson: feed vazio não quebra', () => {
  const seen = [];
  const p = createNdjsonParser((e) => seen.push(e));
  p.feed('');
  p.feed('');
  const res = p.end();
  assert.equal(res.lines, 0);
  assert.equal(seen.length, 0);
});

test('ndjson: múltiplas linhas em um único chunk pequeno', () => {
  const seen = [];
  const p = createNdjsonParser((e) => seen.push(e));
  // caso típico de stream — várias linhas batching no kernel TCP
  p.feed('{"i":0}\n{"i":1}\n{"i":2}\n{"i":3}\n{"i":4}\n');
  p.end();
  assert.equal(seen.length, 5);
  assert.deepEqual(seen.map((x) => x.i), [0, 1, 2, 3, 4]);
});

test('ndjson: lastEvent reflete o último evento emitido', () => {
  const p = createNdjsonParser(() => {});
  p.feed('{"step":"a"}\n{"step":"b"}\n{"step":"done"}\n');
  const res = p.end();
  assert.deepEqual(res.lastEvent, { step: 'done' });
});
