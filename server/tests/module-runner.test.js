import test from 'node:test';
import assert from 'node:assert/strict';

import { createCappedOutputCollector, mapPool } from '../modules/module-runner.mjs';

test('createCappedOutputCollector limita stdout em modo head', () => {
  const c = createCappedOutputCollector({ maxBytes: 5, mode: 'head', marker: '[cut]' });
  c.append('abcdefghi');
  assert.equal(c.toString(), 'abcde[cut]');
  assert.deepEqual(c.stats(), { totalBytes: 9, capturedBytes: 5, truncated: true });
});

test('createCappedOutputCollector preserva tail quando configurado', () => {
  const c = createCappedOutputCollector({ maxBytes: 5, mode: 'tail', marker: '[cut]' });
  c.append('abc');
  c.append('defghi');
  assert.equal(c.toString(), 'efghi[cut]');
});

test('mapPool preserva ordem dos resultados', async () => {
  const out = await mapPool([3, 1, 2], 2, async (n) => {
    await new Promise((r) => setTimeout(r, 5 * n));
    return n * 2;
  });
  assert.deepEqual(out, [6, 2, 4]);
});

test('mapPool aplica timeout por item', async () => {
  await assert.rejects(
    () => mapPool([1], 1, () => new Promise((r) => setTimeout(r, 50)), { timeoutMs: 5, label: 'teste' }),
    /teste timeout/,
  );
});
