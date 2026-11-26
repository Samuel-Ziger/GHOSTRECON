import test from 'node:test';
import assert from 'node:assert/strict';
import { deriveBoundedObjectKeys, runBoundedObjectKeyDiscovery } from '../modules/bounded-object-key-discovery.mjs';

test('deriva somente chaves observadas e respeita budget rígido', async () => {
  const result = await runBoundedObjectKeyDiscovery({
    knownObjectKeys: ['orders/alice/first.json'],
    observations: [{ body: `const object_key = "orders/bob/second.json"; href="exports/report.pdf";` }],
    budget: 2,
  });
  assert.equal(result.candidates.length, 2);
  assert.equal(result.metrics.generatedByWordlist, 0);
  assert.equal(result.metrics.truncated, true);
  assert.deepEqual(result.candidates.map((item) => item.key), ['orders/alice/first.json', 'orders/bob/second.json']);
});

test('recusa URL, traversal e budget zero; nunca faz rede', () => {
  const result = deriveBoundedObjectKeys({
    knownObjectKeys: ['../../etc/passwd', 'http://127.0.0.1/metadata', 'safe/file.json'], budget: 0,
  });
  assert.equal(result.candidates.length, 0);
  const safe = deriveBoundedObjectKeys({
    knownObjectKeys: ['../../etc/passwd', 'http://127.0.0.1/metadata', 'safe/file.json'], budget: 8,
  });
  assert.deepEqual(safe.candidates.map((item) => item.key), ['safe/file.json']);
});
