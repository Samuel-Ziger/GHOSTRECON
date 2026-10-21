import fs from 'node:fs/promises';
import test from 'node:test';
import assert from 'node:assert/strict';

import {
  API_CONTRACT_CANONICALIZATION_VERSION,
  collectOpenApiSummary,
  diffOpenApiSummaries,
} from '../modules/api-contract-diff.mjs';

const CORPUS_URL = new URL('./fixtures/api-contract-ground-truth-v1.json', import.meta.url);
const CONTRACT_URL = 'https://api.example.test/openapi.json';

function signalsFor(diff) {
  const signals = new Set();
  if (diff.addedOperations.length) signals.add('added_operation');
  if (diff.removedOperations.length) signals.add('removed_operation');
  if (diff.addedWebhooks.length) signals.add('added_webhook');
  if (diff.removedWebhooks.length) signals.add('removed_webhook');
  if (diff.modifiedWebhooks.length) signals.add('modified_webhook');
  if (diff.securityRegressions.length) signals.add('security_regression');
  if (diff.securityImprovements.length) signals.add('security_improvement');
  if (diff.componentsChanged) signals.add('components');
  if (diff.serversChanged) signals.add('servers');
  if (diff.rootContractChanged) signals.add('root_contract');
  for (const operation of diff.modifiedOperations) {
    for (const change of operation.changes) signals.add(change);
  }
  return signals;
}

test('corpus ground-truth v1 mede precisão e recall sem rede', async () => {
  const corpus = JSON.parse(await fs.readFile(CORPUS_URL, 'utf8'));
  assert.equal(corpus.schemaVersion, 1);
  assert.equal(corpus.cases.length, 18);

  const matrix = { truePositive: 0, trueNegative: 0, falsePositive: 0, falseNegative: 0 };
  const versions = new Set();
  for (const corpusCase of corpus.cases) {
    const before = collectOpenApiSummary(corpusCase.before, { url: CONTRACT_URL });
    const after = collectOpenApiSummary(corpusCase.after, { url: CONTRACT_URL });
    versions.add(before.version);
    versions.add(after.version);
    assert.equal(before.canonicalizationVersion, API_CONTRACT_CANONICALIZATION_VERSION);
    assert.equal(
      collectOpenApiSummary(structuredClone(corpusCase.before), { url: CONTRACT_URL }).hash,
      before.hash,
      `${corpusCase.id}: hash deve ser determinístico`,
    );

    const diff = diffOpenApiSummaries(before, after);
    const predicted = diff.changed;
    const expected = corpusCase.expectedChanged === true;
    if (predicted && expected) matrix.truePositive += 1;
    else if (!predicted && !expected) matrix.trueNegative += 1;
    else if (predicted) matrix.falsePositive += 1;
    else matrix.falseNegative += 1;

    assert.equal(predicted, expected, `${corpusCase.id}: classificação incorreta`);
    const signals = signalsFor(diff);
    assert.deepEqual(
      [...signals].sort(),
      [...(corpusCase.expectedSignals || [])].sort(),
      `${corpusCase.id}: conjunto exato de sinais incorreto`,
    );
  }

  const precision = matrix.truePositive / (matrix.truePositive + matrix.falsePositive);
  const recall = matrix.truePositive / (matrix.truePositive + matrix.falseNegative);
  assert.deepEqual(matrix, {
    truePositive: 13,
    trueNegative: 5,
    falsePositive: 0,
    falseNegative: 0,
  });
  assert.equal(precision, 1);
  assert.equal(recall, 1);
  assert.deepEqual([...versions].sort(), ['2.0', '3.0', '3.1', '3.2']);
});
