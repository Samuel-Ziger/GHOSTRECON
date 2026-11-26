import test from 'node:test';
import assert from 'node:assert/strict';

import {
  extractRuntimeEndpointCandidates,
  runRuntimeEndpointPivot,
} from '../modules/runtime-endpoint-pivot.mjs';

test('extrai Lambda Function URL como scope candidate sem fazer rede', async () => {
  const url = 'https://fixtureid.lambda-url.ap-south-1.on.aws/fetch_order_status';
  const observations = [{
    url: 'https://shop.test/api/orders/1',
    body: JSON.stringify({ order_status: url }),
  }];
  const candidates = extractRuntimeEndpointCandidates(observations);
  assert.equal(candidates.length, 1);
  assert.equal(candidates[0].provider, 'aws_lambda_function_url');
  assert.equal(candidates[0].state, 'scope_candidate');
  assert.equal(candidates[0].automaticallyFollowed, false);

  const result = await runRuntimeEndpointPivot({ observations });
  assert.equal(result.findings.length, 1);
  assert.match(result.findings[0].meta, /automatically_followed=false/);
});

test('ignora URL comum, malformed e observação marcada como reflexão', () => {
  const candidates = extractRuntimeEndpointCandidates([
    { url: 'https://shop.test/a', body: 'https://example.com/callback' },
    { url: 'https://shop.test/b', body: 'https://fixture.lambda-url.us-east-1.on.aws/x', reflectedInput: true },
    { url: 'https://shop.test/c', body: 'https://bad host.lambda-url.us-east-1.on.aws/x' },
  ]);
  assert.deepEqual(candidates, []);
});
