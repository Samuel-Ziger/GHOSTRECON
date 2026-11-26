import test from 'node:test';
import assert from 'node:assert/strict';

import {
  analyzeCloudDebugObservation,
  runCloudDebugEnvAudit,
} from '../modules/cloud-debug-env-audit.mjs';

const AWS_SESSION_SENTINEL = 'synthetic-aws-session-token-value-123456789';
const METADATA_SENTINEL = 'synthetic-metadata-token-value-987654321';

function debugFixture() {
  return {
    url: 'https://fixture.lambda-url.us-east-1.on.aws/debug',
    status: 200,
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({
      aws_account_id: '123456789012',
      function_arn: 'arn:aws:lambda:us-east-1:123456789012:function:fixture',
      bucket_name: 'fixture-bucket',
      environment_variables: {
        AWS_REGION: 'us-east-1',
        AWS_SESSION_TOKEN: AWS_SESSION_SENTINEL,
        AWS_LAMBDA_METADATA_TOKEN: METADATA_SENTINEL,
      },
    }),
  };
}

test('classifica debug cloud e nunca devolve token bruto', () => {
  const analysis = analyzeCloudDebugObservation(debugFixture());
  assert.ok(analysis);
  assert.equal(analysis.classification, 'confirmed');
  assert.equal(analysis.prio, 'high');
  assert.equal(analysis.metadata.account_id, '123456789012');
  assert.equal(analysis.metadata.bucket_name, 'fixture-bucket');
  assert.equal(analysis.secretRefs.length, 2);
  const serialized = JSON.stringify(analysis);
  assert.equal(serialized.includes(AWS_SESSION_SENTINEL), false);
  assert.equal(serialized.includes(METADATA_SENTINEL), false);
  assert.match(serialized, /sha256:/);
});

test('health genérico e documentação de exemplo não viram confirmed', () => {
  assert.equal(analyzeCloudDebugObservation({
    url: 'https://fixture.test/health',
    status: 200,
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ status: 'ok', version: '1.2.3' }),
  }), null);

  const docs = analyzeCloudDebugObservation({
    ...debugFixture(),
    url: 'https://fixture.test/docs/example',
  });
  assert.ok(docs);
  assert.equal(docs.classification, 'candidate');
});

test('modo passivo não chama fetch e agrega métricas', async () => {
  let calls = 0;
  const result = await runCloudDebugEnvAudit({
    observations: [debugFixture()],
    probeOrigins: false,
    fetchImpl: async () => {
      calls += 1;
      throw new Error('network forbidden');
    },
  });
  assert.equal(calls, 0);
  assert.equal(result.findings.length, 1);
  assert.equal(result.metrics.confirmed, 1);
  assert.equal(result.metrics.secretRefs, 2);
});

test('baseline soft-404 impede falso positivo no probe opcional', async () => {
  const body = debugFixture().body;
  let calls = 0;
  const result = await runCloudDebugEnvAudit({
    origins: ['https://fixture.test'],
    probeOrigins: true,
    urlAllowed: () => true,
    baselinePathFactory: () => '/not-found-fixture',
    fetchImpl: async (url) => {
      calls += 1;
      return new Response(body, {
        status: 200,
        headers: { 'content-type': 'application/json' },
      });
    },
  });
  assert.equal(calls, 2);
  assert.equal(result.findings.length, 0);
  assert.equal(result.outcomes[0].reason, 'soft_404_baseline_match');
});
