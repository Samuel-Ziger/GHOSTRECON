import test from 'node:test';
import assert from 'node:assert/strict';

import {
  isSensitiveAutoKey,
  redactAutoText,
  redactPublicTarget,
  redactAutoValue,
} from '../auto-agent/redaction.mjs';

const AWS_SESSION_SENTINEL = 'synthetic-aws-session-token-value-123456789';
const AWS_METADATA_SENTINEL = 'synthetic-lambda-metadata-token-value-987654321';
const PAN_SENTINEL = '4111111111111111';
const CVV_SENTINEL = '737';

function assertSecretsAbsent(value) {
  const serialized = typeof value === 'string' ? value : JSON.stringify(value);
  for (const secret of [AWS_SESSION_SENTINEL, AWS_METADATA_SENTINEL, PAN_SENTINEL, CVV_SENTINEL]) {
    assert.equal(serialized.includes(secret), false, `segredo escapou: ${secret.slice(0, 8)}`);
  }
}

test('redação estrutural cobre tokens AWS e dados de pagamento por chave canônica', () => {
  const safe = redactAutoValue({
    environment_variables: {
      AWS_SESSION_TOKEN: AWS_SESSION_SENTINEL,
      AWS_LAMBDA_METADATA_TOKEN: AWS_METADATA_SENTINEL,
    },
    payment: {
      card_number: PAN_SENTINEL,
      cvv: CVV_SENTINEL,
    },
    aws_account_id: '123456789012',
    function_arn: 'arn:aws:lambda:us-east-1:123456789012:function:fixture',
    bucket_name: 'fixture-bucket',
  });

  assertSecretsAbsent(safe);
  assert.equal(safe.environment_variables.AWS_SESSION_TOKEN, '[REDACTED]');
  assert.equal(safe.environment_variables.AWS_LAMBDA_METADATA_TOKEN, '[REDACTED]');
  assert.equal(safe.payment.card_number, '[REDACTED]');
  assert.equal(safe.payment.cvv, '[REDACTED]');
  assert.equal(safe.aws_account_id, '123456789012');
  assert.match(safe.function_arn, /^arn:aws:lambda:/);
  assert.equal(safe.bucket_name, 'fixture-bucket');
});

test('redação textual cobre JSON, env e preserva números sem contexto sensível', () => {
  const safe = redactAutoText([
    `AWS_SESSION_TOKEN=${AWS_SESSION_SENTINEL}`,
    `AWS_LAMBDA_METADATA_TOKEN: ${AWS_METADATA_SENTINEL}`,
    `{"card_number":"${PAN_SENTINEL}","cvv":"${CVV_SENTINEL}"}`,
    'order_id=2026111400012345',
  ].join('\n'), {}, { cloud: false });

  assertSecretsAbsent(safe);
  assert.match(safe, /AWS_SESSION_TOKEN=\[REDACTED\]/);
  assert.match(safe, /card_number/);
  assert.match(safe, /order_id=2026111400012345/);
});

test('classificador de chaves entende estilos AWS e payment sem marcar metadados cloud', () => {
  for (const key of [
    'AWS_SESSION_TOKEN',
    'aws-lambda-metadata-token',
    'awsSecretAccessKey',
    'card_number',
    'credit-card-number',
    'CVV',
  ]) {
    assert.equal(isSensitiveAutoKey(key), true, key);
  }
  for (const key of ['aws_account_id', 'function_arn', 'bucket_name', 'region', 'order_id']) {
    assert.equal(isSensitiveAutoKey(key), false, key);
  }
});

test('alvo público preserva origem/path e redige query sensível inclusive percent-encoded', () => {
  const jwt = 'eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJmaXh0dXJlIn0.abcdefghijklmnopqrstuvwxyz123456';
  const safe = redactPublicTarget(
    `http://147.135.87.82:30472/api/v1?view=full&access%5Ftoken=${jwt}&X-Amz-Signature=raw-signature`,
  );
  assert.match(safe, /^http:\/\/147\.135\.87\.82:30472\/api\/v1\?/);
  assert.match(safe, /view=full/);
  assert.match(safe, /access_token=.*REDACTED/i);
  assert.match(safe, /X-Amz-Signature=.*REDACTED/i);
  assert.doesNotMatch(safe, /eyJhbGci|raw-signature/);
});
