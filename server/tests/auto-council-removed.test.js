import test from 'node:test';
import assert from 'node:assert/strict';

import {
  normalizeAutoRequest,
  assertNoRetiredAutoAiFields,
} from '../auto-agent/orchestrator.mjs';

const RETIRED_FIELDS = [
  ['commander', 'codex'],
  ['commanders', ['codex']],
  ['providers', ['openrouter']],
  ['openrouterModel', 'legacy-model'],
  ['model', 'legacy-model'],
  ['cloudEvidenceConsent', true],
];

test('contrato Auto rejeita explicitamente todos os campos do Council aposentado', () => {
  for (const [field, value] of RETIRED_FIELDS) {
    assert.throws(
      () => assertNoRetiredAutoAiFields({ [field]: value }),
      (error) => (
        error?.code === 'AUTO_AI_COUNCIL_RETIRED'
        && error?.status === 410
        && error?.fields?.includes(field)
      ),
      field,
    );
  }
});

test('normalizeAutoRequest rejeita aliases dos módulos Shannon/PentestGPT removidos', () => {
  for (const moduleId of [
    'shannon_whitebox',
    'shannon-whitebox',
    'pentestgpt_validate',
    'pentestgpt-validate',
  ]) {
    assert.throws(
      () => normalizeAutoRequest({ domain: 'example.test', modules: [moduleId] }),
      (error) => error?.code === 'MODULE_RETIRED' && error?.statusCode === 410,
      moduleId,
    );
  }
});

test('normalizeAutoRequest novo não cria contrato implícito de provider', () => {
  const request = normalizeAutoRequest({
    domain: 'example.test',
    modules: ['headers'],
    autonomyLevel: 'observation',
  });
  for (const [field] of RETIRED_FIELDS) {
    assert.equal(Object.hasOwn(request, field), false, field);
  }
});
