import test from 'node:test';
import assert from 'node:assert/strict';
import { analyzeApiExcessiveData, runApiExcessiveDataAudit } from '../modules/api-excessive-data-audit.mjs';

function users(count = 12) {
  return Array.from({ length: count }, (_, i) => ({
    id: `u-${i}`, email: `fixture-${i}@invalid.test`, full_name: `Fixture ${i}`,
  }));
}

test('coleção anônima densa e sem paginação vira provável sem persistir valores', async () => {
  const result = await runApiExcessiveDataAudit({ observations: [{
    url: 'https://lab.invalid/api/demo-users', status: 200, json: { users: users() }, authTrust: 'anonymous',
  }] });
  assert.equal(result.findings.length, 1);
  assert.equal(result.findings[0].state, 'probable');
  assert.doesNotMatch(JSON.stringify(result), /fixture-0@invalid\.test|Fixture 0/);
});

test('catálogo público, dataset sintético, paginação e sessão confiável são negativos', () => {
  const base = { url: 'https://lab.invalid/api/users', status: 200, json: { users: users() }, authTrust: 'anonymous' };
  assert.equal(analyzeApiExcessiveData({ ...base, expectedPublicDirectory: true }).findings.length, 0);
  assert.equal(analyzeApiExcessiveData({ ...base, syntheticDataset: true }).findings.length, 0);
  assert.equal(analyzeApiExcessiveData({ ...base, json: { users: users(), next_cursor: 'fixture' } }).findings.length, 0);
  assert.equal(analyzeApiExcessiveData({ ...base, authTrust: 'trusted' }).findings.length, 0);
});
