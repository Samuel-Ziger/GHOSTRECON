import test from 'node:test';
import assert from 'node:assert/strict';

import { publicArtifactValue } from '../routes/auto-recon.mjs';

test('respostas públicas de Forge/RAG removem caminhos em qualquer profundidade', () => {
  const safe = publicArtifactValue({
    forgeId: 'forge-fixture',
    dir: '/tmp/forge',
    correction: {
      pendingDir: '/tmp/forge/pending',
      history: [{
        revisionDir: '/tmp/forge/revision-1',
        result: { ok: true },
      }],
    },
    verdict: {
      password: 'fixture-password',
      status: 'pending_operator_approval',
    },
  });

  assert.equal(safe.forgeId, 'forge-fixture');
  assert.equal(safe.correction.history[0].result.ok, true);
  assert.equal(safe.verdict.status, 'pending_operator_approval');
  assert.equal(safe.verdict.password, '[REDACTED]');
  assert.equal(JSON.stringify(safe).includes('/tmp/forge'), false);
});
