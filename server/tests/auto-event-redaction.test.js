import test from 'node:test';
import assert from 'node:assert/strict';

import { publicAutoEvent } from '../auto-agent/orchestrator.mjs';

test('eventos Auto redigem segredos e omitem caminhos locais absolutos', () => {
  const event = publicAutoEvent({
    type: 'auto_rag',
    sessionId: 'session-safe-fixture01',
    error: 'falha ao ler /home/operator/private/plan.md',
    memory: {
      name: 'plan.md',
      filePath: '/home/operator/private/plan.md',
      nested: {
        revisionDir: '/tmp/private-revision',
        reportUrl: '/reports/public/report.html',
        authorization: 'Bearer fixture-secret-value',
      },
    },
  }, { root: '/home/operator/private' });

  assert.equal(event.sessionId, 'session-safe-fixture01');
  assert.equal(event.memory.name, 'plan.md');
  assert.equal('filePath' in event.memory, false);
  assert.equal('revisionDir' in event.memory.nested, false);
  assert.equal(event.memory.nested.reportUrl, '/reports/public/report.html');
  assert.equal(event.memory.nested.authorization, '[REDACTED]');
  assert.equal(JSON.stringify(event).includes('/home/operator'), false);
  assert.match(event.error, /\[LOCAL_ROOT\]/);
  assert.equal(JSON.stringify(event).includes('fixture-secret-value'), false);
});

test('eventos Auto preservam o resumo público da sessão sem expor campos sensíveis', () => {
  const event = publicAutoEvent({
    type: 'auto_session',
    phase: 'completed',
    session: {
      sessionId: 'session-safe-fixture02',
      status: 'completed',
      password: 'fixture-password',
    },
  });

  assert.equal(event.session.sessionId, 'session-safe-fixture02');
  assert.equal(event.session.status, 'completed');
  assert.equal(event.session.password, '[REDACTED]');
});
