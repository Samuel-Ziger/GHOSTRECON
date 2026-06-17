import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { runPipeline } from '../pipeline/run-pipeline.mjs';

describe('pipeline smoke — runPipeline', () => {
  it('rdap-only em example.com emite done', async () => {
    const events = [];
    const timeout = setTimeout(() => {
      throw new Error('timeout 90s');
    }, 90_000);

    try {
      await runPipeline({
        domain: 'example.com',
        exactMatch: false,
        modules: ['rdap'],
        profile: 'quick',
        emit: (e) => events.push(e),
      });
    } finally {
      clearTimeout(timeout);
    }

    assert.ok(events.some((e) => e.type === 'log'), 'esperava logs NDJSON');
    assert.ok(events.some((e) => e.type === 'done'), 'esperava evento done');
    const done = events.find((e) => e.type === 'done');
    assert.equal(done.target, 'example.com');
  });
});
