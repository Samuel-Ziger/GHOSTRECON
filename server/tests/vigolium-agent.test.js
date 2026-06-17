import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import {
  resolveVigoliumAgentMode,
  shouldRunGoAgent,
  resolveVigoliumSource,
} from '../../bridge/vigolium-config.mjs';
import { auditRowToFinding } from '../../bridge/findings-normalizer.mjs';

describe('vigolium agent — config', () => {
  it('resolveVigoliumAgentMode via módulos', () => {
    assert.equal(resolveVigoliumAgentMode({ modules: ['vigolium_audit'] }), 'audit');
    assert.equal(resolveVigoliumAgentMode({ modules: ['vigolium_swarm'] }), 'swarm');
    assert.equal(resolveVigoliumAgentMode({ modules: ['rdap'] }), 'none');
  });

  it('shouldRunGoAgent', () => {
    assert.equal(shouldRunGoAgent('none', ['vigolium_audit']), true);
    assert.equal(shouldRunGoAgent('none', ['rdap']), false);
  });

  it('auditRowToFinding', () => {
    const f = auditRowToFinding({
      title: 'SQL injection in login',
      severity: 'high',
      file: 'src/auth.js',
      description: 'User input concatenated in query',
    });
    assert.equal(f.type, 'code_audit');
    assert.equal(f.prio, 'high');
    assert.ok(f.meta.includes('vigolium:audit'));
  });
});

describe('go-agent phase — skip', () => {
  it('skip sem módulos agent', async () => {
    const { runGoAgentPhase } = await import('../pipeline/phases/go-agent.mjs');
    const pipes = [];
    await runGoAgentPhase({
      modules: ['rdap'],
      vigoliumAgentMode: 'none',
      domain: 'example.com',
      log: () => {},
      pipe: (name, state) => pipes.push({ name, state }),
      addFinding: () => {},
      progress: () => {},
      ROOT: process.cwd(),
    });
    assert.ok(pipes.some((p) => p.name === 'vigolium_agent' && p.state === 'skip'));
  });
});
