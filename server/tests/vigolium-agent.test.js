import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import {
  resolveVigoliumAgentMode,
  shouldRunGoAgent,
  resolveVigoliumSource,
} from '../../bridge/vigolium-config.mjs';
import { auditRowToFinding, parseVigoliumJsonl } from '../../bridge/findings-normalizer.mjs';
import { buildVigoliumAgentArgs } from '../../bridge/agent-bridge.mjs';

describe('vigolium agent — config', () => {
  it('resolveVigoliumAgentMode via módulos', () => {
    assert.equal(resolveVigoliumAgentMode({ modules: ['vigolium_audit'] }), 'audit');
    assert.equal(resolveVigoliumAgentMode({ modules: ['vigolium_swarm'] }), 'swarm');
    assert.equal(resolveVigoliumAgentMode({ modules: ['vigolium_autopilot'] }), 'autopilot');
    assert.equal(resolveVigoliumAgentMode({ modules: ['rdap'] }), 'none');
  });

  it('shouldRunGoAgent', () => {
    assert.equal(shouldRunGoAgent('none', ['vigolium_audit']), true);
    assert.equal(shouldRunGoAgent('none', ['vigolium_autopilot']), true);
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

  it('buildVigoliumAgentArgs usa resumo JSON sem -o para audit', () => {
    const built = buildVigoliumAgentArgs({
      domain: 'example.com',
      vigoliumSource: 'C:/repo/app',
      vigoliumAuditMode: 'deep',
    }, 'audit');
    assert.equal(built.skipped, false);
    assert.deepEqual(built.args.slice(0, 5), ['agent', 'audit', '-j', '-F', '--soft-fail']);
    assert.ok(built.args.includes('--source'));
    assert.ok(built.args.includes('C:/repo/app'));
    assert.ok(built.args.includes('--mode'));
    assert.ok(built.args.includes('deep'));
    assert.equal(built.args.includes('-o'), false);
    assert.equal(built.args.includes('--format'), false);
  });

  it('buildVigoliumAgentArgs passa auth-file e auth inline para swarm', () => {
    const built = buildVigoliumAgentArgs({
      domain: 'example.com',
      vigoliumSource: 'C:/repo/app',
      vigoliumAuthFiles: ['admin.json', 'user.json'],
      vigoliumAuthEntries: ['admin:Cookie:sid=1'],
      vigoliumModuleTags: ['access-control'],
    }, 'swarm');
    assert.equal(built.skipped, false);
    assert.ok(built.args.includes('-t'));
    assert.ok(built.args.includes('https://example.com'));
    assert.ok(built.args.includes('--auth-file'));
    assert.ok(built.args.includes('admin.json'));
    assert.ok(built.args.includes('user.json'));
    assert.ok(built.args.includes('--auth'));
    assert.ok(built.args.includes('admin:Cookie:sid=1'));
    assert.ok(built.args.includes('--module-tag'));
    assert.ok(built.args.includes('access-control'));
  });

  it('parseVigoliumJsonl entende top_findings do resumo agent', () => {
    const rows = parseVigoliumJsonl(JSON.stringify({
      agentic_scan_uuid: 'agt-1',
      session_dir: 'C:/tmp/session',
      top_findings: [
        { title: 'Unsafe redirect', severity: 'high', file: 'src/routes.js', confidence: 'firm' },
      ],
    }));
    assert.equal(rows.length, 1);
    assert.equal(rows[0].type, 'code_audit');
    assert.equal(rows[0].sourceEngine, 'vigolium');
    assert.equal(rows[0].moduleId, 'audit');
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
