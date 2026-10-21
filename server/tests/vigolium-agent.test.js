import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import {
  resolveVigoliumAgentMode,
  shouldRunGoAgent,
  resolveVigoliumSource,
} from '../../bridge/vigolium-config.mjs';
import { auditRowToFinding, parseVigoliumJsonl } from '../../bridge/findings-normalizer.mjs';
import { buildVigoliumAgentArgs, runVigoliumAgent } from '../../bridge/agent-bridge.mjs';

describe('vigolium agent — config', () => {
  it('propaga o AbortSignal do pipeline ao subprocesso do agente', async () => {
    const tmp = await fs.mkdtemp(path.join(os.tmpdir(), 'ghostrecon-vig-agent-signal-'));
    const binary = path.join(tmp, process.platform === 'win32' ? 'vigolium.exe' : 'vigolium');
    const oldBin = process.env.GHOSTRECON_VIGOLIUM_BIN;
    const oldDatabaseUrl = process.env.DATABASE_URL;
    const oldJwtSecret = process.env.JWT_SECRET;
    const controller = new AbortController();
    let receivedSignal = null;
    let receivedEnv = null;
    try {
      await fs.writeFile(binary, 'fixture');
      if (process.platform !== 'win32') await fs.chmod(binary, 0o755);
      process.env.GHOSTRECON_VIGOLIUM_BIN = binary;
      process.env.DATABASE_URL = 'postgres://private:secret@db/internal';
      process.env.JWT_SECRET = 'agent-jwt-secret';
      const result = await runVigoliumAgent({
        ROOT: tmp,
        domain: 'example.com',
        vigoliumSource: tmp,
        vigoliumUseCodex: true,
        signal: controller.signal,
        log: () => {},
      }, 'audit', {
        assertVigoliumSourceIdentityImpl: async (_source, _expected, options) => {
          assert.equal(options.signal, controller.signal);
        },
        runProcessImpl: async (_file, _args, options) => {
          receivedSignal = options.signal;
          receivedEnv = options.spawnOpts?.env;
          return {
            code: 0,
            stdout: `${JSON.stringify({ agentic_scan_uuid: 'signal', total_findings: 0 })}\n`,
            stderr: '',
            timedOut: false,
          };
        },
      });
      assert.equal(result.ok, true);
      assert.equal(receivedSignal, controller.signal);
      assert.equal(receivedEnv.DATABASE_URL, undefined);
      assert.equal(receivedEnv.JWT_SECRET, undefined);
      assert.equal(receivedEnv.VIGOLIUM_PROVIDER, 'openai-codex-oauth');
      assert.doesNotMatch(JSON.stringify(receivedEnv), /private:secret|agent-jwt-secret/);
    } finally {
      if (oldBin == null) delete process.env.GHOSTRECON_VIGOLIUM_BIN;
      else process.env.GHOSTRECON_VIGOLIUM_BIN = oldBin;
      if (oldDatabaseUrl == null) delete process.env.DATABASE_URL;
      else process.env.DATABASE_URL = oldDatabaseUrl;
      if (oldJwtSecret == null) delete process.env.JWT_SECRET;
      else process.env.JWT_SECRET = oldJwtSecret;
      await fs.rm(tmp, { recursive: true, force: true });
    }
  });

  it('não rebaixa falhas fatais/cancelamento do agente para resultado parcial ou skip', async () => {
    const tmp = await fs.mkdtemp(path.join(os.tmpdir(), 'ghostrecon-vig-agent-fatal-'));
    const binary = path.join(tmp, process.platform === 'win32' ? 'vigolium.exe' : 'vigolium');
    const oldBin = process.env.GHOSTRECON_VIGOLIUM_BIN;
    const cases = [
      {
        createError() {
          const error = new Error('fixture process aborted');
          error.code = 'PROCESS_ABORTED';
          return error;
        },
        verify: (error) => error?.code === 'PROCESS_ABORTED',
      },
      {
        createError() {
          const error = new Error('fixture process unterminated');
          error.code = 'PROCESS_UNTERMINATED';
          error.unterminated = true;
          return error;
        },
        verify: (error) => (
          error?.code === 'PROCESS_UNTERMINATED' && error?.unterminated === true
        ),
      },
      {
        createError() {
          const error = new Error('fixture binary identity mismatch');
          error.code = 'VIGOLIUM_BINARY_IDENTITY_MISMATCH';
          return error;
        },
        verify: (error) => error?.code === 'VIGOLIUM_BINARY_IDENTITY_MISMATCH',
      },
      {
        createError() {
          const error = new Error('fixture abort error');
          error.name = 'AbortError';
          return error;
        },
        verify: (error) => error?.name === 'AbortError',
      },
    ];

    try {
      await fs.writeFile(binary, 'fixture');
      if (process.platform !== 'win32') await fs.chmod(binary, 0o755);
      process.env.GHOSTRECON_VIGOLIUM_BIN = binary;

      for (const fixture of cases) {
        let calls = 0;
        await assert.rejects(
          runVigoliumAgent({
            ROOT: tmp,
            domain: 'example.com',
            vigoliumAuthEntries: ['operator:Cookie:sid=fatal-agent-secret'],
            log: () => {},
          }, 'query', {
            runProcessImpl: async (_file, args) => {
              calls += 1;
              assert.equal(args.includes('--db'), false);
              throw fixture.createError();
            },
          }),
          (error) => {
            assert.equal(fixture.verify(error), true);
            assert.equal(error?.fatal, true);
            assert.equal(error?.recoverable, false);
            return true;
          },
        );
        assert.equal(calls, 1);
      }
    } finally {
      if (oldBin == null) delete process.env.GHOSTRECON_VIGOLIUM_BIN;
      else process.env.GHOSTRECON_VIGOLIUM_BIN = oldBin;
      await fs.rm(tmp, { recursive: true, force: true });
    }
  });

  it('revalida a fonte imediatamente antes do agente e trata divergência como terminal', async () => {
    const tmp = await fs.mkdtemp(path.join(os.tmpdir(), 'ghostrecon-vig-agent-source-'));
    const binary = path.join(tmp, process.platform === 'win32' ? 'vigolium.exe' : 'vigolium');
    const oldBin = process.env.GHOSTRECON_VIGOLIUM_BIN;
    let sourceChecks = 0;
    let processCalls = 0;
    try {
      await fs.writeFile(binary, 'fixture');
      if (process.platform !== 'win32') await fs.chmod(binary, 0o755);
      process.env.GHOSTRECON_VIGOLIUM_BIN = binary;
      await assert.rejects(
        runVigoliumAgent({
          ROOT: tmp,
          domain: 'example.com',
          vigoliumSource: tmp,
          vigoliumExpectedSourceIdentity: { fixture: true },
          vigoliumSourceAllowedRoots: [tmp],
          log: () => {},
        }, 'audit', {
          assertVigoliumSourceIdentityImpl: async (source, expected, options) => {
            sourceChecks += 1;
            assert.equal(source, tmp);
            assert.deepEqual(expected, { fixture: true });
            assert.deepEqual(options.allowedRoots, [tmp]);
            const error = new Error('source mismatch fixture');
            error.code = 'VIGOLIUM_SOURCE_IDENTITY_MISMATCH';
            throw error;
          },
          runProcessImpl: async () => {
            processCalls += 1;
            throw new Error('não deveria executar');
          },
        }),
        (error) => (
          error?.code === 'VIGOLIUM_SOURCE_IDENTITY_MISMATCH'
          && error?.fatal === true
          && error?.recoverable === false
        ),
      );
      assert.equal(sourceChecks, 1);
      assert.equal(processCalls, 0);
    } finally {
      if (oldBin == null) delete process.env.GHOSTRECON_VIGOLIUM_BIN;
      else process.env.GHOSTRECON_VIGOLIUM_BIN = oldBin;
      await fs.rm(tmp, { recursive: true, force: true });
    }
  });

  it('go-agent preserva divergência de identidade como terminal e não emite skip/done', async () => {
    const tmp = await fs.mkdtemp(path.join(os.tmpdir(), 'ghostrecon-vig-go-agent-fatal-'));
    const binary = path.join(tmp, process.platform === 'win32' ? 'vigolium.exe' : 'vigolium');
    const oldBin = process.env.GHOSTRECON_VIGOLIUM_BIN;
    const pipes = [];
    try {
      if (process.platform === 'win32') {
        await fs.copyFile(process.execPath, binary);
      } else {
        await fs.writeFile(
          binary,
          '#!/usr/bin/env node\nif (process.argv[2] === "version") console.log("Version: fixture");\n',
        );
        await fs.chmod(binary, 0o755);
      }
      process.env.GHOSTRECON_VIGOLIUM_BIN = binary;
      const { runGoAgentPhase } = await import('../pipeline/phases/go-agent.mjs');

      await assert.rejects(
        runGoAgentPhase({
          ROOT: tmp,
          domain: 'example.com',
          modules: ['vigolium_audit'],
          vigoliumAgentMode: 'query',
          vigoliumExpectedIdentity: {
            algorithm: 'sha256',
            sha256: '0'.repeat(64),
            size: 0,
          },
          log: () => {},
          pipe: (name, state) => pipes.push({ name, state }),
          addFinding: () => {},
          progress: () => {},
        }),
        (error) => error?.code === 'VIGOLIUM_BINARY_IDENTITY_MISMATCH',
      );

      assert.equal(
        pipes.some((item) => (
          item.name === 'vigolium_agent'
          && ['skip', 'done'].includes(item.state)
        )),
        false,
      );
    } finally {
      if (oldBin == null) delete process.env.GHOSTRECON_VIGOLIUM_BIN;
      else process.env.GHOSTRECON_VIGOLIUM_BIN = oldBin;
      await fs.rm(tmp, { recursive: true, force: true });
    }
  });

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

  it('swarm falha fechado antes de resolver binário, ler autenticação ou iniciar agente', async () => {
    const state = {
      domain: 'example.test',
      vigoliumAuthFiles: ['/nonexistent/private-auth.json'],
      vigoliumAuthEntries: ['admin:Cookie:sid=fixture-private'],
      vigoliumModules: ['headers'],
      auth: { headers: { Authorization: 'Bearer fixture-private' } },
      log: () => {},
    };
    const built = buildVigoliumAgentArgs(state, 'swarm');
    assert.equal(built.skipped, true);
    assert.deepEqual(built.args, []);
    assert.deepEqual(built.authFiles, []);
    let calls = 0;
    const result = await runVigoliumAgent(state, 'swarm', {
      runProcessImpl: async () => { calls += 1; throw new Error('não deve executar'); },
    });
    assert.equal(calls, 0);
    assert.equal(result.skipped, true);
    assert.equal(result.ok, false);
    assert.deepEqual(result.findings, []);
    assert.doesNotMatch(JSON.stringify(result), /fixture-private|private-auth/);

    const controller = new AbortController();
    controller.abort(new Error('cancel fixture'));
    await assert.rejects(runVigoliumAgent({ ...state, signal: controller.signal }, 'swarm'), /cancel fixture/);
  });

  it('autopilot prévia não recebe auth nem transforma exemplos em findings', async () => {
    const tmp = await fs.mkdtemp(path.join(os.tmpdir(), 'ghostrecon-vig-preview-'));
    const binary = path.join(tmp, 'vigolium');
    try {
      await fs.writeFile(binary, 'fixture');
      const state = {
        ROOT: tmp, domain: 'example.test',
        vigoliumRuntimeConfigFrozen: true,
        vigoliumBinaryPath: binary, vigoliumAgentTimeoutMs: 1000,
        vigoliumAuthFiles: ['/nonexistent/auth.json'],
        auth: { headers: { Authorization: 'Bearer fixture-private' } },
        log: () => {},
      };
      const result = await runVigoliumAgent(state, 'autopilot', {
        runProcessImpl: async (_file, args) => {
          assert.ok(args.includes('--dry-run'));
          assert.ok(args.includes('--no-prescan'));
          assert.ok(args.includes('--no-preflight-discovery'));
          assert.equal(args.includes('--auth-file'), false);
          assert.equal(args.includes('--auth-config'), false);
          assert.equal(args.includes('--db'), false);
          assert.doesNotMatch(args.join(' '), /fixture-private/);
          return {
            code: 0, timedOut: false,
            stdout: JSON.stringify({ type: 'finding', data: { title: 'Exemplo', severity: 'high' } }),
          };
        },
      });
      assert.equal(result.ok, true);
      assert.equal(result.planOnly, true);
      assert.deepEqual(result.findings, []);

      for (const outcome of [{ code: 2, timedOut: false }, { code: 0, timedOut: true }]) {
        const failed = await runVigoliumAgent(state, 'query', {
          runProcessImpl: async () => ({
            ...outcome,
            stdout: JSON.stringify({ type: 'finding', data: { title: 'Parcial', severity: 'low' } }),
          }),
        });
        assert.equal(failed.ok, false);
        assert.equal(failed.partial, true);
      }
    } finally {
      await fs.rm(tmp, { recursive: true, force: true });
    }
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
