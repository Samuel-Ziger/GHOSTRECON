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
        let ephemeralAuthFile = null;
        let calls = 0;
        await assert.rejects(
          runVigoliumAgent({
            ROOT: tmp,
            domain: 'example.com',
            vigoliumAuthEntries: ['operator:Cookie:sid=fatal-agent-secret'],
            log: () => {},
          }, 'swarm', {
            runProcessImpl: async (_file, args) => {
              calls += 1;
              const authFileIndex = args.indexOf('--auth-file');
              ephemeralAuthFile = authFileIndex >= 0 ? args[authFileIndex + 1] : null;
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
        assert.ok(ephemeralAuthFile);
        await assert.rejects(fs.access(ephemeralAuthFile));
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
          modules: ['vigolium_swarm'],
          vigoliumAgentMode: 'swarm',
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
          ['vigolium_agent', 'vigolium_swarm'].includes(item.name)
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

  it('buildVigoliumAgentArgs passa apenas auth-file para swarm', () => {
    const built = buildVigoliumAgentArgs({
      domain: 'example.com',
      vigoliumSource: 'C:/repo/app',
      vigoliumAuthFiles: ['admin.json', 'user.json'],
      vigoliumAuthEntries: ['admin:Cookie:sid=1'],
      vigoliumModuleTags: ['access-control'],
    }, 'swarm', {
      privateDbPath: '/tmp/ghostrecon-agent-private.sqlite',
    });
    assert.equal(built.skipped, false);
    assert.ok(built.args.includes('-t'));
    assert.ok(built.args.includes('https://example.com'));
    assert.ok(built.args.includes('--auth-file'));
    assert.ok(built.args.includes('admin.json'));
    assert.ok(built.args.includes('user.json'));
    assert.ok(built.args.includes('--db'));
    assert.ok(built.args.includes('/tmp/ghostrecon-agent-private.sqlite'));
    assert.equal(built.args.includes('--auth'), false);
    assert.doesNotMatch(built.args.join(' '), /sid=1/);
    assert.ok(built.args.includes('--module-tag'));
    assert.ok(built.args.includes('access-control'));
  });

  it('runVigoliumAgent materializa auth, remove o temporário e não loga segredo', async () => {
    const tmp = await fs.mkdtemp(path.join(os.tmpdir(), 'ghostrecon-fake-vig-agent-auth-'));
    const fakeBin = path.join(tmp, process.platform === 'win32' ? 'vigolium-agent.exe' : 'vigolium-agent');
    const capturePath = path.join(tmp, 'agent-capture.json');
    const oldBin = process.env.GHOSTRECON_VIGOLIUM_BIN;
    const fakeScript = `const fs = require('fs');
const args = process.argv.slice(2);
const at = (flag) => { const i = args.indexOf(flag); return i >= 0 ? args[i + 1] : ''; };
const authFile = at('--auth-file');
const dbPath = at('--db');
const auth = JSON.parse(fs.readFileSync(authFile, 'utf8'));
fs.writeFileSync(${JSON.stringify(capturePath)}, JSON.stringify({ args, authFile, dbPath, auth }), 'utf8');
process.stdout.write(JSON.stringify({
  type: 'finding',
  data: {
    title: 'opaque agent-shared-secret',
    severity: 'medium',
    description: 'cookie agent-inline-secret'
  }
}) + '\\n');
process.stdout.write(JSON.stringify({
  agentic_scan_uuid: 'agent-auth',
  session_dir: '/tmp/agent-shared-secret',
  total_findings: 1
}) + '\\n');
`;
    const logs = [];
    try {
      if (process.platform === 'win32') {
        await fs.copyFile(process.execPath, fakeBin);
        await fs.writeFile(path.join(tmp, 'agent'), fakeScript, 'utf8');
      } else {
        await fs.writeFile(fakeBin, `#!/usr/bin/env node\n${fakeScript}`, 'utf8');
        await fs.chmod(fakeBin, 0o755);
      }
      process.env.GHOSTRECON_VIGOLIUM_BIN = fakeBin;

      const result = await runVigoliumAgent({
        ROOT: tmp,
        domain: 'example.com',
        vigoliumAuthEntries: ['admin:Cookie:agent-inline-secret'],
        auth: { headers: { Authorization: 'Bearer agent-shared-secret' } },
        log: (message) => logs.push(String(message)),
      }, 'swarm');

      assert.equal(result.ok, true);
      const captured = JSON.parse(await fs.readFile(capturePath, 'utf8'));
      assert.equal(captured.args.includes('--auth'), false);
      assert.doesNotMatch(captured.args.join(' '), /agent-inline-secret|agent-shared-secret/);
      assert.equal(captured.auth.sessions[0].headers.Authorization, 'Bearer agent-shared-secret');
      assert.equal(captured.auth.sessions[1].headers.Cookie, 'agent-inline-secret');
      await assert.rejects(fs.access(captured.authFile));
      assert.ok(captured.dbPath);
      await assert.rejects(fs.access(captured.dbPath));
      assert.doesNotMatch(logs.join('\n'), /agent-inline-secret|agent-shared-secret/);
      assert.doesNotMatch(JSON.stringify(result.findings), /agent-inline-secret|agent-shared-secret/);
      assert.doesNotMatch(JSON.stringify(result.summary), /agent-inline-secret|agent-shared-secret/);
    } finally {
      if (oldBin == null) delete process.env.GHOSTRECON_VIGOLIUM_BIN;
      else process.env.GHOSTRECON_VIGOLIUM_BIN = oldBin;
      await fs.rm(tmp, { recursive: true, force: true });
    }
  });

  it('runVigoliumAgent aplica redactor exato aos findings e ao resumo autenticado', async () => {
    const tmp = await fs.mkdtemp(path.join(os.tmpdir(), 'ghostrecon-vig-agent-output-redaction-'));
    const binary = path.join(tmp, process.platform === 'win32' ? 'vigolium.exe' : 'vigolium');
    const oldBin = process.env.GHOSTRECON_VIGOLIUM_BIN;
    const opaqueSecret = 'agent-output-secret-fixture';
    try {
      await fs.writeFile(binary, 'fixture');
      if (process.platform !== 'win32') await fs.chmod(binary, 0o755);
      process.env.GHOSTRECON_VIGOLIUM_BIN = binary;
      const result = await runVigoliumAgent({
        ROOT: tmp,
        domain: 'example.com',
        auth: { headers: { Authorization: `Bearer ${opaqueSecret}` } },
        log: () => {},
      }, 'swarm', {
        runProcessImpl: async () => ({
          code: 0,
          stderr: '',
          timedOut: false,
          stdout: [
            JSON.stringify({
              type: 'finding',
              data: {
                title: `opaque ${opaqueSecret}`,
                severity: 'medium',
                description: `standalone ${opaqueSecret}`,
              },
            }),
            JSON.stringify({
              agentic_scan_uuid: 'auth-redaction',
              session_dir: `/tmp/${opaqueSecret}`,
              total_findings: 1,
            }),
          ].join('\n'),
        }),
      });
      const serialized = JSON.stringify({
        findings: result.findings,
        summary: result.summary,
      });
      assert.equal(result.findings.length, 1);
      assert.equal(serialized.includes(opaqueSecret), false);
      assert.equal(serialized.includes('/tmp/'), false);
      assert.match(serialized, /redacted/i);
      assert.match(serialized, /LOCAL_PATH/);
    } finally {
      if (oldBin == null) delete process.env.GHOSTRECON_VIGOLIUM_BIN;
      else process.env.GHOSTRECON_VIGOLIUM_BIN = oldBin;
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
