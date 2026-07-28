import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { createHash } from 'node:crypto';
import {
  resolveEngineMode,
  shouldRunGoEngine,
  resolveVigoliumStrategy,
  resolveVigoliumEffectiveConfig,
  resolveVigoliumTarget,
  vigoliumBinaryCandidates,
  resolveVigoliumModuleFilter,
  resolveVigoliumAuthFiles,
  resolveVigoliumAuthEntries,
  resolveVigoliumInputFile,
  resolveVigoliumInputType,
  resolveVigoliumOnly,
  resolveVigoliumModuleTags,
  resolveVigoliumSource,
  shouldPreferVigoliumPath,
  buildVigoliumChildEnv,
  shouldUseVigoliumCodex,
} from '../../bridge/vigolium-config.mjs';
import {
  assertVigoliumRuntimeTargetBinding,
  buildVigoliumHtmlReportArgs,
  buildVigoliumScanArgs,
  runVigoliumScan,
  sanitizeVigoliumHtmlReport,
} from '../../bridge/vigolium-runner.mjs';
import { createVigoliumAuthTransport } from '../../bridge/vigolium-auth-transport.mjs';
import { vigoliumRowToFinding, parseVigoliumJsonl } from '../../bridge/findings-normalizer.mjs';
import { getVigoliumCapabilities } from '../../bridge/vigolium-capabilities.mjs';
import { logVigoliumFindingsSummary } from '../../bridge/vigolium-log.mjs';
import { assertVigoliumBinaryIdentity } from '../../bridge/vigolium-binary-integrity.mjs';

describe('vigolium bridge — config', () => {
  it('sanitiza HTML autenticado no mesmo descritor antes de publicar', async () => {
    const tmp = await fs.mkdtemp(path.join(os.tmpdir(), 'ghostrecon-vig-report-redaction-'));
    const reportPath = path.join(tmp, 'report.html');
    const exactSecret = 'opaque-report-session-fixture';
    const genericSecret = `ghp_${'ZyXw9876'.repeat(4)}`;
    try {
      await fs.writeFile(
        reportPath,
        `<html><body>Authorization: Bearer ${exactSecret}\nCookie: sid=${exactSecret}\n${genericSecret}\n${tmp}/private/session.json\n/home/operator/private-auth.json</body></html>`,
      );
      await sanitizeVigoliumHtmlReport(reportPath, {
        redact: (value) => String(value).split(exactSecret).join('<redacted>'),
      });
      const [body, stat] = await Promise.all([
        fs.readFile(reportPath, 'utf8'),
        fs.stat(reportPath),
      ]);
      assert.doesNotMatch(body, /opaque-report-session-fixture|ghp_ZyXw9876/);
      assert.equal(body.includes(tmp), false);
      assert.doesNotMatch(body, /\/home\/operator\/private-auth\.json/);
      assert.match(body, /\[REDACTED\]|<redacted>/);
      if (process.platform !== 'win32') assert.equal(stat.mode & 0o777, 0o600);
    } finally {
      await fs.rm(tmp, { recursive: true, force: true });
    }
  });

  it('revalida a identidade selada do binário e recusa troca pós-aprovação', async () => {
    const tmp = await fs.mkdtemp(path.join(os.tmpdir(), 'ghostrecon-vig-identity-'));
    const binary = path.join(tmp, 'vigolium-fixture');
    try {
      await fs.writeFile(binary, 'vigolium-approved');
      const stat = await fs.stat(binary);
      const expected = {
        algorithm: 'sha256',
        sha256: createHash('sha256').update('vigolium-approved').digest('hex'),
        size: stat.size,
        dev: stat.dev,
        ino: stat.ino,
      };
      const verified = await assertVigoliumBinaryIdentity(binary, expected);
      assert.equal(verified.sha256, expected.sha256);

      await fs.writeFile(binary, 'vigolium-replaced');
      await assert.rejects(
        assertVigoliumBinaryIdentity(binary, expected),
        (error) => error?.code === 'VIGOLIUM_BINARY_IDENTITY_MISMATCH',
      );
    } finally {
      await fs.rm(tmp, { recursive: true, force: true });
    }
  });

  it('resolveEngineMode default node', () => {
    assert.equal(resolveEngineMode({}), 'node');
  });

  it('vigolium_dast força both quando engine node', () => {
    assert.equal(resolveEngineMode({ modules: ['vigolium_dast'] }), 'both');
  });

  it('shouldRunGoEngine com both', () => {
    assert.equal(shouldRunGoEngine('both', []), true);
    assert.equal(shouldRunGoEngine('node', ['rdap']), false);
    assert.equal(shouldRunGoEngine('node', ['vigolium_dast']), true);
  });

  it('resolveVigoliumStrategy', () => {
    assert.equal(resolveVigoliumStrategy({ vigoliumStrategy: 'deep' }), 'deep');
    assert.equal(resolveVigoliumStrategy({}), 'lite');
  });

  it('resolveVigoliumTarget usa https no domínio', () => {
    assert.equal(resolveVigoliumTarget({ domain: 'example.com' }), 'https://example.com');
  });

  it('vigoliumBinaryCandidates inclui variantes .exe para Windows', () => {
    const root = path.resolve('tmp-vigolium-root');
    const candidates = vigoliumBinaryCandidates(root);
    assert.ok(candidates.includes(path.join(root, 'engines', 'vigolium')));
    assert.ok(candidates.includes(path.join(root, 'engines', 'vigolium.exe')));
    assert.ok(candidates.includes(path.join(root, 'vigolium', 'bin', 'vigolium.exe')));
  });

  it('resolveVigoliumAuthFiles aceita lista do contexto', () => {
    assert.deepEqual(resolveVigoliumAuthFiles({ vigoliumAuthFiles: ['admin.json', ' user.yaml '] }), [
      'admin.json',
      'user.yaml',
    ]);
    assert.deepEqual(resolveVigoliumAuthFiles({ vigoliumAuthFile: 'solo.json' }), ['solo.json']);
  });

  it('resolveVigoliumModuleTags aceita lista ou tag unica', () => {
    assert.deepEqual(resolveVigoliumModuleTags({ vigoliumModuleTags: ['access-control', ' xss '] }), [
      'access-control',
      'xss',
    ]);
    assert.deepEqual(resolveVigoliumModuleTags({ vigoliumModuleTag: 'oast' }), ['oast']);
  });

  it('resolveVigolium input/auth/only aceita contexto', () => {
    assert.equal(resolveVigoliumInputFile({ vigoliumInputFile: 'openapi.yaml' }), 'openapi.yaml');
    assert.equal(resolveVigoliumInputType({ vigoliumInputType: 'openapi' }), 'openapi');
    assert.equal(resolveVigoliumOnly({ vigoliumOnly: 'discovery' }), 'discovery');
    assert.deepEqual(resolveVigoliumAuthEntries({ vigoliumAuthEntries: ['admin:Cookie:sid=1', ' user:Cookie:sid=2 '] }), [
      'admin:Cookie:sid=1',
      'user:Cookie:sid=2',
    ]);
    assert.deepEqual(resolveVigoliumAuthEntries({ vigoliumAuth: 'admin:Cookie:sid=1\nuser:Cookie:sid=2' }), [
      'admin:Cookie:sid=1',
      'user:Cookie:sid=2',
    ]);
  });

  it('resolve uma configuração efetiva imutável usando somente o ambiente injetado', () => {
    const effective = resolveVigoliumEffectiveConfig(
      {
        modules: ['rdap'],
        vigoliumVpsProfile: false,
      },
      {
        env: {
          GHOSTRECON_ENGINE: 'go',
          GHOSTRECON_VIGOLIUM_STRATEGY: 'balanced',
          GHOSTRECON_VIGOLIUM_MODULES: 'xss_light_scanner, sqli_error_based',
          GHOSTRECON_VIGOLIUM_MODULE_TAGS: 'access-control, oast',
          GHOSTRECON_VIGOLIUM_AUTH_FILES: '/tmp/admin.json, /tmp/user.json',
          GHOSTRECON_VIGOLIUM_AUTHS: 'admin:Cookie:sid=approved',
          GHOSTRECON_VIGOLIUM_ONLY: 'discovery',
          GHOSTRECON_VIGOLIUM_HTML_REPORT: '1',
          GHOSTRECON_VIGOLIUM_REPORT_ONLY: 'dast',
          GHOSTRECON_VIGOLIUM_PREFER_PATH: '1',
          GHOSTRECON_VIGOLIUM_USE_CODEX: '1',
          GHOSTRECON_VIGOLIUM_SOURCE: '/workspace/approved-source',
          GHOSTRECON_VIGOLIUM_AUDIT_MODE: 'deep',
          GHOSTRECON_VIGOLIUM_TIMEOUT_MS: '1234',
          GHOSTRECON_VIGOLIUM_AGENT_TIMEOUT_MS: '5678',
        },
      },
    );

    assert.equal(Object.isFrozen(effective), true);
    assert.equal(Object.isFrozen(effective.vigoliumModules), true);
    assert.equal(Object.isFrozen(effective.vigoliumAuthEntries), true);
    assert.equal(effective.vigoliumRuntimeConfigFrozen, true);
    assert.equal(effective.engine, 'go');
    assert.equal(effective.vigoliumStrategy, 'balanced');
    assert.deepEqual(effective.vigoliumModules, ['xss_light_scanner', 'sqli_error_based']);
    assert.deepEqual(effective.vigoliumModuleTags, ['access-control', 'oast']);
    assert.deepEqual(effective.vigoliumAuthFiles, ['/tmp/admin.json', '/tmp/user.json']);
    assert.deepEqual(effective.vigoliumAuthEntries, ['admin:Cookie:sid=approved']);
    assert.equal(effective.vigoliumOnly, 'discovery');
    assert.equal(effective.vigoliumHtmlReport, true);
    assert.equal(effective.vigoliumReportOnly, 'dast');
    assert.equal(effective.vigoliumPreferPath, true);
    assert.equal(effective.vigoliumUseCodex, true);
    assert.equal(effective.vigoliumVpsProfile, false);
    assert.equal(effective.vigoliumSource, '/workspace/approved-source');
    assert.equal(effective.vigoliumAuditMode, 'deep');
    assert.equal(effective.vigoliumTimeoutMs, 1234);
    assert.equal(effective.vigoliumAgentTimeoutMs, 5678);
  });

  it('configuração efetiva vazia não reabre opções por ambiente posterior', () => {
    const effective = resolveVigoliumEffectiveConfig(
      {
        modules: ['rdap'],
        vigoliumVpsProfile: false,
        vigoliumUseCodex: false,
        vigoliumHtmlReport: false,
        vigoliumPreferPath: false,
      },
      { env: {} },
    );
    const changedEnv = {
      PATH: '/safe/bin',
      GHOSTRECON_ENGINE: 'go',
      GHOSTRECON_VIGOLIUM_MODULES: 'must-not-reappear',
      GHOSTRECON_VIGOLIUM_MODULE_TAGS: 'must-not-reappear',
      GHOSTRECON_VIGOLIUM_AUTH_FILES: '/tmp/must-not-reappear.json',
      GHOSTRECON_VIGOLIUM_AUTHS: 'admin:Cookie:must-not-reappear',
      GHOSTRECON_VIGOLIUM_ONLY: 'must-not-reappear',
      GHOSTRECON_VIGOLIUM_SOURCE: '/tmp/must-not-reappear',
      GHOSTRECON_VIGOLIUM_PREFER_PATH: '1',
      GHOSTRECON_VIGOLIUM_USE_CODEX: '1',
      GHOSTRECON_VIGOLIUM_VPS_PROFILE: '1',
    };

    assert.deepEqual(resolveVigoliumModuleFilter(effective, changedEnv), []);
    assert.deepEqual(resolveVigoliumModuleTags(effective, changedEnv), []);
    assert.deepEqual(resolveVigoliumAuthFiles(effective, changedEnv), []);
    assert.deepEqual(resolveVigoliumAuthEntries(effective, changedEnv), []);
    assert.equal(resolveVigoliumOnly(effective, changedEnv), null);
    assert.equal(resolveVigoliumSource(effective, changedEnv), null);
    assert.equal(shouldPreferVigoliumPath(effective, changedEnv), false);
    assert.equal(shouldUseVigoliumCodex(effective, changedEnv), false);
    assert.deepEqual(buildVigoliumChildEnv(effective, changedEnv), { PATH: '/safe/bin' });
  });

  it('entrada Vigolium não reaparece pelo ambiente e runtime recusa -T não selado', async () => {
    const previousFile = process.env.GHOSTRECON_VIGOLIUM_INPUT_FILE;
    const previousType = process.env.GHOSTRECON_VIGOLIUM_INPUT_TYPE;
    try {
      process.env.GHOSTRECON_VIGOLIUM_INPUT_FILE = '/tmp/out-of-scope-openapi.yaml';
      process.env.GHOSTRECON_VIGOLIUM_INPUT_TYPE = 'openapi';
      assert.equal(resolveVigoliumInputFile({}), null);
      assert.equal(resolveVigoliumInputType({}), null);
      assert.throws(
        () => assertVigoliumRuntimeTargetBinding({
          domain: 'example.com',
          vigoliumInputFile: '/tmp/out-of-scope-openapi.yaml',
          vigoliumInputType: 'openapi',
        }),
        (error) => error?.code === 'VIGOLIUM_INPUT_SCOPE_UNSEALED',
      );
      await assert.rejects(
        runVigoliumScan({
          domain: 'example.com',
          vigoliumInputFile: '/tmp/out-of-scope-openapi.yaml',
        }),
        (error) => error?.code === 'VIGOLIUM_INPUT_SCOPE_UNSEALED',
      );
    } finally {
      if (previousFile == null) delete process.env.GHOSTRECON_VIGOLIUM_INPUT_FILE;
      else process.env.GHOSTRECON_VIGOLIUM_INPUT_FILE = previousFile;
      if (previousType == null) delete process.env.GHOSTRECON_VIGOLIUM_INPUT_TYPE;
      else process.env.GHOSTRECON_VIGOLIUM_INPUT_TYPE = previousType;
    }
  });

  it('ambiente filho Vigolium usa allowlist e nunca encaminha tokens/DB/JWT', () => {
    const child = buildVigoliumChildEnv({
      vigoliumUseCodex: true,
      vigoliumVpsProfile: false,
    }, {
      PATH: '/safe/bin',
      HOME: '/safe/home',
      LANG: 'pt_BR.UTF-8',
      DATABASE_URL: 'postgres://user:password@db/private',
      JWT_SECRET: 'jwt-secret',
      GITHUB_TOKEN: 'ghp_secret',
      OPENAI_API_KEY: 'sk-secret',
      AUTH_API_KEYS: 'root-secret',
      GHOSTRECON_API_KEY: 'api-secret',
      VIGOLIUM_PROVIDER: 'unapproved-provider',
    });

    assert.deepEqual(child, {
      PATH: '/safe/bin',
      HOME: '/safe/home',
      LANG: 'pt_BR.UTF-8',
      GHOSTRECON_VIGOLIUM_USE_CODEX: '1',
      VIGOLIUM_PROVIDER: 'openai-codex-oauth',
    });
    assert.doesNotMatch(JSON.stringify(child), /password|jwt-secret|ghp_secret|sk-secret|root-secret|api-secret/);
  });

  it('decisão explícita de não usar Codex prevalece sobre o ambiente do servidor', () => {
    const previous = process.env.GHOSTRECON_VIGOLIUM_USE_CODEX;
    try {
      process.env.GHOSTRECON_VIGOLIUM_USE_CODEX = '1';
      assert.equal(shouldUseVigoliumCodex({ vigoliumUseCodex: false }), false);
      assert.equal(shouldUseVigoliumCodex({ vigoliumUseCodex: true }), true);
      assert.equal(shouldUseVigoliumCodex({}), true);

      const child = buildVigoliumChildEnv(
        { vigoliumUseCodex: false, vigoliumVpsProfile: false },
        { PATH: '/safe/bin', GHOSTRECON_VIGOLIUM_USE_CODEX: '1' },
      );
      assert.deepEqual(child, { PATH: '/safe/bin' });
    } finally {
      if (previous == null) delete process.env.GHOSTRECON_VIGOLIUM_USE_CODEX;
      else process.env.GHOSTRECON_VIGOLIUM_USE_CODEX = previous;
    }
  });

  it('buildVigoliumScanArgs inclui modulos e auth-file sem segredos inline no argv', () => {
    const built = buildVigoliumScanArgs({
      domain: 'example.com',
      vigoliumStrategy: 'balanced',
      vigoliumModules: ['xss_light_scanner'],
      vigoliumModuleTags: ['access-control'],
      vigoliumAuthFiles: ['admin.json', 'user.json'],
      vigoliumAuthEntries: ['admin:Cookie:session_id=abc123', 'user:Cookie:session_id=xyz789'],
      auth: {
        cookie: 'sid=abc',
        headers: { Authorization: 'Bearer token' },
      },
    }, { outFile: 'out.jsonl' });
    assert.deepEqual(built.args.slice(0, 8), ['scan', '-t', 'https://example.com', '--strategy', 'balanced', '--format', 'jsonl', '-o']);
    assert.ok(built.args.includes('out.jsonl'));
    assert.ok(built.args.includes('xss_light_scanner'));
    assert.ok(built.args.includes('--module-tag'));
    assert.ok(built.args.includes('access-control'));
    assert.ok(built.args.includes('--auth-file'));
    assert.ok(built.args.includes('admin.json'));
    assert.ok(built.args.includes('user.json'));
    assert.ok(built.args.includes('-S'));
    assert.equal(built.args.includes('--auth'), false);
    assert.equal(built.args.includes('-H'), false);
    assert.doesNotMatch(built.args.join(' '), /abc123|xyz789|sid=abc|Bearer token/);
  });

  it('buildVigoliumScanArgs suporta entrada OpenAPI -T/-I e --only', () => {
    const built = buildVigoliumScanArgs({
      domain: 'api.example.com',
      vigoliumInputFile: 'openapi.yaml',
      vigoliumInputType: 'openapi',
      vigoliumOnly: 'discovery',
      vigoliumStrategy: 'deep',
    }, { outFile: 'out.jsonl' });
    assert.deepEqual(built.args.slice(0, 6), ['scan', '-T', 'openapi.yaml', '-I', 'openapi', '--strategy']);
    assert.equal(built.target, 'openapi.yaml');
    assert.ok(!built.args.includes('-t'));
    assert.ok(built.args.includes('--only'));
    assert.ok(built.args.includes('discovery'));
  });

  it('buildVigoliumHtmlReportArgs gera --format html -o report', () => {
    const built = buildVigoliumHtmlReportArgs({
      domain: 'example.com',
      vigoliumReportOnly: 'discovery',
      vigoliumAuthFiles: ['admin.json'],
    }, { outFile: 'report.html' });
    assert.deepEqual(built.args.slice(0, 3), ['scan', '-t', 'https://example.com']);
    assert.ok(built.args.includes('--format'));
    assert.ok(built.args.includes('html'));
    assert.ok(built.args.includes('-o'));
    assert.ok(built.args.includes('report.html'));
    assert.ok(built.args.includes('--only'));
    assert.ok(built.args.includes('discovery'));
    assert.ok(built.args.includes('admin.json'));
    assert.ok(built.args.includes('-S'));
    assert.equal(built.args.includes('--auth'), false);
  });

  it('materializa auth inline em JSON 0600 e remove no cleanup', async () => {
    const tempRoot = await fs.mkdtemp(path.join(os.tmpdir(), 'ghostrecon-vig-auth-test-'));
    const operatorFile = path.join(tempRoot, 'operator.json');
    await fs.writeFile(operatorFile, JSON.stringify({ sessions: [] }), { mode: 0o600 });
    let transport;
    try {
      transport = await createVigoliumAuthTransport({
        vigoliumAuthFiles: [operatorFile],
        vigoliumAuthEntries: [
          'admin:Cookie:session_id=abc123',
          'admin:Authorization:Bearer inline-token',
        ],
        auth: {
          cookie: 'sid=shared',
          headers: { 'X-Session': 'shared-token' },
        },
      }, { tempRoot, allowedRoots: [tempRoot] });

      assert.notEqual(transport.authFiles[0], operatorFile);
      assert.deepEqual(
        JSON.parse(await fs.readFile(transport.authFiles[0], 'utf8')),
        { sessions: [] },
      );
      assert.ok(transport.ephemeralFile);
      const payload = JSON.parse(await fs.readFile(transport.ephemeralFile, 'utf8'));
      assert.equal(payload.sessions[0].name, 'ghostrecon');
      assert.equal(payload.sessions[0].headers.Cookie, 'sid=shared');
      assert.equal(payload.sessions[0].headers['X-Session'], 'shared-token');
      assert.equal(payload.sessions[1].name, 'admin');
      assert.equal(payload.sessions[1].headers.Cookie, 'session_id=abc123');
      assert.equal(payload.sessions[1].headers.Authorization, 'Bearer inline-token');

      if (process.platform !== 'win32') {
        const dirMode = (await fs.stat(path.dirname(transport.ephemeralFile))).mode & 0o777;
        const fileMode = (await fs.stat(transport.ephemeralFile)).mode & 0o777;
        assert.equal(dirMode, 0o700);
        assert.equal(fileMode, 0o600);
      }

      const built = buildVigoliumScanArgs(
        { domain: 'example.com', vigoliumAuthEntries: ['admin:Cookie:must-not-leak'] },
        { outFile: 'out.jsonl', authFiles: transport.authFiles },
      );
      assert.equal(built.args.includes('--auth'), false);
      assert.equal(built.args.includes('-S'), true);
      assert.doesNotMatch(built.args.join(' '), /must-not-leak|abc123|inline-token|shared-token/);
    } finally {
      const ephemeralFile = transport?.ephemeralFile;
      await transport?.cleanup?.();
      if (ephemeralFile) {
        await assert.rejects(fs.access(ephemeralFile));
      }
      await fs.rm(tempRoot, { recursive: true, force: true });
    }
  });

  it('redige segredo opaco carregado por auth-file sem remover o arquivo do operador', async () => {
    const tempRoot = await fs.mkdtemp(path.join(os.tmpdir(), 'ghostrecon-vig-auth-file-redact-'));
    const authFile = path.join(tempRoot, 'operator-session.json');
    const secret = 'opaque-auth-file-secret-fixture';
    await fs.writeFile(authFile, JSON.stringify({
      sessions: [{
        name: 'operator',
        headers: {
          Authorization: `Bearer ${secret}`,
          Cookie: `sid=${secret}`,
        },
        login: {
          username: 'operator',
          password: secret,
        },
      }],
    }), { mode: 0o600 });

    const transport = await createVigoliumAuthTransport({
      vigoliumAuthFiles: [authFile],
    }, { allowedRoots: [tempRoot] });
    try {
      assert.equal(transport.ephemeralFile, null);
      assert.notEqual(transport.authFiles[0], authFile);
      const safe = transport.redact(`finding ${secret} via ${authFile}`);
      assert.equal(safe.includes(secret), false);
      assert.equal(safe.includes(authFile), false);
      assert.match(safe, /redacted/i);
      assert.match(safe, /LOCAL_PATH/);
    } finally {
      await transport.cleanup();
      await transport.cleanup();
      assert.equal((await fs.stat(authFile)).isFile(), true);
      await assert.rejects(fs.access(transport.authFiles[0]));
      await fs.rm(tempRoot, { recursive: true, force: true });
    }
  });

  it('recusa auth-file com quebra de linha antes de montar argv', async () => {
    await assert.rejects(
      createVigoliumAuthTransport({
        vigoliumAuthFiles: ['operator.json\n--auth attacker:Cookie:sid=1'],
      }),
      /caminho de auth-file Vigolium inválido/,
    );
  });
});

describe('vigolium PATH mode fake binary', () => {
  it('propaga o AbortSignal do pipeline ao subprocesso Vigolium', async () => {
    const tmp = await fs.mkdtemp(path.join(os.tmpdir(), 'ghostrecon-vig-signal-'));
    const binary = path.join(tmp, process.platform === 'win32' ? 'vigolium.exe' : 'vigolium');
    const oldBin = process.env.GHOSTRECON_VIGOLIUM_BIN;
    const oldDatabaseUrl = process.env.DATABASE_URL;
    const oldApiKey = process.env.OPENAI_API_KEY;
    const controller = new AbortController();
    let receivedSignal = null;
    let receivedEnv = null;
    try {
      await fs.writeFile(binary, 'fixture');
      if (process.platform !== 'win32') await fs.chmod(binary, 0o755);
      process.env.GHOSTRECON_VIGOLIUM_BIN = binary;
      process.env.DATABASE_URL = 'postgres://scanner:secret@db/internal';
      process.env.OPENAI_API_KEY = 'sk-scanner-secret';
      const out = await runVigoliumScan({
        ROOT: tmp,
        domain: 'example.com',
        vigoliumVpsProfile: false,
        signal: controller.signal,
      }, {
        log: () => {},
        runProcessImpl: async (_file, _args, options) => {
          receivedSignal = options.signal;
          receivedEnv = options.spawnOpts?.env;
          return {
            code: 0,
            stdout: `${JSON.stringify({
              'template-id': 'signal-fixture',
              url: 'https://example.com/',
              info: { name: 'Signal fixture', severity: 'info' },
            })}\n`,
            stderr: '',
            timedOut: false,
          };
        },
      });
      assert.equal(out.ok, true);
      assert.equal(receivedSignal, controller.signal);
      assert.equal(receivedEnv.DATABASE_URL, undefined);
      assert.equal(receivedEnv.OPENAI_API_KEY, undefined);
      assert.doesNotMatch(JSON.stringify(receivedEnv), /scanner:secret|sk-scanner-secret/);
    } finally {
      if (oldBin == null) delete process.env.GHOSTRECON_VIGOLIUM_BIN;
      else process.env.GHOSTRECON_VIGOLIUM_BIN = oldBin;
      if (oldDatabaseUrl == null) delete process.env.DATABASE_URL;
      else process.env.DATABASE_URL = oldDatabaseUrl;
      if (oldApiKey == null) delete process.env.OPENAI_API_KEY;
      else process.env.OPENAI_API_KEY = oldApiKey;
      await fs.rm(tmp, { recursive: true, force: true });
    }
  });

  it('não rebaixa falhas fatais/cancelamento do scan para resultado parcial ou skip', async () => {
    const tmp = await fs.mkdtemp(path.join(os.tmpdir(), 'ghostrecon-vig-fatal-scan-'));
    const binary = path.join(tmp, process.platform === 'win32' ? 'vigolium.exe' : 'vigolium');
    const oldBin = process.env.GHOSTRECON_VIGOLIUM_BIN;
    const cases = [
      {
        label: 'processo abortado',
        createError() {
          const error = new Error('fixture process aborted');
          error.code = 'PROCESS_ABORTED';
          return error;
        },
        verify(error) {
          return error?.code === 'PROCESS_ABORTED';
        },
      },
      {
        label: 'processo sem confirmação de término',
        createError() {
          const error = new Error('fixture process unterminated');
          error.code = 'PROCESS_UNTERMINATED';
          error.unterminated = true;
          return error;
        },
        verify(error) {
          return error?.code === 'PROCESS_UNTERMINATED' && error?.unterminated === true;
        },
      },
      {
        label: 'identidade do binário divergente',
        createError() {
          const error = new Error('fixture binary identity mismatch');
          error.code = 'VIGOLIUM_BINARY_IDENTITY_MISMATCH';
          return error;
        },
        verify(error) {
          return error?.code === 'VIGOLIUM_BINARY_IDENTITY_MISMATCH';
        },
      },
      {
        label: 'AbortError',
        createError() {
          const error = new Error('fixture abort error');
          error.name = 'AbortError';
          return error;
        },
        verify(error) {
          return error?.name === 'AbortError';
        },
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
          runVigoliumScan({
            ROOT: tmp,
            domain: 'example.com',
            vigoliumVpsProfile: false,
            vigoliumAuthEntries: ['operator:Cookie:sid=fatal-fixture-secret'],
          }, {
            log: () => {},
            runProcessImpl: async (_file, args) => {
              calls += 1;
              const authFileIndex = args.indexOf('--auth-file');
              ephemeralAuthFile = authFileIndex >= 0 ? args[authFileIndex + 1] : null;
              throw fixture.createError();
            },
          }),
          (error) => {
            assert.equal(
              fixture.verify(error),
              true,
              `${fixture.label} deve preservar a identidade terminal`,
            );
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

  it('propaga falha fatal ocorrida na geração do HTML legado', async () => {
    const tmp = await fs.mkdtemp(path.join(os.tmpdir(), 'ghostrecon-vig-fatal-html-'));
    const binary = path.join(tmp, process.platform === 'win32' ? 'vigolium.exe' : 'vigolium');
    const oldBin = process.env.GHOSTRECON_VIGOLIUM_BIN;
    let calls = 0;
    try {
      await fs.writeFile(binary, 'fixture');
      if (process.platform !== 'win32') await fs.chmod(binary, 0o755);
      process.env.GHOSTRECON_VIGOLIUM_BIN = binary;

      await assert.rejects(
        runVigoliumScan({
          ROOT: tmp,
          domain: 'example.com',
          vigoliumVpsProfile: false,
          vigoliumHtmlReport: true,
        }, {
          log: () => {},
          runProcessImpl: async () => {
            calls += 1;
            if (calls === 1) {
              return { code: 0, stdout: '', stderr: '', timedOut: false };
            }
            const error = new Error('fixture HTML child did not terminate');
            error.code = 'PROCESS_UNTERMINATED';
            error.unterminated = true;
            throw error;
          },
        }),
        (error) => (
          error?.code === 'PROCESS_UNTERMINATED'
          && error?.unterminated === true
          && error?.recoverable === false
        ),
      );
      assert.equal(calls, 2);
    } finally {
      if (oldBin == null) delete process.env.GHOSTRECON_VIGOLIUM_BIN;
      else process.env.GHOSTRECON_VIGOLIUM_BIN = oldBin;
      await fs.rm(tmp, { recursive: true, force: true });
    }
  });

  it('propaga cancelamento fatal ocorrido no fallback SQLite', async () => {
    const tmp = await fs.mkdtemp(path.join(os.tmpdir(), 'ghostrecon-vig-fatal-sqlite-'));
    const binary = path.join(tmp, process.platform === 'win32' ? 'vigolium.exe' : 'vigolium');
    const oldBin = process.env.GHOSTRECON_VIGOLIUM_BIN;
    let calls = 0;
    try {
      await fs.writeFile(binary, 'fixture');
      if (process.platform !== 'win32') await fs.chmod(binary, 0o755);
      process.env.GHOSTRECON_VIGOLIUM_BIN = binary;

      await assert.rejects(
        runVigoliumScan({
          ROOT: tmp,
          domain: 'example.com',
          modules: ['vigolium_dast'],
          vigoliumVpsProfile: true,
          vigoliumHtmlReport: false,
        }, {
          log: () => {},
          runProcessImpl: async (_file, args) => {
            calls += 1;
            if (calls === 1) {
              const outputIndex = args.indexOf('-o');
              const outputBase = outputIndex >= 0 ? args[outputIndex + 1] : null;
              assert.ok(outputBase);
              await fs.writeFile(`${outputBase}.jsonl`, '');
              await fs.writeFile(`${outputBase}.sqlite`, 'sqlite-fixture');
              return { code: 0, stdout: '', stderr: '', timedOut: false };
            }
            assert.equal(args[0], 'finding');
            const error = new Error('fixture SQLite import aborted');
            error.code = 'PROCESS_ABORTED';
            throw error;
          },
        }),
        (error) => error?.code === 'PROCESS_ABORTED' && error?.recoverable === false,
      );
      assert.equal(calls, 2);
    } finally {
      if (oldBin == null) delete process.env.GHOSTRECON_VIGOLIUM_BIN;
      else process.env.GHOSTRECON_VIGOLIUM_BIN = oldBin;
      await fs.rm(tmp, { recursive: true, force: true });
    }
  });

  it('go-engine preserva divergência de identidade como terminal e não emite skip/done', async () => {
    const tmp = await fs.mkdtemp(path.join(os.tmpdir(), 'ghostrecon-vig-go-engine-fatal-'));
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
      const { runGoEnginePhase } = await import('../pipeline/phases/go-engine.mjs');

      await assert.rejects(
        runGoEnginePhase({
          ROOT: tmp,
          domain: 'example.com',
          modules: ['vigolium_dast'],
          engineMode: 'go',
          vigoliumVpsProfile: false,
          vigoliumExpectedIdentity: {
            algorithm: 'sha256',
            sha256: '0'.repeat(64),
            size: 0,
          },
          log: () => {},
          emit: () => {},
          pipe: (name, state) => pipes.push({ name, state }),
          addFinding: () => {},
          progress: () => {},
        }),
        (error) => error?.code === 'VIGOLIUM_BINARY_IDENTITY_MISMATCH',
      );

      assert.equal(
        pipes.some((item) => (
          ['vigolium_engine', 'vigolium_dast'].includes(item.name)
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

  it('runVigoliumScan usa vigolium do PATH, normaliza findings e gera report HTML', async () => {
    const tmp = await fs.mkdtemp(path.join(os.tmpdir(), 'ghostrecon-fake-vigolium-'));
    const oldPath = process.env.PATH;
    const oldBin = process.env.GHOSTRECON_VIGOLIUM_BIN;
    const oldCwd = process.cwd();
    const fakeScript = `const fs = require('fs');
let args = process.argv.slice(2);
if (args[0] === 'scan') args = args.slice(1);
const at = (flag) => { const i = args.indexOf(flag); return i >= 0 ? args[i + 1] : ''; };
const target = at('-t') || at('-T') || 'https://example.com';
const out = at('-o') || '-';
const format = at('--format') || 'jsonl';
if (format === 'html') {
  fs.writeFileSync(out, '<!doctype html><title>fake vigolium report</title>', 'utf8');
  process.exit(0);
}
const row = {
  'template-id': 'fake-path-xss',
  type: 'http',
  url: target,
  'matched-at': target + '/search?q=x',
  info: { name: 'Fake PATH XSS', severity: 'high', confidence: 'firm', tags: ['xss'] }
};
const payload = JSON.stringify(row) + '\\n';
if (out === '-') process.stdout.write(payload);
else fs.writeFileSync(out, payload, 'utf8');
`;
    try {
      delete process.env.GHOSTRECON_VIGOLIUM_BIN;
      if (process.platform === 'win32') {
        await fs.copyFile(process.execPath, path.join(tmp, 'vigolium.exe'));
        await fs.writeFile(path.join(tmp, 'scan'), fakeScript, 'utf8');
      } else {
        await fs.writeFile(path.join(tmp, 'vigolium'), `#!/usr/bin/env node\n${fakeScript}`, 'utf8');
        await fs.chmod(path.join(tmp, 'vigolium'), 0o755);
      }
      process.env.PATH = `${tmp}${path.delimiter}${oldPath || ''}`;
      process.chdir(tmp);

      const out = await runVigoliumScan({
        ROOT: tmp,
        domain: 'example.com',
        modules: ['vigolium_dast'],
        kaliMode: true,
        vigoliumPreferPath: true,
        vigoliumStrategy: 'deep',
        vigoliumVpsProfile: false,
        vigoliumHtmlReport: true,
        vigoliumReportOnly: 'discovery',
      }, { log: () => {} });

      assert.equal(out.skipped, false);
      assert.equal(out.ok, true);
      assert.equal(out.binarySource, 'path');
      assert.equal(out.strategy, 'deep');
      assert.equal(out.findings.length, 1);
      assert.equal(out.findings[0].sourceEngine, 'vigolium');
      assert.equal(out.findings[0].moduleId, 'fake-path-xss');
      assert.equal(out.htmlReport.ok, true);
      assert.match(out.htmlReport.url, /^\/api\/vigolium\/reports\//);
      const html = await fs.readFile(out.htmlReport.path, 'utf8');
      assert.match(html, /fake vigolium report/);
    } finally {
      process.chdir(oldCwd);
      process.env.PATH = oldPath;
      if (oldBin == null) delete process.env.GHOSTRECON_VIGOLIUM_BIN;
      else process.env.GHOSTRECON_VIGOLIUM_BIN = oldBin;
      await fs.rm(tmp, { recursive: true, force: true });
    }
  });

  it('runVigoliumScan usa somente --auth-file temporário e não registra segredo', async () => {
    const tmp = await fs.mkdtemp(path.join(os.tmpdir(), 'ghostrecon-fake-vig-auth-'));
    const fakeBin = path.join(tmp, process.platform === 'win32' ? 'vigolium-auth.exe' : 'vigolium-auth');
    const capturePath = path.join(tmp, 'capture.json');
    const oldBin = process.env.GHOSTRECON_VIGOLIUM_BIN;
    const fakeScript = `const fs = require('fs');
const args = process.argv.slice(2);
const at = (flag) => { const i = args.indexOf(flag); return i >= 0 ? args[i + 1] : ''; };
const authFile = at('--auth-file');
const auth = JSON.parse(fs.readFileSync(authFile, 'utf8'));
fs.writeFileSync(${JSON.stringify(capturePath)}, JSON.stringify({ args, authFile, auth }), 'utf8');
const out = at('-o') || '-';
const row = JSON.stringify({
  'template-id': 'auth-transport',
  url: at('-t') + '/private?opaque=runtime-inline-secret',
  'matched-at': 'authenticated runtime-inline-secret',
  request: 'GET /private HTTP/1.1\\r\\nAuthorization: Bearer runtime-inline-secret',
  response: 'HTTP/1.1 200 OK\\r\\nSet-Cookie: sid=runtime-cookie-secret',
  info: { name: 'Auth transport runtime-cookie-secret', severity: 'info' }
}) + '\\n';
if (out === '-') process.stdout.write(row); else fs.writeFileSync(out, row, 'utf8');
`;
    const logs = [];
    try {
      if (process.platform === 'win32') {
        await fs.copyFile(process.execPath, fakeBin);
        await fs.writeFile(path.join(tmp, 'scan'), fakeScript, 'utf8');
      } else {
        await fs.writeFile(fakeBin, `#!/usr/bin/env node\n${fakeScript}`, 'utf8');
        await fs.chmod(fakeBin, 0o755);
      }
      process.env.GHOSTRECON_VIGOLIUM_BIN = fakeBin;

      const result = await runVigoliumScan({
        ROOT: tmp,
        domain: 'example.com',
        vigoliumVpsProfile: true,
        vigoliumHtmlReport: true,
        vigoliumAuthEntries: ['admin:Authorization:Bearer runtime-inline-secret'],
        auth: { cookie: 'sid=runtime-cookie-secret' },
      }, { log: (message) => logs.push(String(message)) });

      assert.equal(result.ok, true);
      const captured = JSON.parse(await fs.readFile(capturePath, 'utf8'));
      assert.equal(captured.args.includes('--auth'), false);
      assert.equal(captured.args.includes('-H'), false);
      assert.equal(captured.args.includes('-S'), true);
      assert.doesNotMatch(captured.args.join(' '), /runtime-inline-secret|runtime-cookie-secret/);
      assert.equal(captured.auth.sessions[0].headers.Cookie, 'sid=runtime-cookie-secret');
      assert.equal(captured.auth.sessions[1].headers.Authorization, 'Bearer runtime-inline-secret');
      await assert.rejects(fs.access(captured.authFile));
      assert.doesNotMatch(logs.join('\n'), /runtime-inline-secret|runtime-cookie-secret/);
      assert.doesNotMatch(JSON.stringify(result.findings), /runtime-inline-secret|runtime-cookie-secret/);
      assert.match(JSON.stringify(result.findings), /redacted/i);
      assert.match(logs.join('\n'), /--auth-file <restricted-file>/);
      assert.equal(result.vpsProfile, false);
      assert.equal(result.htmlReport, null);
      await assert.rejects(fs.access(path.join(tmp, '.runtime', 'vigolium-reports')));
    } finally {
      if (oldBin == null) delete process.env.GHOSTRECON_VIGOLIUM_BIN;
      else process.env.GHOSTRECON_VIGOLIUM_BIN = oldBin;
      await fs.rm(tmp, { recursive: true, force: true });
    }
  });
});

describe('vigolium bridge — normalizer', () => {
  it('vigoliumRowToFinding mapeia ResultEvent', () => {
    const row = {
      'template-id': 'active-xss-light-url-params',
      type: 'http',
      url: 'https://example.com/search?q=test',
      'matched-at': 'https://example.com/search?q=<script>',
      info: {
        name: 'XSS Light - URL Parameters',
        severity: 'high',
        confidence: 'firm',
        tags: ['xss', 'injection'],
        description: 'Reflected XSS in query parameter',
      },
    };
    const f = vigoliumRowToFinding(row);
    assert.ok(f);
    assert.equal(f.type, 'vuln');
    assert.equal(f.prio, 'high');
    assert.ok(f.meta.includes('vigolium:active-xss-light-url-params'));
    assert.equal(f.owasp, 'A03:2021');
    assert.equal(f.sourceEngine, 'vigolium');
    assert.equal(f.moduleId, 'active-xss-light-url-params');
    assert.equal(f.evidence.matchedAt, 'https://example.com/search?q=<script>');
  });

  it('parseVigoliumJsonl ignora linhas inválidas', () => {
    const jsonl = `not json
{"template-id":"active-sqli-error-based","type":"http","url":"https://x.com","info":{"name":"SQLi","severity":"critical","confidence":"certain"}}
`;
    const rows = parseVigoliumJsonl(jsonl);
    assert.equal(rows.length, 1);
    assert.equal(rows[0].prio, 'high');
  });
});

describe('vigolium bridge — capabilities', () => {
  it('getVigoliumCapabilities retorna estrutura', async () => {
    const cap = await getVigoliumCapabilities();
    assert.ok('installed' in cap);
    assert.ok(Array.isArray(cap.candidates));
    assert.ok(cap.strategies?.includes('lite'));
    assert.ok('codex' in cap);
    assert.equal(typeof cap.codex.installed, 'boolean');
  });
});

describe('vigolium bridge — log summary', () => {
  it('logVigoliumFindingsSummary emite linhas find por achado', () => {
    const lines = [];
    logVigoliumFindingsSummary((msg, level) => lines.push({ msg, level }), [
      {
        prio: 'high',
        url: 'https://x.com/a',
        value: 'xss',
        meta: 'source=vigolium:xss-reflected • reflected XSS',
      },
    ], { label: 'Vigolium DAST' });
    assert.equal(lines[0].level, 'warn');
    assert.match(lines[0].msg, /1 achado/);
    assert.equal(lines[1].level, 'find');
    assert.match(lines[1].msg, /\[high\] xss-reflected/);
  });
});

describe('go-engine phase — skip sem módulo', () => {
  it('não corre vigolium quando engine=node e sem vigolium_dast', async () => {
    const { runGoEnginePhase } = await import('../pipeline/phases/go-engine.mjs');
    const pipes = [];
    await runGoEnginePhase({
      modules: ['rdap'],
      engineMode: 'node',
      domain: 'example.com',
      log: () => {},
      pipe: (name, state) => pipes.push({ name, state }),
      addFinding: () => {},
      progress: () => {},
      ROOT: process.cwd(),
    });
    assert.ok(pipes.some((p) => p.name === 'vigolium_engine' && p.state === 'skip'));
  });
});
