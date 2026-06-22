import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import {
  resolveEngineMode,
  shouldRunGoEngine,
  resolveVigoliumStrategy,
  resolveVigoliumTarget,
  vigoliumBinaryCandidates,
  resolveVigoliumAuthFiles,
  resolveVigoliumAuthEntries,
  resolveVigoliumInputFile,
  resolveVigoliumInputType,
  resolveVigoliumOnly,
  resolveVigoliumModuleTags,
} from '../../bridge/vigolium-config.mjs';
import { buildVigoliumHtmlReportArgs, buildVigoliumScanArgs, runVigoliumScan } from '../../bridge/vigolium-runner.mjs';
import { vigoliumRowToFinding, parseVigoliumJsonl } from '../../bridge/findings-normalizer.mjs';
import { getVigoliumCapabilities } from '../../bridge/vigolium-capabilities.mjs';
import { logVigoliumFindingsSummary } from '../../bridge/vigolium-log.mjs';

describe('vigolium bridge — config', () => {
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

  it('buildVigoliumScanArgs inclui modulos, module-tag, auth-file e auth inline', () => {
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
    assert.ok(built.args.includes('admin:Cookie:session_id=abc123'));
    assert.ok(built.args.includes('user:Cookie:session_id=xyz789'));
    assert.ok(built.args.includes('ghostrecon:Cookie:sid=abc'));
    assert.ok(built.args.includes('Authorization: Bearer token'));
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
      vigoliumAuthEntries: ['admin:Cookie:sid=1'],
    }, { outFile: 'report.html' });
    assert.deepEqual(built.args.slice(0, 3), ['scan', '-t', 'https://example.com']);
    assert.ok(built.args.includes('--format'));
    assert.ok(built.args.includes('html'));
    assert.ok(built.args.includes('-o'));
    assert.ok(built.args.includes('report.html'));
    assert.ok(built.args.includes('--only'));
    assert.ok(built.args.includes('discovery'));
    assert.ok(built.args.includes('admin:Cookie:sid=1'));
  });
});

describe('vigolium PATH mode fake binary', () => {
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
