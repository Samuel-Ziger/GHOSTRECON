import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import path from 'node:path';
import {
  resolveEngineMode,
  shouldRunGoEngine,
  resolveVigoliumStrategy,
  resolveVigoliumTarget,
  vigoliumBinaryCandidates,
  resolveVigoliumAuthFiles,
  resolveVigoliumModuleTags,
} from '../../bridge/vigolium-config.mjs';
import { buildVigoliumScanArgs } from '../../bridge/vigolium-runner.mjs';
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

  it('buildVigoliumScanArgs inclui modulos, module-tag, auth-file e auth inline', () => {
    const built = buildVigoliumScanArgs({
      domain: 'example.com',
      vigoliumStrategy: 'balanced',
      vigoliumModules: ['xss_light_scanner'],
      vigoliumModuleTags: ['access-control'],
      vigoliumAuthFiles: ['admin.json', 'user.json'],
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
    assert.ok(built.args.includes('ghostrecon:Cookie:sid=abc'));
    assert.ok(built.args.includes('Authorization: Bearer token'));
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
