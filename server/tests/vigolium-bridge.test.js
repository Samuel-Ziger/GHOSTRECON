import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import {
  resolveEngineMode,
  shouldRunGoEngine,
  resolveVigoliumStrategy,
  resolveVigoliumTarget,
} from '../../bridge/vigolium-config.mjs';
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
