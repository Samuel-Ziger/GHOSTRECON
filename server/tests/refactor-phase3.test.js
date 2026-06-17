import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { createPipelineContext } from '../pipeline/finding-context.mjs';
import { buildPipelineExportPayloadForAi } from '../pipeline/pipeline-helpers.mjs';
import { runPipeline } from '../pipeline/run-pipeline.mjs';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const indexSrc = fs.readFileSync(path.join(__dirname, '../index.js'), 'utf8');

describe('refactor phase 3 — runPipeline extraído', () => {
  it('index.js não define runPipeline inline', () => {
    assert.equal(indexSrc.includes('async function runPipeline'), false);
    assert.match(indexSrc, /from '\.\/pipeline\/run-pipeline\.mjs'/);
  });

  it('createPipelineContext emite finding + stats', () => {
    const events = [];
    const emit = (e) => events.push(e);
    const { addFinding, findings, stats } = createPipelineContext({ domain: 'example.com', emit });
    addFinding({ type: 'intel', prio: 'high', score: 90, value: 'test' });
    assert.equal(findings.length, 1);
    assert.equal(stats.high, 1);
    assert.ok(events.some((e) => e.type === 'finding'));
    assert.ok(events.some((e) => e.type === 'stats'));
  });

  it('buildPipelineExportPayloadForAi inclui schemaVersion', () => {
    const payload = buildPipelineExportPayloadForAi({
      target: 'example.com',
      stats: {},
      findings: [],
      correlation: {},
      reportTemplates: [],
      runId: 1,
      storage: 'sqlite',
      intelMerge: null,
      kaliMode: false,
      modules: ['rdap'],
    });
    assert.equal(payload.schemaVersion, 1);
    assert.equal(payload.target, 'example.com');
  });

  it('runPipeline é função exportada', () => {
    assert.equal(typeof runPipeline, 'function');
  });

  it('runFinalizePhase é função exportada', async () => {
    const { runFinalizePhase } = await import('../pipeline/phases/finalize.mjs');
    assert.equal(typeof runFinalizePhase, 'function');
  });

  it('run-pipeline.mjs é orquestrador fino (<120 linhas)', () => {
    const src = fs.readFileSync(path.join(__dirname, '../pipeline/run-pipeline.mjs'), 'utf8');
    const lines = src.split('\n').length;
    assert.ok(lines < 120, `esperava <120 linhas, tem ${lines}`);
    assert.match(src, /runInputPhase/);
    assert.match(src, /runFinalizePhase/);
  });
});
