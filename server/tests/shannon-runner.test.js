import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import path from 'node:path';
import os from 'node:os';
import {
  waitForShannonWorkflowEnd,
  workflowLogPath,
  shannonReportPath,
  extractTemporalWebUiUrl,
} from '../modules/shannon-runner.js';

test('workflowLogPath junta workspaces e workspace id', () => {
  const p = workflowLogPath('/tmp/shannon', 'ghostrecon-test-1');
  assert.equal(p, path.join('/tmp/shannon', 'workspaces', 'ghostrecon-test-1', 'workflow.log'));
});

test('shannonReportPath aponta para comprehensive_security_assessment_report.md', () => {
  const p = shannonReportPath('/clone/repo');
  assert.match(p, /comprehensive_security_assessment_report\.md$/);
});

test('waitForShannonWorkflowEnd detecta COMPLETED', async () => {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), 'ghostrecon-shannon-'));
  const ws = 'test-ws-1';
  const dir = path.join(root, 'workspaces', ws);
  await fs.mkdir(dir, { recursive: true });
  const logFile = path.join(dir, 'workflow.log');
  await fs.writeFile(logFile, 'line1\nWorkflow COMPLETED\n', 'utf8');
  process.env.GHOSTRECON_SHANNON_WORKFLOW_TIMEOUT_MS = '8000';
  const r = await waitForShannonWorkflowEnd(root, ws, null);
  assert.equal(r.outcome, 'completed');
  assert.match(r.tail, /COMPLETED/);
});

test('extractTemporalWebUiUrl captura Web UI do Shannon (localhost:8233)', () => {
  const seen = new Set();
  const buf = `  Monitor:\n    Web UI:  http://localhost:8233/namespaces/default/workflows/wf-abc\n`;
  const u = extractTemporalWebUiUrl(buf, seen);
  assert.equal(u, 'http://localhost:8233/namespaces/default/workflows/wf-abc');
  assert.equal(extractTemporalWebUiUrl(buf, seen), null);
});

test('extractTemporalWebUiUrl suporta 127.0.0.1:8233', () => {
  const seen = new Set();
  const u = extractTemporalWebUiUrl('x http://127.0.0.1:8233/y z', seen);
  assert.equal(u, 'http://127.0.0.1:8233/y');
});

test('waitForShannonWorkflowEnd detecta FAILED', async () => {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), 'ghostrecon-shannon-'));
  const ws = 'test-ws-2';
  await fs.mkdir(path.join(root, 'workspaces', ws), { recursive: true });
  await fs.writeFile(path.join(root, 'workspaces', ws, 'workflow.log'), 'Workflow FAILED\n', 'utf8');
  process.env.GHOSTRECON_SHANNON_WORKFLOW_TIMEOUT_MS = '8000';
  const r = await waitForShannonWorkflowEnd(root, ws, null);
  assert.equal(r.outcome, 'failed');
});
