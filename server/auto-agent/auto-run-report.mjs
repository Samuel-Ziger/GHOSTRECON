import fs from 'node:fs/promises';
import path from 'node:path';

import { redactAutoValue } from './redaction.mjs';

function safeRunId(runId) {
  const value = String(runId || '').trim();
  if (!/^[A-Za-z0-9][A-Za-z0-9._-]{2,120}$/.test(value)) {
    throw new Error('runId Auto inválido para relatório');
  }
  return value;
}

export function resolveAutoRunReportDir(root, runId) {
  return path.join(String(root || '.'), 'reports', 'auto', safeRunId(runId));
}

export function buildAutoRunReportSummary({
  session = null,
  evaluation = null,
  moduleOutcomes = [],
  plan = null,
  events = [],
} = {}) {
  const runId = String(session?.requestRunId || session?.runId || '').trim();
  const sessionId = String(session?.sessionId || '').trim();
  const findings = Number(evaluation?.findings || 0)
    || (Array.isArray(events) ? events.filter((e) => e?.type === 'finding').length : 0);
  const approvals = Array.isArray(session?.approvalTransitions)
    ? session.approvalTransitions
    : [];
  return redactAutoValue({
    schemaVersion: 1,
    kind: 'ghostrecon.auto.run-report',
    runId,
    sessionId,
    target: session?.target || plan?.target || null,
    status: session?.status || evaluation?.status || 'unknown',
    autonomyLevel: session?.autonomyLevel || null,
    evaluationStatus: evaluation?.status || null,
    ok: evaluation?.ok !== false,
    findings,
    highSignals: Number(evaluation?.highSignals || 0),
    moduleOutcomes: Array.isArray(moduleOutcomes) ? moduleOutcomes.slice(0, 500) : [],
    moduleFailures: Array.isArray(evaluation?.moduleFailures)
      ? evaluation.moduleFailures.slice(0, 200)
      : [],
    engines: plan?.engines || session?.checkpoint?.activePlan?.engines || null,
    planHash: plan?.hash || session?.checkpoint?.activePlan?.hash || null,
    approvalTransitions: approvals.slice(-40),
    startedAt: session?.startedAt || null,
    finishedAt: session?.finishedAt || null,
    costUsd: Number(session?.costUsd || 0) || 0,
    agentCalls: Number(session?.agentCalls || 0) || 0,
    createdAt: new Date().toISOString(),
  }, { preserveSensitiveKeys: new Set(['sessionId', 'runId']) });
}

function summaryToMarkdown(summary) {
  const lines = [
    `# Auto run ${summary.runId || '?'}`,
    '',
    `- Session: \`${summary.sessionId || '?'}\``,
    `- Target: \`${summary.target || '?'}\``,
    `- Status: **${summary.status || 'unknown'}** (evaluation: ${summary.evaluationStatus || 'n/a'})`,
    `- Findings: ${summary.findings}`,
    `- Modules: ${(summary.moduleOutcomes || []).length}`,
    `- Approvals: ${(summary.approvalTransitions || []).length}`,
    `- Cost USD: ${summary.costUsd}`,
    '',
  ];
  if ((summary.moduleFailures || []).length) {
    lines.push('## Module failures', '');
    for (const row of summary.moduleFailures.slice(0, 40)) {
      lines.push(`- \`${row.moduleId || '?'}\`: ${row.status || 'failed'}`);
    }
    lines.push('');
  }
  return `${lines.join('\n')}\n`;
}

export async function writeAutoRunReport(root, summary, env = process.env) {
  const runId = safeRunId(summary?.runId);
  const dir = resolveAutoRunReportDir(root, runId);
  await fs.mkdir(dir, { recursive: true, mode: 0o700 });
  await fs.chmod(dir, 0o700).catch(() => {});
  const jsonPath = path.join(dir, 'summary.json');
  const mdPath = path.join(dir, 'summary.md');
  const payload = `${JSON.stringify(summary, null, 2)}\n`;
  await fs.writeFile(jsonPath, payload, { encoding: 'utf8', mode: 0o600 });
  await fs.chmod(jsonPath, 0o600).catch(() => {});
  await fs.writeFile(mdPath, summaryToMarkdown(summary), { encoding: 'utf8', mode: 0o600 });
  await fs.chmod(mdPath, 0o600).catch(() => {});
  return {
    runId,
    dir,
    jsonPath,
    mdPath,
    reportUrl: `/api/recon/auto/reports/${encodeURIComponent(runId)}/summary.json`,
    disabled: /^(0|false|no|off)$/i.test(String(env.GHOSTRECON_AUTO_REPORT_ENABLED || '1')),
  };
}

export async function persistAutoRunReport({
  root,
  session,
  evaluation,
  moduleOutcomes,
  plan,
  events,
  env = process.env,
} = {}) {
  if (/^(0|false|no|off)$/i.test(String(env.GHOSTRECON_AUTO_REPORT_ENABLED || '1'))) {
    return null;
  }
  const summary = buildAutoRunReportSummary({
    session,
    evaluation,
    moduleOutcomes,
    plan,
    events,
  });
  if (!summary.runId) {
    throw new Error('relatório Auto exige runId/requestRunId');
  }
  return writeAutoRunReport(root, summary, env);
}
