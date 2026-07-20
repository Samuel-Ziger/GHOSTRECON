import fs from 'node:fs/promises';
import { spawn } from 'node:child_process';
import { runFrameSeven, resolveFrameSevenBinary } from './frameseven-adapter.mjs';
import { dedupeBySemanticFamily } from '../modules/semantic-dedupe.js';

const approvals = new Map();
export function requestFrameSevenApproval(id) {
  return new Promise((resolve) => approvals.set(String(id), { resolve, expiresAt: Date.now() + 10 * 60_000 }));
}
export function resolveFrameSevenApproval(id, approved) {
  const item = approvals.get(String(id));
  if (!item || Date.now() >= item.expiresAt) { approvals.delete(String(id)); return false; }
  approvals.delete(String(id)); item.resolve(approved === true); return true;
}
export async function runIntegratedFrameSeven({ root, target, authBrowser = false, requestId, pipeline, emit = () => {}, signal, env = process.env } = {}) {
  const binary = resolveFrameSevenBinary(root, env);
  if (!await fs.access(binary).then(() => true).catch(() => false)) { emit({ type: 'engine_unavailable', engine: 'frameseven', binary }); return { skipped: true }; }
  const findings = [];
  const integratedEmit = (event) => { if (event?.type === 'finding' && event.finding) findings.push(event.finding); emit(event); };
  const runGhostAndVigolium = async (auth) => { integratedEmit({ type: 'engine_started', engine: 'ghostrecon' }); await pipeline(auth, integratedEmit); integratedEmit({ type: 'engine_done', engine: 'ghostrecon' }); integratedEmit({ type: 'engine_done', engine: 'vigolium' }); };
  let result;
  if (!authBrowser) { await runGhostAndVigolium(null); result = await runFrameSeven({ root, target, authBrowser: false, signal, emit: integratedEmit, env }); }
  else result = await runFrameSeven({
    root, target, authBrowser: true, signal, emit, env,
    waitForAuth: () => requestFrameSevenApproval(requestId),
    beforeScan: (auth) => runGhostAndVigolium(auth),
  });
  const reportPath = `${result?.outputDir || ''}/report.json`;
  try {
    const report = JSON.parse(await fs.readFile(reportPath, 'utf8'));
    const incoming = Array.isArray(report.findings) ? report.findings.map((f) => ({
      type: String(f.module || f.type || 'frameseven').toLowerCase(),
      prio: String(f.severity || 'info').toLowerCase(), value: f.title || f.description || f.evidence || '',
      url: f.endpoint || f.url || report.target, meta: `source=frameseven:${f.module || 'scanner'}`, sourceEngine: 'frameseven',
    })) : [];
    const merged = dedupeBySemanticFamily([...findings, ...incoming]);
    const existing = new Set(findings);
    for (const finding of merged.findings) if (!existing.has(finding)) integratedEmit({ type: 'finding', finding });
    const normalizedPath = `${result.outputDir}/integrated-findings.json`;
    await fs.writeFile(normalizedPath, JSON.stringify(merged.findings.map((f) => ({ title: f.value || f.title || 'GHOSTRECON finding', module: f.meta?.match?.(/source=([^\s]+)/)?.[1] || f.sourceEngine || f.type || 'ghostrecon', severity: f.prio || 'info', description: f.description || f.meta || '', endpoint: f.url || '', evidence: f.evidence || '' })), null, 2), { mode: 0o600 });
    await new Promise((resolve) => { const child = spawn(binary, ['-out', result.outputDir, '-merge-findings', normalizedPath], { cwd: root, env, stdio: 'ignore' }); child.once('exit', resolve); child.once('error', resolve); });
    integratedEmit({ type: 'dedupe_summary', engines: ['ghostrecon', 'vigolium', 'frameseven'], input: findings.length + incoming.length, output: merged.findings.length, merged: merged.merged, reportUrl: `/reports/${result.outputDir.split('/reports/').pop()}/report.html` });
  } catch { integratedEmit({ type: 'dedupe_summary', engines: ['ghostrecon', 'vigolium', 'frameseven'], input: findings.length, output: findings.length, merged: 0, reportUnavailable: true }); }
  return result;
}
