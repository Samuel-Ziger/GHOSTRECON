import fs from 'node:fs/promises';
import path from 'node:path';
import { validateForgePackage } from './static-validator.mjs';
import { runForgeTests } from './test-runner.mjs';

export async function validateAndTestForgePackage(pendingDir, opts = {}) {
  const validation = await validateForgePackage(pendingDir);
  const tests = validation.ok
    ? await runForgeTests(pendingDir, opts)
    : { ok: false, skipped: true, reason: 'static_validation_failed' };
  const verdictPath = path.join(pendingDir, 'verdict.json');
  const verdict = await fs.readFile(verdictPath, 'utf8').then(JSON.parse).catch(() => ({}));
  verdict.status = validation.ok && tests.ok ? 'pending_ai_code_review' : 'validation_failed';
  verdict.validation = { ok: validation.ok, errors: validation.errors };
  verdict.tests = { ok: tests.ok, skipped: Boolean(tests.skipped), reason: tests.reason || null };
  verdict.policy = { ...(verdict.policy || {}), pipelineEnabled: false, operatorApprovalRequired: true };
  verdict.updatedAt = new Date().toISOString();
  await fs.writeFile(verdictPath, JSON.stringify(verdict, null, 2), 'utf8');
  return { ok: validation.ok && tests.ok, status: verdict.status, validation, tests, verdict };
}
