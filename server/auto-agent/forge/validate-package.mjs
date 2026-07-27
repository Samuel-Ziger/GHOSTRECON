import fs from 'node:fs/promises';
import path from 'node:path';
import { validateForgePackage } from './static-validator.mjs';
import { runForgeTests } from './test-runner.mjs';
import { throwIfForgeAborted } from './process-runner.mjs';
import { sameForgeArtifactIntegrity } from './artifact-integrity.mjs';

export async function validateAndTestForgePackage(pendingDir, opts = {}) {
  throwIfForgeAborted(opts.signal);
  const validation = await validateForgePackage(pendingDir);
  throwIfForgeAborted(opts.signal);
  const tests = validation.ok
    ? await runForgeTests(pendingDir, opts)
    : { ok: false, skipped: true, reason: 'static_validation_failed' };
  throwIfForgeAborted(opts.signal);
  const artifactIntegrityMatches = sameForgeArtifactIntegrity(
    validation.artifactIntegrity,
    tests.artifactIntegrity,
  );
  const gatesOk = validation.ok && tests.ok && artifactIntegrityMatches;
  const verdictPath = path.join(pendingDir, 'verdict.json');
  const verdict = await fs.readFile(verdictPath, 'utf8').then(JSON.parse).catch(() => ({}));
  verdict.status = gatesOk ? 'pending_ai_code_review' : 'validation_failed';
  verdict.validation = {
    ok: validation.ok,
    errors: validation.errors,
    artifactIntegrity: validation.artifactIntegrity || null,
  };
  verdict.tests = {
    ok: tests.ok && artifactIntegrityMatches,
    skipped: Boolean(tests.skipped || tests.tests?.skipped),
    reason: artifactIntegrityMatches
      ? tests.reason || tests.tests?.reason || null
      : 'artifact_integrity_mismatch',
    isolation: tests.isolation || { strong: false, reason: 'static_validation_failed' },
    artifactIntegrity: tests.artifactIntegrity || null,
  };
  verdict.policy = { ...(verdict.policy || {}), pipelineEnabled: false, operatorApprovalRequired: true };
  verdict.updatedAt = new Date().toISOString();
  await fs.writeFile(verdictPath, JSON.stringify(verdict, null, 2), 'utf8');
  return {
    ok: gatesOk,
    status: verdict.status,
    artifactIntegrityMatches,
    validation,
    tests,
    verdict,
  };
}
