import fs from 'node:fs/promises';
import path from 'node:path';
import { generateCorrectedArtifact } from './generate-artifact.mjs';
import { validateAndTestForgePackage } from './validate-package.mjs';
import { reviewForgePackage } from './code-review.mjs';
import { isForgeAbort, throwIfForgeAborted } from './process-runner.mjs';

async function readJson(file, fallback = {}) {
  return fs.readFile(file, 'utf8').then(JSON.parse).catch(() => fallback);
}

async function snapshotRevision(pendingDir, attempt) {
  const revisionDir = path.join(pendingDir, 'revisions', `revision-${String(attempt - 1).padStart(2, '0')}`);
  await fs.mkdir(revisionDir, { recursive: true });
  const names = ['module.mjs', 'module.test.js', 'manifest.json', 'implementation-notes.json', 'validation-results.json', 'test-results.json', 'ai-reviews.json'];
  await Promise.all(names.map(async (name) => {
    const source = path.join(pendingDir, name);
    const target = path.join(revisionDir, name);
    await fs.copyFile(source, target).catch((error) => {
      if (error?.code !== 'ENOENT') throw error;
    });
  }));
  return revisionDir;
}

async function updateVerdict(pendingDir, patch) {
  const file = path.join(pendingDir, 'verdict.json');
  const verdict = await readJson(file);
  Object.assign(verdict, patch, { updatedAt: new Date().toISOString() });
  verdict.policy = { ...(verdict.policy || {}), pipelineEnabled: false, operatorApprovalRequired: true };
  await fs.writeFile(file, JSON.stringify(verdict, null, 2), 'utf8');
  return verdict;
}

export async function runForgeCorrectionLoop({
  pendingDir, root, provider, target, providers = [], env = process.env,
  fetchImpl = globalThis.fetch, execFileImpl, initialReview,
  isolatedRunner = null, signal = null,
  generateImpl = generateCorrectedArtifact,
  validateImpl = validateAndTestForgePackage,
  reviewImpl = reviewForgePackage,
} = {}) {
  throwIfForgeAborted(signal);
  const maxAttempts = Math.max(0, Math.min(5, Number(env.GHOSTRECON_AUTO_FORGE_MAX_CORRECTIONS || 2)));
  let review = initialReview || await readJson(path.join(pendingDir, 'ai-reviews.json'));
  const request = await readJson(path.join(pendingDir, 'forge-request.json'));
  const history = [];

  for (let attempt = 1; review?.status === 'changes_requested' && attempt <= maxAttempts; attempt += 1) {
    throwIfForgeAborted(signal);
    const revisionDir = await snapshotRevision(pendingDir, attempt);
    await updateVerdict(pendingDir, { status: 'correction_in_progress', correction: { attempt, maxAttempts, provider } });
    try {
      const generated = await generateImpl({
        provider, request, target, root, pendingDir, attempt, env, execFileImpl, signal,
      });
      const gates = await validateImpl(pendingDir, { env, isolatedRunner, signal });
      review = gates.ok
        ? await reviewImpl({
            pendingDir, root, providers, env, fetchImpl, execFileImpl, signal,
          })
        : { status: 'validation_failed', approved: false };
      history.push({ attempt, ok: Boolean(gates.ok), revisionDir, generated, gates: { ok: gates.ok, status: gates.status }, reviewStatus: review.status });
      if (!gates.ok) break;
    } catch (error) {
      if (isForgeAbort(error, signal)) throw error;
      history.push({ attempt, ok: false, revisionDir, error: error?.message || String(error) });
      review = { status: 'correction_failed', approved: false, error: error?.message || String(error) };
      await updateVerdict(pendingDir, { status: review.status, correction: { attempt, maxAttempts, provider, error: review.error } });
      break;
    }
  }

  if (review?.status === 'changes_requested') {
    review = { ...review, status: 'correction_attempts_exhausted', approved: false };
    await updateVerdict(pendingDir, { status: review.status, correction: { attempts: history.length, maxAttempts, provider } });
  }
  const result = { ok: review?.status === 'pending_operator_approval', status: review?.status || 'correction_failed', attempts: history.length, history, finalReview: review };
  await fs.writeFile(path.join(pendingDir, 'correction-history.json'), JSON.stringify(result, null, 2), 'utf8');
  return result;
}
