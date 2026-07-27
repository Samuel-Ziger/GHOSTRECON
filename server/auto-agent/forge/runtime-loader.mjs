import fs from 'node:fs/promises';
import path from 'node:path';
import { createHash } from 'node:crypto';
import { resolveForgeRoot } from './forge-store.mjs';
import { withProvenance } from '../../modules/finding-provenance.js';
import { redactAutoText, redactAutoValue } from '../redaction.mjs';
import { FORGE_MIN_INDEPENDENT_REVIEW_QUORUM } from './code-review.mjs';
import {
  isStrongForgeSandboxAttestation,
  runStrongForgeSandboxOperation,
  validateStrongForgeSandboxRunner,
} from './sandbox-policy.mjs';
import {
  computeForgeArtifactIntegrity,
  sameForgeArtifactIntegrity,
} from './artifact-integrity.mjs';
import { isForgeAbort } from './process-runner.mjs';
import { sameForgeEngagementBinding } from './lifecycle.mjs';

const MAX_MODULE_BYTES = 256 * 1024;
const MAX_MANIFEST_BYTES = 64 * 1024;

function sha256(value) {
  return createHash('sha256').update(value).digest('hex');
}

function targetKey(value) {
  const raw = String(value || '').trim().toLowerCase();
  if (!raw) return '';
  try { return new URL(raw.includes('://') ? raw : `https://${raw}`).hostname.toLowerCase(); } catch { return raw; }
}

function enabled(value, fallback = true) {
  if (value == null || value === '') return fallback;
  return !/^(0|false|no|off)$/i.test(String(value).trim());
}

function runtimeError(message, code) {
  const error = new Error(message);
  error.code = code;
  return error;
}

async function walk(dir, depth = 0) {
  if (depth > 7) return [];
  const entries = await fs.readdir(dir, { withFileTypes: true }).catch(() => []);
  const out = [];
  for (const entry of entries) {
    const full = path.join(dir, entry.name);
    if (entry.isDirectory()) out.push(...await walk(full, depth + 1));
    else if (entry.name === 'provenance.json' && full.split(path.sep).includes('active')) out.push(path.dirname(full));
  }
  return out;
}

async function readSealedCandidate(dir, {
  canaryForgeId = null,
  canaryActivation = null,
} = {}) {
  const [provenanceRaw, verdictRaw, manifestRaw, moduleSource] = await Promise.all([
    fs.readFile(path.join(dir, 'provenance.json')).catch(() => null),
    fs.readFile(path.join(dir, 'verdict.json')).catch(() => null),
    fs.readFile(path.join(dir, 'manifest.json')).catch(() => null),
    fs.readFile(path.join(dir, 'module.mjs')).catch(() => null),
  ]);
  if (!provenanceRaw || !verdictRaw || !manifestRaw || !moduleSource) return null;
  if (manifestRaw.length > MAX_MANIFEST_BYTES || moduleSource.length > MAX_MODULE_BYTES) return null;
  let provenance;
  let verdict;
  let manifest;
  try {
    provenance = JSON.parse(provenanceRaw.toString('utf8'));
    verdict = JSON.parse(verdictRaw.toString('utf8'));
    manifest = JSON.parse(manifestRaw.toString('utf8'));
  } catch {
    return null;
  }
  const integrity = provenance?.runtimeIntegrity;
  const artifactIntegrity = await computeForgeArtifactIntegrity(dir).catch(() => null);
  const globallyEnabled = verdict?.policy?.pipelineEnabled === true;
  const exclusiveFirstCanary = Boolean(
    canaryForgeId
    && canaryForgeId === provenance?.forgeId
    && globallyEnabled === false
    && verdict?.status === 'active_pending_first_run'
    && verdict?.activation?.status === 'pending_first_run'
    && String(canaryActivation?.activationId || '') === String(verdict?.activation?.id || '')
    && targetKey(canaryActivation?.expectedTarget) === targetKey(provenance?.target)
    && sameForgeArtifactIntegrity(
      canaryActivation?.expectedArtifactIntegrity,
      artifactIntegrity,
    )
    && sameForgeArtifactIntegrity(
      verdict?.activation?.authorization?.artifactIntegrity,
      artifactIntegrity,
    )
    && sameForgeEngagementBinding(
      canaryActivation?.engagementBinding,
      verdict?.activation?.authorization?.engagement,
    ),
  );
  if (
    !provenance?.forgeId
    || provenance.state !== 'active'
    || (!globallyEnabled && !exclusiveFirstCanary)
    || verdict?.validation?.ok !== true
    || verdict?.tests?.ok !== true
    || !isStrongForgeSandboxAttestation(verdict?.tests?.isolation)
    || verdict?.aiReview?.approved !== true
    || verdict?.aiReview?.authorExcluded !== true
    || verdict?.aiReview?.quorumMet !== true
    || verdict?.aiReview?.minimumQuorum !== FORGE_MIN_INDEPENDENT_REVIEW_QUORUM
    || Number(verdict?.aiReview?.independentVotes) < FORGE_MIN_INDEPENDENT_REVIEW_QUORUM
    || !manifest?.id
    || manifest.intrusive !== false
    || manifest.requiresAuth !== false
    || !sameForgeArtifactIntegrity(verdict?.validation?.artifactIntegrity, artifactIntegrity)
    || !sameForgeArtifactIntegrity(verdict?.tests?.artifactIntegrity, artifactIntegrity)
    || !sameForgeArtifactIntegrity(verdict?.aiReview?.artifactIntegrity, artifactIntegrity)
    || integrity?.algorithm !== 'sha256'
    || integrity.moduleSha256 !== sha256(moduleSource)
    || integrity.manifestSha256 !== sha256(manifestRaw)
    || integrity.artifactSha256 !== artifactIntegrity?.artifactSha256
  ) return null;
  return {
    dir,
    provenance,
    verdict,
    manifest,
    modulePath: path.join(dir, 'module.mjs'),
    moduleSource: moduleSource.toString('utf8'),
    exclusiveFirstCanary,
  };
}

export async function listActiveDynamicModules(root, {
  target = null,
  canaryForgeId = null,
  canaryActivation = null,
} = {}) {
  const dirs = await walk(resolveForgeRoot(root));
  const wantedTarget = targetKey(target);
  const items = [];
  for (const dir of dirs) {
    const item = await readSealedCandidate(dir, {
      canaryForgeId,
      canaryActivation,
    });
    if (!item) continue;
    if (wantedTarget && targetKey(item.provenance.target) !== wantedTarget) continue;
    items.push(item);
  }
  return items;
}

export async function listActiveDynamicManifests(root, { target = null } = {}) {
  return (await listActiveDynamicModules(root, { target })).map((item) => ({
    ...item.manifest,
    dynamic: true,
    forgeId: item.provenance.forgeId,
    runtimeIntegrity: {
      algorithm: 'sha256',
      artifactSha256: item.provenance.runtimeIntegrity.artifactSha256,
      moduleSha256: item.provenance.runtimeIntegrity.moduleSha256,
      manifestSha256: item.provenance.runtimeIntegrity.manifestSha256,
    },
    runtime: 'strong_os_sandbox_required',
  }));
}

function normalizeFindings(rows, moduleId, target) {
  const targetHost = targetKey(target);
  const safeUrl = (value) => {
    const raw = String(value || '').trim();
    if (!raw) return '';
    try {
      const parsed = new URL(raw, `https://${targetHost}`);
      if (
        !['http:', 'https:'].includes(parsed.protocol)
        || parsed.username
        || parsed.password
        || parsed.hostname.toLowerCase() !== targetHost
      ) return '';
      return redactAutoText(parsed.toString()).slice(0, 4000);
    } catch {
      return '';
    }
  };
  const safeMeta = (value) => {
    const normalized = redactAutoValue(value ?? {});
    let encoded = '';
    try { encoded = JSON.stringify(normalized); } catch { return {}; }
    return encoded.length <= 8000
      ? normalized
      : { summary: redactAutoText(value).slice(0, 8000), truncated: true };
  };
  return (Array.isArray(rows) ? rows : []).slice(0, 1000).map((row) => ({
    type: redactAutoText(String(row?.type || moduleId)).slice(0, 120),
    prio: ['info', 'low', 'med', 'high', 'critical'].includes(row?.prio) ? row.prio : 'info',
    score: Math.max(0, Math.min(100, Number(row?.score) || 0)),
    value: redactAutoText(String(row?.value || `${moduleId}: resultado`)).slice(0, 2000),
    meta: safeMeta(row?.meta),
    url: safeUrl(row?.url || target),
  })).map((row) => withProvenance(row, {
    how: `Forge ${moduleId} em sandbox isolado`,
    relation: `resultado limitado ao alvo autorizado ${targetHost}`,
  }));
}

export function runIsolatedForgeModule() {
  return Promise.reject(runtimeError(
    'runtime Forge legado desativado: configure um runner com isolamento forte de SO e rede deny-all',
    'AUTO_FORGE_STRONG_SANDBOX_REQUIRED',
  ));
}

export async function runActiveDynamicModules(state, {
  root = state.ROOT,
  env = state.env || process.env,
  isolatedRunner = state.forgeSandboxRunner || null,
} = {}) {
  const availableCandidates = await listActiveDynamicModules(root, {
    target: state.domain,
    canaryForgeId: state.forgeCanaryId || null,
    canaryActivation: state.forgeCanaryActivation || null,
  });
  // O primeiro canário é uma capacidade exclusiva: nem outra versão do mesmo
  // moduleId nem qualquer módulo globalmente ativo pode entrar nessa execução.
  const candidates = state.forgeCanaryId
    ? availableCandidates.filter((item) => (
        item.provenance.forgeId === state.forgeCanaryId
        && item.exclusiveFirstCanary === true
      ))
    : availableCandidates;
  const selected = candidates.filter((item) => state.modules.includes(item.manifest.id));
  const sandbox = validateStrongForgeSandboxRunner(isolatedRunner, 'runtime');
  if (!enabled(env.GHOSTRECON_AUTO_FORGE_RUNTIME_ENABLED, true) || !sandbox.ok) {
    for (const item of selected) {
      state.pipe(item.manifest.id, 'skip');
      state.emit({
        type: 'dynamic_module_skipped',
        moduleId: item.manifest.id,
        forgeId: item.provenance.forgeId,
        reason: !sandbox.ok ? sandbox.reason : 'runtime_disabled',
      });
    }
    return { available: candidates.length, selected: selected.length, executed: 0, completed: 0, failed: 0, skipped: selected.length };
  }

  let executed = 0;
  let completed = 0;
  let failed = 0;
  let skipped = 0;
  for (const item of selected) {
    const id = item.manifest.id;
    const canaryPercentage = Math.max(1, Math.min(100, Number(item.verdict?.policy?.canaryPercentage || 100)));
    const canaryBucket = Number.parseInt(createHash('sha256')
      .update(`${state.requestRunId || state.runId || state.domain}:${item.provenance.forgeId}`)
      .digest('hex').slice(0, 8), 16) % 100;
    if (canaryPercentage < 100 && canaryBucket >= canaryPercentage) {
      skipped += 1;
      state.pipe(id, 'skip');
      state.emit({ type: 'dynamic_module_canary_skipped', moduleId: id, forgeId: item.provenance.forgeId, canaryPercentage, canaryBucket });
      continue;
    }
    executed += 1;
    state.pipe(id, 'active');
    state.emit({ type: 'dynamic_module_started', moduleId: id, forgeId: item.provenance.forgeId, runtime: 'strong_os_sandbox' });
    try {
      state.throwIfAborted?.();
      const result = await runStrongForgeSandboxOperation(
        isolatedRunner,
        'runtime',
        {
          moduleId: id,
          source: item.moduleSource,
          context: {
            target: state.domain,
            domain: state.domain,
            requestRunId: state.requestRunId || '',
            runId: state.runId || '',
            engagementId: state.forgeCanaryActivation?.engagementBinding?.engagementId || '',
            engagementVersion: state.forgeCanaryActivation?.engagementBinding?.version || '',
            authorizationBindingSha256:
              state.forgeCanaryActivation?.engagementBinding?.bindingSha256 || '',
            artifactSha256:
              state.forgeCanaryActivation?.expectedArtifactIntegrity?.artifactSha256 || '',
          },
        },
        {
          timeoutMs: item.manifest.timeoutMs,
          signal: state.signal,
          label: `Forge module ${id}`,
        },
      );
      state.throwIfAborted?.();
      if (
        result?.ok === false
        && (
          Object.prototype.hasOwnProperty.call(result, 'error')
          || Object.prototype.hasOwnProperty.call(result, 'result')
        )
      ) {
        throw runtimeError(
          String(result.error || 'runner Forge retornou wrapper de falha').slice(0, 2000),
          'AUTO_FORGE_RUNTIME_FAILED',
        );
      }
      const findings = normalizeFindings(result?.findings, id, state.domain);
      for (const finding of findings) state.addFinding(finding, null);
      completed += 1;
      state.log(`Módulo IA ${id}: ${findings.length} achado(s)`, findings.length ? 'success' : 'info');
      state.emit({ type: 'dynamic_module_completed', moduleId: id, forgeId: item.provenance.forgeId, findings: findings.length, runtime: 'strong_os_sandbox' });
      state.pipe(id, 'done');
    } catch (error) {
      failed += 1;
      const cancelled = isForgeAbort(error, state.signal);
      const message = redactAutoText(error?.message || String(error)).slice(0, 2000);
      const eventType = error?.code === 'AUTO_FORGE_TIMEOUT' ? 'dynamic_module_timeout'
        : cancelled ? 'dynamic_module_cancelled'
          : 'dynamic_module_error';
      state.log(`Módulo IA ${id}: ${message}`, 'warn');
      state.emit({ type: eventType, moduleId: id, forgeId: item.provenance.forgeId, error: message, runtime: 'strong_os_sandbox' });
      state.pipe(id, eventType === 'dynamic_module_cancelled' ? 'cancelled' : eventType === 'dynamic_module_timeout' ? 'timeout' : 'failed');
      if (cancelled || error?.code === 'AUTO_FORGE_SANDBOX_UNTERMINATED') throw error;
    }
  }
  return { available: candidates.length, selected: selected.length, executed, completed, failed, skipped };
}
