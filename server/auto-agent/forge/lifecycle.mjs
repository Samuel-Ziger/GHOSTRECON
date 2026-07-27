import fs from 'node:fs/promises';
import path from 'node:path';
import { createHash, randomUUID } from 'node:crypto';
import { resolveForgeRoot } from './forge-store.mjs';
import { FORGE_MIN_INDEPENDENT_REVIEW_QUORUM } from './code-review.mjs';
import { isStrongForgeSandboxAttestation } from './sandbox-policy.mjs';
import {
  computeForgeArtifactIntegrity,
  sameForgeArtifactIntegrity,
} from './artifact-integrity.mjs';

function sha256(value) {
  return createHash('sha256').update(value).digest('hex');
}

function stableJson(value) {
  if (Array.isArray(value)) return `[${value.map(stableJson).join(',')}]`;
  if (value && typeof value === 'object') {
    return `{${Object.keys(value).sort().map((key) => (
      `${JSON.stringify(key)}:${stableJson(value[key])}`
    )).join(',')}}`;
  }
  return JSON.stringify(value);
}

function normalizedTarget(value) {
  const raw = String(value || '').trim().toLowerCase();
  if (!raw) return '';
  try {
    return new URL(raw.includes('://') ? raw : `https://${raw}`).hostname.toLowerCase();
  } catch {
    return raw;
  }
}

function normalizedStringList(value) {
  return [...new Set((Array.isArray(value) ? value : [])
    .map((entry) => String(entry || '').trim().toLowerCase())
    .filter(Boolean))]
    .sort();
}

export function createForgeEngagementBinding({
  engagement,
  engagementId = engagement?.id,
  target,
} = {}) {
  const id = String(engagementId || '').trim();
  const boundTarget = normalizedTarget(target);
  if (!id || !boundTarget || !engagement || String(engagement.id || '').trim() !== id) {
    throw new Error('binding de engagement Forge inválido');
  }
  const authorization = {
    id,
    target: boundTarget,
    status: String(engagement.status || '').trim().toLowerCase(),
    roeSigned: engagement.roeSigned === true,
    scopeDomains: normalizedStringList(engagement.scopeDomains),
    scopeIps: normalizedStringList(engagement.scopeIps),
    exclusions: normalizedStringList(engagement.exclusions),
    window: {
      startsAt: engagement.window?.startsAt ? String(engagement.window.startsAt) : null,
      endsAt: engagement.window?.endsAt ? String(engagement.window.endsAt) : null,
      tz: engagement.window?.tz ? String(engagement.window.tz) : null,
    },
    closedAt: engagement.closedAt ? String(engagement.closedAt) : null,
    updatedAt: engagement.updatedAt ? String(engagement.updatedAt) : null,
  };
  const bindingSha256 = sha256(stableJson(authorization));
  return Object.freeze({
    schemaVersion: 1,
    engagementId: id,
    target: boundTarget,
    version: String(
      engagement.version
      ?? engagement.updatedAt
      ?? engagement.createdAt
      ?? `sha256:${bindingSha256}`,
    ),
    bindingSha256,
  });
}

export function sameForgeEngagementBinding(left, right) {
  return Boolean(
    left?.schemaVersion === 1
    && right?.schemaVersion === 1
    && String(left.engagementId || '') === String(right.engagementId || '')
    && normalizedTarget(left.target) === normalizedTarget(right.target)
    && String(left.version || '') === String(right.version || '')
    && /^[a-f0-9]{64}$/.test(String(left.bindingSha256 || ''))
    && left.bindingSha256 === right.bindingSha256
  );
}

function assertExpectedActivationBinding({
  item,
  currentArtifactIntegrity,
  expectedTarget,
  expectedArtifactIntegrity,
  engagementBinding,
}) {
  const target = normalizedTarget(expectedTarget);
  if (!target || normalizedTarget(item.target) !== target) {
    const stale = new Error('alvo do pacote Forge diverge do alvo aprovado');
    stale.code = 'FORGE_APPROVAL_STALE';
    throw stale;
  }
  if (!sameForgeArtifactIntegrity(expectedArtifactIntegrity, currentArtifactIntegrity)) {
    const stale = new Error('artefato Forge diverge da versão apresentada ao operador');
    stale.code = 'FORGE_APPROVAL_STALE';
    throw stale;
  }
  if (
    engagementBinding?.schemaVersion !== 1
    || normalizedTarget(engagementBinding.target) !== target
    || !String(engagementBinding.engagementId || '').trim()
    || !String(engagementBinding.version || '').trim()
    || !/^[a-f0-9]{64}$/.test(String(engagementBinding.bindingSha256 || ''))
  ) {
    const stale = new Error('binding/version do engagement Forge é inválido');
    stale.code = 'FORGE_APPROVAL_STALE';
    throw stale;
  }
  return target;
}

function hasIndependentReviewGate(verdict) {
  return verdict?.aiReview?.approved === true
    && verdict?.aiReview?.authorExcluded === true
    && verdict?.aiReview?.quorumMet === true
    && verdict?.aiReview?.minimumQuorum === FORGE_MIN_INDEPENDENT_REVIEW_QUORUM
    && Number(verdict?.aiReview?.independentVotes) >= FORGE_MIN_INDEPENDENT_REVIEW_QUORUM;
}

function hasApprovalGates(verdict, artifactIntegrity) {
  return verdict?.validation?.ok === true
    && verdict?.tests?.ok === true
    && isStrongForgeSandboxAttestation(verdict?.tests?.isolation)
    && hasIndependentReviewGate(verdict)
    && sameForgeArtifactIntegrity(
      verdict?.validation?.artifactIntegrity,
      artifactIntegrity,
    )
    && sameForgeArtifactIntegrity(
      verdict?.tests?.artifactIntegrity,
      artifactIntegrity,
    )
    && sameForgeArtifactIntegrity(
      verdict?.aiReview?.artifactIntegrity,
      artifactIntegrity,
    );
}

async function assertStoredRuntimeGates(item, verdict, provenance) {
  const [moduleSource, manifestSource, artifactIntegrity] = await Promise.all([
    fs.readFile(path.join(item.dir, 'module.mjs')),
    fs.readFile(path.join(item.dir, 'manifest.json')),
    computeForgeArtifactIntegrity(item.dir),
  ]);
  if (!hasApprovalGates(verdict, artifactIntegrity)) {
    throw new Error('gates obrigatórios não aprovados para o artefato atual');
  }
  if (moduleSource.length > 256 * 1024 || manifestSource.length > 64 * 1024) {
    throw new Error('pacote Forge excede o limite de integridade do runtime');
  }
  let manifest;
  try {
    manifest = JSON.parse(manifestSource.toString('utf8'));
  } catch {
    throw new Error('manifest Forge inválido no lifecycle');
  }
  if (
    manifest.id !== item.moduleId
    || manifest.intrusive !== false
    || manifest.requiresAuth !== false
  ) {
    throw new Error('runtime Forge aceita somente manifest explícito não intrusivo e sem autenticação');
  }
  const integrity = provenance?.runtimeIntegrity;
  if (
    integrity?.algorithm !== 'sha256'
    || integrity.moduleSha256 !== sha256(moduleSource)
    || integrity.manifestSha256 !== sha256(manifestSource)
    || integrity.artifactSha256 !== artifactIntegrity.artifactSha256
  ) {
    throw new Error('integridade selada do pacote Forge é inválida');
  }
  return artifactIntegrity;
}

async function withForgeLifecycleLock(root, forgeId, callback) {
  const locksDir = path.join(resolveForgeRoot(root), '.lifecycle-locks');
  await fs.mkdir(locksDir, { recursive: true, mode: 0o700 });
  const lockName = `${sha256(String(forgeId || '')).slice(0, 40)}.lock`;
  const lockPath = path.join(locksDir, lockName);
  let handle;
  for (let attempt = 0; attempt < 2 && !handle; attempt += 1) {
    try {
      handle = await fs.open(lockPath, 'wx', 0o600);
      await handle.writeFile(JSON.stringify({
        forgeId: String(forgeId || ''),
        pid: process.pid,
        acquiredAt: new Date().toISOString(),
      }));
    } catch (error) {
      await handle?.close().catch(() => {});
      if (handle) await fs.rm(lockPath, { force: true }).catch(() => {});
      handle = null;
      if (error?.code !== 'EEXIST') throw error;
      const stat = await fs.stat(lockPath).catch(() => null);
      const stale = stat && Date.now() - stat.mtimeMs > 15 * 60_000;
      if (stale && attempt === 0) {
        const stalePath = `${lockPath}.stale-${randomUUID()}`;
        await fs.rename(lockPath, stalePath).catch(() => {});
        await fs.rm(stalePath, { force: true }).catch(() => {});
        continue;
      }
      const busy = new Error('pacote Forge possui outra transição em andamento');
      busy.code = 'FORGE_LIFECYCLE_BUSY';
      throw busy;
    }
  }
  if (!handle) throw new Error('não foi possível adquirir lock de lifecycle Forge');
  try {
    return await callback();
  } finally {
    await handle?.close().catch(() => {});
    await fs.rm(lockPath, { force: true }).catch(() => {});
  }
}

async function walk(dir, depth = 0) {
  if (depth > 6) return [];
  const entries = await fs.readdir(dir, { withFileTypes: true }).catch(() => []);
  const out = [];
  for (const entry of entries) {
    const full = path.join(dir, entry.name);
    if (entry.isDirectory()) out.push(...await walk(full, depth + 1));
    else if (entry.isFile() && entry.name === 'provenance.json') out.push(path.dirname(full));
  }
  return out;
}

export async function listForgePackages(root) {
  const dirs = await walk(resolveForgeRoot(root));
  const items = [];
  for (const dir of dirs) {
    const [provenance, verdict, manifest, request] = await Promise.all([
      fs.readFile(path.join(dir, 'provenance.json'), 'utf8').then(JSON.parse).catch(() => null),
      fs.readFile(path.join(dir, 'verdict.json'), 'utf8').then(JSON.parse).catch(() => null),
      fs.readFile(path.join(dir, 'manifest.json'), 'utf8').then(JSON.parse).catch(() => null),
      fs.readFile(path.join(dir, 'forge-request.json'), 'utf8').then(JSON.parse).catch(() => null),
    ]);
    if (!provenance?.forgeId) continue;
    items.push({
      forgeId: provenance.forgeId,
      state: provenance.state || 'unknown',
      author: provenance.author,
      model: provenance.authorModel || null,
      target: provenance.target,
      createdAt: provenance.createdAt,
      version: Number(provenance.version) || 0,
      status: verdict?.status || null,
      pipelineEnabled: verdict?.policy?.pipelineEnabled === true,
      moduleId: manifest?.id || request?.proposedId || null,
      dir,
    });
  }
  return items.sort((a, b) => String(b.createdAt).localeCompare(String(a.createdAt)));
}

async function locate(root, forgeId) {
  const item = (await listForgePackages(root)).find((x) => x.forgeId === forgeId);
  if (!item) throw new Error('forgeId não encontrado');
  return item;
}

export async function readForgePackage(root, forgeId) {
  const item = await locate(root, forgeId);
  const jsonNames = ['provenance.json', 'verdict.json', 'manifest.json', 'forge-request.json', 'validation-results.json', 'test-results.json', 'ai-reviews.json', 'correction-history.json'];
  const textNames = ['module.mjs', 'module.test.js', 'README.md'];
  const artifacts = {};
  await Promise.all([
    ...jsonNames.map(async (name) => {
      artifacts[name] = await fs.readFile(path.join(item.dir, name), 'utf8').then(JSON.parse).catch(() => null);
    }),
    ...textNames.map(async (name) => {
      artifacts[name] = await fs.readFile(path.join(item.dir, name), 'utf8').then((value) => value.slice(0, 250_000)).catch(() => null);
    }),
  ]);
  return { ...item, artifacts };
}

export async function transitionForgePackage({
  root,
  forgeId,
  decision,
  reason = '',
  operator = 'local',
  expectedTarget = null,
  expectedArtifactIntegrity = null,
  engagementBinding = null,
  verifyEngagementBinding = null,
} = {}) {
  if (!['approve', 'reject'].includes(decision)) throw new Error('decisão inválida');
  return withForgeLifecycleLock(root, forgeId, async () => {
  const item = await locate(root, forgeId);
  const verdictPath = path.join(item.dir, 'verdict.json');
  const provenancePath = path.join(item.dir, 'provenance.json');
  const verdict = await fs.readFile(verdictPath, 'utf8').then(JSON.parse);
  const provenance = await fs.readFile(provenancePath, 'utf8').then(JSON.parse);
  if (decision === 'approve') {
    if (verdict.status !== 'pending_operator_approval') throw new Error(`pacote não está pronto para aprovação: ${verdict.status}`);
    const [moduleSource, manifestSource, artifactIntegrity] = await Promise.all([
      fs.readFile(path.join(item.dir, 'module.mjs')),
      fs.readFile(path.join(item.dir, 'manifest.json')),
      computeForgeArtifactIntegrity(item.dir),
    ]);
    if (!hasApprovalGates(verdict, artifactIntegrity)) {
      throw new Error('gates obrigatórios não aprovados para o artefato atual');
    }
    const activationTarget = assertExpectedActivationBinding({
      item,
      currentArtifactIntegrity: artifactIntegrity,
      expectedTarget,
      expectedArtifactIntegrity,
      engagementBinding,
    });
    if (typeof verifyEngagementBinding !== 'function') {
      const stale = new Error('revalidação atômica do engagement Forge é obrigatória');
      stale.code = 'FORGE_APPROVAL_STALE';
      throw stale;
    }
    const currentEngagementBinding = await verifyEngagementBinding({
      expected: engagementBinding,
      target: activationTarget,
      forgeId,
      moduleId: item.moduleId,
      artifactIntegrity,
    });
    if (!sameForgeEngagementBinding(engagementBinding, currentEngagementBinding)) {
      const stale = new Error('engagement Forge mudou durante a aprovação');
      stale.code = 'FORGE_APPROVAL_STALE';
      throw stale;
    }
    if (moduleSource.length > 256 * 1024 || manifestSource.length > 64 * 1024) {
      throw new Error('pacote Forge excede o limite de integridade do runtime');
    }
    let sealedManifest;
    try {
      sealedManifest = JSON.parse(manifestSource.toString('utf8'));
    } catch {
      throw new Error('manifest Forge inválido na aprovação');
    }
    if (
      sealedManifest.id !== item.moduleId
      || sealedManifest.intrusive !== false
      || sealedManifest.requiresAuth !== false
    ) {
      throw new Error('runtime Forge aceita somente manifest explícito não intrusivo e sem autenticação');
    }
    provenance.runtimeIntegrity = {
      algorithm: 'sha256',
      moduleSha256: sha256(moduleSource),
      manifestSha256: sha256(manifestSource),
      artifactSha256: artifactIntegrity.artifactSha256,
      sealedAt: new Date().toISOString(),
    };
    verdict.activation = {
      id: randomUUID(),
      status: 'pending_first_run',
      artifactSha256: artifactIntegrity.artifactSha256,
      authorization: {
        target: activationTarget,
        artifactIntegrity,
        engagement: { ...engagementBinding },
      },
      issuedAt: new Date().toISOString(),
    };
  }
  const pendingIndex = item.dir.split(path.sep).lastIndexOf('pending');
  if (pendingIndex < 0) throw new Error('somente pacotes pending podem mudar de estado');
  const parts = item.dir.split(path.sep);
  const ownerRoot = parts.slice(0, pendingIndex).join(path.sep) || path.sep;
  const finalState = decision === 'approve' ? 'active' : 'rejected';
  const moduleId = item.moduleId || 'unknown-module';
  const siblings = (await listForgePackages(root)).filter((entry) => entry.moduleId === moduleId && entry.forgeId !== forgeId);
  provenance.version = Math.max(0, ...siblings.map((entry) => Number(entry.version) || 0)) + 1;
  const destination = path.join(ownerRoot, finalState, moduleId, forgeId);
  verdict.status = decision === 'approve' ? 'active_pending_first_run' : 'rejected';
  verdict.operatorDecision = { decision, reason: String(reason).slice(0, 4000), operator, at: new Date().toISOString() };
  verdict.policy = {
    ...(verdict.policy || {}),
    // O primeiro canário usa um bypass exclusivo por forgeId. O pacote só
    // entra no catálogo global após recordForgeRuntimeResult confirmar sucesso.
    pipelineEnabled: false,
    operatorApprovalRequired: false,
  };
  provenance.state = finalState;
  provenance.updatedAt = new Date().toISOString();
  await Promise.all([
    fs.writeFile(verdictPath, JSON.stringify(verdict, null, 2), 'utf8'),
    fs.writeFile(provenancePath, JSON.stringify(provenance, null, 2), 'utf8'),
  ]);
  await fs.mkdir(path.dirname(destination), { recursive: true });
  await fs.rename(item.dir, destination);
  return {
    ok: true,
    forgeId,
    decision,
    state: finalState,
    status: verdict.status,
    dir: destination,
    pipelineEnabled: false,
    activationId: decision === 'approve' ? verdict.activation.id : null,
    artifactIntegrity: decision === 'approve'
      ? verdict.activation.authorization.artifactIntegrity
      : null,
    engagementBinding: decision === 'approve'
      ? verdict.activation.authorization.engagement
      : null,
    target: item.target,
    moduleId,
  };
  });
}

export async function recordForgeRuntimeResult({
  root,
  forgeId,
  activationId,
  expectedTarget,
  expectedArtifactIntegrity,
  engagementBinding,
  success,
  findings = 0,
  error = null,
} = {}) {
  return withForgeLifecycleLock(root, forgeId, async () => {
  const item = await locate(root, forgeId);
  const verdictPath = path.join(item.dir, 'verdict.json');
  const provenancePath = path.join(item.dir, 'provenance.json');
  const verdict = await fs.readFile(verdictPath, 'utf8').then(JSON.parse);
  const provenance = await fs.readFile(provenancePath, 'utf8').then(JSON.parse);
  if (
    verdict.status !== 'active_pending_first_run'
    || verdict?.policy?.pipelineEnabled === true
    || verdict?.activation?.status !== 'pending_first_run'
    || !activationId
    || verdict.activation.id !== activationId
    || provenance.state !== 'active'
  ) {
    const stale = new Error('resultado de canário Forge obsoleto ou já invalidado');
    stale.code = 'FORGE_ACTIVATION_STALE';
    throw stale;
  }
  const currentIntegrity = await assertStoredRuntimeGates(item, verdict, provenance);
  const activationAuthorization = verdict?.activation?.authorization;
  if (
    verdict.activation.artifactSha256 !== currentIntegrity.artifactSha256
    || provenance?.runtimeIntegrity?.artifactSha256 !== currentIntegrity.artifactSha256
    || normalizedTarget(expectedTarget) !== normalizedTarget(item.target)
    || normalizedTarget(activationAuthorization?.target) !== normalizedTarget(item.target)
    || !sameForgeArtifactIntegrity(expectedArtifactIntegrity, currentIntegrity)
    || !sameForgeArtifactIntegrity(activationAuthorization?.artifactIntegrity, currentIntegrity)
    || !sameForgeEngagementBinding(engagementBinding, activationAuthorization?.engagement)
  ) {
    const stale = new Error('target/artefato/engagement do canário Forge diverge da ativação aprovada');
    stale.code = 'FORGE_ACTIVATION_STALE';
    throw stale;
  }
  const at = new Date().toISOString();
  verdict.status = success ? 'enabled_for_canary' : 'activation_failed';
  verdict.policy = { ...(verdict.policy || {}), pipelineEnabled: Boolean(success) };
  verdict.activation = {
    ...verdict.activation,
    status: success ? 'completed' : 'failed',
    completedAt: at,
  };
  verdict.firstRun = {
    activationId,
    success: Boolean(success),
    findings: Number(findings) || 0,
    error: error ? String(error).slice(0, 4000) : null,
    artifactSha256: currentIntegrity.artifactSha256,
    target: activationAuthorization.target,
    engagementId: activationAuthorization.engagement.engagementId,
    engagementVersion: activationAuthorization.engagement.version,
    engagementBindingSha256: activationAuthorization.engagement.bindingSha256,
    at,
  };
  verdict.runtimeHistory ||= [];
  verdict.runtimeHistory.push(verdict.firstRun);
  verdict.runtimeHistory = verdict.runtimeHistory.slice(-100);
  provenance.state = success ? 'active' : 'disabled';
  provenance.updatedAt = at;
  await Promise.all([
    fs.writeFile(verdictPath, JSON.stringify(verdict, null, 2), 'utf8'),
    fs.writeFile(provenancePath, JSON.stringify(provenance, null, 2), 'utf8'),
  ]);
  return { ok: Boolean(success), forgeId, status: verdict.status, state: provenance.state, pipelineEnabled: verdict.policy.pipelineEnabled, findings: verdict.firstRun.findings };
  });
}

export async function compareForgeVersions(root, moduleId) {
  const items = (await listForgePackages(root)).filter((item) => item.moduleId === moduleId);
  const versions = [];
  for (const item of items) {
    const verdict = await fs.readFile(path.join(item.dir, 'verdict.json'), 'utf8').then(JSON.parse).catch(() => ({}));
    const history = verdict.runtimeHistory || (verdict.firstRun ? [verdict.firstRun] : []);
    const successes = history.filter((run) => run.success).length;
    versions.push({
      forgeId: item.forgeId, version: item.version, state: item.state, status: item.status,
      runs: history.length, successes, successRate: history.length ? successes / history.length : null,
      findings: history.reduce((sum, run) => sum + (Number(run.findings) || 0), 0),
      lastRunAt: history.at(-1)?.at || null,
    });
  }
  return versions.sort((a, b) => b.version - a.version);
}

async function setPackageEnabled(item, enabled, status, operator, reason) {
  const verdictPath = path.join(item.dir, 'verdict.json');
  const provenancePath = path.join(item.dir, 'provenance.json');
  const [verdict, provenance] = await Promise.all([
    fs.readFile(verdictPath, 'utf8').then(JSON.parse),
    fs.readFile(provenancePath, 'utf8').then(JSON.parse),
  ]);
  if (enabled) await assertStoredRuntimeGates(item, verdict, provenance);
  if (verdict?.activation?.status === 'pending_first_run') {
    verdict.activation = {
      ...verdict.activation,
      status: 'invalidated',
      invalidatedAt: new Date().toISOString(),
      invalidatedBy: operator,
    };
  }
  verdict.status = status;
  verdict.policy = { ...(verdict.policy || {}), pipelineEnabled: enabled };
  verdict.lifecycle ||= [];
  verdict.lifecycle.push({ status, operator, reason: String(reason || '').slice(0, 4000), at: new Date().toISOString() });
  provenance.state = enabled ? 'active' : 'disabled';
  provenance.updatedAt = new Date().toISOString();
  await Promise.all([
    fs.writeFile(verdictPath, JSON.stringify(verdict, null, 2), 'utf8'),
    fs.writeFile(provenancePath, JSON.stringify(provenance, null, 2), 'utf8'),
  ]);
}

export async function manageForgePackage({ root, forgeId, action, reason = '', operator = 'local', percentage = null } = {}) {
  return withForgeLifecycleLock(root, forgeId, async () => {
  const item = await locate(root, forgeId);
  if (!['promote', 'disable', 'enable', 'rollback', 'canary'].includes(action)) throw new Error('ação de lifecycle inválida');
  if (
    item.status === 'active_pending_first_run'
    && !['disable', 'rollback'].includes(action)
  ) {
    throw new Error('pacote aguarda o primeiro canário exclusivo');
  }
  if (
    item.status === 'activation_failed'
    && ['promote', 'enable', 'canary'].includes(action)
  ) {
    throw new Error('pacote com primeiro canário falho não pode ser habilitado');
  }
  if (action === 'promote') {
    if (!['enabled_for_canary', 'active'].includes(item.status)) throw new Error(`pacote não está em canary: ${item.status}`);
    await setPackageEnabled(item, true, 'promoted', operator, reason);
    return { ok: true, forgeId, action, status: 'promoted', pipelineEnabled: true };
  }
  if (action === 'disable') {
    await setPackageEnabled(item, false, 'disabled', operator, reason);
    return { ok: true, forgeId, action, status: 'disabled', pipelineEnabled: false };
  }
  if (action === 'enable') {
    if (!item.dir.split(path.sep).includes('active')) throw new Error('somente versão ativa pode ser habilitada');
    await setPackageEnabled(item, true, 'enabled_for_canary', operator, reason);
    return { ok: true, forgeId, action, status: 'enabled_for_canary', pipelineEnabled: true };
  }
  if (action === 'canary') {
    const value = Number(percentage);
    if (!Number.isFinite(value) || value < 1 || value > 100) throw new Error('percentage deve estar entre 1 e 100');
    const verdictPath = path.join(item.dir, 'verdict.json');
    const provenancePath = path.join(item.dir, 'provenance.json');
    const [verdict, provenance] = await Promise.all([
      fs.readFile(verdictPath, 'utf8').then(JSON.parse),
      fs.readFile(provenancePath, 'utf8').then(JSON.parse),
    ]);
    await assertStoredRuntimeGates(item, verdict, provenance);
    verdict.status = 'enabled_for_canary';
    verdict.policy = { ...(verdict.policy || {}), pipelineEnabled: true, canaryPercentage: value };
    verdict.lifecycle ||= [];
    verdict.lifecycle.push({ status: 'enabled_for_canary', percentage: value, operator, reason: String(reason).slice(0, 4000), at: new Date().toISOString() });
    await fs.writeFile(verdictPath, JSON.stringify(verdict, null, 2), 'utf8');
    return { ok: true, forgeId, action, status: 'enabled_for_canary', percentage: value, pipelineEnabled: true };
  }
  const candidates = (await listForgePackages(root))
    .filter((entry) => entry.moduleId === item.moduleId && entry.forgeId !== forgeId && entry.dir.split(path.sep).includes('active'))
    .sort((a, b) => (Number(b.version) || 0) - (Number(a.version) || 0));
  const previous = candidates[0];
  if (!previous) throw new Error('nenhuma versão anterior disponível para rollback');
  await setPackageEnabled(item, false, 'rolled_back', operator, reason);
  await setPackageEnabled(previous, true, 'promoted', operator, `rollback de ${forgeId}: ${reason}`);
  return { ok: true, forgeId, action, status: 'rolled_back', pipelineEnabled: false, restoredForgeId: previous.forgeId };
  });
}
