import fs from 'node:fs/promises';
import path from 'node:path';
import { resolveForgeRoot } from './forge-store.mjs';

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

export async function transitionForgePackage({ root, forgeId, decision, reason = '', operator = 'local' } = {}) {
  if (!['approve', 'reject'].includes(decision)) throw new Error('decisão inválida');
  const item = await locate(root, forgeId);
  const verdictPath = path.join(item.dir, 'verdict.json');
  const provenancePath = path.join(item.dir, 'provenance.json');
  const verdict = await fs.readFile(verdictPath, 'utf8').then(JSON.parse);
  const provenance = await fs.readFile(provenancePath, 'utf8').then(JSON.parse);
  if (decision === 'approve') {
    if (verdict.status !== 'pending_operator_approval') throw new Error(`pacote não está pronto para aprovação: ${verdict.status}`);
    if (!verdict.validation?.ok || !verdict.tests?.ok || !verdict.aiReview?.approved) throw new Error('gates obrigatórios não aprovados');
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
  verdict.policy = { ...(verdict.policy || {}), pipelineEnabled: decision === 'approve', operatorApprovalRequired: false };
  provenance.state = finalState;
  provenance.updatedAt = new Date().toISOString();
  await Promise.all([
    fs.writeFile(verdictPath, JSON.stringify(verdict, null, 2), 'utf8'),
    fs.writeFile(provenancePath, JSON.stringify(provenance, null, 2), 'utf8'),
  ]);
  await fs.mkdir(path.dirname(destination), { recursive: true });
  await fs.rename(item.dir, destination);
  return { ok: true, forgeId, decision, state: finalState, status: verdict.status, dir: destination, pipelineEnabled: decision === 'approve', target: item.target, moduleId };
}

export async function recordForgeRuntimeResult({ root, forgeId, success, findings = 0, error = null } = {}) {
  const item = await locate(root, forgeId);
  const verdictPath = path.join(item.dir, 'verdict.json');
  const provenancePath = path.join(item.dir, 'provenance.json');
  const verdict = await fs.readFile(verdictPath, 'utf8').then(JSON.parse);
  const provenance = await fs.readFile(provenancePath, 'utf8').then(JSON.parse);
  const at = new Date().toISOString();
  verdict.status = success ? 'enabled_for_canary' : 'activation_failed';
  verdict.policy = { ...(verdict.policy || {}), pipelineEnabled: Boolean(success) };
  verdict.firstRun = { success: Boolean(success), findings: Number(findings) || 0, error: error ? String(error).slice(0, 4000) : null, at };
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
  const item = await locate(root, forgeId);
  if (!['promote', 'disable', 'enable', 'rollback', 'canary'].includes(action)) throw new Error('ação de lifecycle inválida');
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
    const verdict = await fs.readFile(verdictPath, 'utf8').then(JSON.parse);
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
}
