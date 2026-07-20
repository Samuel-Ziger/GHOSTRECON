import fs from 'node:fs/promises';
import path from 'node:path';
import { pathToFileURL } from 'node:url';
import { createHash } from 'node:crypto';
import { resolveForgeRoot } from './forge-store.mjs';
import { withProvenance } from '../../modules/finding-provenance.js';

function targetKey(value) {
  const raw = String(value || '').trim().toLowerCase();
  if (!raw) return '';
  try { return new URL(raw.includes('://') ? raw : `https://${raw}`).hostname.toLowerCase(); } catch { return raw; }
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

export async function listActiveDynamicModules(root, { target = null } = {}) {
  const dirs = await walk(resolveForgeRoot(root));
  const wantedTarget = targetKey(target);
  const items = [];
  for (const dir of dirs) {
    const [provenance, verdict, manifest] = await Promise.all([
      fs.readFile(path.join(dir, 'provenance.json'), 'utf8').then(JSON.parse).catch(() => null),
      fs.readFile(path.join(dir, 'verdict.json'), 'utf8').then(JSON.parse).catch(() => null),
      fs.readFile(path.join(dir, 'manifest.json'), 'utf8').then(JSON.parse).catch(() => null),
    ]);
    if (!provenance?.forgeId || provenance.state !== 'active' || verdict?.policy?.pipelineEnabled !== true || !manifest?.id) continue;
    if (wantedTarget && targetKey(provenance.target) !== wantedTarget) continue;
    items.push({ dir, provenance, verdict, manifest, modulePath: path.join(dir, 'module.mjs') });
  }
  return items;
}

export async function listActiveDynamicManifests(root) {
  return (await listActiveDynamicModules(root)).map((item) => ({ ...item.manifest, dynamic: true, forgeId: item.provenance.forgeId }));
}

function normalizeFindings(rows, moduleId, target) {
  return (Array.isArray(rows) ? rows : []).slice(0, 1000).map((row) => ({
    type: String(row?.type || moduleId).slice(0, 120),
    prio: ['info', 'low', 'med', 'high', 'critical'].includes(row?.prio) ? row.prio : 'info',
    score: Math.max(0, Math.min(100, Number(row?.score) || 0)),
    value: String(row?.value || `${moduleId}: resultado`).slice(0, 2000),
    meta: String(row?.meta || '').slice(0, 8000),
    url: String(row?.url || target || '').slice(0, 4000),
  })).map((row) => withProvenance(row, moduleId));
}

export async function runActiveDynamicModules(state, { root = state.ROOT } = {}) {
  const candidates = await listActiveDynamicModules(root, { target: state.domain });
  const selected = candidates.filter((item) => state.modules.includes(item.manifest.id));
  for (const item of selected) {
    const id = item.manifest.id;
    const canaryPercentage = Math.max(1, Math.min(100, Number(item.verdict?.policy?.canaryPercentage || 100)));
    const canaryBucket = Number.parseInt(createHash('sha256')
      .update(`${state.requestRunId || state.runId || state.domain}:${item.provenance.forgeId}`)
      .digest('hex').slice(0, 8), 16) % 100;
    if (canaryPercentage < 100 && canaryBucket >= canaryPercentage) {
      state.emit({ type: 'dynamic_module_canary_skipped', moduleId: id, forgeId: item.provenance.forgeId, canaryPercentage, canaryBucket });
      continue;
    }
    state.pipe(id, 'active');
    try {
      state.throwIfAborted?.();
      const imported = await import(`${pathToFileURL(item.modulePath).href}?v=${encodeURIComponent(item.provenance.updatedAt || item.provenance.createdAt || '')}`);
      const runner = imported.run || imported.default;
      if (typeof runner !== 'function') throw new Error('módulo dinâmico não exporta run(ctx)');
      const timeoutMs = Math.max(1000, Math.min(120000, Number(item.manifest.timeoutMs || 30000)));
      const result = await Promise.race([
        runner({ ...state, target: state.domain, fetchImpl: globalThis.fetch, signal: state.signal }),
        new Promise((_, reject) => setTimeout(() => reject(new Error(`timeout após ${timeoutMs}ms`)), timeoutMs)),
      ]);
      const findings = normalizeFindings(result?.findings, id, state.domain);
      for (const finding of findings) state.addFinding(finding, null);
      state.log(`Módulo IA ${id}: ${findings.length} achado(s)`, findings.length ? 'success' : 'info');
      state.emit({ type: 'dynamic_module_completed', moduleId: id, forgeId: item.provenance.forgeId, findings: findings.length });
    } catch (error) {
      state.log(`Módulo IA ${id}: ${error?.message || error}`, 'warn');
      state.emit({ type: 'dynamic_module_error', moduleId: id, forgeId: item.provenance.forgeId, error: error?.message || String(error) });
    }
    state.pipe(id, 'done');
  }
  return { available: candidates.length, executed: selected.length };
}
