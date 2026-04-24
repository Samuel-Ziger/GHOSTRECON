/**
 * Projects — agrupamento de runs por "programa/cliente" de bug bounty.
 *
 * Storage: JSON store em `.ghostrecon-projects/projects.json` (portable, zero-dep).
 * Opt-in: zero impacto em runs antigos e em runPipeline existente — apenas
 * anexa `projectName` quando CLI/scheduler passam.
 *
 * Schema:
 *   {
 *     projects: [
 *       {
 *         name, description,
 *         scope: ["*.example.com", "api.example.com"],
 *         outOfScope: ["staging.example.com"],
 *         defaultModules: [...],
 *         defaultPlaybook: "api-first",
 *         notes: [{ at, text }],
 *         runs: [{ runId, target, at }],
 *         createdAt, updatedAt
 *       }
 *     ]
 *   }
 */

import fs from 'node:fs/promises';
import path from 'node:path';

function storeDir() {
  return path.resolve(process.cwd(), process.env.GHOSTRECON_PROJECTS_DIR || '.ghostrecon-projects');
}
function storeFile() {
  return path.join(storeDir(), 'projects.json');
}

async function loadStore() {
  try {
    const raw = await fs.readFile(storeFile(), 'utf8');
    const j = JSON.parse(raw);
    if (!Array.isArray(j.projects)) j.projects = [];
    return j;
  } catch {
    return { projects: [] };
  }
}

async function saveStore(store) {
  await fs.mkdir(storeDir(), { recursive: true });
  await fs.writeFile(storeFile(), JSON.stringify(store, null, 2), 'utf8');
}

function normalizeName(name) {
  const n = String(name || '').trim();
  if (!n || n.length > 120 || !/^[A-Za-z0-9._ @:/-]+$/.test(n)) {
    throw new Error('nome de projeto inválido');
  }
  return n;
}

export async function listProjects() {
  const s = await loadStore();
  return s.projects.map((p) => ({
    name: p.name,
    description: p.description,
    scope: p.scope || [],
    outOfScope: p.outOfScope || [],
    defaultModules: p.defaultModules || [],
    defaultPlaybook: p.defaultPlaybook || null,
    runCount: (p.runs || []).length,
    updatedAt: p.updatedAt,
    createdAt: p.createdAt,
  }));
}

export async function getProject(name) {
  const s = await loadStore();
  return s.projects.find((p) => p.name.toLowerCase() === String(name || '').toLowerCase()) || null;
}

export async function upsertProject(input) {
  const name = normalizeName(input.name);
  const s = await loadStore();
  const now = new Date().toISOString();
  const idx = s.projects.findIndex((p) => p.name.toLowerCase() === name.toLowerCase());
  const prev = idx >= 0 ? s.projects[idx] : null;
  const merged = {
    name,
    description: input.description ?? prev?.description ?? '',
    scope: uniqueStrings([...(prev?.scope || []), ...(input.scope || [])]),
    outOfScope: uniqueStrings([...(prev?.outOfScope || []), ...(input.outOfScope || [])]),
    defaultModules: uniqueStrings([...(prev?.defaultModules || []), ...(input.defaultModules || [])]),
    defaultPlaybook: input.defaultPlaybook ?? prev?.defaultPlaybook ?? null,
    notes: [...(prev?.notes || []), ...(input.notes || [])].slice(-200),
    runs: prev?.runs || [],
    createdAt: prev?.createdAt || now,
    updatedAt: now,
  };
  if (idx >= 0) s.projects[idx] = merged;
  else s.projects.push(merged);
  await saveStore(s);
  return merged;
}

export async function removeProject(name) {
  const s = await loadStore();
  const before = s.projects.length;
  s.projects = s.projects.filter((p) => p.name.toLowerCase() !== String(name || '').toLowerCase());
  if (s.projects.length !== before) {
    await saveStore(s);
    return true;
  }
  return false;
}

export async function addProjectScope(name, rule) {
  const s = await loadStore();
  const p = s.projects.find((x) => x.name.toLowerCase() === String(name || '').toLowerCase());
  if (!p) throw new Error(`projeto "${name}" não existe`);
  p.scope = uniqueStrings([...(p.scope || []), String(rule || '').trim()]).filter(Boolean);
  p.updatedAt = new Date().toISOString();
  await saveStore(s);
  return p;
}

export async function removeProjectScope(name, rule) {
  const s = await loadStore();
  const p = s.projects.find((x) => x.name.toLowerCase() === String(name || '').toLowerCase());
  if (!p) throw new Error(`projeto "${name}" não existe`);
  const r = String(rule || '').trim();
  p.scope = (p.scope || []).filter((x) => x !== r);
  p.updatedAt = new Date().toISOString();
  await saveStore(s);
  return p;
}

export async function attachRunToProject(name, { runId, target }) {
  if (!name || runId == null) return;
  const s = await loadStore();
  const p = s.projects.find((x) => x.name.toLowerCase() === String(name).toLowerCase());
  if (!p) return;
  p.runs = p.runs || [];
  p.runs.push({ runId, target, at: new Date().toISOString() });
  p.runs = p.runs.slice(-500);
  p.updatedAt = new Date().toISOString();
  await saveStore(s);
}

export function hostMatchesScope(host, scope) {
  const h = String(host || '').toLowerCase();
  if (!h) return false;
  if (!Array.isArray(scope) || !scope.length) return true;
  for (const rule of scope) {
    const r = String(rule || '').trim().toLowerCase();
    if (!r) continue;
    if (r.startsWith('*.')) {
      const suffix = r.slice(1);
      if (h.endsWith(suffix) && h.length > suffix.length) return true;
    } else if (r === h) {
      return true;
    }
  }
  return false;
}

function uniqueStrings(arr) {
  const seen = new Set();
  const out = [];
  for (const x of arr) {
    const s = String(x || '').trim();
    if (!s || seen.has(s)) continue;
    seen.add(s);
    out.push(s);
  }
  return out;
}
