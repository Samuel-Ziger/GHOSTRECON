/**
 * GhostDesk store — camada de clientes e vínculos cliente↔projeto.
 *
 * Filosofia idêntica a projects.mjs: JSON store portátil, zero-dep, aditivo.
 * NÃO duplica dados de runs/findings/projects — apenas adiciona a entidade
 * "cliente" (que o GHOSTRECON não tinha) e mapeia projeto → cliente.
 *
 * Storage: `.ghostrecon-ghostdesk/ghostdesk.json`
 *
 * Schema:
 *   {
 *     clients: [{ id, company, name, email, phone, notes, createdAt, updatedAt }],
 *     projectClient: { "<projectName>": "<clientId>" }
 *   }
 */

import fs from 'node:fs/promises';
import path from 'node:path';
import crypto from 'node:crypto';

function storeDir() {
  return path.resolve(process.cwd(), process.env.GHOSTDESK_DIR || '.ghostrecon-ghostdesk');
}
function storeFile() {
  return path.join(storeDir(), 'ghostdesk.json');
}

async function loadStore() {
  try {
    const raw = await fs.readFile(storeFile(), 'utf8');
    const j = JSON.parse(raw);
    if (!Array.isArray(j.clients)) j.clients = [];
    if (!j.projectClient || typeof j.projectClient !== 'object') j.projectClient = {};
    return j;
  } catch {
    return { clients: [], projectClient: {} };
  }
}

async function saveStore(store) {
  await fs.mkdir(storeDir(), { recursive: true });
  await fs.writeFile(storeFile(), JSON.stringify(store, null, 2), 'utf8');
}

function sanitizeStr(v, max = 200) {
  return String(v ?? '').trim().slice(0, max);
}

export async function listClients() {
  const s = await loadStore();
  // anexa contagem de projetos vinculados
  const counts = {};
  for (const cid of Object.values(s.projectClient)) {
    counts[cid] = (counts[cid] || 0) + 1;
  }
  return s.clients
    .map((c) => ({ ...c, projectCount: counts[c.id] || 0 }))
    .sort((a, b) => a.company.localeCompare(b.company));
}

export async function getClient(id) {
  const s = await loadStore();
  return s.clients.find((c) => c.id === id) || null;
}

export async function upsertClient(input) {
  const company = sanitizeStr(input.company, 160);
  if (!company) throw new Error('company é obrigatório');

  const s = await loadStore();
  const now = new Date().toISOString();

  if (input.id) {
    const idx = s.clients.findIndex((c) => c.id === input.id);
    if (idx < 0) throw new Error('cliente não encontrado');
    s.clients[idx] = {
      ...s.clients[idx],
      company,
      name: sanitizeStr(input.name, 160),
      email: sanitizeStr(input.email, 160),
      phone: sanitizeStr(input.phone, 60),
      notes: sanitizeStr(input.notes, 2000),
      updatedAt: now,
    };
    await saveStore(s);
    return s.clients[idx];
  }

  const client = {
    id: crypto.randomUUID(),
    company,
    name: sanitizeStr(input.name, 160),
    email: sanitizeStr(input.email, 160),
    phone: sanitizeStr(input.phone, 60),
    notes: sanitizeStr(input.notes, 2000),
    createdAt: now,
    updatedAt: now,
  };
  s.clients.push(client);
  await saveStore(s);
  return client;
}

export async function removeClient(id) {
  const s = await loadStore();
  const before = s.clients.length;
  s.clients = s.clients.filter((c) => c.id !== id);
  for (const [proj, cid] of Object.entries(s.projectClient)) {
    if (cid === id) delete s.projectClient[proj];
  }
  if (s.clients.length !== before) {
    await saveStore(s);
    return true;
  }
  return false;
}

/** Vincula um projeto (do projects.mjs) a um cliente. */
export async function linkProjectToClient(projectName, clientId) {
  const s = await loadStore();
  const client = s.clients.find((c) => c.id === clientId);
  if (!client) throw new Error('cliente não encontrado');
  s.projectClient[projectName] = clientId;
  await saveStore(s);
  return { projectName, clientId };
}

export async function unlinkProject(projectName) {
  const s = await loadStore();
  if (projectName in s.projectClient) {
    delete s.projectClient[projectName];
    await saveStore(s);
    return true;
  }
  return false;
}

/** Mapa { projectName -> client } para enriquecer a listagem de projetos. */
export async function projectClientMap() {
  const s = await loadStore();
  const byId = new Map(s.clients.map((c) => [c.id, c]));
  const out = {};
  for (const [proj, cid] of Object.entries(s.projectClient)) {
    const c = byId.get(cid);
    if (c) out[proj] = { id: c.id, company: c.company };
  }
  return out;
}
