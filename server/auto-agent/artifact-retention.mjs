import fs from 'node:fs/promises';
import path from 'node:path';

import { resolveAutoRagRoot } from './session-store.mjs';

function retentionDays(env = process.env) {
  const parsed = Number(env.GHOSTRECON_AUTO_ARTIFACT_TTL_DAYS
    ?? env.GHOSTRECON_AUTO_RAG_TTL_DAYS
    ?? 30);
  if (!Number.isFinite(parsed) || parsed <= 0) return 0;
  return Math.min(3650, Math.floor(parsed));
}

async function mtimeMs(filePath) {
  try {
    const st = await fs.stat(filePath);
    return st.mtimeMs;
  } catch {
    return null;
  }
}

async function collectSessionDirs(ragRoot) {
  const found = [];
  const legacy = path.join(ragRoot, 'sessions');
  try {
    for (const entry of await fs.readdir(legacy, { withFileTypes: true })) {
      if (entry.isDirectory()) found.push(path.join(legacy, entry.name));
    }
  } catch {
    // ausente
  }

  const tenants = path.join(ragRoot, 'tenants');
  async function walk(dir, depth) {
    if (depth < 0) return;
    let entries = [];
    try {
      entries = await fs.readdir(dir, { withFileTypes: true });
    } catch {
      return;
    }
    if (path.basename(dir) === 'sessions') {
      for (const entry of entries) {
        if (entry.isDirectory()) found.push(path.join(dir, entry.name));
      }
      return;
    }
    for (const entry of entries) {
      if (entry.isDirectory()) await walk(path.join(dir, entry.name), depth - 1);
    }
  }
  await walk(tenants, 8);
  return found;
}

/**
 * Política comum de retenção para snapshots Auto e reports/auto/*.
 * RAG markdown continua com prune próprio; este helper cobre artefatos de sessão.
 */
export async function pruneExpiredAutoArtifacts(root, env = process.env, {
  now = Date.now(),
} = {}) {
  const days = retentionDays(env);
  if (days <= 0) {
    return { ok: true, skipped: true, reason: 'ttl_disabled', removed: [] };
  }
  const cutoffMs = now - (days * 86_400_000);
  const removed = [];
  const ragRoot = resolveAutoRagRoot(root, env);

  for (const dir of await collectSessionDirs(ragRoot)) {
    const marker = path.join(dir, 'session.json');
    const ms = (await mtimeMs(marker)) ?? (await mtimeMs(dir));
    if (ms != null && ms < cutoffMs) {
      await fs.rm(dir, { recursive: true, force: true });
      removed.push(dir);
    }
  }

  const reportsDir = path.join(String(root || '.'), 'reports', 'auto');
  try {
    for (const entry of await fs.readdir(reportsDir, { withFileTypes: true })) {
      if (!entry.isDirectory()) continue;
      const dir = path.join(reportsDir, entry.name);
      const marker = path.join(dir, 'summary.json');
      const ms = (await mtimeMs(marker)) ?? (await mtimeMs(dir));
      if (ms != null && ms < cutoffMs) {
        await fs.rm(dir, { recursive: true, force: true });
        removed.push(dir);
      }
    }
  } catch {
    // ausente
  }

  return {
    ok: true,
    skipped: false,
    days,
    cutoffIso: new Date(cutoffMs).toISOString(),
    removedCount: removed.length,
    removed: removed.slice(0, 100),
  };
}
