/**
 * CT log monitor — diff incremental de subdomínios via crt.sh ou outro
 * provider. Persiste estado em arquivo JSON; emite findings só pra subs novos.
 *
 * Uso:
 *   const r = await monitorCt(apex, { fetcher });
 *   r.fresh   → array de novos subs encontrados desde última execução
 *   r.findings → findings prontos pra reporting
 */

import fs from 'node:fs/promises';
import path from 'node:path';
import os from 'node:os';

function dir() {
  return process.env.GHOSTRECON_CT_DIR || path.join(os.tmpdir(), '.ghostrecon-ct');
}

async function ensureDir() { await fs.mkdir(dir(), { recursive: true }); }

function statePath(apex) {
  return path.join(dir(), `${apex.replace(/[^a-z0-9.-]+/gi, '_')}.json`);
}

async function loadState(apex) {
  await ensureDir();
  try { return JSON.parse(await fs.readFile(statePath(apex), 'utf8')); }
  catch { return { apex, seen: [], lastUpdate: null }; }
}

async function saveState(apex, state) {
  await ensureDir();
  const tmp = `${statePath(apex)}.tmp.${process.pid}`;
  await fs.writeFile(tmp, JSON.stringify(state, null, 2));
  await fs.rename(tmp, statePath(apex));
}

/**
 * Default: crt.sh. Fetcher injetável para testes.
 */
export async function fetchCrtsh(apex, { fetcher } = {}) {
  if (typeof fetcher !== 'function') throw new Error('fetchCrtsh: fetcher obrigatório');
  const url = `https://crt.sh/?q=%25.${encodeURIComponent(apex)}&output=json`;
  const data = await fetcher(url);
  if (!Array.isArray(data)) return [];
  const subs = new Set();
  for (const row of data) {
    const names = String(row.name_value || '').split(/\n/);
    for (const n of names) {
      const t = n.trim().toLowerCase();
      if (!t) continue;
      if (t.includes(' ')) continue;
      if (t.startsWith('*.')) subs.add(t.slice(2));
      else subs.add(t);
    }
  }
  return [...subs].filter((s) => s === apex || s.endsWith(`.${apex}`));
}

export async function monitorCt(apex, { fetcher, source = fetchCrtsh } = {}) {
  if (!apex) throw new Error('monitorCt: apex obrigatório');
  const state = await loadState(apex);
  const seenSet = new Set(state.seen || []);
  const current = await source(apex, { fetcher });
  const fresh = current.filter((s) => !seenSet.has(s));
  for (const s of current) seenSet.add(s);
  const newState = { apex, seen: [...seenSet].sort(), lastUpdate: new Date().toISOString() };
  await saveState(apex, newState);

  const findings = fresh.map((s) => ({
    severity: 'low', category: 'ct-new-subdomain',
    title: `Novo subdomínio em CT logs: ${s}`,
    description: `Subdomínio ${s} apareceu em CT logs desde a última verificação (${state.lastUpdate || 'inicial'}).`,
    evidence: { target: apex, host: s, source: 'crt.sh', firstSeen: newState.lastUpdate },
  }));
  return { apex, total: current.length, fresh, findings, lastUpdate: newState.lastUpdate, previousUpdate: state.lastUpdate };
}

/**
 * Helper: dado uma lista de subs novos, classifica os "interessantes" por
 * heurística (admin/internal/dev/staging) com severity bumped.
 */
export function classifyNewSubs(subs = []) {
  const HOT = /^(admin|api|api-internal|internal|mgmt|console|dashboard|graphql|kibana|grafana|jenkins|vpn|sso|auth|idp|backup|legacy|old|debug|dev|staging|stage|qa|test|preview|beta)/i;
  return subs.map((s) => ({
    sub: s,
    hot: HOT.test(s.split('.')[0]),
    severity: HOT.test(s.split('.')[0]) ? 'medium' : 'low',
  }));
}
