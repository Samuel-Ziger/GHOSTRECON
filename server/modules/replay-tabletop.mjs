/**
 * Replay + tabletop — re-consumir runs sem bater no alvo.
 *
 * Dois modos:
 *   1. replayNdjson(file, onEvent) — tempo real simulado a partir de um NDJSON
 *      gravado de `/api/recon/stream`. Usa timestamps para respeitar intervalo
 *      entre eventos (opcional: speed=N para acelerar).
 *   2. tabletopRerank(run, {bountyContext, playbook}) — reimporta um run antigo
 *      e re-pontua/filtra findings com novo contexto, sem executar nada.
 */

import fs from 'node:fs/promises';
import fsSync from 'node:fs';

// ============================================================================
// Replay NDJSON
// ============================================================================

/**
 * Replay de NDJSON — emite eventos com spacing proporcional ao original.
 * `speed`: 1 = tempo real, 10 = 10x mais rápido, Infinity = instantâneo.
 */
export async function replayNdjson(filePath, onEvent, { speed = 10, limit = null } = {}) {
  const content = await fs.readFile(filePath, 'utf8');
  const lines = content.split('\n').filter((l) => l.trim());
  const events = [];
  for (const l of lines) {
    try { events.push(JSON.parse(l)); } catch { /* skip */ }
  }
  if (!events.length) return { replayed: 0 };

  const capped = limit != null ? events.slice(0, limit) : events;
  const startRef = findFirstTimestamp(capped);
  const replayStart = Date.now();

  for (const evt of capped) {
    const tRef = findEventTimestamp(evt);
    if (startRef && tRef && speed !== Infinity) {
      const elapsedOriginal = tRef - startRef;
      const target = replayStart + elapsedOriginal / speed;
      const wait = target - Date.now();
      if (wait > 0) await sleep(wait);
    }
    await onEvent(evt);
  }
  return { replayed: capped.length };
}

function findFirstTimestamp(events) {
  for (const e of events) {
    const t = findEventTimestamp(e);
    if (t) return t;
  }
  return null;
}

function findEventTimestamp(evt) {
  if (!evt || typeof evt !== 'object') return null;
  const candidates = [evt.at, evt.timestamp, evt.ts, evt.time];
  for (const c of candidates) {
    if (!c) continue;
    if (typeof c === 'number') return c;
    const d = Date.parse(c);
    if (!Number.isNaN(d)) return d;
  }
  return null;
}

function sleep(ms) { return new Promise((r) => setTimeout(r, ms)); }

/**
 * Conveniência — replay síncrono (sem timing, só dispara eventos em ordem).
 */
export function replayNdjsonSync(filePath, onEvent) {
  const raw = fsSync.readFileSync(filePath, 'utf8');
  const lines = raw.split('\n').filter((l) => l.trim());
  let count = 0;
  for (const l of lines) {
    try {
      const evt = JSON.parse(l);
      onEvent(evt);
      count++;
    } catch { /* skip */ }
  }
  return { replayed: count };
}

// ============================================================================
// Tabletop — re-score / re-prioritize
// ============================================================================

/**
 * Re-avalia findings com novo `bountyContext` (mapa category→weight, severity
 * bump/drop, excludes) e/ou com novo playbook. Não toca o alvo — apenas
 * produz um "what-if" view.
 *
 * bountyContext schema:
 *   {
 *     bumpSeverity: { "rce": "critical", "auth-bypass": "high" },
 *     dropIfCategory: ["info-banner"],
 *     weightByCategory: { "oidc-config": 2, "content-discovery": 0.5 },
 *     excludeHosts: ["staging.*"],
 *     onlyHosts: ["*.prod.acme.com"],
 *   }
 */
export function tabletopRerank(run, { bountyContext = null, playbook = null } = {}) {
  if (!run) throw new Error('run obrigatório');
  const ctx = bountyContext || {};
  const findings = Array.isArray(run.findings) ? run.findings : [];

  const SEV_ORDER = { info: 0, low: 1, medium: 2, high: 3, critical: 4 };
  const SEV_LABELS = Object.keys(SEV_ORDER);

  const processed = [];
  const dropped = [];

  for (const f of findings) {
    const cat = String(f.category || '').toLowerCase();
    const host = f.evidence?.target || f.evidence?.host || run.target || '';

    // Exclude/only hosts
    if (ctx.excludeHosts && ctx.excludeHosts.some((r) => hostMatchesGlob(host, r))) {
      dropped.push({ finding: f, reason: `excludeHosts (${host})` });
      continue;
    }
    if (ctx.onlyHosts && ctx.onlyHosts.length && !ctx.onlyHosts.some((r) => hostMatchesGlob(host, r))) {
      dropped.push({ finding: f, reason: `onlyHosts fora (${host})` });
      continue;
    }

    // Drop by category
    if (ctx.dropIfCategory && ctx.dropIfCategory.includes(cat)) {
      dropped.push({ finding: f, reason: `dropIfCategory (${cat})` });
      continue;
    }

    let newSev = String(f.severity || 'info').toLowerCase();
    // Bump severity
    if (ctx.bumpSeverity && ctx.bumpSeverity[cat]) {
      const bumped = String(ctx.bumpSeverity[cat]).toLowerCase();
      if (SEV_ORDER[bumped] != null) newSev = bumped;
    }

    // Score com peso de categoria
    const base = SEV_ORDER[newSev] ?? 0;
    const weight = ctx.weightByCategory?.[cat] ?? 1;
    const score = base * weight;

    processed.push({
      ...f,
      severity: newSev,
      rerank: {
        originalSeverity: f.severity || null,
        newSeverity: newSev,
        score,
        weight,
        category: cat,
      },
    });
  }

  processed.sort((a, b) => (b.rerank.score - a.rerank.score));

  return {
    target: run.target,
    runId: run.id,
    playbook: playbook || null,
    total: findings.length,
    kept: processed.length,
    dropped: dropped.length,
    findings: processed,
    droppedDetails: dropped,
    summary: summarizeBySev(processed, SEV_LABELS),
  };
}

function summarizeBySev(findings, labels) {
  const bySev = Object.fromEntries(labels.map((l) => [l, 0]));
  for (const f of findings) {
    const k = String(f.severity || 'info').toLowerCase();
    if (bySev[k] != null) bySev[k]++;
  }
  return bySev;
}

function hostMatchesGlob(host, pattern) {
  const h = String(host || '').toLowerCase();
  const p = String(pattern || '').toLowerCase().trim();
  if (!h || !p) return false;
  if (p === h) return true;
  if (p.startsWith('*.')) {
    const suffix = p.slice(1);
    return h.endsWith(suffix) && h.length > suffix.length;
  }
  if (p.endsWith('.*')) {
    const prefix = p.slice(0, -2);
    return h.startsWith(prefix) && h.length > prefix.length;
  }
  if (p.includes('*')) {
    const re = new RegExp('^' + p.replace(/[.+?^${}()|[\]\\]/g, '\\$&').replace(/\*/g, '.*') + '$', 'i');
    return re.test(h);
  }
  return false;
}
