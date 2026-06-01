/**
 * GhostDesk — painel de gestão de pentests integrado ao GHOSTRECON.
 *
 * NÃO reimplementa scans: consome diretamente a camada `db.js` do GHOSTRECON
 * (runs/findings/bounty_intel — SQLite, Postgres OU Supabase, transparente) e o
 * `projects.mjs`. Adiciona apenas a entidade "cliente" e a visão de gestão.
 *
 * Rotas (montadas em /api/ghostdesk/*, auth por scope do GHOSTRECON):
 *   GET  /overview                      → KPIs do dashboard
 *   GET  /clients | POST /clients | DELETE /clients/:id
 *   GET  /projects                      → projects.mjs + cliente vinculado
 *   POST /projects/:name/client         → vincula projeto a cliente
 *   GET  /scans                         → runs do GHOSTRECON (todos os scans)
 *   GET  /scans/:id                     → detalhe do run (findings incluídos)
 *   POST /scans/:id/attach              → anexa run a um projeto
 *   GET  /scans/:id/report-payload      → pacote handoff p/ GhostTrace (→ DOCX)
 *   GET  /intel/:target                 → corpus deduplicado (Supabase/SQLite)
 *   GET  /search?q=                     → busca global (clientes/projetos/scans)
 */

import { storageLabel, remoteStorageConfigured } from './db.js';
import {
  listRunsMerged,
  listIntelMerged,
  getRunByRef,
  normalizeRunRef,
  rollupSeverityFast,
} from './db-runs-merge.mjs';
import { listProjects, getProject, attachRunToProject } from './projects.mjs';
import {
  listClients,
  upsertClient,
  removeClient,
  linkProjectToClient,
  projectClientMap,
} from './ghostdesk-store.mjs';
import { requireScope } from './auth.js';

const projectsList = listProjects;

function normalizeTarget(t) {
  const s = String(t || '').trim().toLowerCase();
  return /^[a-z0-9][a-z0-9.-]*[a-z0-9]$/.test(s) ? s : null;
}

/** Query ?supabase=1 — interruptor no GhostDesk para incluir nuvem. */
function wantsSupabase(req) {
  const q = req.query?.supabase;
  return q === '1' || q === 'true' || String(q || '').toLowerCase() === 'on';
}

/** Mapeia um finding do GHOSTRECON para o contrato GhostreconFinding (GhostTrace). */
function toHandoffFinding(f) {
  let meta = {};
  if (f.meta && typeof f.meta === 'string') {
    try { meta = JSON.parse(f.meta); } catch { /* meta livre */ }
  } else if (f.meta && typeof f.meta === 'object') {
    meta = f.meta;
  }
  return {
    type: f.type,
    prio: f.prio,
    value: f.value,
    url: f.url || meta.url,
    meta: typeof f.meta === 'string' ? f.meta : JSON.stringify(f.meta ?? {}),
    score: f.score ?? null,
    owasp: meta.owasp || meta.owasp_top10 || undefined,
    mitre: meta.mitre || meta.mitre_attack || undefined,
    cvss: meta.cvss || meta.cvss_vector || undefined,
    fingerprint: f.fingerprint || meta.fingerprint || undefined,
  };
}

export function registerGhostDeskRoutes(app, { validateCsrfToken } = {}) {
  const requireCsrf = (req, res) => {
    if (typeof validateCsrfToken === 'function' && !validateCsrfToken(req)) {
      res.status(403).json({ ok: false, error: 'CSRF' });
      return false;
    }
    return true;
  };

  app.get('/api/ghostdesk/config', requireScope('recon.read'), (_req, res) => {
    res.json({
      ok: true,
      defaultStorage: 'sqlite',
      remoteConfigured: remoteStorageConfigured(),
      storageLabel: storageLabel(),
      cacheMs: Number(process.env.GHOSTDESK_LOCAL_CACHE_MS) || 4000,
    });
  });

  // ---- Dashboard ----------------------------------------------------------
  app.get('/api/ghostdesk/overview', requireScope('recon.read'), async (req, res) => {
    try {
      const includeSupabase = wantsSupabase(req);
      const [merged, projects, clients] = await Promise.all([
        listRunsMerged(500, { includeSupabase }),
        projectsList(),
        listClients(),
      ]);
      const runs = merged.runs;
      const targets = new Set(runs.map((r) => String(r.target || '').toLowerCase()));
      const bySeverity = rollupSeverityFast(runs, 12);
      res.json({
        ok: true,
        storage: merged.storage,
        storagePrimary: storageLabel(),
        includeSupabase,
        remoteConfigured: merged.remoteConfigured,
        remoteError: merged.remoteError,
        sources: merged.sources,
        totals: {
          scans: runs.length,
          targets: targets.size,
          projects: projects.length,
          clients: clients.length,
          findingsSampled: Object.values(bySeverity).reduce((a, b) => a + b, 0),
        },
        findingsBySeverity: bySeverity,
        recentScans: runs.slice(0, 10),
      });
    } catch (e) {
      res.status(500).json({ ok: false, error: e?.message || String(e) });
    }
  });

  // ---- Clientes -----------------------------------------------------------
  app.get('/api/ghostdesk/clients', requireScope('recon.read'), async (_req, res) => {
    try {
      res.json({ ok: true, clients: await listClients() });
    } catch (e) {
      res.status(500).json({ ok: false, error: e?.message || String(e) });
    }
  });

  app.post('/api/ghostdesk/clients', requireScope('project.write'), async (req, res) => {
    if (!requireCsrf(req, res)) return;
    try {
      const client = await upsertClient(req.body || {});
      res.json({ ok: true, client });
    } catch (e) {
      res.status(400).json({ ok: false, error: e?.message || String(e) });
    }
  });

  app.delete('/api/ghostdesk/clients/:id', requireScope('project.write'), async (req, res) => {
    if (!requireCsrf(req, res)) return;
    try {
      const removed = await removeClient(req.params.id);
      res.json({ ok: removed });
    } catch (e) {
      res.status(400).json({ ok: false, error: e?.message || String(e) });
    }
  });

  // ---- Projetos (reusa projects.mjs + cliente) ----------------------------
  app.get('/api/ghostdesk/projects', requireScope('recon.read'), async (_req, res) => {
    try {
      const [projects, map] = await Promise.all([projectsList(), projectClientMap()]);
      res.json({
        ok: true,
        projects: projects.map((p) => ({ ...p, client: map[p.name] || null })),
      });
    } catch (e) {
      res.status(500).json({ ok: false, error: e?.message || String(e) });
    }
  });

  app.post('/api/ghostdesk/projects/:name/client', requireScope('project.write'), async (req, res) => {
    if (!requireCsrf(req, res)) return;
    try {
      const project = await getProject(req.params.name);
      if (!project) return res.status(404).json({ ok: false, error: 'projeto não encontrado' });
      const link = await linkProjectToClient(project.name, String(req.body?.clientId || ''));
      res.json({ ok: true, link });
    } catch (e) {
      res.status(400).json({ ok: false, error: e?.message || String(e) });
    }
  });

  // ---- Scans (runs do GHOSTRECON) -----------------------------------------
  app.get('/api/ghostdesk/scans', requireScope('recon.read'), async (req, res) => {
    try {
      const limit = Math.min(Number(req.query.limit) || 100, 1000);
      const merged = await listRunsMerged(limit, { includeSupabase: wantsSupabase(req) });
      let runs = merged.runs;
      const target = normalizeTarget(req.query.target);
      if (target) runs = runs.filter((r) => String(r.target || '').toLowerCase() === target);
      res.json({
        ok: true,
        storage: merged.storage,
        sources: merged.sources,
        includeSupabase: merged.includeSupabase,
        remoteError: merged.remoteError,
        scans: runs,
      });
    } catch (e) {
      res.status(500).json({ ok: false, error: e?.message || String(e) });
    }
  });

  app.get('/api/ghostdesk/scans/:id', requireScope('recon.read'), async (req, res) => {
    try {
      const ref = normalizeRunRef(decodeURIComponent(req.params.id));
      if (!ref) return res.status(400).json({ ok: false, error: 'id inválido' });
      const run = await getRunByRef(ref);
      if (!run) return res.status(404).json({ ok: false, error: 'scan não encontrado' });
      res.json({ ok: true, scan: run });
    } catch (e) {
      res.status(500).json({ ok: false, error: e?.message || String(e) });
    }
  });

  app.post('/api/ghostdesk/scans/:id/attach', requireScope('project.write'), async (req, res) => {
    if (!requireCsrf(req, res)) return;
    try {
      const ref = normalizeRunRef(decodeURIComponent(req.params.id));
      if (!ref) return res.status(400).json({ ok: false, error: 'id inválido' });
      const run = await getRunByRef(ref);
      if (!run) return res.status(404).json({ ok: false, error: 'scan não encontrado' });
      const name = String(req.body?.project || '').trim();
      if (!name) return res.status(400).json({ ok: false, error: 'project é obrigatório' });
      const runId = run.numericId ?? Number(String(ref).split(':').pop());
      const updated = await attachRunToProject(name, { runId, target: run.target });
      res.json({ ok: true, project: updated });
    } catch (e) {
      res.status(400).json({ ok: false, error: e?.message || String(e) });
    }
  });

  // ---- Relatório: monta pacote de handoff p/ GhostTrace (→ DOCX) ----------
  app.get('/api/ghostdesk/scans/:id/report-payload', requireScope('recon.read'), async (req, res) => {
    try {
      const ref = normalizeRunRef(decodeURIComponent(req.params.id));
      if (!ref) return res.status(400).json({ ok: false, error: 'id inválido' });
      const run = await getRunByRef(ref);
      if (!run) return res.status(404).json({ ok: false, error: 'scan não encontrado' });
      const payload = {
        target: run.target,
        updatedAt: new Date().toISOString(),
        findings: (run.findings || []).map(toHandoffFinding),
      };
      res.json({ ok: true, payload, importPath: '/anotacao/ghostrecon/import' });
    } catch (e) {
      res.status(500).json({ ok: false, error: e?.message || String(e) });
    }
  });

  // ---- Intel / Supabase corpus --------------------------------------------
  app.get('/api/ghostdesk/intel/:target', requireScope('recon.read'), async (req, res) => {
    try {
      const target = normalizeTarget(req.params.target);
      if (!target) return res.status(400).json({ ok: false, error: 'domínio inválido' });
      const intel = await listIntelMerged(target, 500, { includeSupabase: wantsSupabase(req) });
      res.json({
        ok: true,
        target,
        source: intel.source,
        totalUnique: intel.totalUnique,
        items: intel.items,
        includeSupabase: intel.includeSupabase,
        remoteError: intel.remoteError,
      });
    } catch (e) {
      res.status(500).json({ ok: false, error: e?.message || String(e) });
    }
  });

  // ---- Busca global -------------------------------------------------------
  app.get('/api/ghostdesk/search', requireScope('recon.read'), async (req, res) => {
    try {
      const q = String(req.query.q || '').trim().toLowerCase();
      if (q.length < 2) return res.json({ ok: true, query: q, results: {} });
      const [merged, projects, clients] = await Promise.all([
        listRunsMerged(500, { includeSupabase: wantsSupabase(req) }),
        projectsList(),
        listClients(),
      ]);
      const runs = merged.runs;
      res.json({
        ok: true,
        query: q,
        results: {
          clients: clients.filter((c) => `${c.company} ${c.name} ${c.email}`.toLowerCase().includes(q)).slice(0, 10),
          projects: projects.filter((p) => `${p.name} ${p.description || ''}`.toLowerCase().includes(q)).slice(0, 10),
          scans: runs.filter((r) => String(r.target || '').toLowerCase().includes(q)).slice(0, 15),
        },
      });
    } catch (e) {
      res.status(500).json({ ok: false, error: e?.message || String(e) });
    }
  });
}
