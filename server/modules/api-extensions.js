/**
 * API extensions — rotas novas adicionadas sem tocar em rotas existentes.
 *
 *  GET  /api/playbooks                   → lista playbooks disponíveis
 *  GET  /api/playbooks/:name             → detalhes de um playbook
 *  GET  /api/projects                    → lista projetos
 *  GET  /api/projects/:name              → detalhes
 *  POST /api/projects                    → upsert (CSRF-protected)
 *  DELETE /api/projects/:name            → remove (CSRF-protected)
 *  POST /api/cve/enrich                  → enrichment on-demand (CSRF-protected)
 *  POST /api/evidence/capture/:runId     → re-run evidence capture (CSRF-protected)
 *  GET  /api/runs/:id/diff-summary/:baselineId   → summary do diff (alternativa ao endpoint existente)
 *
 *  RT / purple (read-mostly + mutações CSRF):
 *  GET  /api/engagements | GET /api/engagements/:id
 *  POST /api/engagements | POST /api/engagements/:id/close | POST /api/engagements/checklist
 *  POST /api/opsec/gate
 *  GET  /api/runs/:id/narrative | GET /api/runs/:id/purple
 *  GET /api/team/locks | GET /api/team/trail
 *  POST /api/team/lock | POST /api/team/unlock | POST /api/team/force-unlock
 */

import { listPlaybooks, resolvePlaybook } from './playbooks/loader.mjs';
import { listProjects, getProject, upsertProject, removeProject } from './projects.mjs';
import { enrichFromTechStrings } from './cve-enrichment.js';
import { captureEvidenceForRun } from './evidence-capture.js';
import { summarizeDiff } from './diff-engine.mjs';
import {
  listEngagements,
  getEngagement,
  upsertEngagement,
  closeEngagement,
  preRunChecklist,
} from './engagement.mjs';
import { gateModules } from './opsec.mjs';
import { narrate, narrativeToMarkdown } from './attack-narrative.mjs';
import { exportPurpleTeamReport } from './purple-team.mjs';
import {
  listLocks,
  acquireLock,
  releaseLock,
  forceReleaseLock,
  listTrail,
} from './team-concurrency.mjs';
import { requireScope, requireRole } from './auth.js';

export function registerNewApiRoutes(app, { validateCsrfToken } = {}) {
  const requireCsrf = (req, res) => {
    if (typeof validateCsrfToken === 'function' && !validateCsrfToken(req)) {
      res.status(403).json({ ok: false, error: 'CSRF' });
      return false;
    }
    return true;
  };

  // ----- Playbooks ----------------------------------------------------------
  app.get('/api/playbooks', async (_req, res) => {
    try {
      const list = await listPlaybooks();
      res.json({ ok: true, playbooks: list });
    } catch (e) {
      res.status(500).json({ ok: false, error: e.message });
    }
  });

  app.get('/api/playbooks/:name', async (req, res) => {
    try {
      const pb = await resolvePlaybook(req.params.name);
      res.json({ ok: true, playbook: pb });
    } catch (e) {
      res.status(404).json({ ok: false, error: e.message });
    }
  });

  // ----- Projects -----------------------------------------------------------
  app.get('/api/projects', async (_req, res) => {
    try { res.json({ ok: true, projects: await listProjects() }); }
    catch (e) { res.status(500).json({ ok: false, error: e.message }); }
  });

  app.get('/api/projects/:name', async (req, res) => {
    const p = await getProject(req.params.name);
    if (!p) return res.status(404).json({ ok: false, error: 'projeto não encontrado' });
    res.json({ ok: true, project: p });
  });

  app.post('/api/projects', requireScope('project.write'), async (req, res) => {
    if (!requireCsrf(req, res)) return;
    try {
      const p = await upsertProject(req.body || {});
      res.json({ ok: true, project: p });
    } catch (e) {
      res.status(400).json({ ok: false, error: e.message });
    }
  });

  app.delete('/api/projects/:name', requireRole('admin'), async (req, res) => {
    if (!requireCsrf(req, res)) return;
    const ok = await removeProject(req.params.name);
    res.json({ ok });
  });

  // ----- CVE enrichment -----------------------------------------------------
  app.post('/api/cve/enrich', requireScope('cve.enrich'), async (req, res) => {
    if (!requireCsrf(req, res)) return;
    const strings = Array.isArray(req.body?.techStrings) ? req.body.techStrings : [];
    if (!strings.length) return res.status(400).json({ ok: false, error: 'techStrings vazio' });
    try {
      const findings = await enrichFromTechStrings(strings, {
        source: String(req.body?.source || 'banner'),
        useNvd: req.body?.useNvd !== false,
        useOsv: req.body?.useOsv !== false,
        checkExploits: Boolean(req.body?.checkExploits),
        maxPerProduct: Math.min(20, Math.max(1, Number(req.body?.maxPerProduct) || 5)),
      });
      res.json({ ok: true, findings });
    } catch (e) {
      res.status(500).json({ ok: false, error: e.message });
    }
  });

  // ----- Evidence capture (on-demand) --------------------------------------
  app.post('/api/evidence/capture/:runId', requireScope('evidence.capture'), async (req, res) => {
    if (!requireCsrf(req, res)) return;
    try {
      // Lazy require do db.js para evitar acoplar este ficheiro.
      const { getRunById } = await import('./db.js');
      const run = await getRunById(req.params.runId);
      if (!run) return res.status(404).json({ ok: false, error: 'run não encontrado' });
      const result = await captureEvidenceForRun(run, {
        minSeverity: String(req.body?.minSeverity || 'medium'),
        maxCaptures: Math.min(60, Math.max(1, Number(req.body?.maxCaptures) || 25)),
        fullPage: Boolean(req.body?.fullPage),
        timeoutMs: Math.min(60_000, Math.max(3000, Number(req.body?.timeoutMs) || 15_000)),
      });
      res.json({
        ok: true,
        runId: run.id,
        captureCount: result.captures.filter((c) => !c.error).length,
        failed: result.captures.filter((c) => c.error).length,
        outputDir: result.outputDir,
      });
    } catch (e) {
      res.status(500).json({ ok: false, error: e.message });
    }
  });

  // ----- Diff summary -------------------------------------------------------
  app.get('/api/runs/:id/diff-summary/:baselineId', async (req, res) => {
    try {
      const { compareRuns } = await import('./db-compare.js');
      const diff = await compareRuns(req.params.baselineId, req.params.id);
      if (diff.error) return res.status(400).json({ ok: false, error: diff.error });
      const summary = summarizeDiff(diff, {
        minSeverity: String(req.query.minSeverity || 'low'),
        onlyNew: String(req.query.onlyNew || '') === '1',
      });
      res.json({ ok: true, summary });
    } catch (e) {
      res.status(500).json({ ok: false, error: e.message });
    }
  });

  // ----- Engagements (RT metadata) ----------------------------------------
  app.get('/api/engagements', async (_req, res) => {
    try {
      res.json({ ok: true, engagements: await listEngagements() });
    } catch (e) {
      res.status(500).json({ ok: false, error: e.message });
    }
  });

  app.get('/api/engagements/:id', async (req, res) => {
    try {
      const e = await getEngagement(req.params.id);
      if (!e) return res.status(404).json({ ok: false, error: 'engagement não encontrado' });
      res.json({ ok: true, engagement: e });
    } catch (e) {
      res.status(500).json({ ok: false, error: e.message });
    }
  });

  app.post('/api/engagements', requireScope('engagement.write'), async (req, res) => {
    if (!requireCsrf(req, res)) return;
    try {
      const e = await upsertEngagement(req.body || {});
      res.json({ ok: true, engagement: e });
    } catch (e) {
      res.status(400).json({ ok: false, error: e.message });
    }
  });

  app.post('/api/engagements/:id/close', requireScope('engagement.write'), async (req, res) => {
    if (!requireCsrf(req, res)) return;
    try {
      const e = await closeEngagement(req.params.id, { reason: req.body?.reason });
      if (!e) return res.status(404).json({ ok: false, error: 'engagement não encontrado' });
      res.json({ ok: true, engagement: e });
    } catch (e) {
      res.status(400).json({ ok: false, error: e.message });
    }
  });

  app.post('/api/engagements/checklist', requireScope('engagement.write'), async (req, res) => {
    if (!requireCsrf(req, res)) return;
    try {
      const id = String(req.body?.engagementId || '').trim();
      const engagement = id ? await getEngagement(id) : null;
      if (id && !engagement) return res.status(404).json({ ok: false, error: 'engagement não encontrado' });
      const target = String(req.body?.target || '').trim();
      const modules = Array.isArray(req.body?.modules) ? req.body.modules : [];
      const playbook = req.body?.playbook != null ? String(req.body.playbook) : null;
      const checklist = preRunChecklist({ engagement, target, modules, playbook });
      res.json({ ok: true, checklist });
    } catch (e) {
      res.status(400).json({ ok: false, error: e.message });
    }
  });

  // ----- OPSEC gate (preview) -----------------------------------------------
  app.post('/api/opsec/gate', requireRole('admin'), async (req, res) => {
    if (!requireCsrf(req, res)) return;
    try {
      const modules = Array.isArray(req.body?.modules) ? req.body.modules : [];
      const profile = String(req.body?.opsecProfile || req.body?.profile || 'standard').toLowerCase();
      const confirm = Boolean(req.body?.confirmActive);
      let engagement = null;
      const eid = String(req.body?.engagementId || '').trim();
      if (eid) {
        engagement = await getEngagement(eid);
        if (!engagement) return res.status(404).json({ ok: false, error: 'engagement não encontrado' });
      }
      const gate = gateModules({
        modules,
        profile,
        confirm: confirm || process.env.GHOSTRECON_CONFIRM_ACTIVE === '1',
        engagement,
      });
      res.json({ ok: true, gate });
    } catch (e) {
      res.status(400).json({ ok: false, error: e.message });
    }
  });

  // ----- Narrative + purple (por run) ---------------------------------------
  app.get('/api/runs/:id/narrative', async (req, res) => {
    try {
      const { getRunById } = await import('./db.js');
      const run = await getRunById(req.params.id);
      if (!run) return res.status(404).json({ ok: false, error: 'run não encontrado' });
      const includeInfo = String(req.query.includeInfo || '') === '1';
      const narrative = narrate(run, { includeInfo });
      const fmt = String(req.query.format || 'json').toLowerCase();
      if (fmt === 'md' || fmt === 'markdown') {
        res.setHeader('content-type', 'text/markdown; charset=utf-8');
        res.send(narrativeToMarkdown(narrative));
        return;
      }
      res.json({ ok: true, narrative });
    } catch (e) {
      res.status(500).json({ ok: false, error: e.message });
    }
  });

  app.get('/api/runs/:id/purple', async (req, res) => {
    try {
      const { getRunById } = await import('./db.js');
      const run = await getRunById(req.params.id);
      if (!run) return res.status(404).json({ ok: false, error: 'run não encontrado' });
      const minSeverity = String(req.query.minSeverity || 'low');
      const fmt = String(req.query.format || 'md').toLowerCase();
      const md = exportPurpleTeamReport(run, { minSeverity });
      if (fmt === 'json') {
        res.json({ ok: true, markdown: md, runId: run.id, target: run.target });
        return;
      }
      res.setHeader('content-type', 'text/markdown; charset=utf-8');
      res.send(md);
    } catch (e) {
      res.status(500).json({ ok: false, error: e.message });
    }
  });

  // ----- Team locks / trail ---------------------------------------------------
  app.get('/api/team/locks', async (_req, res) => {
    try {
      res.json({ ok: true, locks: await listLocks() });
    } catch (e) {
      res.status(500).json({ ok: false, error: e.message });
    }
  });

  app.get('/api/team/trail', async (req, res) => {
    try {
      const target = req.query.target != null ? String(req.query.target) : null;
      const operator = req.query.operator != null ? String(req.query.operator) : null;
      const runIdNum = req.query.runId != null && req.query.runId !== '' ? Number(req.query.runId) : null;
      const runId = Number.isFinite(runIdNum) ? runIdNum : null;
      const sinceIso = req.query.since != null ? String(req.query.since) : null;
      const limit = Math.min(10_000, Math.max(1, Number(req.query.limit) || 500));
      const entries = await listTrail({
        target,
        operator,
        runId,
        sinceIso,
        limit,
      });
      res.json({ ok: true, count: entries.length, entries });
    } catch (e) {
      res.status(500).json({ ok: false, error: e.message });
    }
  });

  app.post('/api/team/lock', requireScope('team.lock'), async (req, res) => {
    if (!requireCsrf(req, res)) return;
    try {
      const target = String(req.body?.target || '').trim();
      if (!target) return res.status(400).json({ ok: false, error: 'target obrigatório' });
      const out = await acquireLock(target, {
        operator: String(req.body?.operator || 'unknown'),
        ttlMs: Math.min(3_600_000, Math.max(60_000, Number(req.body?.ttlMs) || 600_000)),
        purpose: String(req.body?.purpose || 'scan'),
      });
      res.json({ ok: true, ...out });
    } catch (e) {
      res.status(400).json({ ok: false, error: e.message });
    }
  });

  app.post('/api/team/unlock', requireScope('team.lock'), async (req, res) => {
    if (!requireCsrf(req, res)) return;
    try {
      const target = String(req.body?.target || '').trim();
      const token = String(req.body?.token || '').trim();
      if (!target || !token) return res.status(400).json({ ok: false, error: 'target e token obrigatórios' });
      const ok = await releaseLock(target, token);
      res.json({ ok, released: ok });
    } catch (e) {
      res.status(400).json({ ok: false, error: e.message });
    }
  });

  app.post('/api/team/force-unlock', requireRole('admin'), async (req, res) => {
    if (!requireCsrf(req, res)) return;
    try {
      const target = String(req.body?.target || '').trim();
      if (!target) return res.status(400).json({ ok: false, error: 'target obrigatório' });
      const ok = await forceReleaseLock(target);
      res.json({ ok, released: ok });
    } catch (e) {
      res.status(400).json({ ok: false, error: e.message });
    }
  });
}
