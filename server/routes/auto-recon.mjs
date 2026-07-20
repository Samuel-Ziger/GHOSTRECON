import { parseReconTarget } from '../modules/recon-target.js';
import { requireScope, reconBodyIsIntrusive, audit as auditAuth } from '../modules/auth.js';
import { reconHttpContext } from '../lib/http-history.mjs';
import { runAutoRecon } from '../auto-agent/orchestrator.mjs';
import {
  listAutoRagMarkdown,
  resolveAutoRagDir,
  searchAutoRagMarkdown,
  writeAutoLesson,
  writeAutoRagNote,
} from '../auto-agent/rag-memory.mjs';
import { compareForgeVersions, listForgePackages, manageForgePackage, readForgePackage, recordForgeRuntimeResult, transitionForgePackage } from '../auto-agent/forge/lifecycle.mjs';
import { cancelActiveAutoSession, listActiveAutoSessions } from '../auto-agent/active-sessions.mjs';

export function registerAutoReconRoutes(app, deps = {}) {
  const {
    runPipeline,
    validateCsrfToken,
    allowReconRequest,
    ROOT,
  } = deps;

  app.get('/api/recon/auto/sessions', requireScope('recon.read'), (_req, res) => {
    res.json({ ok: true, sessions: listActiveAutoSessions() });
  });

  app.post('/api/recon/auto/:sessionId/cancel', requireScope('recon.run'), (req, res) => {
    if (!validateCsrfToken(req)) {
      res.status(403).json({ ok: false, error: 'CSRF invalido/ausente' });
      return;
    }
    const sessionId = String(req.params.sessionId || '');
    const cancelled = cancelActiveAutoSession(sessionId, `cancelled_by_${req.principal?.sub || 'operator'}`);
    res.status(cancelled ? 202 : 404).json({ ok: cancelled, sessionId, error: cancelled ? null : 'sessão AUTO ativa não encontrada' });
  });

  app.get('/api/auto-forge', requireScope('recon.read'), async (_req, res) => {
    try {
      res.json({ ok: true, items: await listForgePackages(ROOT) });
    } catch (e) {
      res.status(500).json({ ok: false, error: e?.message || String(e) });
    }
  });

  app.get('/api/auto-forge/:forgeId', requireScope('recon.read'), async (req, res) => {
    try {
      res.json({ ok: true, item: await readForgePackage(ROOT, String(req.params.forgeId || '')) });
    } catch (e) {
      res.status(404).json({ ok: false, error: e?.message || String(e) });
    }
  });

  app.get('/api/auto-forge-module/:moduleId/compare', requireScope('recon.read'), async (req, res) => {
    try {
      res.json({ ok: true, moduleId: req.params.moduleId, versions: await compareForgeVersions(ROOT, String(req.params.moduleId || '')) });
    } catch (error) {
      res.status(400).json({ ok: false, error: error?.message || String(error) });
    }
  });

  app.post('/api/auto-forge/:forgeId/verdict', requireScope('recon.run'), async (req, res) => {
    if (!validateCsrfToken(req)) {
      res.status(403).json({ ok: false, error: 'CSRF invalido/ausente' });
      return;
    }
    try {
      const result = await transitionForgePackage({
        root: ROOT,
        forgeId: String(req.params.forgeId || ''),
        decision: String(req.body?.decision || ''),
        reason: String(req.body?.reason || ''),
        percentage: req.body?.percentage,
        operator: req.principal?.sub || 'local',
      });
      if (result.decision !== 'approve') {
        res.json(result);
        return;
      }
      const runtimeEvents = [];
      let runtime;
      try {
        await runPipeline({
          domain: result.target,
          exactMatch: false,
          modules: [result.moduleId],
          profile: 'standard',
          opsecProfile: 'standard',
          autoAiReports: false,
          emit: (event) => runtimeEvents.push(event),
        });
        const completed = runtimeEvents.find((event) => event.type === 'dynamic_module_completed' && event.forgeId === result.forgeId);
        const moduleError = runtimeEvents.find((event) => event.type === 'dynamic_module_error' && event.forgeId === result.forgeId);
        if (!completed || moduleError) throw new Error(moduleError?.error || 'módulo aprovado não concluiu a primeira execução');
        runtime = await recordForgeRuntimeResult({ root: ROOT, forgeId: result.forgeId, success: true, findings: completed.findings });
      } catch (error) {
        runtime = await recordForgeRuntimeResult({ root: ROOT, forgeId: result.forgeId, success: false, error: error?.message || String(error) });
      }
      res.status(runtime.ok ? 200 : 422).json({ ...result, ok: runtime.ok, runtime, eventCount: runtimeEvents.length });
    } catch (e) {
      res.status(400).json({ ok: false, error: e?.message || String(e) });
    }
  });

  app.post('/api/auto-forge/:forgeId/lifecycle', requireScope('recon.run'), async (req, res) => {
    if (!validateCsrfToken(req)) {
      res.status(403).json({ ok: false, error: 'CSRF invalido/ausente' });
      return;
    }
    try {
      res.json(await manageForgePackage({
        root: ROOT,
        forgeId: String(req.params.forgeId || ''),
        action: String(req.body?.action || ''),
        reason: String(req.body?.reason || ''),
        operator: req.principal?.sub || 'local',
      }));
    } catch (error) {
      res.status(400).json({ ok: false, error: error?.message || String(error) });
    }
  });

  app.get('/api/auto-rag/status', requireScope('recon.read'), async (_req, res) => {
    try {
      const memories = await listAutoRagMarkdown({ root: ROOT, limit: 500 });
      const counts = memories.reduce((acc, item) => {
        acc[item.folder || 'decisions'] = (acc[item.folder || 'decisions'] || 0) + 1;
        return acc;
      }, {});
      res.json({
        ok: true,
        dir: resolveAutoRagDir({ root: ROOT }),
        count: memories.length,
        counts,
        recent: memories.slice(0, 12),
      });
    } catch (e) {
      res.status(500).json({ ok: false, error: e?.message || String(e) });
    }
  });

  app.get('/api/auto-rag/search', requireScope('recon.read'), async (req, res) => {
    try {
      const query = String(req.query?.q || req.query?.query || '').trim();
      const limit = Math.max(1, Math.min(50, Number(req.query?.limit || 8)));
      res.json({
        ok: true,
        dir: resolveAutoRagDir({ root: ROOT }),
        query,
        memories: await searchAutoRagMarkdown({ root: ROOT, query, limit }),
      });
    } catch (e) {
      res.status(500).json({ ok: false, error: e?.message || String(e) });
    }
  });

  app.post('/api/auto-rag/note', requireScope('notes.write'), async (req, res) => {
    if (!validateCsrfToken(req)) {
      res.status(403).json({ ok: false, error: 'CSRF invalido/ausente' });
      return;
    }
    try {
      const body = req.body || {};
      const note = body.kind === 'lesson'
        ? await writeAutoLesson({
          root: ROOT,
          target: body.target,
          problem: body.problem,
          decision: body.decision,
          outcome: body.outcome,
          modules: Array.isArray(body.modules) ? body.modules : [],
          commanders: body.commanders || null,
          confidence: body.confidence,
          tags: Array.isArray(body.tags) ? body.tags : [],
          metadata: body.metadata || null,
        })
        : await writeAutoRagNote({
          root: ROOT,
          kind: body.kind || 'note',
          title: body.title || 'Auto note',
          body: body.body || '',
          target: body.target || '',
          tags: Array.isArray(body.tags) ? body.tags : [],
          metadata: body.metadata || null,
        });
      res.json({ ok: true, note });
    } catch (e) {
      res.status(500).json({ ok: false, error: e?.message || String(e) });
    }
  });

  app.post('/api/recon/auto/stream', requireScope('recon.run', { intrusiveCheck: (req) => reconBodyIsIntrusive(req.body) }), async (req, res) => {
    res.setHeader('Content-Type', 'application/x-ndjson; charset=utf-8');
    res.setHeader('Cache-Control', 'no-cache, no-transform');
    res.setHeader('X-Accel-Buffering', 'no');

    const send = (obj) => {
      res.write(`${JSON.stringify(obj)}\n`);
    };

    if (!validateCsrfToken(req)) {
      send({ type: 'error', message: 'CSRF token invalido/ausente' });
      res.end();
      return;
    }

    if (!allowReconRequest(req)) {
      send({ type: 'error', message: 'Rate limit - aguarde antes de novo recon auto' });
      res.end();
      return;
    }

    const parsed = parseReconTarget(req.body?.domain || req.body?.target);
    if (!parsed.ok) {
      send({ type: 'error', message: parsed.message || 'Alvo invalido' });
      res.end();
      return;
    }

    const body = {
      ...req.body,
      domain: parsed.target,
    };

    auditAuth(req, req.principal, 'allow', {
      action: 'recon.auto.start',
      target: parsed.target,
      commanders: Array.isArray(body.commanders) ? body.commanders : [],
      mode: body.autoMode || body.mode || 'balanced',
    });

    const requestRunId = `auto-http-${Date.now().toString(36)}`;
    const controller = new AbortController();
    req.once('aborted', () => controller.abort(new Error('cliente desconectado')));
    res.once('close', () => {
      if (!res.writableEnded) controller.abort(new Error('stream encerrado pelo cliente'));
    });
    try {
      await reconHttpContext.run({ requestRunId, target: parsed.target, emit: send }, async () => {
        await runAutoRecon({
          body,
          runPipeline,
          emit: send,
          ROOT,
          signal: controller.signal,
        });
      });
    } catch (e) {
      send({ type: 'error', message: e?.message || String(e) });
    } finally {
      res.end();
    }
  });
}
