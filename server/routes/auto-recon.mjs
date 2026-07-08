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

export function registerAutoReconRoutes(app, deps = {}) {
  const {
    runPipeline,
    validateCsrfToken,
    allowReconRequest,
    ROOT,
  } = deps;

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
    try {
      await reconHttpContext.run({ requestRunId, target: parsed.target, emit: send }, async () => {
        await runAutoRecon({
          body,
          runPipeline,
          emit: send,
          ROOT,
        });
      });
    } catch (e) {
      send({ type: 'error', message: e?.message || String(e) });
    } finally {
      res.end();
    }
  });
}
