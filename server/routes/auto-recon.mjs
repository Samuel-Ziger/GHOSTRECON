import { parseReconTarget } from '../modules/recon-target.js';
import { requireScope, reconBodyIsIntrusive, audit as auditAuth } from '../modules/auth.js';
import { reconHttpContext } from '../lib/http-history.mjs';
import { runAutoRecon } from '../auto-agent/orchestrator.mjs';

export function registerAutoReconRoutes(app, deps = {}) {
  const {
    runPipeline,
    validateCsrfToken,
    allowReconRequest,
    ROOT,
  } = deps;

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
