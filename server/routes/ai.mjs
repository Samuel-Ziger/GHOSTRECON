import { listRuns } from '../modules/db.js';
import { compareRuns } from '../modules/db-compare.js';
import {
  runDualAiReports,
  pickAiReportForWebhook,
  probeLmStudioConnection,
  normalizeOpenrouterOnlyFlag,
} from '../modules/ai-dual-report.js';
import { postAiReportWebhook, postReconDeltaFullWebhook } from '../modules/webhook-notify.js';
import { requireScope } from '../modules/auth.js';

export function registerAiRoutes(app, { validateCsrfToken }) {
  app.post('/api/ai-reports', requireScope('ai.run'), async (req, res) => {
  if (!validateCsrfToken(req)) {
    res.status(403).json({ ok: false, error: 'CSRF token inválido ou ausente' });
    return;
  }
  const payload = req.body?.payload;
  if (!payload || typeof payload !== 'object' || Array.isArray(payload)) {
    res.status(400).json({ ok: false, error: 'Corpo inválido: falta object "payload" (export JSON do pipeline).' });
    return;
  }
  const projectName = String(req.body?.projectName ?? payload.projectName ?? '').trim();
  const targetDomain = String(req.body?.targetDomain ?? payload.target ?? '').trim();
  if (!targetDomain) {
    res.status(400).json({ ok: false, error: 'Define Target ($) ou inclui "target" no payload.' });
    return;
  }
  try {
    const out = await runDualAiReports(payload, {
      projectName,
      targetDomain,
      aiProviderMode: String(req.body?.aiProviderMode || 'auto'),
      aiUseOpenrouter: req.body?.aiUseOpenrouter !== false,
      aiOpenrouterOnly: normalizeOpenrouterOnlyFlag(req.body?.aiOpenrouterOnly),
      aiPrimaryCloud:
        typeof req.body?.aiPrimaryCloud === 'string'
          ? req.body.aiPrimaryCloud
          : typeof req.body?.aiPrimaryReport === 'string'
            ? req.body.aiPrimaryReport
            : null,
    });
    const whUrl = process.env.GHOSTRECON_WEBHOOK_URL?.trim();
    if (whUrl) {
      const picked = pickAiReportForWebhook(out);
      let reconDeltaApi = null;
      const rid = payload.runId != null ? Number(payload.runId) : null;
      if (Number.isFinite(rid)) {
        try {
          const runs = await listRuns(120);
          const nt = targetDomain.trim().toLowerCase();
          const prev = runs.find((r) => String(r.target).trim().toLowerCase() === nt && r.id < rid);
          if (prev) {
            const diff = await compareRuns(prev.id, rid);
            if (!diff.error) {
              reconDeltaApi = {
                baselineId: diff.baselineId,
                baselineCreatedAt: diff.baselineCreatedAt,
                newerCreatedAt: diff.newerCreatedAt,
                added: diff.added,
                removedCount: diff.removedCount,
              };
            }
          }
        } catch (e) {
          console.warn('[GHOSTRECON webhook diff ai-reports]', e?.message || e);
        }
      }
      if (picked) {
        void postAiReportWebhook(whUrl, {
          target: targetDomain,
          runId: payload.runId ?? null,
          provider: picked.provider,
          relatorio: picked.relatorio,
          proximos_passos: picked.proximos_passos,
        });
        if (reconDeltaApi) {
          void postReconDeltaFullWebhook(whUrl, {
            target: targetDomain,
            runId: rid,
            baselineId: reconDeltaApi.baselineId,
            baselineCreatedAt: reconDeltaApi.baselineCreatedAt,
            newerCreatedAt: reconDeltaApi.newerCreatedAt,
            added: reconDeltaApi.added,
            removedCount: reconDeltaApi.removedCount,
          });
        }
      } else if (reconDeltaApi) {
        void postReconDeltaFullWebhook(whUrl, {
          target: targetDomain,
          runId: rid,
          baselineId: reconDeltaApi.baselineId,
          baselineCreatedAt: reconDeltaApi.baselineCreatedAt,
          newerCreatedAt: reconDeltaApi.newerCreatedAt,
          added: reconDeltaApi.added,
          removedCount: reconDeltaApi.removedCount,
        });
      }
    }
    res.json({ ok: true, ...out });
  } catch (e) {
    res.status(500).json({ ok: false, error: e?.message || String(e) });
  }
});

  app.get('/api/ai/lmstudio-check', async (_req, res) => {
  try {
    const out = await probeLmStudioConnection();
    res.json(out);
  } catch (e) {
    res.status(503).json({ ok: false, error: e?.message || String(e) });
  }
});
}
