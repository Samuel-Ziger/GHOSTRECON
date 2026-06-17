import { listRuns, getRunById, listIntelForTarget, intelCountForTarget } from '../modules/db.js';
import { compareRuns } from '../modules/db-compare.js';

export function registerRunsRoutes(app) {
  app.get('/api/runs', async (req, res) => {
    const lim = Number(req.query.limit) || 50;
    try {
      const runs = await listRuns(lim);
      res.json({ runs });
    } catch (e) {
      res.status(500).json({ error: e?.message || String(e) });
    }
  });

  app.get('/api/runs/:id', async (req, res) => {
    const id = Number(req.params.id);
    if (!Number.isFinite(id)) {
      res.status(400).json({ error: 'id inválido' });
      return;
    }
    try {
      const run = await getRunById(id);
      if (!run) {
        res.status(404).json({ error: 'run não encontrado' });
        return;
      }
      res.json(run);
    } catch (e) {
      res.status(500).json({ error: e?.message || String(e) });
    }
  });

  app.get('/api/runs/:newerId/diff/:baselineId', async (req, res) => {
    const newerId = Number(req.params.newerId);
    const baselineId = Number(req.params.baselineId);
    if (!Number.isFinite(newerId) || !Number.isFinite(baselineId)) {
      res.status(400).json({ error: 'ids inválidos' });
      return;
    }
    try {
      const result = await compareRuns(baselineId, newerId);
      if (result.error) {
        res.status(result.error === 'run não encontrado' ? 404 : 400).json(result);
        return;
      }
      res.json(result);
    } catch (e) {
      res.status(500).json({ error: e?.message || String(e) });
    }
  });

  app.get('/api/intel/:target', async (req, res) => {
    const t = String(req.params.target || '')
      .trim()
      .toLowerCase();
    if (!t || !/^[a-z0-9][a-z0-9.-]*[a-z0-9]$/.test(t)) {
      res.status(400).json({ error: 'domínio inválido' });
      return;
    }
    try {
      const [totalUnique, items] = await Promise.all([
        intelCountForTarget(t),
        listIntelForTarget(t, 500),
      ]);
      res.json({
        target: t,
        totalUnique,
        items,
      });
    } catch (e) {
      res.status(500).json({ error: e?.message || String(e) });
    }
  });
}
