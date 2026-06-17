import {
  listBrainCategories,
  createBrainCategory,
  updateBrainCategoryDescription,
  upsertBrainLink,
  getBrainCategoryById,
  listBrainLinksForCategory,
  listManualValidationsForTarget,
} from '../modules/db.js';
import { syncValidatedCortexFindingToGhostKb } from '../modules/ghost-kb-sync.js';
import { requireScope } from '../modules/auth.js';

export function registerBrainRoutes(app, { validateCsrfToken }) {
  app.get('/api/brain/categories', async (_req, res) => {
  try {
    const items = await listBrainCategories();
    res.json({ items });
  } catch (e) {
    res.status(500).json({ error: e?.message || String(e) });
  }
});

  app.post('/api/brain/categories', requireScope('brain.write'), async (req, res) => {
  if (!validateCsrfToken(req)) {
    res.status(403).json({ ok: false, error: 'CSRF token inválido ou ausente' });
    return;
  }
  const title = req.body?.title;
  const description = req.body?.description;
  try {
    const out = await createBrainCategory(title, description);
    res.json({ ok: true, ...out });
  } catch (e) {
    res.status(400).json({ ok: false, error: e?.message || String(e) });
  }
});

  app.post('/api/brain/categories/:id/description', requireScope('brain.write'), async (req, res) => {
  if (!validateCsrfToken(req)) {
    res.status(403).json({ ok: false, error: 'CSRF token inválido ou ausente' });
    return;
  }
  const id = Number(req.params.id);
  const description = req.body?.description;
  try {
    const out = await updateBrainCategoryDescription(id, description);
    res.json({ ok: true, category: out });
  } catch (e) {
    res.status(400).json({ ok: false, error: e?.message || String(e) });
  }
});

  app.post('/api/brain/link', requireScope('brain.write'), async (req, res) => {
  if (!validateCsrfToken(req)) {
    res.status(403).json({ ok: false, error: 'CSRF token inválido ou ausente' });
    return;
  }
  const target = String(req.body?.target || '')
    .trim()
    .toLowerCase();
  const fp = String(req.body?.fingerprint || '').trim().toLowerCase();
  const categoryId = req.body?.categoryId;
  try {
    const out = await upsertBrainLink({ target, fingerprint: fp, categoryId });
    let ghostKbSync = { ok: false, skipped: true, reason: 'not_attempted' };
    try {
      const category = await getBrainCategoryById(Number(categoryId));
      const validated = await listManualValidationsForTarget(target);
      const row = validated.find((x) => String(x.fingerprint || '').trim().toLowerCase() === fp);
      ghostKbSync = await syncValidatedCortexFindingToGhostKb({
        target,
        fingerprint: fp,
        snapshot: row?.snapshot || null,
        notes: row?.notes || '',
        brainCategoryTitle: category?.title || '',
      });
    } catch (e) {
      ghostKbSync = { ok: false, error: e?.message || String(e) };
    }
    res.json({ ok: true, ...out, ghostKbSync });
  } catch (e) {
    res.status(400).json({ ok: false, error: e?.message || String(e) });
  }
});

/** Uma categoria do cérebro + achados ligados (para a página Cortex). */
  app.get('/api/brain/category/:id', async (req, res) => {
  const id = Number(req.params.id);
  if (!Number.isFinite(id) || id < 1) {
    res.status(400).json({ error: 'id inválido' });
    return;
  }
  try {
    const category = await getBrainCategoryById(id);
    if (!category) {
      res.status(404).json({ error: 'categoria não encontrada' });
      return;
    }
    const links = await listBrainLinksForCategory(id);
    res.json({ category, links });
  } catch (e) {
    res.status(500).json({ error: e?.message || String(e) });
  }
});
}
