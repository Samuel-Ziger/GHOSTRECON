import { randomBytes } from 'node:crypto';
import { requireScope } from '../modules/auth.js';

const ANOTACAO_HANDOFF_TTL_MS = 20 * 60 * 1000;
const anotacaoHandoffStore = new Map();

function pruneAnotacaoHandoffStore() {
  const now = Date.now();
  for (const [k, v] of anotacaoHandoffStore) {
    if (!v || v.exp <= now) anotacaoHandoffStore.delete(k);
  }
}

export function registerHandoffRoutes(app, { validateCsrfToken }) {
  app.post('/api/anotacao-handoff', requireScope('notes.write'), (req, res) => {
  if (!validateCsrfToken(req)) {
    res.status(403).json({ ok: false, error: 'CSRF token inválido ou ausente' });
    return;
  }
  const payload = req.body?.payload;
  if (!payload || typeof payload !== 'object') {
    res.status(400).json({ ok: false, error: 'Indica { payload: { target, findings, … } } no corpo.' });
    return;
  }
  pruneAnotacaoHandoffStore();
  const id = randomBytes(16).toString('hex');
  anotacaoHandoffStore.set(id, { data: payload, exp: Date.now() + ANOTACAO_HANDOFF_TTL_MS });
  res.json({ ok: true, id });
});

  app.get('/api/anotacao-handoff/:id', (req, res) => {
  pruneAnotacaoHandoffStore();
  const id = String(req.params.id || '')
    .trim()
    .toLowerCase()
    .replace(/[^a-f0-9]/g, '');
  if (!/^[a-f0-9]{32}$/.test(id)) {
    res.status(400).json({ error: 'id de handoff inválido' });
    return;
  }
  const row = anotacaoHandoffStore.get(id);
  if (!row || row.exp < Date.now()) {
    res.status(404).json({ error: 'Pacote expirado ou já consumido. Volta ao Reporte e clica ANOTAÇÃO de novo.' });
    return;
  }
  anotacaoHandoffStore.delete(id);
  res.json(row.data);
});
}
