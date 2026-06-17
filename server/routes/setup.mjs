import { clientIp, isLoopbackIp } from '../lib/client-ip.mjs';
import { requireScope } from '../modules/auth.js';

export function registerSetupRoutes(app, { issueCsrfToken, validateCsrfToken, CSRF_TTL_MS, reconHttpHistory }) {
  app.get('/api/setup/auto-auth', (req, res) => {
    const ip = clientIp(req);
    const loopback = isLoopbackIp(ip);
    if (!loopback) return res.status(403).json({ error: 'apenas loopback' });

    const raw = process.env.AUTH_API_KEYS || '';
    const first = raw.split(/[|\n]/).map((s) => s.trim()).filter(Boolean)[0];
    if (!first) return res.status(404).json({ error: 'AUTH_API_KEYS não configuradas' });

    const key = first.split(':')[0];
    if (!key || key.length < 24) return res.status(404).json({ error: 'chave inválida' });

    res.json({ apiKey: key });
  });

  app.get('/api/csrf-token', (req, res) => {
    const token = issueCsrfToken(req);
    res.setHeader('Cache-Control', 'no-store');
    res.json({ token, expiresInMs: CSRF_TTL_MS });
  });

  app.get('/api/history/recon', requireScope('recon.read'), (req, res) => {
    const limitRaw = Number(req.query.limit || 500);
    const limit = Number.isFinite(limitRaw) ? Math.max(1, Math.min(1000, Math.floor(limitRaw))) : 500;
    const target = String(req.query.target || '').trim().toLowerCase();
    const afterRaw = Number(req.query.after || 0);
    const after = Number.isFinite(afterRaw) ? Math.max(0, Math.floor(afterRaw)) : 0;
    let rows = reconHttpHistory;
    if (target) rows = rows.filter((x) => String(x.target || '').toLowerCase() === target);
    if (after > 0) rows = rows.filter((x) => Number(x.id) > after);
    res.setHeader('Cache-Control', 'no-store');
    res.json({ ok: true, count: rows.length, items: rows.slice(-limit) });
  });
}
