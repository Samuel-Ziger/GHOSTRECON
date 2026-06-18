import { requireScope } from '../modules/auth.js';
import { listVigoliumModules } from '../../bridge/vigolium-catalog.mjs';
import { buildVigoliumAuthConfig, saveVigoliumAuthConfig } from '../../bridge/vigolium-auth-config.mjs';
import {
  getVigoliumServerStatus,
  serverEndpointFor,
  vigoliumServerFetch,
} from '../../bridge/vigolium-server-client.mjs';

function boolParam(v) {
  return ['1', 'true', 'yes', 'on'].includes(String(v || '').trim().toLowerCase());
}

function forwardQuery(req) {
  const out = {};
  for (const [k, v] of Object.entries(req.query || {})) {
    if (['kind', 'limit', 'offset'].includes(k)) continue;
    out[k] = v;
  }
  return out;
}

function intParam(v, fallback, { min = 0, max = 500 } = {}) {
  const n = Number.parseInt(String(v ?? ''), 10);
  if (!Number.isFinite(n)) return fallback;
  return Math.max(min, Math.min(max, n));
}

async function proxyAgentMode(req, res, mode) {
  const out = await vigoliumServerFetch(`/api/agent/run/${mode}`, { method: 'POST', body: req.body || {} });
  res.status(out.ok ? 200 : (out.status || 502)).json(out);
}

export function registerVigoliumRoutes(app, { ROOT }) {
  app.get('/api/vigolium/modules', async (req, res) => {
    try {
      const out = await listVigoliumModules({
        root: ROOT,
        kind: req.query?.kind ? String(req.query.kind) : '',
        tag: req.query?.tag ? String(req.query.tag) : '',
        q: req.query?.q ? String(req.query.q) : '',
      });
      const limit = intParam(req.query?.limit, 100, { min: 1, max: 500 });
      const offset = intParam(req.query?.offset, 0, { min: 0, max: 100000 });
      const modules = out.modules.slice(offset, offset + limit);
      out.page = { limit, offset, returned: modules.length };
      out.modules = modules;
      res.json(out);
    } catch (e) {
      res.status(500).json({ ok: false, error: e?.message || String(e) });
    }
  });

  app.post('/api/vigolium/auth-config', requireScope('recon.run'), async (req, res) => {
    try {
      if (boolParam(req.body?.save)) {
        res.json(await saveVigoliumAuthConfig(req.body || {}, { root: ROOT }));
      } else {
        res.json({ ok: true, config: buildVigoliumAuthConfig(req.body || {}) });
      }
    } catch (e) {
      res.status(400).json({ ok: false, error: e?.message || String(e) });
    }
  });

  app.get('/api/vigolium/server/status', async (_req, res) => {
    res.json(await getVigoliumServerStatus());
  });

  app.get('/api/vigolium/server/:kind', requireScope('recon.read'), async (req, res) => {
    const endpoint = serverEndpointFor(req.params.kind);
    if (!endpoint) {
      res.status(404).json({ ok: false, error: `endpoint Vigolium desconhecido: ${req.params.kind}` });
      return;
    }
    const out = await vigoliumServerFetch(endpoint, { query: forwardQuery(req) });
    res.status(out.ok ? 200 : (out.status || 502)).json(out);
  });

  app.post('/api/vigolium/ingest-http', requireScope('recon.run'), async (req, res) => {
    const out = await vigoliumServerFetch('/api/ingest-http', { method: 'POST', body: req.body || {} });
    res.status(out.ok ? 200 : (out.status || 502)).json(out);
  });

  app.post('/api/vigolium/agent/query', requireScope('recon.run'), async (req, res) => {
    await proxyAgentMode(req, res, 'query');
  });

  app.post('/api/vigolium/agent/:mode', requireScope('recon.intrusive'), async (req, res) => {
    const mode = String(req.params.mode || '').trim().toLowerCase();
    if (!['swarm', 'autopilot', 'audit'].includes(mode)) {
      res.status(404).json({ ok: false, error: `modo agent desconhecido: ${mode}` });
      return;
    }
    await proxyAgentMode(req, res, mode);
  });
}
