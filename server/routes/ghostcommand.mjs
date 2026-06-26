import { requireScope } from '../modules/auth.js';
import {
  authorizeGhostCommandRequest,
  closeGhostCommandGate,
  createGhostCommandRunner,
  ghostCommandConfig,
  loadGhostCommandGate,
  openGhostCommandGate,
} from '../modules/ghostcommand.mjs';

export function registerGhostCommandRoutes(app, { runPipeline } = {}) {
  const runner = createGhostCommandRunner({ runPipeline, config: ghostCommandConfig() });

  const guard = (req, res) => {
    const auth = authorizeGhostCommandRequest(req);
    if (!auth.ok) {
      res.status(auth.status).json({ ok: false, error: auth.code, ip: auth.ip });
      return null;
    }
    return auth;
  };

  app.get('/api/ghostcommand/status', requireScope('recon.read'), async (req, res) => {
    const auth = guard(req, res);
    if (!auth) return;
    res.json({
      ok: true,
      ip: auth.ip,
      gate: await loadGhostCommandGate(),
      worker: runner.status(),
    });
  });

  app.post('/api/ghostcommand/gate/open', requireScope('recon.run'), async (req, res) => {
    const auth = guard(req, res);
    if (!auth) return;
    const gate = await openGhostCommandGate({ reason: req.body?.reason || 'mobile', by: auth.ip });
    res.json({ ok: true, gate });
  });

  app.post('/api/ghostcommand/gate/close', requireScope('recon.run'), async (req, res) => {
    const auth = guard(req, res);
    if (!auth) return;
    const gate = await closeGhostCommandGate({ reason: req.body?.reason || 'mobile', by: auth.ip });
    res.json({ ok: true, gate });
  });

  app.post('/api/ghostcommand/recon', requireScope('recon.run'), async (req, res) => {
    const auth = guard(req, res);
    if (!auth) return;
    const result = await runner.submit({
      target: req.body?.target,
      outOfScope: req.body?.outOfScope,
      requestedBy: auth.ip,
    });
    if (!result.ok) {
      res.status(result.status || 400).json(result);
      return;
    }
    res.status(202).json(result);
  });
}
