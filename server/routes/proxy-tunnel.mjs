import {
  executeNavegationPlaybook,
  getNavegationTunnelStatus,
  validateNavegationTorPath,
} from '../modules/navegation.js';
import { requireScope, requireRole, audit as auditAuth } from '../modules/auth.js';
import { newnym as torNewnym, torHealth as torControlHealth } from '../modules/tor-control.js';
import {
  isStrict as torIsStrict,
  strictPrereqs as torStrictPrereqs,
  snapshotTelemetry as torSnapshotTelemetry,
} from '../modules/tor-strict.js';

export function registerProxyTunnelRoutes(app, { validateCsrfToken, ghostProxy, ROOT }) {
  app.get('/api/proxy/status', requireScope('recon.read'), (_req, res) => {
    res.json({ ok: true, ...ghostProxy.status() });
  });

  app.post('/api/proxy/start', requireScope('recon.run'), async (req, res) => {
    if (!validateCsrfToken(req)) { res.status(403).json({ ok: false, error: 'CSRF inválido' }); return; }
    try {
      const result = await ghostProxy.start();
      res.json({ ok: true, ...result, ...ghostProxy.status() });
    } catch (e) {
      res.status(500).json({ ok: false, error: e?.message || String(e) });
    }
  });

  app.post('/api/proxy/stop', requireScope('recon.run'), async (req, res) => {
    if (!validateCsrfToken(req)) { res.status(403).json({ ok: false, error: 'CSRF inválido' }); return; }
    try {
      await ghostProxy.stop();
      res.json({ ok: true, ...ghostProxy.status() });
    } catch (e) {
      res.status(500).json({ ok: false, error: e?.message || String(e) });
    }
  });

  app.post('/api/proxy/mitm', requireScope('recon.run'), (req, res) => {
    if (!validateCsrfToken(req)) { res.status(403).json({ ok: false, error: 'CSRF inválido' }); return; }
    const enabled = Boolean(req.body?.enabled !== false);
    ghostProxy.setMitm(enabled);
    res.json({ ok: true, mitmEnabled: enabled, ...ghostProxy.status() });
  });

  app.get('/api/proxy/ca.crt', (_req, res) => {
    const cert = ghostProxy.caCert;
    if (!cert) { res.status(404).json({ ok: false, error: 'CA não gerada — OpenSSL disponível?' }); return; }
    res.setHeader('Content-Type', 'application/x-x509-ca-cert');
    res.setHeader('Content-Disposition', 'attachment; filename="ghostrecon-ca.crt"');
    res.send(cert);
  });

  app.get('/api/tunnel/status', async (_req, res) => {
    try {
      const status = await getNavegationTunnelStatus(ROOT);
      res.json({ ok: true, ...status });
    } catch (e) {
      res.status(500).json({ ok: false, error: e?.message || String(e) });
    }
  });

  app.get('/api/tunnel/validate', async (_req, res) => {
    try {
      const report = await validateNavegationTorPath(ROOT);
      res.json(report);
    } catch (e) {
      res.status(500).json({ ok: false, error: e?.message || String(e) });
    }
  });

  app.post('/api/tunnel/enable', requireRole('admin'), async (req, res) => {
    if (!validateCsrfToken(req)) {
      res.status(403).json({ ok: false, error: 'CSRF token inválido/ausente' });
      return;
    }
    try {
      const dryRun = Boolean(req.body?.dryRun);
      const run = await executeNavegationPlaybook(ROOT, {
        action: 'up',
        dryRun,
        userMode: req.body?.systemMode !== true,
        timeoutMs: Number(process.env.GHOSTRECON_NAVEGATION_TIMEOUT_MS || 900000),
      });
      const status = await getNavegationTunnelStatus(ROOT);
      res.json({ ok: run.ok, run, status });
    } catch (e) {
      res.status(500).json({ ok: false, error: e?.message || String(e) });
    }
  });

  app.get('/api/tunnel/health', requireScope('recon.read'), async (_req, res) => {
    try {
      const health = await torControlHealth();
      res.json({ ok: true, ...health, strict: { active: torIsStrict() } });
    } catch (e) {
      res.status(500).json({ ok: false, error: e?.message || String(e) });
    }
  });

  app.get('/api/tunnel/strict-check', requireScope('recon.read'), async (_req, res) => {
    try {
      const p = torStrictPrereqs();
      res.json({ ok: true, ...p });
    } catch (e) {
      res.status(500).json({ ok: false, error: e?.message || String(e) });
    }
  });

  app.get('/api/tunnel/telemetry/:runId', requireScope('recon.read'), (req, res) => {
    const t = torSnapshotTelemetry(String(req.params.runId));
    if (!t) return res.status(404).json({ ok: false, error: 'sem telemetria para esse runId' });
    res.json({ ok: true, runId: req.params.runId, ...t });
  });

  app.post('/api/tunnel/newnym', requireScope('recon.run'), async (req, res) => {
    if (!validateCsrfToken(req)) {
      res.status(403).json({ ok: false, error: 'CSRF token inválido/ausente' });
      return;
    }
    try {
      const r = await torNewnym({ timeoutMs: 5_000 });
      auditAuth(req, req.principal, 'allow', { action: 'tunnel.newnym', ok: r.ok });
      res.json({ ok: true, ...r });
    } catch (e) {
      res.status(500).json({ ok: false, error: e?.message || String(e) });
    }
  });

  app.post('/api/tunnel/disable', requireRole('admin'), async (req, res) => {
    if (!validateCsrfToken(req)) {
      res.status(403).json({ ok: false, error: 'CSRF token inválido/ausente' });
      return;
    }
    try {
      const dryRun = Boolean(req.body?.dryRun);
      const run = await executeNavegationPlaybook(ROOT, {
        action: 'down',
        dryRun,
        timeoutMs: Number(process.env.GHOSTRECON_NAVEGATION_TIMEOUT_MS || 900000),
      });
      const status = await getNavegationTunnelStatus(ROOT);
      res.json({ ok: run.ok, run, status });
    } catch (e) {
      res.status(500).json({ ok: false, error: e?.message || String(e) });
    }
  });

  app.post('/api/tool-path-refresh', requireRole('admin'), (req, res) => {
    if (!validateCsrfToken(req)) {
      res.status(403).json({ ok: false, error: 'CSRF' });
      return;
    }
    // PATH participates in binary selection and is therefore part of the
    // execution policy sealed at boot. Mutating the process-global PATH while
    // sessions are running could select a different executable after approval.
    res.status(409).json({
      ok: false,
      error: 'PATH_REFRESH_RESTART_REQUIRED',
      message: 'Configure o PATH no ambiente e reinicie a stack para atualizar ferramentas.',
    });
  });
}
