import fs from 'node:fs/promises';
import { constants as fsConstants } from 'node:fs';
import path from 'node:path';
import { requireScope } from '../modules/auth.js';
import { redactAutoText } from '../auto-agent/redaction.mjs';
import {
  redactFindingForPublic,
  redactLocalPathsForPublic,
} from '../modules/finding-redaction.mjs';
import { listVigoliumModules } from '../../bridge/vigolium-catalog.mjs';
import {
  buildVigoliumAuthConfig,
  publicVigoliumAuthConfig,
  saveVigoliumAuthConfig,
} from '../../bridge/vigolium-auth-config.mjs';
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
    if (['kind', 'id', 'tail', 'limit', 'offset'].includes(k)) continue;
    out[k] = v;
  }
  return out;
}

function appendPathPart(base, value) {
  const s = String(value || '').trim();
  if (!s) return base;
  return `${base.replace(/\/+$/, '')}/${encodeURIComponent(s)}`;
}

function intParam(v, fallback, { min = 0, max = 500 } = {}) {
  const n = Number.parseInt(String(v ?? ''), 10);
  if (!Number.isFinite(n)) return fallback;
  return Math.max(min, Math.min(max, n));
}

function vigoliumReportPath(root, file) {
  const name = path.basename(String(file || '').trim());
  if (!name || !/\.html?$/i.test(name)) return null;
  const dir = path.resolve(root, '.runtime', 'vigolium-reports');
  const full = path.resolve(dir, name);
  if (full !== dir && !full.startsWith(`${dir}${path.sep}`)) return null;
  return full;
}

function safeReportName(value, fallback = 'vigolium-report.html') {
  const name = path.basename(String(value || fallback).trim() || fallback)
    .replace(/[\\/:*?"<>|\x00-\x1f]+/g, '-')
    .replace(/^-+|-+$/g, '');
  const withExt = /\.html?$/i.test(name) ? name : `${name}.html`;
  return withExt.slice(0, 120) || fallback;
}

function reportDir(root) {
  return path.resolve(root, '.runtime', 'vigolium-reports');
}

const MAX_REPORT_BYTES = 50 * 1024 * 1024;

async function readSanitizedVigoliumReport(full, { root = null } = {}) {
  const noFollow = typeof fsConstants.O_NOFOLLOW === 'number' ? fsConstants.O_NOFOLLOW : 0;
  const handle = await fs.open(full, fsConstants.O_RDONLY | noFollow);
  try {
    const stat = await handle.stat();
    if (!stat.isFile()) throw new Error('report informado nao e arquivo');
    if (stat.size > MAX_REPORT_BYTES) throw new Error('report maior que 50MB');
    return redactLocalPathsForPublic(
      redactAutoText(await handle.readFile('utf8')),
      { paths: [root, full].filter(Boolean) },
    );
  } finally {
    await handle.close();
  }
}

async function writeSanitizedVigoliumReport(dest, html, { root = null } = {}) {
  const safe = redactLocalPathsForPublic(
    redactAutoText(String(html ?? '')),
    { paths: [root, dest].filter(Boolean) },
  );
  if (Buffer.byteLength(safe, 'utf8') > MAX_REPORT_BYTES) {
    throw new Error('report maior que 50MB');
  }
  await fs.writeFile(dest, safe, {
    encoding: 'utf8',
    mode: 0o600,
    flag: 'wx',
  });
  await fs.chmod(dest, 0o600);
}

async function reportRowForPath(root, full, { origin = 'runtime' } = {}) {
  const dir = reportDir(root);
  const resolved = path.resolve(full);
  if (resolved !== dir && !resolved.startsWith(`${dir}${path.sep}`)) return null;
  const st = await fs.stat(resolved);
  const file = path.basename(resolved);
  return {
    file,
    url: `/api/vigolium/reports/${encodeURIComponent(file)}`,
    size: st.size,
    mtime: st.mtime.toISOString(),
    origin,
  };
}

async function listVigoliumReports(root) {
  const dir = reportDir(root);
  let entries = [];
  try {
    entries = await fs.readdir(dir, { withFileTypes: true });
  } catch {
    return [];
  }
  const rows = [];
  for (const ent of entries) {
    if (!ent.isFile() || !/\.html?$/i.test(ent.name)) continue;
    const full = path.join(dir, ent.name);
    try {
      const st = await fs.stat(full);
      rows.push({
        file: ent.name,
        url: `/api/vigolium/reports/${encodeURIComponent(ent.name)}`,
        size: st.size,
        mtime: st.mtime.toISOString(),
        origin: 'runtime',
      });
    } catch {
      // ignore files removed while listing
    }
  }
  rows.sort((a, b) => String(b.mtime).localeCompare(String(a.mtime)));
  return rows;
}

async function importVigoliumReport(root, body = {}) {
  const dir = reportDir(root);
  await fs.mkdir(dir, { recursive: true });
  const stamp = new Date().toISOString().replace(/[:.]/g, '-');
  const sourcePath = String(body.sourcePath || body.path || body.file || '').trim();
  const html = body.html != null ? String(body.html) : '';
  const requestedName = safeReportName(body.name || sourcePath || 'vigolium-report.html');
  const dest = path.join(dir, `${stamp}-import-${requestedName}`);

  if (sourcePath) {
    const src = path.resolve(root, sourcePath);
    if (!/\.html?$/i.test(src)) throw new Error('report precisa ser .html/.htm');
    await writeSanitizedVigoliumReport(
      dest,
      await readSanitizedVigoliumReport(src, { root }),
      { root },
    );
    return {
      ok: true,
      report: await reportRowForPath(root, dest, { origin: 'imported-local-file' }),
      importedFrom: 'local-file',
    };
  }

  if (!html.trim()) throw new Error('informe sourcePath/path ou html');
  await writeSanitizedVigoliumReport(dest, html, { root });
  return {
    ok: true,
    report: await reportRowForPath(root, dest, { origin: 'imported-inline-html' }),
    importedFrom: 'inline-html',
  };
}

async function proxyAgentMode(req, res, mode) {
  const out = await vigoliumServerFetch(`/api/agent/run/${mode}`, { method: 'POST', body: req.body || {} });
  res.status(out.ok ? 200 : (out.status || 502)).json(publicVigoliumResponse(out));
}

function publicVigoliumResponse(value) {
  return redactFindingForPublic(value) || {
    ok: false,
    error: 'resposta Vigolium invalida',
  };
}

export function registerVigoliumRoutes(app, { ROOT, validateCsrfToken = null }) {
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
      res.json(publicVigoliumResponse(out));
    } catch (e) {
      res.status(500).json(publicVigoliumResponse({
        ok: false,
        error: e?.message || String(e),
      }));
    }
  });

  app.post('/api/vigolium/auth-config', requireScope('recon.run'), async (req, res) => {
    try {
      if (boolParam(req.body?.save)) {
        const saved = await saveVigoliumAuthConfig(req.body || {}, { root: ROOT });
        res.json({
          ok: true,
          file: saved.file,
          origin: 'restricted-runtime-file',
          config: publicVigoliumAuthConfig(saved.config),
        });
      } else {
        res.json({
          ok: true,
          origin: 'preview',
          config: publicVigoliumAuthConfig(buildVigoliumAuthConfig(req.body || {})),
        });
      }
    } catch (e) {
      res.status(400).json(publicVigoliumResponse({
        ok: false,
        error: e?.message || String(e),
      }));
    }
  });

  app.get('/api/vigolium/server/status', async (_req, res) => {
    res.json(publicVigoliumResponse(await getVigoliumServerStatus()));
  });

  app.get('/api/vigolium/reports', requireScope('recon.read'), async (_req, res) => {
    try {
      const reports = await listVigoliumReports(ROOT);
      res.json({ ok: true, reports, total: reports.length });
    } catch (e) {
      res.status(500).json(publicVigoliumResponse({
        ok: false,
        error: e?.message || String(e),
      }));
    }
  });

  app.post('/api/vigolium/reports/import', requireScope('recon.run'), async (req, res) => {
    if (typeof validateCsrfToken === 'function' && !validateCsrfToken(req)) {
      res.status(403).json({ ok: false, error: 'CSRF token inválido/ausente' });
      return;
    }
    try {
      res.json(await importVigoliumReport(ROOT, req.body || {}));
    } catch (e) {
      res.status(400).json(publicVigoliumResponse({
        ok: false,
        error: e?.message || String(e),
      }));
    }
  });

  app.get('/api/vigolium/reports/:file', requireScope('recon.read'), async (req, res) => {
    const reportPath = vigoliumReportPath(ROOT, req.params.file);
    if (!reportPath) {
      res.status(404).type('text/plain').send('report not found');
      return;
    }
    try {
      const report = await readSanitizedVigoliumReport(reportPath, { root: ROOT });
      res.setHeader('Content-Type', 'text/html; charset=utf-8');
      res.setHeader('Content-Disposition', `inline; filename="${path.basename(reportPath).replace(/"/g, '')}"`);
      res.setHeader(
        'Content-Security-Policy',
        "sandbox; default-src 'none'; style-src 'unsafe-inline'; img-src data:",
      );
      res.setHeader('Referrer-Policy', 'no-referrer');
      res.setHeader('X-Content-Type-Options', 'nosniff');
      res.send(report);
    } catch {
      res.status(404).type('text/plain').send('report not found');
    }
  });

  app.get('/api/vigolium/server/:kind', requireScope('recon.read'), async (req, res) => {
    const endpoint = serverEndpointFor(req.params.kind);
    if (!endpoint) {
      res.status(404).json({ ok: false, error: `endpoint Vigolium desconhecido: ${req.params.kind}` });
      return;
    }
    const out = await vigoliumServerFetch(endpoint, { query: forwardQuery(req) });
    res.status(out.ok ? 200 : (out.status || 502)).json(publicVigoliumResponse(out));
  });

  app.get('/api/vigolium/server/:kind/:id', requireScope('recon.read'), async (req, res) => {
    const endpoint = serverEndpointFor(req.params.kind);
    if (!endpoint) {
      res.status(404).json({ ok: false, error: `endpoint Vigolium desconhecido: ${req.params.kind}` });
      return;
    }
    const out = await vigoliumServerFetch(appendPathPart(endpoint, req.params.id), { query: forwardQuery(req) });
    res.status(out.ok ? 200 : (out.status || 502)).json(publicVigoliumResponse(out));
  });

  app.get('/api/vigolium/server/:kind/:id/:tail', requireScope('recon.read'), async (req, res) => {
    const endpoint = serverEndpointFor(req.params.kind);
    const tail = String(req.params.tail || '').trim();
    if (!endpoint || !['logs'].includes(tail)) {
      res.status(404).json({ ok: false, error: `endpoint Vigolium desconhecido: ${req.params.kind}/${tail}` });
      return;
    }
    const out = await vigoliumServerFetch(appendPathPart(appendPathPart(endpoint, req.params.id), tail), {
      query: forwardQuery(req),
    });
    res.status(out.ok ? 200 : (out.status || 502)).json(publicVigoliumResponse(out));
  });

  app.post('/api/vigolium/server/scan-url', requireScope('recon.intrusive'), async (req, res) => {
    const out = await vigoliumServerFetch('/api/scan-url', { method: 'POST', body: req.body || {} });
    res.status(out.ok ? 200 : (out.status || 502)).json(publicVigoliumResponse(out));
  });

  app.post('/api/vigolium/server/scan-request', requireScope('recon.intrusive'), async (req, res) => {
    const out = await vigoliumServerFetch('/api/scan-request', { method: 'POST', body: req.body || {} });
    res.status(out.ok ? 200 : (out.status || 502)).json(publicVigoliumResponse(out));
  });

  app.post('/api/vigolium/server/scans-run', requireScope('recon.intrusive'), async (req, res) => {
    const out = await vigoliumServerFetch('/api/scans/run', { method: 'POST', body: req.body || {} });
    res.status(out.ok ? 200 : (out.status || 502)).json(publicVigoliumResponse(out));
  });

  app.post('/api/vigolium/ingest-http', requireScope('recon.run'), async (req, res) => {
    const out = await vigoliumServerFetch('/api/ingest-http', { method: 'POST', body: req.body || {} });
    res.status(out.ok ? 200 : (out.status || 502)).json(publicVigoliumResponse(out));
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
