import { listProjectSecretDuplicates, sanitizePathSegment } from '../modules/db.js';

export function registerMiscRoutes(app) {
  app.get('/api/health', (_req, res) => {
    res.json({ ok: true, service: 'ghostrecon' });
  });

  app.get('/api/searchsploit', async (req, res) => {
    const query = String(req.query.q || '').trim().replace(/[;&|`$(){}[\]<>\\]/g, '');
    if (!query || query.length < 2) return res.status(400).json({ error: 'query too short' });
    const { execFile } = await import('child_process');
    const { promisify } = await import('util');
    const execFileAsync = promisify(execFile);
    try {
      const args = ['--json', ...query.split(/\s+/).filter(Boolean)];
      const { stdout } = await execFileAsync('searchsploit', args, { timeout: 12000, maxBuffer: 1024 * 512 });
      res.setHeader('Content-Type', 'application/json');
      res.send(stdout);
    } catch (err) {
      if (err.code === 'ENOENT') return res.status(503).json({ error: 'searchsploit not found — install exploitdb' });
      res.status(500).json({ error: String(err.message || err) });
    }
  });

  app.get('/api/project-secret-peers', (req, res) => {
    const project = String(req.query.project || '').trim();
    if (!project) {
      res.status(400).json({ ok: false, error: 'Query ?project= é obrigatório (nome do projeto na UI).' });
      return;
    }
    try {
      const duplicates = listProjectSecretDuplicates(project);
      res.json({ ok: true, project: sanitizePathSegment(project), duplicates });
    } catch (e) {
      res.status(500).json({ ok: false, error: e?.message || String(e) });
    }
  });
}
