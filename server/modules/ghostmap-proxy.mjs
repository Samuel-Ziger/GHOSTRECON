/**
 * Proxy HTTP para a UI GhostMap (Next.js) em /ghostmap.
 * Ative com GHOSTMAP_PROXY=1 e suba o frontend na porta GHOSTMAP_PORT (3020).
 */
import http from 'http';

const DEFAULT_PORT = 3020;
const PREFIX = '/ghostmap';

export function ghostmapProxyMiddleware(opts = {}) {
  const port = Number(opts.port ?? process.env.GHOSTMAP_PORT ?? DEFAULT_PORT);
  const host = String(opts.host ?? process.env.GHOSTMAP_HOST ?? '127.0.0.1');
  const prefix = String(opts.prefix ?? PREFIX);
  const enabled =
    opts.enabled ?? (String(process.env.GHOSTMAP_PROXY || '1').trim() !== '0');

  return (req, res, next) => {
    if (!enabled) return next();
    const p = req.path || req.url?.split('?')[0] || '';
    if (p !== prefix && !p.startsWith(`${prefix}/`)) return next();

    const stripPrefix = String(process.env.GHOSTMAP_STRIP_PREFIX || '0').trim() === '1';
    const targetPath = stripPrefix
      ? p === prefix
        ? '/'
        : p.slice(prefix.length) || '/'
      : p || '/';
    const qs = req.url?.includes('?') ? req.url.slice(req.url.indexOf('?')) : '';

    const headers = { ...req.headers, host: `${host}:${port}` };
    delete headers.connection;

    const proxyReq = http.request(
      {
        hostname: host,
        port,
        method: req.method,
        path: targetPath + qs,
        headers
      },
      (proxyRes) => {
        res.status(proxyRes.statusCode || 502);
        for (const [k, v] of Object.entries(proxyRes.headers)) {
          if (v != null && k.toLowerCase() !== 'transfer-encoding') res.setHeader(k, v);
        }
        proxyRes.pipe(res);
      }
    );

    proxyReq.on('error', () => {
      if (!res.headersSent) {
        res.status(503).type('html').send(
          `<!DOCTYPE html><html lang="pt"><head><meta charset="utf-8"><title>GHOSTRECON · GhostMap</title></head><body style="font-family:system-ui;background:#080c10;color:#c4d4da;padding:2rem"><h1>GhostMap offline</h1><p>Inicia a UI: <code>npm run start:ghostmap</code> (porta ${port}).</p></body></html>`
        );
      }
    });

    req.pipe(proxyReq);
  };
}
