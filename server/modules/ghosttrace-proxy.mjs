/**
 * Proxy HTTP para a UI GhostTrace (Next.js) em /anotacao.
 * Ative com GHOSTTRACE_PROXY=1 e suba GhostTrace na porta GHOSTTRACE_PORT (3010).
 */
import http from 'http';

const DEFAULT_PORT = 3010;
const PREFIX = '/anotacao';

export function ghosttraceProxyMiddleware(opts = {}) {
  const port = Number(opts.port ?? process.env.GHOSTTRACE_PORT ?? DEFAULT_PORT);
  const host = String(opts.host ?? process.env.GHOSTTRACE_HOST ?? '127.0.0.1');
  const prefix = String(opts.prefix ?? PREFIX);
  const enabled =
    opts.enabled ??
    (String(process.env.GHOSTTRACE_PROXY || '1').trim() !== '0');

  return (req, res, next) => {
    if (!enabled) return next();
    const p = req.path || req.url?.split('?')[0] || '';
    if (p !== prefix && !p.startsWith(`${prefix}/`)) return next();

    // Next.js com NEXT_PUBLIC_BASE_PATH=/anotacao espera o path completo (incl. /anotacao).
    const stripPrefix = String(process.env.GHOSTTRACE_STRIP_PREFIX || '0').trim() === '1';
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
          `<!DOCTYPE html><html lang="pt"><head><meta charset="utf-8"><title>GHOSTRECON · Anotações</title></head><body style="font-family:system-ui;background:#07090d;color:#c8d8e4;padding:2rem"><h1>GhostTrace offline</h1><p>Inicia a UI de anotações: <code>npm run start:anotacao</code> (porta ${port}).</p><p>Ou define <code>GHOSTTRACE_PROXY=0</code> e abre <code>GhostTrace</code> em modo dev na porta 3000.</p></body></html>`
        );
      }
    });

    req.pipe(proxyReq);
  };
}
