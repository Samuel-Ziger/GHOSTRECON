import http from 'node:http';

/**
 * Factory para proxy HTTP de apps Next.js (GhostTrace, GhostMap, etc.).
 */
export function createNextProxyMiddleware({
  prefix,
  defaultPort,
  envEnabledKey,
  envPortKey,
  envHostKey = null,
  envStripPrefixKey,
  offlineTitle,
  offlineBodyHtml,
  enabled: enabledOverride,
  port: portOverride,
  host: hostOverride = '127.0.0.1',
}) {
  const normalizedPrefix = String(prefix || '').replace(/\/$/, '') || '/';

  return function nextProxyMiddleware(opts = {}) {
    const port = Number(
      opts.port ?? (envPortKey ? process.env[envPortKey] : undefined) ?? portOverride ?? defaultPort,
    );
    const host = String(opts.host ?? (envHostKey ? process.env[envHostKey] : undefined) ?? hostOverride);
    const enabled =
      opts.enabled ??
      (envEnabledKey ? String(process.env[envEnabledKey] || '1').trim() !== '0' : true);

    return (req, res, next) => {
      if (!enabled) return next();
      const p = req.path || req.url?.split('?')[0] || '';
      if (p !== normalizedPrefix && !p.startsWith(`${normalizedPrefix}/`)) return next();

      const stripEnv = envStripPrefixKey ? process.env[envStripPrefixKey] : '0';
      const stripPrefix = String(opts.stripPrefix ?? stripEnv).trim() === '1';
      const targetPath = stripPrefix
        ? p === normalizedPrefix
          ? '/'
          : p.slice(normalizedPrefix.length) || '/'
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
          headers,
        },
        (proxyRes) => {
          res.status(proxyRes.statusCode || 502);
          for (const [k, v] of Object.entries(proxyRes.headers)) {
            if (v != null && k.toLowerCase() !== 'transfer-encoding') res.setHeader(k, v);
          }
          proxyRes.pipe(res);
        },
      );

      proxyReq.on('error', () => {
        if (!res.headersSent) {
          res.status(503).type('html').send(
            `<!DOCTYPE html><html lang="pt"><head><meta charset="utf-8"><title>${offlineTitle}</title></head><body style="font-family:system-ui;background:#07090d;color:#c8d8e4;padding:2rem">${offlineBodyHtml}</body></html>`,
          );
        }
      });

      req.pipe(proxyReq);
    };
  };
}
