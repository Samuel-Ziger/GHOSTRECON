import path from 'node:path';
import express from 'express';
import { ghosttraceProxyMiddleware } from '../modules/ghosttrace-proxy.mjs';
import { ghostmapProxyMiddleware } from '../modules/ghostmap-proxy.mjs';

export function registerStaticRoutes(app, { ROOT }) {
  const PUBLIC = path.join(ROOT, 'public');

  app.use(ghosttraceProxyMiddleware());
  app.use(ghostmapProxyMiddleware());
  app.use('/mitre-attack', express.static(path.join(ROOT, 'mitre-attack')));
  app.use(express.static(PUBLIC, { index: false }));

  app.get('/anotacao.html', (_req, res) => {
    res.sendFile(path.join(PUBLIC, 'legacy/anotacao.html'));
  });
  app.get('/history.html', (_req, res) => {
    res.sendFile(path.join(PUBLIC, 'legacy/history.html'));
  });
  app.get('/brain.html', (_req, res) => {
    res.redirect(301, '/cortex.html');
  });
  app.get('/', (_req, res) => {
    res.sendFile(path.join(PUBLIC, 'index.html'));
  });
}
