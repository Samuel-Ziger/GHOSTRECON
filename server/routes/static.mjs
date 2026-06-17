import path from 'node:path';
import express from 'express';
import { ghosttraceProxyMiddleware } from '../modules/ghosttrace-proxy.mjs';
import { ghostmapProxyMiddleware } from '../modules/ghostmap-proxy.mjs';

export function registerStaticRoutes(app, { ROOT }) {
  app.use(ghosttraceProxyMiddleware());
  app.use(ghostmapProxyMiddleware());
  app.use(express.static(ROOT, { index: false }));
  app.get('/', (_req, res) => {
    res.sendFile(path.join(ROOT, 'index.html'));
  });
}
