/**
 * Proxy HTTP para a UI GhostMap (Next.js) em /ghostmap.
 * Ative com GHOSTMAP_PROXY=1 e suba o frontend na porta GHOSTMAP_PORT (3020).
 */
import { createNextProxyMiddleware } from '../lib/create-next-proxy.mjs';

const build = createNextProxyMiddleware({
  prefix: '/ghostmap',
  defaultPort: 3020,
  envEnabledKey: 'GHOSTMAP_PROXY',
  envPortKey: 'GHOSTMAP_PORT',
  envHostKey: 'GHOSTMAP_HOST',
  envStripPrefixKey: 'GHOSTMAP_STRIP_PREFIX',
  offlineTitle: 'GHOSTRECON · GhostMap',
  offlineBodyHtml:
    '<h1>GhostMap offline</h1><p>Inicia a UI: <code>npm run start:ghostmap</code> (porta 3020).</p>',
});

export function ghostmapProxyMiddleware(opts = {}) {
  return build(opts);
}
