/**
 * Proxy HTTP para a UI GhostTrace (Next.js) em /anotacao.
 * Ative com GHOSTTRACE_PROXY=1 e suba GhostTrace na porta GHOSTTRACE_PORT (3010).
 */
import { createNextProxyMiddleware } from '../lib/create-next-proxy.mjs';

const build = createNextProxyMiddleware({
  prefix: '/anotacao',
  defaultPort: 3010,
  envEnabledKey: 'GHOSTTRACE_PROXY',
  envPortKey: 'GHOSTTRACE_PORT',
  envHostKey: 'GHOSTTRACE_HOST',
  envStripPrefixKey: 'GHOSTTRACE_STRIP_PREFIX',
  offlineTitle: 'GHOSTRECON · Anotações',
  offlineBodyHtml:
    '<h1>GhostTrace offline</h1><p>Inicia a UI de anotações: <code>npm run start:anotacao</code> (porta 3010).</p><p>Ou define <code>GHOSTTRACE_PROXY=0</code> e abre <code>GhostTrace</code> em modo dev na porta 3000.</p>',
});

export function ghosttraceProxyMiddleware(opts = {}) {
  return build(opts);
}
