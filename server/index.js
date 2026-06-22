import './load-env.js';
import express from 'express';
import path from 'path';
import { fileURLToPath } from 'url';
import { createCsrfProtection } from './middleware/csrf.mjs';
import { createReconRateLimiter } from './middleware/rate-limit.mjs';
import { createHttpHistoryStore, reconHttpContext } from './lib/http-history.mjs';
import { installOutboundFetch } from './lib/outbound-fetch.mjs';
import { createProxyCapture, PROXY_DEFAULT_PORT } from './modules/proxy-capture.mjs';
import { createSocksDispatcher } from './modules/socks5-dispatcher.js';
import { initAuth, requireAuth } from './modules/auth.js';
import {
  isStrict as torIsStrict,
  initTorStrict,
  strictPrereqs as torStrictPrereqs,
} from './modules/tor-strict.js';
import { registerAllRoutes } from './app/register-routes.mjs';
import { runPipeline } from './pipeline/run-pipeline.mjs';
import { reconRateLimitConfig } from './config.js';

const httpHistory = createHttpHistoryStore();
const {
  entries: reconHttpHistory,
  normalizeHeadersForHistory,
  redactBodyTextForHistory,
  recordReconHttpHistory,
} = httpHistory;

const { CSRF_TTL_MS, issueCsrfToken, validateCsrfToken, requireCsrf } = createCsrfProtection();
const allowReconRequest = createReconRateLimiter(() => reconRateLimitConfig());

const PORT = Number(process.env.PORT) || 3847;
const HOST = String(process.env.HOST || '127.0.0.1').trim();
const allowedOrigins = new Set([`http://127.0.0.1:${PORT}`, `http://localhost:${PORT}`]);

const PROXY_PORT = Number(process.env.GHOSTRECON_PROXY_CAPTURE_PORT || PROXY_DEFAULT_PORT);
const ghostProxy = createProxyCapture({
  port: PROXY_PORT,
  mitmEnabled: String(process.env.GHOSTRECON_PROXY_MITM || '1').trim() !== '0',
  onCapture: (entry) => {
    recordReconHttpHistory({
      ...entry,
      ts: entry.ts || new Date().toISOString(),
      requestHeaders: normalizeHeadersForHistory(entry.requestHeaders),
      requestBody: entry.requestBody || '',
      responseHeaders: normalizeHeadersForHistory(entry.responseHeaders),
      responseBody: entry.responseBody || '',
      requestRunId: null,
      target: null,
      ok: entry.status ? entry.status < 400 : null,
    });
  },
});

installOutboundFetch({
  history: httpHistory,
  torIsStrict,
  createSocksDispatcher,
});

function isLocalHostBind(host) {
  const h = String(host || '').trim().toLowerCase();
  return h === '127.0.0.1' || h === 'localhost' || h === '::1';
}

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const ROOT = path.join(__dirname, '..');

const app = express();

app.use((req, res, next) => {
  const origin = String(req.headers.origin || '').trim();
  const hasOrigin = Boolean(origin);
  const originAllowed = hasOrigin ? origin === 'null' || allowedOrigins.has(origin) : true;

  if (hasOrigin && originAllowed) {
    res.setHeader('Access-Control-Allow-Origin', origin === 'null' ? '*' : origin);
    res.setHeader('Vary', 'Origin');
  }
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, X-CSRF-Token, X-Engagement-Id');
  if (req.method === 'OPTIONS') {
    if (!originAllowed) {
      res.sendStatus(403);
      return;
    }
    res.sendStatus(204);
    return;
  }
  if (!originAllowed) {
    res.status(403).json({ error: 'origin não permitido' });
    return;
  }
  next();
});

// ── Tor STRICT: inicializa primeiro para que o DNS lockdown e a config de
//    proxychains estejam activos antes de qualquer chamada outbound do server.
if (torIsStrict()) {
  initTorStrict();
  const p = torStrictPrereqs();
  if (!p.ok) {
    console.error('[tor-strict] prereqs em falta — runs intrusivos serão recusados:', p.missing);
  }
}

// ── Auth (P0): inicializa antes de qualquer parser/route, plugamos requireAuth
//    a seguir ao CORS para que rotas privilegiadas exijam Bearer/X-API-Key.
//    Allowlist: rotas read-only sem segredo + estáticos + health + csrf-token
//    (issuer do CSRF não exige auth — CSRF é defesa-em-profundidade contra
//    cross-site, não substitui a autenticação que vem a seguir).
initAuth();
const AUTH_ALLOWLIST = [
  /^\/api\/health$/,
  /^\/api\/csrf-token$/,
  /^\/api\/capabilities$/,  // público para UI buscar capacidades
  /^\/api\/setup\/auto-auth$/, // loopback-only: UI busca chave automaticamente no 1º acesso
  // /api/inbound/* tem auth própria (HMAC + Bearer-secret por source)
  /^\/api\/inbound\//,
  /^\/$/,
  /^\/index\.html$/,
  /^\/(?:favicon\.ico|robots\.txt)$/,
  /^\/(?:assets|public|static)\//,
  /^\/mitre-attack\//,
  /^\/[^\/]+\.(?:html|css|js|map|svg|png|jpg|jpeg|gif|webp|ico|woff2?|ttf)$/,
  /^\/anotacao(?:\/|$)/, // GhostTrace (UI de anotações via proxy)
  /^\/ghostmap(?:\/|$)/, // GhostMap (HTTP History + grafo via proxy)
];
app.use(requireAuth({ allowlist: AUTH_ALLOWLIST }));

app.use(express.json({ limit: '5mb' }));

registerAllRoutes(app, {
  runPipeline,
  ROOT,
  ghostProxy,
  httpHistory,
  issueCsrfToken,
  validateCsrfToken,
  requireCsrf,
  CSRF_TTL_MS,
  allowReconRequest,
  reconHttpHistory,
});


const NO_HTTP_LISTEN =
  String(process.env.GHOSTRECON_NO_HTTP_LISTEN || '').trim() === '1' ||
  /^true$/i.test(String(process.env.GHOSTRECON_NO_HTTP_LISTEN || ''));

if (!NO_HTTP_LISTEN) {
  const server = app.listen(PORT, HOST, () => {
    console.log(`GHOSTRECON → http://${HOST}:${PORT}`);
    if (!isLocalHostBind(HOST)) {
      console.warn(
        `[auth] Aviso: HOST=${HOST} (bind não-local). O perfil recomendado do GHOSTRECON é localhost-first; reveja AUTH_MODE/AUTH_DISABLE antes de expor a API.`,
      );
    }
  });
  server.on('error', (err) => {
    if (err.code === 'EADDRINUSE') {
      console.error(
        `[GHOSTRECON] Porta ${PORT} em uso. Encerre a instância anterior (ex.: netstat -ano | findstr :${PORT}) ou defina PORT=3850 antes de npm start.`,
      );
    } else {
      console.error('[GHOSTRECON]', err.message);
    }
    process.exit(1);
  });
}

export { runPipeline, reconHttpContext, app };
