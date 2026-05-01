import './load-env.js';
import express from 'express';
import path from 'path';
import fs from 'fs';
import { fileURLToPath } from 'url';
import { randomBytes } from 'crypto';
import { AsyncLocalStorage } from 'async_hooks';
import { fetchCrtShSubdomains } from './modules/subdomains.js';
import { resolves } from './modules/dns.js';
import { probeHttp, mapPool } from './modules/probe.js';
import { extractSuspiciousHtmlComments } from './modules/html-surface.js';
import { analyzeSecurityHeaders } from './modules/security-headers.js';
import { analyzeSuspiciousResponseHeaders } from './modules/header-intel.js';
import { peekTlsCertificate } from './modules/tls-cert.js';
import { crawlRobotsAndSitemapsForOrigin } from './modules/robots-sitemap.js';
import {
  parseOutOfScopeEnv,
  hostInReconScope,
  urlInReconScope,
  parseOutOfScopeClientInput,
  mergeOutOfScopeLists,
} from './modules/scope.js';
import { fetchCommonCrawlUrls } from './modules/commoncrawl.js';
import { fetchRdapSummary } from './modules/rdap.js';
import { fetchVirustotalSubdomains } from './modules/virustotal.js';
import { compareRuns } from './modules/db-compare.js';
import { postReconWebhook, postAiReportWebhook, postReconDeltaFullWebhook } from './modules/webhook-notify.js';
import { fetchWaybackUrls, filterInterestingUrls, extractJsUrls } from './modules/wayback.js';
import { extractParamsFromUrls } from './modules/params.js';
import { analyzeJsUrl } from './modules/js-analyzer.js';
import { scanSecrets } from './modules/secrets.js';
import { githubCodeSearch, githubRepoSearch } from './modules/github.js';
import { cloneGithubReposForTarget, githubCloneConfig } from './modules/github-clone.js';
import { parseGithubManualRepoList } from './modules/github-manual-repos.js';
import { buildDorks } from './modules/dorks.js';
import { scoreEndpointPath, scoreParamName } from './modules/scoring.js';
import { correlate } from './modules/correlation.js';
import { suggestVectors, buildExploitChecklist } from './modules/intelligence.js';
import { applyPrioritizationV2, topHighProbability } from './modules/prioritization.js';
import { extractCveHintsFromTechStrings } from './modules/cve-hints.js';
import { fetchDnsEnrichment } from './modules/dns-enrichment.js';
import { fetchWellKnownSecurityTxt, fetchWellKnownOpenIdConfiguration } from './modules/wellknown.js';
import { runEvidenceVerification, runMicroExploitVariants } from './modules/verify.js';
import { runWebshellHeuristicProbe } from './modules/webshell-probe.js';
import { buildMysqlConfigSurfaceCorrelationFindings } from './modules/mysql-config-correlation.js';
import { runSqlmapModule } from './modules/sqlmap-runner.js';
import { harvestOpenApiFromOrigins, tryGraphqlMinimalProbe } from './modules/openapi-harvest.js';
import { dedupeBySemanticFamily } from './modules/semantic-dedupe.js';
import { buildReportTemplates } from './modules/report-template.js';
import { discoverAssetHints, detectTakeoverCandidates } from './modules/asset-discovery.js';
import { resolveReconProfile } from './modules/runtime-profile.js';
import { fetchArchiveToolUrls } from './modules/archive-tools.js';
import { wafw00fFingerprint } from './modules/waf-fingerprint.js';
import { discoverParamsActive } from './modules/param-discovery.js';
import { resolveCnameChain, matchProviderByCname, matchProviderBody } from './modules/takeover.js';
import { crawlWithKatana } from './modules/js-crawler.js';
import { validateSecretFindings } from './modules/secret-validation.js';
import { captureTokenFinding } from './modules/token-capture.js';
import { limits, reconRateLimitConfig } from './config.js';
import {
  saveRun,
  listRuns,
  getRunById,
  listIntelForTarget,
  intelCountForTarget,
  listManualValidationsForTarget,
  upsertManualValidation,
  deleteManualValidation,
  listBrainCategories,
  createBrainCategory,
  updateBrainCategoryDescription,
  upsertBrainLink,
  getBrainCategoryById,
  listBrainLinksForCategory,
  storageLabel,
  fingerprintFinding,
  listProjectSecretDuplicates,
  sanitizePathSegment,
} from './modules/db.js';
import { collectUniqueIpv4, shodanHostSummary } from './modules/ip-intel.js';
import { googleCseSearch } from './modules/google-cse.js';
import { getKaliCapabilities, runKaliAggressiveScan } from './modules/kali-scan.js';
import {
  augmentProcessPathFromCommonDirs,
  prependExtraPathToEnvPath,
  parseExtraPathInput,
} from './modules/tool-path.js';
import {
  runDualAiReports,
  callOpenRouter,
  aiKeysConfigured,
  pickAiReportForWebhook,
  probeLmStudioConnection,
  normalizeOpenrouterOnlyFlag,
} from './modules/ai-dual-report.js';
import {
  getShannonCapabilities,
  shannonPullUpstreamWorkerImage,
} from './modules/shannon-capabilities.js';
import { runShannonOnClone, shannonMaxClonesPerRun } from './modules/shannon-runner.js';
import { runPentestGptValidation, pentestGptHealthUrl, resolvePentestGptUrl } from './modules/pentestgpt-local.js';
import { getPentestGptCapabilities } from './modules/pentestgpt-capabilities.js';
import { enumerateSubdomainsWithSubfinder, enumerateSubdomainsWithAmass } from './modules/kali-subdomain-tools.js';
import { withProvenance } from './modules/finding-provenance.js';
import { serializeFindingsForRunSnapshot } from './modules/finding-serialize.js';
import { buildReconCoverageSnapshot } from './modules/recon-coverage.js';
import { runHighPrioHttpRecheck } from './modules/recheck-high.js';
import { runOptionalPlaywrightXssProbe } from './modules/browser-xss-verify.js';
import { applyOwaspTagsToFindings, inferOwaspTags } from './modules/owasp-top10.js';
import { applyMitreTagsToFindings, inferMitreTechniqueIds } from './modules/mitre-recon.js';
import { parseReconTarget, hostLiteralForUrl, targetIsIp } from './modules/recon-target.js';
import { secretMaterialFingerprint } from './modules/db-common.js';
import { syncValidatedCortexFindingToGhostKb } from './modules/ghost-kb-sync.js';
import { registerInboundWebhooks } from './modules/inbound-webhooks.js';
import { registerNewApiRoutes } from './modules/api-extensions.js';
import { getEngagement, preRunChecklist, attachRunToEngagement } from './modules/engagement.mjs';
import { gateModules, applyWatermarkHeaders } from './modules/opsec.mjs';
import { createIdentityController, normalizeIdentityOptions } from './modules/identity-controller.mjs';
import { createSocksDispatcher } from './modules/socks5-dispatcher.js';
import { recordAction } from './modules/team-concurrency.mjs';
import { buildAuthzPlan, runAuthzMatrix, fingerprintBody } from './modules/authz-matrix.mjs';
import { summarizeValue, prioritize as prioritizeBounty } from './modules/bounty-estimator.mjs';
import { applyScopeFilter, dedupeFindings as dedupeBountyFindings } from './modules/bounty-scope.mjs';
import { applyChains } from './modules/chaining.mjs';
import { bruteforceCloud } from './modules/cloud-bruteforce.mjs';
import { monitorCt, classifyNewSubs } from './modules/ct-monitor.mjs';
import { buildVerificationPlan } from './modules/dom-xss-verify.mjs';
import { probeGraphqlEndpoint } from './modules/graphql-recon.mjs';
import { jsBundleToFindings } from './modules/js-intel.mjs';
import { analyzeJwt } from './modules/jwt-lab.mjs';
import { buildOobPayloads } from './modules/oob-collaborator.mjs';
import { detectOriginCandidates, originDiscoveryToFindings, resolveSubsForOrigin } from './modules/origin-discovery.mjs';
import { mutatePayload } from './modules/payload-mutator.mjs';
import { buildRacePlan } from './modules/race-harness.mjs';
import { planSpray } from './modules/cred-spray.mjs';
import { fingerprintLovable } from './modules/lovable-fingerprint.js';
import { runSupabaseAudit } from './modules/supabase-audit.mjs';
import { createProxyCapture, PROXY_DEFAULT_PORT, PROXY_CA_CERT_PATH } from './modules/proxy-capture.mjs';
import { runCurlProbeModule } from './modules/curl-probe.mjs';
import {
  loadNavegationPlaybook,
  quickValidateTor,
  executeNavegationPlaybook,
  getNavegationTunnelStatus,
  validateNavegationTorPath,
} from './modules/navegation.js';
import {
  initAuth,
  requireAuth,
  requireScope,
  requireRole,
  reconBodyIsIntrusive,
  audit as auditAuth,
} from './modules/auth.js';
import { newnym as torNewnym, torHealth as torControlHealth } from './modules/tor-control.js';
import {
  isStrict as torIsStrict,
  initTorStrict,
  beginTorStrictScope,
  strictPrereqs as torStrictPrereqs,
  refuseToRun as torRefuseToRun,
  snapshotTelemetry as torSnapshotTelemetry,
} from './modules/tor-strict.js';

function firstIpv4FromDnsRecords(records) {
  for (const r of records || []) {
    const m = String(r).match(/^A:([\d.]+)$/);
    if (m) return m[1];
  }
  return '';
}

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const sevToPrio = (sev) => {
  const s = String(sev || '').toLowerCase();
  if (s === 'critical' || s === 'high') return 'high';
  if (s === 'medium') return 'med';
  return 'low';
};
const sevToScore = (sev) => {
  const s = String(sev || '').toLowerCase();
  if (s === 'critical') return 95;
  if (s === 'high') return 86;
  if (s === 'medium') return 68;
  return 42;
};

const reconRlHits = new Map();
const csrfTokens = new Map();
const CSRF_TTL_MS = 2 * 60 * 60 * 1000;
const reconHttpHistory = [];
const reconHttpContext = new AsyncLocalStorage();
let reconHttpSeq = 0;
const RECON_HTTP_HISTORY_MAX = Number(process.env.GHOSTRECON_HTTP_HISTORY_MAX || 1200);
const RECON_HTTP_RESPONSE_PREVIEW_MAX = Number(process.env.GHOSTRECON_HTTP_HISTORY_RESPONSE_MAX || 120000);

const PORT = Number(process.env.PORT) || 3847;
const HOST = String(process.env.HOST || '127.0.0.1').trim();
const allowedOrigins = new Set([`http://127.0.0.1:${PORT}`, `http://localhost:${PORT}`]);

const PROXY_PORT = Number(process.env.GHOSTRECON_PROXY_CAPTURE_PORT || PROXY_DEFAULT_PORT);
const ghostProxy = createProxyCapture({
  port: PROXY_PORT,
  mitmEnabled: String(process.env.GHOSTRECON_PROXY_MITM || '1').trim() !== '0',
  onCapture: (entry) => {
    const row = {
      ...entry,
      id: ++reconHttpSeq,
      ts: entry.ts || new Date().toISOString(),
      requestRunId: null,
      target: null,
      ok: entry.status ? entry.status < 400 : null,
    };
    reconHttpHistory.push(row);
    while (reconHttpHistory.length > RECON_HTTP_HISTORY_MAX) reconHttpHistory.shift();
  },
});

function isLocalHostBind(host) {
  const h = String(host || '').trim().toLowerCase();
  return h === '127.0.0.1' || h === 'localhost' || h === '::1';
}

function clientIp(req) {
  return String(
    req.headers['x-forwarded-for']?.split(',')[0]?.trim() || req.socket?.remoteAddress || '_',
  );
}

function cleanupExpiredCsrfTokens(now = Date.now()) {
  for (const [token, entry] of csrfTokens.entries()) {
    if (!entry?.expiresAt || entry.expiresAt <= now) csrfTokens.delete(token);
  }
}

function issueCsrfToken(req) {
  cleanupExpiredCsrfTokens();
  const token = randomBytes(24).toString('hex');
  csrfTokens.set(token, { ip: clientIp(req), expiresAt: Date.now() + CSRF_TTL_MS });
  return token;
}

function validateCsrfToken(req) {
  cleanupExpiredCsrfTokens();
  const token = String(req.headers['x-csrf-token'] || '').trim();
  if (!token) return false;
  const entry = csrfTokens.get(token);
  if (!entry) return false;
  if (entry.ip !== clientIp(req)) return false;
  if (entry.expiresAt <= Date.now()) {
    csrfTokens.delete(token);
    return false;
  }
  return true;
}

function redactHttpHeader(name, value) {
  const n = String(name || '').toLowerCase();
  if (/authorization|cookie|x-api-key|token|secret|password|key/.test(n)) return '[redacted]';
  return String(value ?? '').slice(0, 800);
}

function normalizeHeadersForHistory(headers) {
  const out = {};
  try {
    if (!headers) return out;
    if (typeof headers.forEach === 'function') {
      headers.forEach((v, k) => {
        out[String(k).toLowerCase()] = redactHttpHeader(k, v);
      });
      return out;
    }
    for (const [k, v] of Object.entries(headers)) out[String(k).toLowerCase()] = redactHttpHeader(k, v);
  } catch {
    /* best effort */
  }
  return out;
}

function bodyPreviewForHistory(body) {
  if (body == null) return '';
  if (typeof body === 'string') return body.slice(0, 8000);
  if (body instanceof URLSearchParams) return body.toString().slice(0, 8000);
  if (Buffer.isBuffer(body)) return body.toString('utf8', 0, Math.min(body.length, 8000));
  if (body instanceof ArrayBuffer) return Buffer.from(body).toString('utf8', 0, 8000);
  if (ArrayBuffer.isView(body)) {
    const b = Buffer.from(body.buffer, body.byteOffset, body.byteLength);
    return b.toString('utf8', 0, Math.min(b.length, 8000));
  }
  return `[${Object.prototype.toString.call(body).replace(/^\[object |\]$/g, '')}]`;
}

function safeJsonBodyForHistory(obj) {
  const seen = new WeakSet();
  const scrub = (v, key = '') => {
    if (/authorization|cookie|token|secret|password|api.?key/i.test(key)) return '[redacted]';
    if (v == null || typeof v !== 'object') return v;
    if (seen.has(v)) return '[circular]';
    seen.add(v);
    if (Array.isArray(v)) return v.map((x) => scrub(x));
    const out = {};
    for (const [k, val] of Object.entries(v)) out[k] = scrub(val, k);
    return out;
  };
  try {
    return JSON.stringify(scrub(obj), null, 2).slice(0, 8000);
  } catch {
    return '';
  }
}

function recordReconHttpHistory(entry) {
  const row = {
    id: ++reconHttpSeq,
    ts: new Date().toISOString(),
    requestRunId: entry.requestRunId || null,
    target: entry.target || null,
    source: entry.source || 'fetch',
    method: String(entry.method || 'GET').toUpperCase(),
    url: String(entry.url || '').slice(0, 2000),
    requestHeaders: entry.requestHeaders || {},
    requestBody: entry.requestBody || '',
    status: entry.status ?? null,
    statusText: entry.statusText || '',
    ok: entry.ok ?? null,
    durationMs: entry.durationMs ?? null,
    error: entry.error || '',
    responseHeaders: entry.responseHeaders || {},
    responseBody: entry.responseBody || '',
    mimeType: entry.mimeType || '',
    responseSize: entry.responseSize ?? null,
  };
  reconHttpHistory.push(row);
  while (reconHttpHistory.length > RECON_HTTP_HISTORY_MAX) reconHttpHistory.shift();
  try {
    if (typeof entry.emit === 'function') entry.emit({ type: 'http_history', entry: row });
  } catch {
    /* ignore stream write races */
  }
  return row;
}

const originalFetch = globalThis.fetch ? globalThis.fetch.bind(globalThis) : null;
const strictFetchDispatchers = new Map();

function firstProxyPoolEntry() {
  return String(process.env.GHOSTRECON_PROXY_POOL || '')
    .split(/[,;\n]/)
    .map((s) => s.trim())
    .filter(Boolean)[0] || 'socks5h://127.0.0.1:9050';
}

function isLoopbackFetchTarget(input) {
  try {
    const raw = typeof input === 'string' ? input : String(input?.url || input || '');
    const u = new URL(raw);
    return u.hostname === '127.0.0.1' || u.hostname === 'localhost' || u.hostname === '::1';
  } catch {
    return false;
  }
}

async function strictFetchInit(input, init = {}) {
  if (!torIsStrict() || init?.dispatcher || isLoopbackFetchTarget(input)) return init || {};
  const proxyHref = firstProxyPoolEntry();
  if (!/^socks(5h?|4a?):\/\//i.test(proxyHref)) {
    throw new Error('tor-strict: GHOSTRECON_PROXY_POOL sem SOCKS — fetch direto bloqueado');
  }
  let dispatcher = strictFetchDispatchers.get(proxyHref);
  if (!dispatcher) {
    dispatcher = await createSocksDispatcher(proxyHref);
    strictFetchDispatchers.set(proxyHref, dispatcher);
  }
  return { ...(init || {}), dispatcher };
}

if (originalFetch && !globalThis.__ghostreconFetchHistoryWrapped) {
  globalThis.__ghostreconFetchHistoryWrapped = true;
  globalThis.fetch = async (input, init = {}) => {
    const ctx = reconHttpContext.getStore();
    if (!ctx) return originalFetch(input, await strictFetchInit(input, init));

    const started = Date.now();
    let method = String(init?.method || '').toUpperCase();
    let url = '';
    let reqHeaders = {};
    let reqBody = bodyPreviewForHistory(init?.body);
    try {
      if (typeof Request !== 'undefined' && input instanceof Request) {
        url = input.url;
        method = method || String(input.method || 'GET').toUpperCase();
        reqHeaders = normalizeHeadersForHistory(input.headers);
        if (!reqBody && method !== 'GET' && method !== 'HEAD') {
          try {
            reqBody = await input.clone().text();
            reqBody = reqBody.slice(0, 8000);
          } catch {
            reqBody = '';
          }
        }
      } else {
        url = typeof input === 'string' ? input : String(input?.url || input || '');
        method = method || 'GET';
      }
      reqHeaders = { ...reqHeaders, ...normalizeHeadersForHistory(init?.headers) };
    } catch {
      url = String(input || '');
      method = method || 'GET';
    }

    try {
      const effectiveInit = await strictFetchInit(input, init);
      const response = await originalFetch(input, effectiveInit);
      const respHeaders = normalizeHeadersForHistory(response.headers);
      const mimeType = (response.headers.get('content-type') || '').split(';')[0].trim();
      const contentLengthHdr = response.headers.get('content-length');
      const row = recordReconHttpHistory({
        ...ctx,
        source: 'fetch',
        method,
        url,
        requestHeaders: reqHeaders,
        requestBody: reqBody,
        status: response.status,
        statusText: response.statusText,
        ok: response.ok,
        durationMs: Date.now() - started,
        responseHeaders: respHeaders,
        mimeType,
        responseSize: contentLengthHdr ? Number(contentLengthHdr) : null,
      });
      response.clone().text().then((body) => {
        row.responseBody = body.slice(0, RECON_HTTP_RESPONSE_PREVIEW_MAX);
        if (row.responseSize == null) row.responseSize = body.length;
      }).catch(() => {});
      return response;
    } catch (e) {
      recordReconHttpHistory({
        ...ctx,
        source: 'fetch',
        method,
        url,
        requestHeaders: reqHeaders,
        requestBody: reqBody,
        durationMs: Date.now() - started,
        error: e?.message || String(e),
      });
      throw e;
    }
  };
}

function allowReconRequest(req) {
  const { max, windowMs } = reconRateLimitConfig();
  if (max <= 0) return true;
  // Identidade efetiva: principal (sub) > engagement-id > ip
  const sub = req.principal?.sub;
  const engagement = String(req.headers['x-engagement-id'] || '').trim();
  const ip = clientIp(req);
  const key = sub ? `sub:${sub}` : engagement ? `eng:${engagement}` : `ip:${ip}`;
  const now = Date.now();
  const arr = (reconRlHits.get(key) || []).filter((t) => now - t < windowMs);
  if (arr.length >= max) return false;
  arr.push(now);
  reconRlHits.set(key, arr);
  return true;
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
  /^\/[^\/]+\.(?:html|css|js|map|svg|png|jpg|jpeg|gif|webp|ico|woff2?|ttf)$/,
];
app.use(requireAuth({ allowlist: AUTH_ALLOWLIST }));

app.use(express.json({ limit: '5mb' }));

// ── Auto-auth (loopback-only): devolve a primeira API key configurada para que a
//    UI possa salvar no localStorage sem intervenção manual na 1ª visita.
app.get('/api/setup/auto-auth', (req, res) => {
  const ip = String(
    req.headers['x-forwarded-for']?.split(',')[0]?.trim() || req.socket?.remoteAddress || '',
  );
  const loopback = ip === '127.0.0.1' || ip === '::1' || ip === '::ffff:127.0.0.1';
  if (!loopback) return res.status(403).json({ error: 'apenas loopback' });

  const raw = process.env.AUTH_API_KEYS || '';
  const first = raw.split(/[|\n]/).map((s) => s.trim()).filter(Boolean)[0];
  if (!first) return res.status(404).json({ error: 'AUTH_API_KEYS não configuradas' });

  const key = first.split(':')[0];
  if (!key || key.length < 24) return res.status(404).json({ error: 'chave inválida' });

  res.json({ apiKey: key });
});

function aiAutoReportsServerAllowed() {
  const v = String(process.env.GHOSTRECON_AI_AUTO ?? '1').trim().toLowerCase();
  return v !== '0' && v !== 'false' && v !== 'no';
}

/** Mesmo formato que `buildPipelineExportPayload()` na UI — para `runDualAiReports`. */
/** Lê os .md de próximos passos gerados pela IA e envia para o terminal NDJSON (decisão antes do próximo alvo na fila). */
function emitIaProximosPassosToLog(aiOut, log) {
  if (!aiOut || typeof log !== 'function') return;
  const parts = [];
  const order = Array.isArray(aiOut._reportCascadeOrder)
    ? aiOut._reportCascadeOrder
    : ['gemini', 'openrouter', 'claude', 'lmstudio'];
  const labels = {
    gemini: 'Gemini — próximos passos',
    openrouter: 'OpenRouter — próximos passos',
    claude: 'Claude (Anthropic) — próximos passos',
    lmstudio: 'LM Studio (local) — próximos passos',
  };
  for (const key of order) {
    const b = aiOut[key];
    if (b?.ok && b.proximosPath && labels[key]) parts.push({ label: labels[key], path: b.proximosPath });
  }
  if (!parts.length) return;
  log('═══ DECISÃO / PRÓXIMOS PASSOS (IA) ═══', 'section');
  for (const { label, path: fpath } of parts) {
    log(`── ${label} ──`, 'section');
    try {
      const text = fs.readFileSync(fpath, 'utf8');
      for (const line of text.split('\n')) {
        const t = line.replace(/\r$/, '');
        if (t.trim() === '') log(' ', 'info');
        else if (t.length > 2400) log(`${t.slice(0, 2400)}…`, 'info');
        else log(t, 'info');
      }
    } catch (e) {
      log(`Não foi possível ler ${fpath}: ${e.message}`, 'warn');
    }
  }
  log('═══ Fim decisão IA — pode seguir para o próximo alvo ═══', 'section');
}

function buildPipelineExportPayloadForAi({
  target,
  projectName,
  stats,
  findings,
  correlation,
  reportTemplates,
  runId,
  storage,
  intelMerge,
  kaliMode,
  modules,
  bountyContext = null,
  auth = null,
}) {
  const findingsExport = findings.map((f) => {
    const ev = f.verification;
    let verificationOut;
    if (ev && typeof ev === 'object') {
      const rsp = ev.evidence?.responseSnippet;
      const req = ev.evidence?.requestSnippet;
      verificationOut = {
        classification: ev.classification,
        confidenceScore: ev.confidenceScore,
        verifiedAt: ev.verifiedAt,
        evidenceHash: ev.evidence?.evidenceHash,
        responseSnippetPreview: typeof rsp === 'string' ? rsp.slice(0, 2000) : undefined,
        requestSnippetPreview: typeof req === 'string' ? req.slice(0, 900) : undefined,
      };
    }
    return {
      type: f.type,
      priority: f.prio,
      score: f.score || 0,
      value: f.value,
      meta: f.meta || '',
      url: f.url || '',
      fingerprint: f.fingerprint || '',
      compositeScore: f.compositeScore,
      attackTier: f.attackTier,
      priorityWhy: f.priorityWhy,
      bountyProbability: f.bountyProbability,
      provenance: f.provenance && (f.provenance.how || f.provenance.relation) ? { ...f.provenance } : undefined,
      verification: verificationOut,
      owasp: Array.isArray(f.owasp) && f.owasp.length ? f.owasp : undefined,
      mitre: Array.isArray(f.mitre) && f.mitre.length ? f.mitre : undefined,
    };
  });
  return {
    schemaVersion: 1,
    source: 'ghostrecon-server-pipeline',
    exportedAt: new Date().toISOString(),
    projectName: projectName || undefined,
    target,
    stats: { ...stats },
    findings: findingsExport,
    correlation,
    reportTemplates,
    runId,
    storage,
    intelMerge,
    kaliMode,
    modules,
    bountyContext: bountyContext || undefined,
    authProfile:
      auth && (auth.cookie || (auth.headers && Object.keys(auth.headers).length))
        ? {
            hasCookie: Boolean(auth.cookie),
            headerKeys: auth.headers ? Object.keys(auth.headers).slice(0, 24) : [],
          }
        : undefined,
  };
}

async function runPipeline(ctx) {
  const {
    domain,
    exactMatch,
    modules,
    emit,
    kaliMode = false,
    auth = null,
    profile = 'standard',
    outOfScope: outOfScopeClientRaw = null,
    projectName: projectNameRaw = '',
    autoAiReports = false,
    aiProviderMode = 'auto',
    aiUseOpenrouter = true,
    aiOpenrouterOnly = false,
    /** Preferência bruta do POST (`gemini` | `openrouter`); o servidor ajusta se faltar chave. */
    aiPrimaryCloud = null,
    shannonPrecheck = true,
    shannonSkipDepsVerify = false,
    shannonGithubRepos = null,
    pentestgptUrl: pentestgptUrlOverride = null,
    bountyContext: bountyContextBody = null,
    engagementId: engagementIdRaw = null,
    engagementOperator: engagementOperatorRaw = null,
    identityCtrl = null,
    navegation = null,
  } = ctx;
  const apexHostIsIp = targetIsIp(domain);

  let bountyCtx =
    bountyContextBody && typeof bountyContextBody === 'object' ? bountyContextBody : null;
  if (!bountyCtx && process.env.GHOSTRECON_BOUNTY_CONTEXT?.trim()) {
    try {
      bountyCtx = JSON.parse(process.env.GHOSTRECON_BOUNTY_CONTEXT);
    } catch {
      bountyCtx = { note: String(process.env.GHOSTRECON_BOUNTY_CONTEXT).slice(0, 400) };
    }
  }
  let reconCoverageSnapshot = null;
  const runtimeProfile = resolveReconProfile(profile);
  const domainStr = exactMatch ? `"${domain}"` : domain;
  const findings = [];
  const stats = { subs: 0, endpoints: 0, params: 0, secrets: 0, dorks: 0, high: 0 };

  const addFinding = (f, statKey) => {
    try {
      f.fingerprint = fingerprintFinding(domain, f);
    } catch {
      /* ignore */
    }
    if (statKey) stats[statKey] = (stats[statKey] || 0) + 1;
    findings.push(f);
    if (f.prio === 'high') stats.high += 1;
    emit({
      type: 'finding',
      finding: f,
      mitreHints: inferMitreTechniqueIds(f),
      owaspHints: inferOwaspTags(f),
    });
    emit({ type: 'stats', stats: { ...stats } });
    // Captura automática de tokens: baixa a página fonte e grava em tokens/<domain>/
    if (f.type === 'secret' && f.url) {
      captureTokenFinding(f, domain, emit).catch(() => {});
    }
  };

  const log = (msg, level = 'info') => emit({ type: 'log', msg, level });
  const pipe = (name, state) => emit({ type: 'pipe', name, state });
  /** Marcos extra no Ghostmap quando a fase Kali não corre (emitidos por `kali-scan.js` durante o scan). */
  const KALI_SUB_PIPE_STEPS = [
    'nmap',
    'nmap_udp',
    'whois',
    'ffuf',
    'dirsearch',
    'nuclei',
    'nuclei_xss',
    'nuclei_sqli',
    'wpscan',
    'dalfox',
    'xss_vibes',
  ];
  const skipKaliSubPipe = () => {
    for (const n of KALI_SUB_PIPE_STEPS) pipe(n, 'skip');
  };
  const progress = (p) => emit({ type: 'progress', pct: p });

  let pipelineAiOut = null;

  let subdomainsAlive = [];
  const probedHosts = new Set();
  const seenEp = new Set();
  let vtHostnames = [];
  let tlsSanHosts = [];
  /** FQDN (lower) → primeiro IPv4 (A) visto no recon — para sugestões /etc/hosts no módulo header_intel. */
  const dnsAForHost = new Map();

  log(`Alvo: ${domain} | Módulos: ${modules.join(', ')} | Perfil: ${runtimeProfile.name}`, 'info');
  if (apexHostIsIp) {
    log(
      'Alvo é endereço IP — enumeração por CT/VirusTotal/subfinder e arquivo web por wildcard de domínio não se aplicam; HTTP/TLS/Kali seguem no IP.',
      'info',
    );
  }
  log(exactMatch ? 'Modo: exact match (aspas nos dorks)' : 'Modo: broad match', 'info');
  const outOfScopeFromEnv = parseOutOfScopeEnv(process.env.GHOSTRECON_OUT_OF_SCOPE);
  let outOfScopeList = [...outOfScopeFromEnv];
  if (modules.includes('out_of_scope') && outOfScopeClientRaw != null && outOfScopeClientRaw !== '') {
    const fromUi = parseOutOfScopeClientInput(outOfScopeClientRaw);
    outOfScopeList = mergeOutOfScopeLists(outOfScopeFromEnv, fromUi);
  }
  if (outOfScopeList.length) {
    log(`Fora de escopo (${outOfScopeList.length} regra(s)): ${outOfScopeList.join(', ')}`, 'info');
  }

  // ── INPUT ─────────────────────────────────────
  pipe('input', 'active');
  progress(5);
  pipe('input', 'done');

  // ── LOVABLE FINGERPRINT ───────────────────────
  let lovableContext = null;
  if (!apexHostIsIp && modules.includes('lovable_fingerprint')) {
    pipe('lovable_fingerprint', 'active');
    try {
      const targetUrl = `https://${hostLiteralForUrl(domain)}/`;
      log(`Lovable fingerprint: analisando ${targetUrl}`, 'info');
      const lov = await fingerprintLovable(targetUrl, {
        pocDir: path.join(ROOT, 'pocs', 'supabase'),
        storeRawSecrets: String(process.env.GHOSTRECON_POC_STORE_SECRETS || '').trim() === '1',
      });
      lovableContext = lov?.context || null;
      const lovFindings = Array.isArray(lov?.findings) ? lov.findings : [];
      for (const f of lovFindings) addFinding(withProvenance(f, 'lovable_fingerprint'));
      if (lov?.context?.pocPath) {
        const rel = path.relative(ROOT, lov.context.pocPath);
        log(`Lovable fingerprint: PoC Supabase salva em ${rel}`, 'success');
      } else if (lov?.context?.pocError) {
        log(`Lovable fingerprint: falha ao salvar PoC Supabase (${lov.context.pocError})`, 'warn');
      }
      if (lovFindings.length) {
        log(`Lovable fingerprint: ${lovFindings.length} achado(s)`, 'success');
      } else {
        log('Lovable fingerprint: sem achados relevantes', 'info');
      }
    } catch (e) {
      log(`Lovable fingerprint: ${e?.message || e}`, 'warn');
    }
    pipe('lovable_fingerprint', 'done');
  }

  // ── SUPABASE AUDIT ────────────────────────────
  if (!apexHostIsIp && modules.includes('supabase_audit')) {
    pipe('supabase_audit', 'active');
    try {
      const targetUrl = `https://${hostLiteralForUrl(domain)}/`;

      // Reutiliza contexto do lovable_fingerprint se disponível, caso contrário extrai agora
      let auditCtx = lovableContext;
      if (!auditCtx?.supabaseUrl || !auditCtx?.anonKey) {
        log('Supabase audit: executando fingerprint para obter Supabase URL/key', 'info');
        const lov = await fingerprintLovable(targetUrl, { probeRls: false, probeMisconfig: false });
        auditCtx = lov?.context || null;
      }

      if (auditCtx?.supabaseUrl && auditCtx?.anonKey) {
        const authToken = String(process.env.GHOSTRECON_SUPABASE_AUTH_TOKEN || '').trim() || null;
        const { findings: auditFindings, summary } = await runSupabaseAudit(auditCtx, {
          authToken,
          targetUrl,
          log,
        });
        for (const f of auditFindings) addFinding(withProvenance(f, 'supabase_audit'));
        const crit = summary?.critical || 0;
        const high = summary?.high || 0;
        if (auditFindings.length) {
          log(`Supabase audit: ${auditFindings.length} achado(s) — ${crit} crítico(s) / ${high} alto(s)`, crit > 0 ? 'warn' : 'success');
        } else {
          log('Supabase audit: nenhuma vulnerabilidade detectada', 'info');
        }
        if (!authToken) {
          log('Supabase audit: probes de escrita (business logic, payment bypass) desabilitados — defina GHOSTRECON_SUPABASE_AUTH_TOKEN para habilitar', 'info');
        }
      } else {
        log('Supabase audit: Supabase URL/key não encontrados — alvo pode não usar Supabase', 'info');
      }
    } catch (e) {
      log(`Supabase audit: ${e?.message || e}`, 'warn');
    }
    pipe('supabase_audit', 'done');
  }

  // ── SUBDOMAINS ──────────────────────────────
  if (!apexHostIsIp && modules.includes('virustotal')) {
    const vt = await fetchVirustotalSubdomains(domain, process.env.VIRUSTOTAL_API_KEY);
    if (vt.ok && vt.items?.length) {
      vtHostnames = vt.items;
      log(`VirusTotal: ${vtHostnames.length} hostname(s)`, 'success');
    } else {
      log(vt.note || 'VirusTotal: sem dados', vt.ok ? 'info' : 'warn');
    }
  }

  let allSubs = [];
  /** Hostnames normalizados devolvidos pelo subfinder (para meta `tool=subfinder` na UI). */
  const subfinderHostsNorm = new Set();
  const runCrtSubdomains = modules.includes('subdomains');
  const runKaliSubfinderAmass = Boolean(kaliMode) && (modules.includes('subfinder') || modules.includes('amass'));
  if (runCrtSubdomains || runKaliSubfinderAmass) {
    pipe('subdomains', 'active');
    progress(12);
    if (apexHostIsIp) {
      log(
        'Alvo é endereço IP — Certificate Transparency, VirusTotal (subdomínios), subfinder e amass são omitidos nesta fase.',
        'info',
      );
    } else {
      if (runCrtSubdomains) {
        log('Consultando crt.sh (Certificate Transparency)...', 'info');
        try {
          allSubs = await fetchCrtShSubdomains(domain);
          log(`${allSubs.length} nomes únicos em CT logs`, 'success');
        } catch (e) {
          log(`crt.sh: ${e.message}`, 'warn');
        }
        if (vtHostnames.length) {
          const before = allSubs.length;
          allSubs = [...new Set([...allSubs, ...vtHostnames])];
          if (allSubs.length > before) log(`VirusTotal fundido em enum: +${allSubs.length - before} nome(s)`, 'info');
        }
      } else {
        log('crt.sh (subdomains) desativado — usando enum Kali (se selecionado).', 'info');
      }

      if (runKaliSubfinderAmass) {
        if (modules.includes('subfinder')) {
          try {
            const extra = await enumerateSubdomainsWithSubfinder(domain, log);
            for (const h of extra) {
              const hn = String(h).trim().toLowerCase();
              if (hn) subfinderHostsNorm.add(hn);
            }
            if (extra.length) {
              allSubs = [...new Set([...allSubs, ...extra])];
            }
          } catch (e) {
            log(`subfinder: ${e.message}`, 'warn');
          }
        }
        if (modules.includes('amass')) {
          try {
            const extra = await enumerateSubdomainsWithAmass(domain, log);
            if (extra.length) {
              allSubs = [...new Set([...allSubs, ...extra])];
            }
          } catch (e) {
            log(`amass: ${e.message}`, 'warn');
          }
        }
      }
    }

    const capped = allSubs.filter((s) => s !== domain).slice(0, 150);
    const vtHostSet = new Set(vtHostnames.map((h) => String(h).trim().toLowerCase()));
    log(`Resolvendo DNS (máx. ${capped.length} hosts)...`, 'info');
    for (const host of capped) {
      const r = await resolves(host);
      if (r.ok) {
        log(`✓ ${host} → ${r.records.slice(0, 2).join(', ')}`, 'success');
        const { score, prio } = { score: 52, prio: 'med' };
        const hn = String(host).trim().toLowerCase();
        const viaSubfinder = subfinderHostsNorm.has(hn);
        const fromVt = vtHostSet.has(hn);
        const sources = [];
        if (runCrtSubdomains) sources.push('Certificate Transparency (crt.sh)');
        if (vtHostnames.length) sources.push('API VirusTotal');
        if (runKaliSubfinderAmass && modules.includes('subfinder')) sources.push('subfinder (Kali)');
        if (runKaliSubfinderAmass && modules.includes('amass')) sources.push('amass (Kali)');
        const how =
          (sources.length > 0
            ? `Nomes candidatos obtidos com: ${sources.join(', ')}. `
            : '') +
          'Este nome foi confirmado com consulta DNS recursiva (A/AAAA).';
        const relation =
          `**${host}** pertence ao âmbito do alvo **${domain}** (subdomínio ou host relacionado). ` +
          `Os registos DNS provam que o nome resolve na Internet — integra a superfície do recon.` +
          (fromVt ? ' Consta também da lista VirusTotal para este domínio.' : '');
        addFinding(
          withProvenance(
            {
              type: 'subdomain',
              prio,
              score,
              value: host,
              meta: `DNS: ${r.records.join(', ')}${viaSubfinder ? ' · tool=subfinder' : ''}`,
              url: `https://${hostLiteralForUrl(host)}/`,
            },
            { how, relation },
          ),
          'subs',
        );
        subdomainsAlive.push(host);
        probedHosts.add(host);
        const ipv4 = firstIpv4FromDnsRecords(r.records);
        if (ipv4) dnsAForHost.set(String(host).trim().toLowerCase(), ipv4);
      } else {
        log(`✗ ${host} (sem A/AAAA)`, 'warn');
      }
    }
    pipe('subdomains', 'done');
  } else {
    log('Subdomain discovery desativado', 'info');
    pipe('subdomains', 'done');
  }

  if (!apexHostIsIp && modules.includes('ct_monitor')) {
    pipe('ct_monitor', 'active');
    try {
      const ct = await monitorCt(domain, {
        fetcher: async (url) => {
          const r = await fetch(url, { signal: AbortSignal.timeout(20000) });
          return r.ok ? r.json() : [];
        },
      });
      for (const f of ct.findings || []) {
        addFinding({
          type: 'intel',
          prio: sevToPrio(f.severity),
          score: sevToScore(f.severity),
          value: f.title,
          meta: f.description,
          url: f.evidence?.host ? `https://${hostLiteralForUrl(f.evidence.host)}/` : undefined,
        });
      }
      const hot = classifyNewSubs(ct.fresh || []).filter((x) => x.hot);
      if (hot.length) {
        log(`CT monitor: ${ct.fresh.length} novo(s), ${hot.length} subdomínio(s) sensível(is)`, 'warn');
      } else {
        log(`CT monitor: ${ct.fresh.length} novo(s)`, 'info');
      }
    } catch (e) {
      log(`CT monitor: ${e.message}`, 'warn');
    }
    pipe('ct_monitor', 'done');
  }

  if (!apexHostIsIp && modules.includes('origin_discovery')) {
    pipe('origin_discovery', 'active');
    try {
      const discovered = await resolveSubsForOrigin(domain);
      const report = detectOriginCandidates({ apex: domain, subdomainIps: discovered });
      for (const f of originDiscoveryToFindings(report, { target: domain })) {
        addFinding({
          type: 'intel',
          prio: sevToPrio(f.severity),
          score: sevToScore(f.severity),
          value: f.title,
          meta: f.description,
          url: f.evidence?.host ? `https://${hostLiteralForUrl(f.evidence.host)}/` : undefined,
        });
      }
      log(`Origin discovery: ${report.candidates?.length || 0} candidato(s)`, 'info');
    } catch (e) {
      log(`Origin discovery: ${e.message}`, 'warn');
    }
    pipe('origin_discovery', 'done');
  }

  // ── DNS ENRICHMENT (TXT/MX/SPF/DMARC) ─────────
  if (modules.includes('dns_enrichment')) {
    pipe('dns_enrichment', 'active');
    progress(14);
    log('Enriquecimento DNS (MX/TXT/SPF/DMARC)...', 'info');
    try {
      const { findings } = await fetchDnsEnrichment(domain, subdomainsAlive, { maxHosts: limits.dnsEnrichMaxHosts });
      if (findings.length) log(`DNS intel: ${findings.length} achado(s)`, 'success');
      for (const f of findings) addFinding(f, null);
    } catch (e) {
      log(`DNS Enrichment: ${e.message}`, 'warn');
    }
    pipe('dns_enrichment', 'done');
  }

  if (modules.includes('rdap')) {
    if (apexHostIsIp) {
      log('RDAP omitido — alvo é endereço IP (este módulo consulta registo de domínio por FQDN).', 'info');
      emit({ type: 'pipe', name: 'rdap', state: 'skip' });
    } else {
      pipe('rdap', 'active');
      progress(18);
      log('Consultando RDAP (registo de domínio)...', 'info');
      try {
        const rd = await fetchRdapSummary(domain);
        addFinding(
          {
            type: 'rdap',
            prio: 'low',
            score: 24,
            value: rd.handle || domain,
            meta: `Estado: ${rd.statuses || '—'} · NS: ${(rd.nameservers || []).slice(0, 10).join(', ') || '—'}`,
          },
          null,
        );
        if (rd.events?.length) log(`RDAP: ${rd.events.join(' | ')}`, 'info');
      } catch (e) {
        log(`RDAP: ${e.message}`, 'warn');
      }
      pipe('rdap', 'done');
    }
  } else {
    emit({ type: 'pipe', name: 'rdap', state: 'skip' });
  }

  if (apexHostIsIp) {
    dnsAForHost.set(String(domain).trim(), String(domain).trim());
  } else {
    const hn = String(domain).trim().toLowerCase();
    if (!dnsAForHost.has(hn)) {
      try {
        const rApex = await resolves(domain);
        if (rApex.ok) {
          const ipv4 = firstIpv4FromDnsRecords(rApex.records);
          if (ipv4) dnsAForHost.set(hn, ipv4);
        }
      } catch {
        /* ignore */
      }
    }
  }

  // ── ALIVE / PROBE ───────────────────────────
  pipe('alive', 'active');
  progress(28);
  const hostsToProbe = [
    domain,
    ...new Set([...subdomainsAlive, ...(modules.includes('subdomains') ? [] : vtHostnames)]),
  ].slice(0, runtimeProfile.maxHostsToProbe);
  const urlsToProbe = [];
  for (const h of hostsToProbe) {
    const hl = hostLiteralForUrl(h);
    urlsToProbe.push(`https://${hl}/`, `http://${hl}/`);
  }
  log(`HTTP probing em ${hostsToProbe.length} hosts (GET, timeout ${limits.probeTimeoutMs}ms)...`, 'info');

  const probeResults = await mapPool(urlsToProbe, limits.probeConcurrency, async (u) => {
    const r = await probeHttp(u, { auth, modules, identityCtrl });
    return { u, r };
  });

  const seenTech = new Set();
  const seenHtmlCommentIntel = new Set();
  for (const { r } of probeResults) {
    if (!r.ok) continue;
    const host = new URL(r.url).hostname;
    if (r.status > 0 && r.status < 500) {
      log(`ALIVE ${r.url} → ${r.status} ${r.title ? `"${r.title.slice(0, 60)}"` : ''}`, 'success');
      // WAFW00F (fase 2 – opcional, melhor em quick<= off; standard/deep só se ferramenta existir)
      if (modules.includes('wafw00f') || runtimeProfile.name !== 'quick') {
        try {
          const wf = await wafw00fFingerprint(host);
          if (wf?.waf) {
            addFinding({
              type: 'intel',
              prio: 'low',
              score: 30,
              value: `WAF detected: ${wf.waf} @ ${host}`,
              meta: `waf=${wf.waf} • tool=wafw00f`,
              url: r.url,
            });
          }
        } catch {}
      }
      for (const t of r.tech || []) {
        const tk = `${host}::${t}`;
        if (seenTech.has(tk)) continue;
        seenTech.add(tk);
        addFinding({
          type: 'tech',
          prio: 'low',
          score: 28,
          value: t,
          meta: `Detectado em ${host}`,
        });
        if (String(t).toLowerCase().includes('cloudflare')) {
          addFinding({
            type: 'intel',
            prio: 'low',
            score: 28,
            value: `WAF hint @ ${host}`,
            meta: 'waf=cloudflare',
            url: r.url,
          });
        }
      }
      if (r.htmlSample && hostInReconScope(host, domain, outOfScopeList)) {
        for (const h of extractSuspiciousHtmlComments(r.htmlSample)) {
          const key = `${host}::${h.slice(0, 48)}`;
          if (seenHtmlCommentIntel.has(key)) continue;
          seenHtmlCommentIntel.add(key);
          addFinding(
            {
              type: 'intel',
              prio: 'med',
              score: 52,
              value: `Comentário HTML suspeito @ ${host}`,
              meta: `html_comment • ${h.slice(0, 280)}`,
              url: r.url,
            },
            null,
          );
        }
      }
    }
  }

  {
    let surfaceN = 0;
    const cap = limits.htmlSurfaceMaxEndpoints;
    for (const { r } of probeResults) {
      if (!r.ok || !r.surface) continue;
      if (surfaceN >= cap) break;
      let pageHost = '';
      try {
        pageHost = new URL(r.url).hostname;
      } catch {
        continue;
      }
      const merged = [...(r.surface.links || []), ...(r.surface.formActions || [])];
      for (const link of merged) {
        if (surfaceN >= cap) break;
        let u;
        try {
          u = new URL(link);
        } catch {
          continue;
        }
        if (!hostInReconScope(u.hostname, domain, outOfScopeList)) continue;
        const href = u.href;
        if (seenEp.has(href)) continue;
        seenEp.add(href);
        const { score, prio } = scoreEndpointPath(u.pathname);
        addFinding(
          withProvenance(
            {
              type: 'endpoint',
              prio,
              score: Math.max(score, 42),
              value: href,
              meta: `HTML surface • ${pageHost}`,
              url: href,
            },
            {
              how: `Link extraído do HTML da resposta HTTP (atributos href / action) ao analisar a página **${pageHost}**.`,
              relation: `URL no âmbito do alvo **${domain}** (mesmo host ou host autorizado no recon). Indica superfície navegável descoberta a partir de conteúdo já obtido.`,
            },
          ),
          'endpoints',
        );
        surfaceN++;
      }
    }
    if (surfaceN) log(`Superfície HTML: +${surfaceN} URL(s) (href/forms)`, 'info');
  }

  if (modules.includes('security_headers')) {
    for (const { r } of probeResults) {
      if (!r.ok || !r.securityHeaders) continue;
      if (r.status <= 0 || r.status >= 500) continue;
      let host;
      try {
        host = new URL(r.url).hostname;
      } catch {
        continue;
      }
      for (const issue of analyzeSecurityHeaders(r.url, r.securityHeaders)) {
        addFinding(
          {
            type: 'security',
            prio: issue.prio,
            score: issue.score,
            value: `${issue.text} @ ${host}`,
            meta: `HTTP ${r.status}`,
            url: r.url,
          },
          null,
        );
      }
    }
  }

  if (modules.includes('header_intel')) {
    for (const { r } of probeResults) {
      if (!r.ok || !r.responseHeadersFlat?.length) continue;
      if (r.status <= 0 || r.status >= 500) continue;
      let pageHost = '';
      try {
        pageHost = new URL(r.url).hostname;
      } catch {
        continue;
      }
      const pickIp =
        dnsAForHost.get(pageHost.toLowerCase()) ||
        dnsAForHost.get(String(domain).trim().toLowerCase()) ||
        (apexHostIsIp ? String(domain).trim() : '');
      for (const hit of analyzeSuspiciousResponseHeaders(r.responseHeadersFlat, {
        pageUrl: r.url,
        pageHost,
        apexDomain: domain,
        primaryIpv4: pickIp || '',
      })) {
        addFinding(
          {
            type: 'intel',
            prio: hit.prio,
            score: hit.score,
            value: hit.value,
            meta: hit.meta,
            url: r.url,
          },
          null,
        );
      }
    }
  }

  const originByHost = new Map();
  for (const { r } of probeResults) {
    if (!r.ok || r.status <= 0 || r.status >= 500) continue;
    let u;
    try {
      u = new URL(r.url);
    } catch {
      continue;
    }
    if (!hostInReconScope(u.hostname, domain, outOfScopeList)) continue;
    const prefer = u.protocol === 'https:' ? 2 : 1;
    const cur = originByHost.get(u.hostname);
    if (!cur || prefer > cur.prefer) {
      const port = u.port ? `:${u.port}` : '';
      originByHost.set(u.hostname, { origin: `${u.protocol}//${u.hostname}${port}/`, prefer });
    }
  }

  const runWellKnown = modules.includes('wellknown_security_txt') || modules.includes('wellknown_openid');
  const runSurface =
    modules.includes('security_headers') || modules.includes('robots_sitemap') || runWellKnown;
  if (runSurface) {
    pipe('surface', 'active');
    progress(33);
    if (modules.includes('security_headers')) {
      const hostsTls = [...originByHost.entries()].filter(([, v]) => v.prefer === 2).map(([h]) => h);
      if (hostsTls.length) log(`Inspeção TLS (${hostsTls.length} host HTTPS)...`, 'info');
      await mapPool(hostsTls, limits.surfaceConcurrency, async (hostname) => {
        const cert = await peekTlsCertificate(hostname, 443, limits.tlsProbeTimeoutMs);
        if (cert.ok) {
          const soon = cert.daysLeft != null && cert.daysLeft < 30;
          addFinding(
            {
              type: 'tls',
              prio: soon ? 'med' : 'low',
              score: soon ? 52 : 28,
              value: `${hostname} — cert válido até ${cert.validTo || '?'}`,
              meta: `Assunto: ${cert.subject || '—'} · Emissor: ${cert.issuer || '—'}${cert.daysLeft != null ? ` · ~${cert.daysLeft}d` : ''}`,
              url: `https://${hostLiteralForUrl(hostname)}/`,
            },
            null,
          );
          if (cert.subjectAltName) {
            const sanHosts = String(cert.subjectAltName)
              .split(',')
              .map((x) => x.replace(/DNS:/gi, '').trim().toLowerCase().replace(/^\*\./, ''))
              .filter((x) => /^[a-z0-9][a-z0-9.-]+\.[a-z]{2,}$/i.test(x))
              .slice(0, 30);
            tlsSanHosts = [...new Set([...tlsSanHosts, ...sanHosts])];
          }
        }
      });
    }
    if (modules.includes('robots_sitemap')) {
      const bases = [...originByHost.values()].map((v) => v.origin);
      log(`robots.txt / sitemap (${bases.length} origem(ns))...`, 'info');
      await mapPool(bases, limits.surfaceConcurrency, async (baseOrigin) => {
        const crawl = await crawlRobotsAndSitemapsForOrigin(baseOrigin, domain, outOfScopeList);
        for (const p of (crawl.disallowHints || []).slice(0, 20)) {
          addFinding(
            {
              type: 'intel',
              prio: 'low',
              score: 36,
              value: `robots Disallow: ${p}`,
              meta: crawl.robotsUrl || baseOrigin,
              url: crawl.robotsUrl || baseOrigin,
            },
            null,
          );
        }
        for (const pageUrl of crawl.pageUrls || []) {
          let pathname = '/';
          try {
            pathname = new URL(pageUrl).pathname;
          } catch {
            continue;
          }
          const { score, prio } = scoreEndpointPath(pathname);
          if (seenEp.has(pageUrl)) continue;
          seenEp.add(pageUrl);
          addFinding(
            {
              type: 'endpoint',
              prio,
              score: Math.max(score, 44),
              value: pageUrl,
              meta: `robots/sitemap • ${new URL(baseOrigin).hostname}`,
              url: pageUrl,
            },
            'endpoints',
          );
        }
      });
    }

    // ── /.well-known (security.txt + OIDC discovery) ──
    if (runWellKnown) {
      const origins = [...originByHost.values()].map((v) => v.origin).slice(0, limits.wellKnownMaxHosts);
      if (origins.length) log(`/.well-known (${origins.length} origem(ns))...`, 'info');

      await mapPool(origins, limits.wellKnownConcurrency, async (baseOrigin) => {
        if (modules.includes('wellknown_security_txt')) {
          try {
            const sec = await fetchWellKnownSecurityTxt(baseOrigin);
            if (sec.ok && sec.findings?.length) {
              for (const f of sec.findings) addFinding(f, null);
            }
          } catch (e) {
            log(`security.txt: ${e.message}`, 'warn');
          }
        }

        if (modules.includes('wellknown_openid')) {
          try {
            const oid = await fetchWellKnownOpenIdConfiguration(baseOrigin);
            if (oid.ok && oid.endpoints?.length) {
              for (const ep of oid.endpoints) {
                let pathname = '/';
                try {
                  pathname = new URL(ep.url).pathname;
                } catch {
                  // keep default
                }
                const { score, prio } = scoreEndpointPath(pathname);
                addFinding(
                  {
                    type: 'endpoint',
                    prio: prio === 'low' ? 'med' : prio,
                    score: Math.max(score, 55),
                    value: ep.url,
                    meta: `OIDC discovery (.well-known) • ${ep.label}`,
                    url: ep.url,
                  },
                  'endpoints',
                );
              }
            }
          } catch (e) {
            log(`OIDC discovery: ${e.message}`, 'warn');
          }
        }
      });
    }
    pipe('surface', 'done');
  } else {
    emit({ type: 'pipe', name: 'surface', state: 'skip' });
  }

  pipe('alive', 'done');
  progress(40);

  if (modules.includes('shodan')) {
    const sk = process.env.SHODAN_API_KEY?.trim();
    if (!sk) {
      log('Shodan: define SHODAN_API_KEY para lookup passivo (api.shodan.io)', 'warn');
    } else {
      log('Shodan: resolução IPv4 + host lookup (passivo)...', 'info');
      try {
        const ips = await collectUniqueIpv4(
          hostsToProbe,
          limits.shodanResolveMaxHosts,
          limits.shodanMaxIps,
        );
        for (const ip of ips) {
          const s = await shodanHostSummary(ip, sk);
          if (!s.ok) {
            log(`Shodan ${ip}: ${s.note}`, 'warn');
            continue;
          }
          const portStr = s.ports?.length ? s.ports.join(', ') : '—';
          const hn = s.hostnames?.length ? s.hostnames.join(', ') : '—';
          const vn = s.vulns?.length ? s.vulns.join(', ') : '';
          addFinding(
            withProvenance(
              {
                type: 'intel',
                prio: s.vulns?.length ? 'high' : 'med',
                score: s.vulns?.length ? 74 : 50,
                value: `Shodan host ${ip}`,
                meta: [
                  s.org && `org: ${s.org}`,
                  `ports: ${portStr}`,
                  `hostnames: ${hn}`,
                  vn && `cve/tags: ${vn}`,
                ]
                  .filter(Boolean)
                  .join(' · '),
                url: `https://www.shodan.io/host/${ip}`,
              },
              {
                how: `API Shodan (GET /shodan/host/{ip}) com a tua chave. O **${ip}** foi escolhido após resolver IPv4 de hosts do alvo **${domain}** em DNS.`,
                relation:
                  'O IP aparece porque um ou mais hostnames do recon resolvem para ele. O Shodan mostra portos/serviços e hostnames historicamente vistos — liga o endereço à superfície exposta na Internet relacionada ao programa.',
              },
            ),
            null,
          );
        }
      } catch (e) {
        log(`Shodan: ${e.message}`, 'warn');
      }
    }
  }

  if (modules.includes('openapi_specs')) {
    log('OpenAPI/Swagger: a procurar specs em paths comuns…', 'info');
    try {
      const bases = [...originByHost.values()].map((v) => v.origin);
      const specRows = await harvestOpenApiFromOrigins(bases, domain, outOfScopeList, modules, log);
      for (const row of specRows) {
        addFinding(row, row.type === 'param' ? 'params' : row.type === 'endpoint' ? 'endpoints' : null);
      }
    } catch (e) {
      log(`OpenAPI harvest: ${e.message}`, 'warn');
    }
  }

  // ── WAYBACK / URLS ──────────────────────────
  let waybackUrls = [];
  pipe('urls', 'active');
  if (modules.includes('wayback')) {
    if (apexHostIsIp) {
      log('Wayback (CDX) omitido — índice *.domínio não se aplica a alvo só-IP.', 'info');
    } else {
      log('Coletando URLs do Wayback Machine (CDX)...', 'info');
      try {
        waybackUrls = await fetchWaybackUrls(domain);
        log(`${waybackUrls.length} URLs únicas (200) no escopo *.${domain}`, 'success');
      } catch (e) {
        log(`Wayback: ${e.message}`, 'warn');
      }
    }
  } else {
    log('Wayback desativado', 'info');
  }

  let ccUrls = [];
  if (modules.includes('common_crawl')) {
    if (apexHostIsIp) {
      log('Common Crawl omitido — padrão *.domínio não se aplica a alvo só-IP.', 'info');
    } else {
      log('Common Crawl (índice CDX)...', 'info');
      try {
        ccUrls = await fetchCommonCrawlUrls(domain);
        log(`${ccUrls.length} URLs únicas (200) no Common Crawl`, 'success');
      } catch (e) {
        log(`Common Crawl: ${e.message}`, 'warn');
      }
    }
  }

  let archiveCliUrls = [];
  if (runtimeProfile.includeCliArchives || modules.includes('gau') || modules.includes('waybackurls')) {
    if (apexHostIsIp) {
      log('gau / waybackurls (CLI) omitidos — arquivo por domínio não se aplica a alvo só-IP.', 'info');
    } else {
      try {
        archiveCliUrls = await fetchArchiveToolUrls(domain, log);
      } catch (e) {
        log(`Archive CLI: ${e.message}`, 'warn');
      }
    }
  }

  let urlCorpus = [...new Set([...waybackUrls, ...ccUrls, ...archiveCliUrls])];
  if (runtimeProfile.name === 'deep') {
    const apexLit = hostLiteralForUrl(domain);
    const seeds = [`https://${apexLit}/`, `http://${apexLit}/`];
    for (const seed of seeds) {
      try {
        const k = await crawlWithKatana(seed, { depth: 3 });
        if (k.ok && k.urls.length) {
          let added = 0;
          for (const u of k.urls.slice(0, 300)) {
            if (!urlInReconScope(u, domain, outOfScopeList)) continue;
            if (!urlCorpus.includes(u)) {
              urlCorpus.push(u);
              added++;
            }
          }
          log(`Katana: +${added} URL(s) no escopo via crawl JS (${k.urls.length} brutas)`, 'info');
        }
      } catch (e) {
        log(`Katana: ${e.message}`, 'warn');
      }
    }
  }
  urlCorpus = urlCorpus.filter((u) => urlInReconScope(u, domain, outOfScopeList));

  if (modules.includes('graphql_probe')) {
    const gqlUrls = [...new Set(urlCorpus.filter((u) => /graphql/i.test(u)))].slice(0, 10);
    if (!gqlUrls.length) {
      log(
        'GraphQL: módulo activo mas nenhuma URL com "graphql" no corpus — liga Wayback/Common Crawl ou outras fontes de URLs.',
        'info',
      );
    } else {
      try {
        const gqlFindings = await tryGraphqlMinimalProbe(gqlUrls, domain, outOfScopeList, modules, log);
        for (const gf of gqlFindings) addFinding(gf, null);
      } catch (e) {
        log(`GraphQL probe: ${e.message}`, 'warn');
      }
    }
  }

  if (modules.includes('graphql_recon')) {
    const gqlUrls = [...new Set(urlCorpus.filter((u) => /graphql/i.test(u)))].slice(0, 8);
    if (!gqlUrls.length) {
      log('GraphQL recon: sem endpoints com "graphql" no corpus', 'info');
    } else {
      pipe('graphql_recon', 'active');
      try {
        const headers = { ...(auth?.headers || {}) };
        if (auth?.cookie) headers.Cookie = auth.cookie;
        for (const gqlUrl of gqlUrls) {
          const out = await probeGraphqlEndpoint(gqlUrl, {
            headers,
            executor: async (query, variables, extraHeaders) => {
              const r = await fetch(gqlUrl, {
                method: 'POST',
                headers: { 'content-type': 'application/json', ...headers, ...(extraHeaders || {}) },
                body: JSON.stringify({ query, variables }),
                signal: AbortSignal.timeout(15000),
              });
              try {
                return await r.json();
              } catch {
                return { errors: [{ message: `HTTP ${r.status}` }] };
              }
            },
          });
          for (const f of out.findings || []) {
            addFinding({
              type: 'intel',
              prio: sevToPrio(f.severity),
              score: sevToScore(f.severity),
              value: f.title,
              meta: f.description,
              url: gqlUrl,
            });
          }
        }
      } catch (e) {
        log(`GraphQL recon: ${e.message}`, 'warn');
      }
      pipe('graphql_recon', 'done');
    }
  }

  const waybackSet = new Set(waybackUrls);
  const ccSet = new Set(ccUrls);
  const interesting = filterInterestingUrls(urlCorpus);
  log(`${interesting.length} URLs marcadas como interessantes (filtro heurístico)`, 'info');

  // URLs com query string (bons alvos para templates de XSS/SQLi no modo Kali)
  const paramUrlsForKali = [...new Set(urlCorpus.filter((u) => /\?.+=/i.test(u)))].slice(0, 40);

  for (const rawUrl of interesting.slice(0, runtimeProfile.maxInterestingUrls)) {
    let pathname = '/';
    try {
      pathname = new URL(rawUrl).pathname;
    } catch {
      continue;
    }
    const { score, prio } = scoreEndpointPath(pathname);
    if (seenEp.has(rawUrl)) continue;
    seenEp.add(rawUrl);
    const src = waybackSet.has(rawUrl) ? 'Wayback' : ccSet.has(rawUrl) ? 'Common Crawl' : 'arquivo web';
    addFinding(
      withProvenance(
        {
          type: 'endpoint',
          prio,
          score,
          value: rawUrl,
          meta: `Score ${score}/100 • ${src}`,
          url: rawUrl,
        },
        {
          how: `URL recolhida do corpus passivo (**${src}** / CDX ou índice), filtrada pelo escopo *.${domain} e heurísticas de caminho.`,
          relation: `Endereço histórico ou indexado associado ao domínio alvo **${domain}**. Pode ou não responder hoje; confirma manualmente antes de reportar.`,
        },
      ),
      'endpoints',
    );
  }
  pipe('urls', 'done');
  progress(52);

  // ── PARAMS ──────────────────────────────────
  pipe('params', 'active');
  const paramRows = extractParamsFromUrls(urlCorpus.length ? urlCorpus : interesting);
  for (const { name, count, sampleUrl } of paramRows.slice(0, 60)) {
    const { score, prio } = scoreParamName(name);
    const vuln =
      ['redirect', 'url', 'file', 'path', 'callback'].includes(name.toLowerCase()) ? ' → Open Redirect/SSRF?' : '';
    addFinding(
      withProvenance(
        {
          type: 'param',
          prio,
          score,
          value: `?${name}=`,
          meta: `~${count} ocorrências em URLs${vuln}`,
          url: sampleUrl || undefined,
        },
        {
          how: 'Nome de parâmetro de query extraído do agregado de URLs do recon (Wayback, CSE, HTML, JS, etc.).',
          relation: `Parâmetro observado em URLs cujo host está no âmbito do alvo **${domain}** — candidato a testes manuais no programa.`,
        },
      ),
      'params',
    );

    // Heurística (passivo): marcar parâmetros comuns para XSS / SQLi como candidatos (não confirmados)
    const n = String(name).toLowerCase();
    const xssCandidates = new Set(['q', 'query', 'search', 's', 'keyword', 'term', 'message', 'comment', 'title', 'name']);
    const sqliCandidates = new Set([
      'id',
      'ids',
      'user',
      'user_id',
      'uid',
      'account',
      'order',
      'order_id',
      'page',
      'sort',
      'filter',
      'where',
      'username',
      'email',
      'passwd',
      'pwd',
      'login',
    ]);
    if (xssCandidates.has(n)) {
      addFinding(
        {
          type: 'intel',
          prio: prio === 'high' ? 'med' : 'low',
          score: 54,
          value: `XSS candidate param: ?${name}=`,
          meta: 'Heurístico (passivo) — priorizar testes de reflexão/encoding • confidence=heuristic',
          url: sampleUrl || undefined,
        },
        null,
      );
    }
    if (sqliCandidates.has(n)) {
      addFinding(
        {
          type: 'intel',
          prio: prio === 'high' ? 'med' : 'low',
          score: 56,
          value: `SQLi candidate param: ?${name}=`,
          meta: 'Heurístico (passivo) — priorizar filtros/IDs/ordenação • confidence=heuristic',
          url: sampleUrl || undefined,
        },
        null,
      );
    }
  }
  log(`${paramRows.length} nomes de parâmetros distintos (amostra Wayback)`, 'success');
  pipe('params', 'done');
  progress(60);

  // ── JS ANALYSIS ─────────────────────────────
  pipe('js', 'active');
  const jsList = extractJsUrls(urlCorpus.length ? urlCorpus : [], 120).slice(0, limits.maxJsFetch);
  log(`Analisando ${jsList.length} arquivos JS (passivo)...`, 'info');
  for (const jsUrl of jsList) {
    const a = await analyzeJsUrl(jsUrl, { modules });
    if (!a.ok) {
      log(`JS skip: ${jsUrl} (${a.error || a.status})`, 'warn');
      continue;
    }
    if (modules.includes('js_intel')) {
      try {
        const intel = jsBundleToFindings(a.body || '', { url: jsUrl, target: domain });
        for (const jf of intel.findings || []) {
          addFinding({
            type: 'intel',
            prio: sevToPrio(jf.severity),
            score: sevToScore(jf.severity),
            value: jf.title,
            meta: jf.description,
            url: jsUrl,
          });
        }
      } catch (e) {
        log(`JS intel: ${e.message}`, 'warn');
      }
    }
    for (const ep of a.endpoints.slice(0, 25)) {
      const { score, prio } = scoreEndpointPath(ep);
      addFinding(
        {
          type: 'js',
          prio: prio === 'low' ? 'med' : prio,
          score: Math.max(score, 55),
          value: ep,
          meta: `Extraído de ${jsUrl}`,
          url: jsUrl,
        },
        'endpoints',
      );
    }
    for (const ins of a.insights || []) {
      addFinding(
        {
          type: 'intel',
          prio: ins.kind === 'role_admin_hint' ? 'high' : 'med',
          score: ins.kind === 'role_admin_hint' ? 72 : 58,
          value: `JS insight (${ins.kind}): ${ins.snippet.slice(0, 160)}`,
          meta: `js_context • kind=${ins.kind} • confidence=heuristic`,
          url: jsUrl,
        },
        null,
      );
    }
    const sec = scanSecrets(a.body || '');
    for (const s of sec) {
      const fpMeta = s.correlationFp ? `value_fp=${s.correlationFp}` : '';
      addFinding(
        {
          type: 'secret',
          prio: 'high',
          score: 92,
          value: `[${s.kind}] ${s.masked}`,
          meta: ['Possível segredo em JS (verificar falso positivo)', fpMeta].filter(Boolean).join(' • '),
          url: jsUrl,
        },
        'secrets',
      );
    }
  }
  pipe('js', 'done');
  progress(72);

  // ── DORKS (URLs apenas) ─────────────────────
  pipe('dorks', 'active');
  const techHintsForDorks = findings.filter((f) => f.type === 'tech').map((f) => f.value);
  const dorks = buildDorks(domainStr, modules, techHintsForDorks);
  for (const d of dorks) {
    emit({
      type: 'dork',
      googleUrl: d.googleUrl,
      query: d.query,
      mod: d.mod,
      prio: d.prio,
    });
    addFinding(
      {
        type: 'dork',
        prio: d.prio,
        score: d.prio === 'high' ? 68 : 55,
        value: d.query,
        meta: `Categoria: ${d.mod}`,
        url: d.googleUrl,
      },
      'dorks',
    );
  }
  log(`${dorks.length} dorks gerados (abertura no browser com fila configurável)`, 'success');

  if (modules.includes('google_cse')) {
    const gKey = process.env.GOOGLE_CSE_KEY;
    const gCx = process.env.GOOGLE_CSE_CX;
    if (!gKey || !gCx) {
      log(
        'Google CSE desativado: defina GOOGLE_CSE_KEY e GOOGLE_CSE_CX (Programmable Search Engine) para descobrir URLs reais via API.',
        'warn',
      );
    } else if (dorks.length === 0) {
      log('Google CSE: nenhum dork gerado — ative categorias de dork na sidebar.', 'warn');
    } else {
      log(
        `Google Custom Search: até ${limits.googleCseMaxQueries} queries neste run (quota diária típica 100 grátis).`,
        'info',
      );
      const seenG = new Set();
      const slice = dorks.slice(0, limits.googleCseMaxQueries);
      for (let i = 0; i < slice.length; i++) {
        const d = slice[i];
        if (i > 0) await sleep(limits.googleCseDelayMs);
        try {
          const items = await googleCseSearch(d.query, gKey, gCx);
          for (const it of items) {
            if (!urlInReconScope(it.link, domain, outOfScopeList)) continue;
            if (seenG.has(it.link)) continue;
            seenG.add(it.link);
            let pathname = '/';
            try {
              pathname = new URL(it.link).pathname;
            } catch {
              continue;
            }
            const { score, prio } = scoreEndpointPath(pathname);
            addFinding(
              {
                type: 'endpoint',
                prio,
                score: Math.max(score, 62),
                value: it.link,
                meta: `Google CSE • ${d.mod} • ${it.title ? it.title.slice(0, 60) : d.query.slice(0, 60)}`,
                url: it.link,
              },
              'endpoints',
            );
            log(`CSE → ${it.link}`, 'find');
          }
        } catch (e) {
          log(`CSE [${d.mod}]: ${e.message}`, 'warn');
        }
      }
      log(`${seenG.size} URL(s) no alvo descoberta(s) via Google CSE`, seenG.size ? 'success' : 'info');
    }
  }

  pipe('dorks', 'done');
  progress(82);

  // ── GITHUB API (opcional) ───────────────────
  pipe('secrets', 'active');
  /** Clones bem-sucedidos neste run (para Shannon white-box). */
  let githubClonedItems = [];
  const manualGithubRepos = parseGithubManualRepoList(shannonGithubRepos);
  if (manualGithubRepos.length) {
    log(`GitHub: ${manualGithubRepos.length} repositório(s) indicado(s) manualmente (UI Shannon)`, 'info');
  }

  const recordClonedFindings = (clonedList) => {
    for (const item of clonedList) {
      addFinding({
        type: 'intel',
        prio: 'low',
        score: 38,
        value: `GitHub clone local: ${item.full_name}`,
        meta: `path=${item.local_path} • size=${Math.round((item.size_bytes || 0) / (1024 * 1024))}MB`,
        url: `https://github.com/${item.full_name}`,
      });
    }
  };

  if (modules.includes('github')) {
    log('GitHub Code Search (API pública, rate limit)...', 'info');
    const gh = await githubCodeSearch(domain, process.env.GITHUB_TOKEN);
    if (gh.ok && gh.items?.length) {
      for (const it of gh.items) {
        const ghMat = `${it.repo || ''}|${it.path || ''}`;
        const ghf = secretMaterialFingerprint('github_code_hit', ghMat);
        addFinding(
          {
            type: 'secret',
            prio: 'high',
            score: 78,
            value: `${it.repo || ''}/${it.path || ''}`,
            meta: `Resultado GitHub Code Search — revisar manualmente • value_fp=${ghf}`,
            url: it.html_url,
          },
          'secrets',
        );
      }
      log(`${gh.items.length} resultados GitHub (total estimado ${gh.total})`, 'warn');
    } else {
      log(gh.note || 'Sem resultados GitHub ou limite atingido', 'info');
    }

    log('GitHub Repo Search (candidatos para clone local)...', 'info');
    const ghRepos = await githubRepoSearch(domain, process.env.GITHUB_TOKEN, { perPage: 8 });
    const codeRepos = (gh.items || []).map((x) => String(x.repo || '').trim()).filter(Boolean);
    const repoMap = new Map();

    if (ghRepos.ok && ghRepos.items?.length) {
      for (const r of ghRepos.items || []) {
        if (!r?.full_name) continue;
        repoMap.set(r.full_name, r);
      }
    }

    for (const fullName of codeRepos) {
      if (!fullName || repoMap.has(fullName)) continue;
      repoMap.set(fullName, {
        full_name: fullName,
        clone_url: `https://github.com/${fullName}.git`,
        html_url: `https://github.com/${fullName}`,
      });
    }

    for (const m of manualGithubRepos) {
      repoMap.set(m.full_name, m);
    }

    const repoCandidates = [...repoMap.values()];
    if (repoCandidates.length) {
      log(`GitHub repos candidatos: ${repoCandidates.length}`, 'success');

      const cloneCfg = githubCloneConfig();
      if (cloneCfg.enabled) {
        log(
          `Clone local ativo: até ${cloneCfg.maxRepos} repo(s), timeout ${cloneCfg.cloneTimeoutMs}ms, retenção ${Math.round(cloneCfg.retentionMs / (24 * 60 * 60 * 1000))} dia(s)`,
          'info',
        );
      } else {
        log('Clone local desativado (GHOSTRECON_GITHUB_CLONE_ENABLED=1 para ativar).', 'info');
      }

      try {
        const cloned = await cloneGithubReposForTarget({
          targetDomain: domain,
          repos: repoCandidates,
          log,
        });
        if (cloned.skipped) {
          // clone desativado por config
        } else {
          if (cloned.cloned?.length) {
            githubClonedItems = cloned.cloned;
            recordClonedFindings(cloned.cloned);
            log(`Clone local concluído: ${cloned.cloned.length} repo(s) em ${cloned.base_dir}`, 'success');
          } else {
            log('Clone local: nenhum repositório clonado nesta execução.', 'info');
          }
          if (cloned.failed?.length) {
            for (const item of cloned.failed.slice(0, 4)) {
              log(`Clone falhou (${item.full_name}): ${item.error}`, 'warn');
            }
            if (cloned.failed.length > 4) {
              log(`+${cloned.failed.length - 4} falha(s) de clone adicionais`, 'warn');
            }
          }
        }
      } catch (e) {
        log(`Clone local GitHub: ${e.message}`, 'warn');
      }
    } else {
      log(ghRepos.note || 'GitHub Repo Search sem resultados (e sem repos manuais válidos)', 'info');
    }
  } else if (manualGithubRepos.length && modules.includes('shannon_whitebox')) {
    const cloneCfg = githubCloneConfig();
    if (!cloneCfg.enabled) {
      log('Repos GitHub manuais: clone local desativado — define GHOSTRECON_GITHUB_CLONE_ENABLED=1.', 'warn');
    } else {
      log(
        `Clone só de repos manuais (${manualGithubRepos.length}) — módulo «GitHub leaks» desligado; Shannon white-box activo.`,
        'info',
      );
      try {
        const cloned = await cloneGithubReposForTarget({
          targetDomain: domain,
          repos: manualGithubRepos,
          log,
        });
        if (!cloned.skipped && cloned.cloned?.length) {
          githubClonedItems = cloned.cloned;
          recordClonedFindings(cloned.cloned);
          log(`Clone local concluído: ${cloned.cloned.length} repo(s) em ${cloned.base_dir}`, 'success');
        } else if (!cloned.skipped && cloned.failed?.length) {
          for (const item of cloned.failed.slice(0, 4)) {
            log(`Clone falhou (${item.full_name}): ${item.error}`, 'warn');
          }
        }
      } catch (e) {
        log(`Clone local GitHub (manual): ${e.message}`, 'warn');
      }
    }
  } else if (manualGithubRepos.length) {
    log(
      'Repos GitHub na caixa manual ignorados: activa «GitHub leaks» ou «Shannon white-box» para clonar.',
      'info',
    );
  }
  if (modules.includes('pastebin')) {
    log('Pastebin: sem API pública confiável — use os dorks gerados', 'info');
  }
  // Validação activa de tokens/secrets (fase 3)
  try {
    const sv = await validateSecretFindings(findings, log);
    for (const row of sv) {
      const isLive     = row.status === 'live';
      const isProbable = row.status === 'probable';
      const tokenLabel = row.tokenType && row.tokenType !== 'unknown'
        ? ` [${row.tokenType}]` : '';
      const statusLabel =
        row.tokenStatus === 'valid'    ? 'VALID'    :
        row.tokenStatus === 'expired'  ? 'EXPIRED'  :
        row.tokenStatus === 'invalid'  ? 'INVALID'  :
        row.tokenStatus === 'revoked'  ? 'REVOKED'  :
        row.tokenStatus === 'probable' ? 'PROBABLE' :
        row.status.toUpperCase();
      addFinding({
        type:  'secret_validation',
        prio:  isLive ? 'high' : isProbable ? 'med' : 'low',
        score: isLive ? 86     : isProbable ? 62    : 24,
        value: `Token ${statusLabel}${tokenLabel} • ${row.ref}`,
        meta:  [
          `tokenStatus=${row.tokenStatus ?? row.status}`,
          `tokenType=${row.tokenType ?? 'unknown'}`,
          row.offlineExpired            ? `offlineExpired=true`           : null,
          row.expiredAt                 ? `expiredAt=${row.expiredAt}`    : null,
          row.expiresAt                 ? `expiresAt=${row.expiresAt}`    : null,
          row.noExpiration              ? `noExpiration=true`             : null,
          row.jwtClaims?.iss            ? `iss=${row.jwtClaims.iss}`      : null,
          row.jwtClaims?.role           ? `role=${row.jwtClaims.role}`    : null,
          `reason=${row.reason}`,
        ].filter(Boolean).join('|'),
        tokenValidation: {
          status:         row.tokenStatus ?? row.status,
          tokenType:      row.tokenType,
          offlineExpired: row.offlineExpired,
          expiredAt:      row.expiredAt    ?? null,
          expiresAt:      row.expiresAt    ?? null,
          noExpiration:   row.noExpiration ?? false,
          jwtClaims:      row.jwtClaims    ?? null,
          evidence:       row.reason,
          probes:         row.probes       ?? [],
        },
      });
    }
    const live    = sv.filter((r) => r.status === 'live').length;
    const expired = sv.filter((r) => r.tokenStatus === 'expired').length;
    if (sv.length) log(`Token validation: ${sv.length} token(s) — ${live} válido(s), ${expired} expirado(s)`, 'info');
  } catch (e) {
    log(`Secret validation: ${e.message}`, 'warn');
  }
  pipe('secrets', 'done');

  if (!modules.includes('shannon_whitebox')) {
    emit({ type: 'pipe', name: 'shannon', state: 'skip' });
  } else {
    log(
      'Shannon white-box: fase após PRIORITIZE e antes de PentestGPT HTTP (verify/Kali/score correm primeiro).',
      'info',
    );
  }

  // ── VERIFY (evidence-guided) ─────────────────
  pipe('verify', 'active');
  progress(84);
  try {
    if (identityCtrl?.enabled) {
      const st = identityCtrl.getStats();
      log(
        `Rotação de identidade: ativa (proxies=${st.proxies}, backoff≈${st.backoffMul.toFixed(1)})`,
        'info',
      );
    }
    const verified = await runEvidenceVerification({
      findings,
      auth,
      log,
      maxEndpoints: runtimeProfile.maxVerifyEndpoints,
      modules,
      identityCtrl,
    });
    for (const vf of verified) addFinding(vf, null);
    if (verified.length) log(`Verify: ${verified.length} resultado(s) xss/sqli/open_redirect/idor/lfi`, 'success');
  } catch (e) {
    log(`Verify: ${e.message}`, 'warn');
  }
  if (modules.includes('micro_exploit')) {
    try {
      const micro = await runMicroExploitVariants({
        findings,
        auth,
        log,
        modules,
        maxTests: 16,
        identityCtrl,
      });
      for (const mf of micro) addFinding(mf, null);
    } catch (e) {
      log(`Micro-exploit: ${e.message}`, 'warn');
    }
  }

  if (modules.includes('webshell_probe')) {
    pipe('webshell_probe', 'active');
    try {
      const origins = [];
      const seenO = new Set();
      for (const [, v] of originByHost) {
        const o = String(v?.origin || '').trim();
        if (!o || seenO.has(o) || origins.length >= 11) continue;
        seenO.add(o);
        origins.push(o.endsWith('/') ? o : `${o}/`);
      }
      try {
        const hl = hostLiteralForUrl(domain);
        for (const scheme of ['https', 'http']) {
          const o = `${scheme}://${hl}/`;
          if (!seenO.has(o) && origins.length < 12) {
            seenO.add(o);
            origins.push(o);
          }
        }
      } catch {
        /* ignore */
      }
      const ws = await runWebshellHeuristicProbe({ origins, auth, modules, log, maxOrigins: 10 });
      for (const w of ws) addFinding(w, null);
      if (ws.length) log(`Webshell heurístico: ${ws.length} achado(s) — rever manualmente`, 'warn');
      else log('Webshell heurístico: sem sinais fortes (cmd=id)', 'info');
    } catch (e) {
      log(`Webshell heurístico: ${e.message}`, 'warn');
    }
    pipe('webshell_probe', 'done');
  } else {
    pipe('webshell_probe', 'skip');
  }

  // Param discovery ativo (fase 2): tentar em endpoints sem query
  try {
    const candidates = findings
      .filter((f) => f.type === 'endpoint' && typeof f.value === 'string' && /^https?:\/\//i.test(f.value))
      .filter((f) => !/\?/.test(String(f.value)))
      .slice(0, Math.max(6, Math.round(runtimeProfile.maxVerifyEndpoints / 3)));
    for (const ep of candidates) {
      const r = await discoverParamsActive(ep.value, { timeoutMs: 70000 });
      const ps = [...new Set(r.params || [])].slice(0, 20);
      for (const p of ps) {
        addFinding(
          {
            type: 'param',
            prio: 'med',
            score: 62,
            value: `?${p}=`,
            meta: `active_discovery • tool=${r.tool || 'n/a'}`,
            url: `${ep.value}${ep.value.includes('?') ? '&' : '?'}${p}=X`,
          },
          'params',
        );
      }
      if (ps.length) log(`Param discovery: ${ps.length} em ${ep.value}`, 'info');
    }
  } catch (e) {
    log(`Param discovery: ${e.message}`, 'warn');
  }

  if (modules.includes('sqlmap')) {
    pipe('sqlmap', 'active');
    try {
      const maxT = Math.max(1, Math.min(6, Number(process.env.GHOSTRECON_SQLMAP_TARGETS) || 2));
      const sm = await runSqlmapModule({
        findings,
        auth,
        log,
        maxTargets: maxT,
        profile: runtimeProfile.name,
        identityCtrl,
      });
      for (const x of sm) addFinding(x, null);
      if (sm.length) log(`sqlmap: ${sm.length} achado(s) SQLi (ferramenta) registado(s)`, 'success');
    } catch (e) {
      log(`sqlmap: ${e.message}`, 'warn');
    }
    pipe('sqlmap', 'done');
  } else {
    pipe('sqlmap', 'skip');
  }

  if (modules.includes('curl_probe')) {
    pipe('curl_probe', 'active');
    try {
      const cp = await runCurlProbeModule({
        target: domain,
        findings,
        auth,
        profile: runtimeProfile.name,
        identityCtrl,
        log,
      });
      for (const x of cp) addFinding(x, null);
      if (cp.length) log(`curl_probe: ${cp.length} achado(s)`, 'success');
      else log('curl_probe: sem achados relevantes', 'info');
    } catch (e) {
      log(`curl_probe: ${e?.message || e}`, 'warn');
    }
    pipe('curl_probe', 'done');
  } else {
    pipe('curl_probe', 'skip');
  }

  pipe('verify', 'done');

  if (modules.includes('authz_matrix')) {
    pipe('authz_matrix', 'active');
    try {
      const endpointUrls = [...new Set(findings.filter((f) => f.type === 'endpoint' && /^https?:\/\//i.test(String(f.value || ''))).map((f) => f.value))].slice(0, 8);
      const requests = [];
      const reqSeen = new Set();
      const pushReq = (r) => {
        if (!r || !r.method || !r.path) return;
        const k = `${r.method}:${r.path}`;
        if (reqSeen.has(k)) return;
        reqSeen.add(k);
        requests.push(r);
      };
      for (const u of endpointUrls) {
        try {
          const uu = new URL(u);
          const pathOnly = uu.pathname || '/';
          const perUser = /\/(me|profile|account|user)/i.test(u);
          const adminOnly = /\/admin/i.test(u);
          pushReq({ method: 'GET', path: pathOnly, perUser, adminOnly, url: u });
          if (/\/(graphql|gql)(\/|$)/i.test(pathOnly)) {
            pushReq({
              method: 'POST',
              path: pathOnly,
              perUser: false,
              adminOnly: false,
              url: u,
              body: { query: '{ __typename }' },
              headers: { 'Content-Type': 'application/json' },
            });
          }
        } catch {
          /* ignore */
        }
      }
      const personas = [
        { id: 'anon', expectedRole: 'guest', headers: {} },
        ...(auth?.cookie || (auth?.headers && Object.keys(auth.headers).length)
          ? [{ id: 'auth', expectedRole: 'user', headers: { ...(auth?.headers || {}), ...(auth?.cookie ? { Cookie: auth.cookie } : {}) } }]
          : []),
      ];
      if (requests.length && personas.length > 1) {
        const plan = buildAuthzPlan(requests, personas);
        const matrix = await runAuthzMatrix({
          requests,
          personas,
          concurrency: 2,
          executor: async (reqShape, persona) => {
            const picked = reqShape.url || endpointUrls.find((u) => {
              try { return new URL(u).pathname === reqShape.path; } catch { return false; }
            });
            if (!picked) return { status: 0, fingerprint: null, bodyLen: 0 };
            const mergedHeaders = { ...(persona.headers || {}), ...(reqShape.headers || {}) };
            const reqBody =
              reqShape.method === 'POST' || reqShape.method === 'PUT'
                ? (typeof reqShape.body === 'string' ? reqShape.body : JSON.stringify(reqShape.body || {}))
                : undefined;
            const r = await fetch(picked, {
              method: reqShape.method || 'GET',
              headers: mergedHeaders,
              body: reqBody,
              signal: AbortSignal.timeout(12000),
            });
            const body = await r.text();
            let ownerMarker = null;
            try {
              const parsed = JSON.parse(body);
              const obj = parsed && typeof parsed === 'object' ? parsed : null;
              if (obj) {
                const owner = obj.user_id || obj.userId || obj.owner_id || obj.ownerId || obj.account_id || obj.accountId || obj.tenant_id || obj.tenantId || obj.email || obj.username || null;
                if (owner != null) ownerMarker = String(owner).slice(0, 120);
              }
            } catch {
              /* non-json */
            }
            return { status: r.status, fingerprint: fingerprintBody(body), bodyLen: body.length, ownerMarker };
          },
        });
        for (const f of matrix.findings || []) {
          addFinding({
            type: 'intel',
            prio: sevToPrio(f.severity),
            score: sevToScore(f.severity),
            value: f.title,
            meta: f.description,
          });
        }
        log(`AuthZ matrix: ${plan.length} tentativa(s), ${matrix.findings?.length || 0} sinal(is)`, 'info');
      } else {
        log('AuthZ matrix: insuficiente (requer endpoints HTTP + contexto autenticado)', 'info');
      }
    } catch (e) {
      log(`AuthZ matrix: ${e.message}`, 'warn');
    }
    pipe('authz_matrix', 'done');
  }

  if (modules.includes('jwt_lab')) {
    pipe('jwt_lab', 'active');
    try {
      const candidates = [];
      if (auth?.cookie) candidates.push(...String(auth.cookie).split(/[;,\s]+/).filter((x) => x.split('.').length === 3));
      for (const v of Object.values(auth?.headers || {})) {
        const s = String(v || '');
        const m = s.match(/([A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,})/);
        if (m?.[1]) candidates.push(m[1]);
      }
      const seen = new Set();
      for (const tok of candidates) {
        if (seen.has(tok)) continue;
        seen.add(tok);
        const r = analyzeJwt(tok);
        if (!r.ok) continue;
        for (const f of r.findings || []) {
          addFinding({
            type: 'intel',
            prio: sevToPrio(f.severity),
            score: sevToScore(f.severity),
            value: `JWT lab: ${f.issue}`,
            meta: f.detail,
          });
        }
      }
      log(`JWT lab: ${seen.size} token(s) analisado(s)`, 'info');
    } catch (e) {
      log(`JWT lab: ${e.message}`, 'warn');
    }
    pipe('jwt_lab', 'done');
  }

  if (modules.includes('dom_xss_verify')) {
    pipe('dom_xss_verify', 'active');
    try {
      const urls = [...new Set(findings.filter((f) => f.type === 'endpoint' && /\?/.test(String(f.value || ''))).map((f) => f.value))].slice(0, 6);
      const plan = buildVerificationPlan({ urls, params: ['q', 'search', 'id'], maxPerUrl: 3 });
      if (plan.length) {
        addFinding({
          type: 'intel',
          prio: 'med',
          score: 58,
          value: `DOM XSS verify plan: ${plan.length} probes`,
          meta: 'Plano gerado para validação browser-assisted (Playwright/manual).',
        });
      }
    } catch (e) {
      log(`DOM XSS verify: ${e.message}`, 'warn');
    }
    pipe('dom_xss_verify', 'done');
  }

  if (modules.includes('payload_mutator')) {
    pipe('payload_mutator', 'active');
    try {
      const variants = mutatePayload(`' OR 1=1--`, { context: 'generic' }).slice(0, 12);
      addFinding({
        type: 'intel',
        prio: 'low',
        score: 44,
        value: `Payload mutator ready: ${variants.length} variantes`,
        meta: `Amostra: ${variants.slice(0, 3).join(' | ').slice(0, 220)}`,
      });
    } catch (e) {
      log(`Payload mutator: ${e.message}`, 'warn');
    }
    pipe('payload_mutator', 'done');
  }

  if (modules.includes('race_harness')) {
    pipe('race_harness', 'active');
    try {
      const candidate = findings.find((f) => f.type === 'endpoint' && /coupon|payment|transfer|withdraw|cart|checkout/i.test(String(f.value || '')));
      if (candidate?.value) {
        const plan = buildRacePlan({ request: { method: 'POST', url: candidate.value, headers: auth?.headers || {}, body: '{}' }, parallel: 20 });
        addFinding({
          type: 'intel',
          prio: 'med',
          score: 60,
          value: `Race harness plan criado (${plan.total} paralelos)`,
          meta: `Alvo candidato: ${candidate.value}`,
          url: candidate.value,
        });
      } else {
        log('Race harness: sem endpoint financeiro óbvio para plano automático', 'info');
      }
    } catch (e) {
      log(`Race harness: ${e.message}`, 'warn');
    }
    pipe('race_harness', 'done');
  }

  if (modules.includes('oob_collaborator')) {
    pipe('oob_collaborator', 'active');
    try {
      const token = randomBytes(8).toString('hex');
      const host = String(process.env.GHOSTRECON_OOB_HOST || '127.0.0.1');
      const payloads = buildOobPayloads({ token, host, httpPort: Number(process.env.GHOSTRECON_OOB_HTTP_PORT || 8054) });
      addFinding({
        type: 'intel',
        prio: 'med',
        score: 57,
        value: `OOB payload pack gerado (${token})`,
        meta: `ssrf=${payloads.ssrf[0]} xxe=${payloads.xxe[0]}`.slice(0, 340),
      });
    } catch (e) {
      log(`OOB collaborator: ${e.message}`, 'warn');
    }
    pipe('oob_collaborator', 'done');
  }

  if (modules.includes('cred_spray')) {
    pipe('cred_spray', 'active');
    try {
      const users = String(process.env.GHOSTRECON_SPRAY_USERS || '')
        .split(',')
        .map((x) => x.trim())
        .filter(Boolean)
        .slice(0, 100);
      const passwords = String(process.env.GHOSTRECON_SPRAY_PASSWORDS || '')
        .split(',')
        .map((x) => x.trim())
        .filter(Boolean)
        .slice(0, 20);
      if (users.length && passwords.length) {
        const plan = planSpray({ users, passwords, usersPerBatch: 25 });
        addFinding({
          type: 'intel',
          prio: 'low',
          score: 38,
          value: `Cred spray plan: ${plan.estimateTotal} tentativas`,
          meta: `batches=${plan.batches.length} cooldownMs=${plan.cooldownMs}`,
        });
      } else {
        log('Cred spray: defina GHOSTRECON_SPRAY_USERS e GHOSTRECON_SPRAY_PASSWORDS para gerar plano', 'info');
      }
    } catch (e) {
      log(`Cred spray: ${e.message}`, 'warn');
    }
    pipe('cred_spray', 'done');
  }

  // ── KALI: nmap / searchsploit / ffuf / nuclei ──
  if (kaliMode) {
    pipe('kali', 'active');
    progress(86);
    const cap = await getKaliCapabilities();
    if (cap.kali) {
      // Só roda wpscan se o passivo já indicou WordPress.
      // Evidência vem de findings do tipo "tech" (geradas no probeHttp).
      const wpHosts = new Set();
      for (const f of findings) {
        if (f?.type !== 'tech') continue;
        const v = String(f.value || '');
        if (!/wordpress/i.test(v)) continue;
        const meta = String(f.meta || '');
        const m = meta.match(/Detectado em\s+(.+)\s*$/i);
        if (m?.[1]) wpHosts.add(m[1]);
      }

      const wordpressTargets = [...wpHosts]
        .slice(0, 10)
        .map((h) => {
          const origin = originByHost.get(h)?.origin;
          if (origin) return origin;
          const hl = hostLiteralForUrl(h);
          return [`https://${hl}/`, `http://${hl}/`];
        })
        .flat()
        .filter(Boolean);

      let xssSignals = false;
      let sqliSignals = false;
      const xssParamRe = /[?&](q|query|search|s|keyword|term|message|comment|title|name)=/i;
      const sqliParamRe =
        /[?&](id|ids|user|user_id|uid|account|order|order_id|page|sort|filter|where|username|email|passwd|pwd|login)=/i;
      for (const u of paramUrlsForKali) {
        if (xssParamRe.test(u)) xssSignals = true;
        if (sqliParamRe.test(u)) sqliSignals = true;
        if (xssSignals && sqliSignals) break;
      }
      for (const f of findings) {
        if (f.type !== 'intel') continue;
        const v = String(f.value || '');
        if (/XSS candidate param/i.test(v)) xssSignals = true;
        if (/SQLi candidate param/i.test(v)) sqliSignals = true;
      }
      if (!xssSignals && !sqliSignals) {
        log(
          'Scan agressivo XSS/SQLi: sem sinais (URLs com parâmetros típicos nem candidatos intel) — nuclei tags xss/sqli, dalfox e xss_vibes em skip',
          'info',
        );
      } else {
        log(
          `Scan agressivo: sinais XSS=${xssSignals ? 'sim' : 'não'} SQLi=${sqliSignals ? 'sim' : 'não'}`,
          'info',
        );
      }

      const runKaliNuclei = Boolean(modules.includes('kali_nuclei'));
      const runKaliFfuf = Boolean(modules.includes('kali_ffuf'));
      const runKaliDirsearch = Boolean(modules.includes('kali_dirsearch'));
      const runKaliNmapAggressive = Boolean(modules.includes('kali_nmap_aggressive'));
      const runKaliNmapUdp = Boolean(modules.includes('kali_nmap_udp'));
      const runMysql3306Intel = Boolean(modules.includes('mysql_3306_intel'));
      const runKaliProxychains = Boolean(modules.includes('kali_proxychains'));

      await runKaliAggressiveScan({
        domain,
        subdomainsAlive,
        cap,
        log,
        addFinding,
        wordpressTargets,
        paramUrls: paramUrlsForKali,
        xssSignals,
        sqliSignals,
        runNuclei: runKaliNuclei,
        runFfuf: runKaliFfuf,
        runDirsearch: runKaliDirsearch,
        runNmapAggressive: runKaliNmapAggressive,
        runNmapUdp: runKaliNmapUdp,
        runMysql3306Intel: runMysql3306Intel,
        useProxychains: runKaliProxychains,
        auth,
        emit,
      });
    } else {
      log(`Modo Kali pedido mas ambiente não suporta: ${cap.message}`, 'warn');
      skipKaliSubPipe();
    }
    pipe('kali', 'done');
  } else {
    pipe('kali', 'skip');
    skipKaliSubPipe();
  }

  progress(90);

  // ── ASSET DISCOVERY (passivo complementar) ──
  pipe('assets', 'active');
  try {
    const assets = await discoverAssetHints(domain, subdomainsAlive, tlsSanHosts);
    for (const a of assets) addFinding(a, null);
    const tk = detectTakeoverCandidates(findings);
    for (const t of tk) addFinding(t, null);
    // Takeover avançado (fase 2): CNAME + corpo
    const aliveHosts = [...new Set(findings.filter((f) => f.type === 'subdomain').map((f) => f.value))].slice(0, 20);
    for (const h of aliveHosts) {
      try {
        const chain = await resolveCnameChain(h, 4);
        const prov = matchProviderByCname(chain);
        if (!prov) continue;
        let body = '';
        try {
          const hl = hostLiteralForUrl(h);
          const res = await fetch(`https://${hl}/`, { redirect: 'follow', signal: AbortSignal.timeout(9000) });
          body = await res.text();
        } catch {}
        const match = matchProviderBody(prov, body);
        addFinding(
          {
            type: 'takeover',
            prio: match ? 'high' : 'med',
            score: match ? 82 : 60,
            value: `Takeover ${match ? 'CONFIRMED' : 'candidate'}: ${h} → ${prov.name}`,
            meta: `cname_chain=${chain.join(' > ').slice(0, 160)} • body_match=${match ? 'yes' : 'no'}`,
            url: `https://${hostLiteralForUrl(h)}/`,
          },
          null,
        );
      } catch {}
    }
    if (assets.length || tk.length) {
      log(`Asset discovery: +${assets.length} hints, takeover candidates: ${tk.length}`, 'info');
    }
  } catch (e) {
    log(`Asset discovery: ${e.message}`, 'warn');
  }
  pipe('assets', 'done');

  if (modules.includes('cloud_bruteforce') && !apexHostIsIp) {
    pipe('cloud_bruteforce', 'active');
    try {
      const rootName = String(domain).split('.')[0];
      const bf = await bruteforceCloud({
        name: rootName,
        target: domain,
        executor: async ({ method, url }) => {
          try {
            const r = await fetch(url, { method, redirect: 'manual', signal: AbortSignal.timeout(10000) });
            const body = await r.text();
            return { status: r.status, body };
          } catch (e) {
            return { error: e?.message || String(e) };
          }
        },
      });
      for (const f of bf.findings || []) {
        addFinding({
          type: 'intel',
          prio: sevToPrio(f.severity),
          score: sevToScore(f.severity),
          value: f.title,
          meta: f.description,
          url: f.evidence?.url || undefined,
        });
      }
      log(`Cloud bruteforce: ${bf.summary?.public || 0} público(s) / ${bf.findings?.length || 0} total`, 'info');
    } catch (e) {
      log(`Cloud bruteforce: ${e.message}`, 'warn');
    }
    pipe('cloud_bruteforce', 'done');
  }

  if (modules.includes('navegation')) {
    pipe('navegation', 'active');
    try {
      const nav = await loadNavegationPlaybook(ROOT);
      if (!nav.steps.length) {
        log('Navegation: ficheiro encontrado, mas sem comandos úteis.', 'warn');
      } else {
        addFinding(
          {
            type: 'intel',
            prio: 'med',
            score: 58,
            value: 'Navegation playbook carregado',
            meta: `source=${nav.filePath} • steps=${nav.steps.length}`,
          },
          null,
        );
        for (const step of nav.steps.slice(0, 12)) {
          emit({ type: 'intel', line: `NAVEGATION: ${step}` });
        }
        log(`Navegation: ${nav.steps.length} passo(s) carregado(s) do playbook local`, 'info');
      }
      const navExecEnabled =
        (navegation && typeof navegation === 'object' && navegation.exec === true) ||
        String(process.env.GHOSTRECON_NAVEGATION_EXEC || '0').trim() === '1';
      if (navExecEnabled) {
        const navDryRun =
          navegation && typeof navegation === 'object' && typeof navegation.dryRun === 'boolean'
            ? navegation.dryRun
            : String(process.env.GHOSTRECON_NAVEGATION_DRY_RUN || '1').trim() !== '0';
        log(`Navegation: execução automática ativada (dry-run=${navDryRun ? 'on' : 'off'})`, 'warn');
        const execRes = await executeNavegationPlaybook(ROOT, {
          dryRun: navDryRun,
          timeoutMs: Number(process.env.GHOSTRECON_NAVEGATION_TIMEOUT_MS || 900000),
        });
        if (execRes.ok) {
          addFinding(
            {
              type: 'intel',
              prio: 'med',
              score: 62,
              value: 'Navegation executado automaticamente',
              meta: `cmd=${execRes.command} • code=${execRes.code} • dry_run=${navDryRun ? '1' : '0'}`,
            },
            null,
          );
          log(`Navegation exec: sucesso (${execRes.command})`, 'success');
        } else {
          log(
            `Navegation exec: falhou (${execRes.command}) code=${execRes.code} timeout=${execRes.timedOut ? '1' : '0'}`,
            'warn',
          );
          if (execRes.stderr) emit({ type: 'intel', line: `NAVEGATION STDERR: ${String(execRes.stderr).slice(0, 400)}` });
        }
      } else {
        log('Navegation: execução automática desligada (define GHOSTRECON_NAVEGATION_EXEC=1 para executar).', 'info');
      }
    } catch (e) {
      log(`Navegation: ${e.message}`, 'warn');
    }
    pipe('navegation', 'done');
  } else {
    emit({ type: 'pipe', name: 'navegation', state: 'skip' });
  }

  // ── PRIORIZAÇÃO V2 + CVE hints + CORRELATION + INTEL ──
  pipe('score', 'active');
  progress(93);
  log('═══ Priorização v2 (composite + HIGH PROBABILITY) ═══', 'section');
  applyPrioritizationV2(findings, bountyCtx);
  for (const f of findings) {
    if (f.type === 'endpoint' && f.url && /\?.+=/i.test(f.url)) {
      f.meta = [f.meta, 'status_consistent=true'].filter(Boolean).join(' • ');
    }
    if (f.type === 'endpoint' && /\/(admin|dashboard|account|profile|settings|billing)(\/|$)/i.test(String(f.value || ''))) {
      f.meta = [f.meta, 'auth=required'].filter(Boolean).join(' • ');
    }
  }
  const techStrs = findings.filter((f) => f.type === 'tech').map((f) => f.value);
  const cveHints = extractCveHintsFromTechStrings(techStrs);
  for (const f of findings) {
    if (cveHints.length && f.type === 'tech') {
      f.meta = [f.meta, 'cve_hint=true'].filter(Boolean).join(' • ');
    }
  }
  try {
    const mysqlCorr = buildMysqlConfigSurfaceCorrelationFindings(findings, { max: 16 });
    for (const c of mysqlCorr) addFinding(c, null);
    if (mysqlCorr.length) log(`Correlação MySQL 3306 + ficheiros de config: ${mysqlCorr.length} achado(s)`, 'info');
  } catch (e) {
    log(`Correlação MySQL + config: ${e.message}`, 'warn');
  }
  applyPrioritizationV2(findings, bountyCtx);

  const semantic = dedupeBySemanticFamily(findings);
  if (semantic.merged > 0) {
    findings.length = 0;
    findings.push(...semantic.findings);
    log(`Dedupe semântico: ${semantic.merged} achado(s) colapsado(s) por família`, 'info');
  }

  if (modules.includes('chaining')) {
    try {
      const chained = applyChains({ findings });
      if (chained?.chains?.length) {
        findings.length = 0;
        findings.push(...(chained.findings || []));
        log(`Chaining: ${chained.chains.length} cadeia(s) detectada(s)`, 'warn');
      }
    } catch (e) {
      log(`Chaining: ${e.message}`, 'warn');
    }
  }

  if (modules.includes('bounty_scope')) {
    try {
      const scope = Array.isArray(bountyCtx?.scope) ? bountyCtx.scope : [];
      if (scope.length) {
        const shaped = findings.map((f) => ({
          category: f.type || 'intel',
          title: String(f.value || ''),
          evidence: { url: f.url || undefined, target: domain },
        }));
        const filtered = applyScopeFilter(shaped, scope);
        const removed = (filtered.outOfScope || []).length;
        if (removed > 0) log(`Bounty scope: ${removed} achado(s) fora de escopo no contexto atual`, 'warn');
      } else {
        log('Bounty scope: sem bountyContext.scope no payload, skip filtro', 'info');
      }
      const dedupe = await dedupeBountyFindings(
        findings.map((f) => ({
          category: f.type || 'intel',
          title: String(f.value || ''),
          evidence: { url: f.url || undefined, target: domain },
        })),
      );
      if ((dedupe.duplicate || []).length) {
        log(`Bounty dedupe: ${(dedupe.duplicate || []).length} potencial(is) duplicado(s) de submissão`, 'info');
      }
    } catch (e) {
      log(`Bounty scope/dedupe: ${e.message}`, 'warn');
    }
  }

  if (modules.includes('bounty_estimator')) {
    try {
      const normalized = findings.map((f) => ({
        severity: f.prio === 'high' ? 'high' : f.prio === 'med' ? 'medium' : 'low',
        category: f.type || 'intel',
      }));
      const value = summarizeValue(normalized, { tier: String(bountyCtx?.tier || 'standard').toLowerCase() });
      const top = prioritizeBounty(normalized, { tier: String(bountyCtx?.tier || 'standard').toLowerCase() }).slice(0, 3);
      log(`Bounty estimator: total esperado ~${value.totalExpected} (${Object.entries(value.byRecommendation).map(([k, v]) => `${k}:${v}`).join(', ')})`, 'info');
      for (const t of top) {
        addFinding({
          type: 'intel',
          prio: t.estimate.recommendation === 'go-now' ? 'high' : t.estimate.recommendation === 'priority' ? 'med' : 'low',
          score: Math.min(98, Math.max(30, Math.round(t.estimate.ratio / 2))),
          value: `Bounty value hint: ${t.estimate.recommendation}`,
          meta: `expected=${t.estimate.expectedPayout} ratio=${t.estimate.ratio}/h`,
        });
      }
    } catch (e) {
      log(`Bounty estimator: ${e.message}`, 'warn');
    }
  }
  stats.high = findings.filter((f) => f.prio === 'high').length;
  emit({ type: 'stats', stats: { ...stats } });
  emit({ type: 'findings_rescore', findings });

  try {
    await runHighPrioHttpRecheck({ findings, auth, modules, log });
    emit({ type: 'findings_rescore', findings: [...findings] });
  } catch (e) {
    log(`Recheck HIGH: ${e.message}`, 'warn');
  }
  try {
    const pwFindings = await runOptionalPlaywrightXssProbe({ findings, log, limit: 4 });
    for (const pf of pwFindings) addFinding(pf, null);
  } catch (e) {
    log(`Playwright XSS: ${e.message}`, 'warn');
  }
  try {
    const kaliCapSnap = await getKaliCapabilities();
    reconCoverageSnapshot = buildReconCoverageSnapshot({
      domain,
      modules,
      kaliMode,
      findings,
      kaliCap: kaliCapSnap,
    });
    emit({ type: 'recon_coverage', snapshot: reconCoverageSnapshot });
  } catch (e) {
    log(`Cobertura recon: ${e.message}`, 'warn');
  }

  if (cveHints.length) {
    log('═══ Versões detectadas → lookup CVE (manual) ═══', 'section');
    for (const h of cveHints) {
      const label = `${h.product}${h.version ? ` ${h.version}` : ''}`;
      log(`🔎 ${label} — NVD: ${h.nvdUrl}`, 'info');
      log(`   OSV: ${h.osvUrl}`, 'info');
    }
  }

  const hpt = topHighProbability(findings, 8);
  if (hpt.length) {
    log(`═══ HIGH PROBABILITY TARGET (${hpt.length}) ═══`, 'section');
    for (const t of hpt) {
      const w = (t.priorityWhy || []).slice(0, 3).join('; ');
      log(`🎯 [${t.compositeScore}] ${t.type}: ${String(t.value).slice(0, 100)}${w ? ` — ${w}` : ''}`, 'warn');
    }
    emit({
      type: 'priority_pass',
      top: hpt.map((f) => ({
        value: f.value,
        type: f.type,
        compositeScore: f.compositeScore,
        attackTier: f.attackTier,
        why: f.priorityWhy || [],
      })),
    });
  }

  progress(96);
  const corr = correlate({
    subdomainsAlive,
    endpoints: findings.filter((f) => f.type === 'endpoint').map((f) => f.value),
    params: paramRows,
  });
  log('═══ Correlação ═══', 'section');
  log(corr.summary, 'info');
  if (corr.riskyParams.length) {
    log(`Parâmetros de risco presentes: ${corr.riskyParams.join(', ')}`, 'warn');
  }

  log('═══ Workflow de testes (checklist) ═══', 'section');
  const checklist = buildExploitChecklist(findings);
  for (const c of checklist) {
    emit({ type: 'intel', line: `☐ CHECKLIST: ${c}` });
  }

  const hints = suggestVectors({ findings, selectedMods: modules });
  for (const h of hints) {
    emit({ type: 'intel', line: h });
  }
  const reportTemplates = buildReportTemplates(findings, domain);
  for (const tpl of reportTemplates) {
    emit({ type: 'report_template', template: tpl });
    emit({ type: 'intel', line: `REPORT: ${tpl.title}` });
  }
  pipe('score', 'done');
  progress(97);

  // Shannon white-box: após priorização/correlação (payload PentestGPT inclui achados Shannon).
  if (modules.includes('shannon_whitebox')) {
    if (shannonSkipDepsVerify) {
      log('Shannon white-box: verificação de dependências omitida pelo utilizador.', 'warn');
    } else {
      log('Shannon white-box: dependências já validadas no início do pedido HTTP.', 'info');
    }
    const autoOff = Boolean(String(process.env.GHOSTRECON_SHANNON_AUTO_RUN || '1').trim().match(/^(0|false|no)$/i));
    if (autoOff) {
      log('Shannon: GHOSTRECON_SHANNON_AUTO_RUN=0 — não executar ./shannon start (só diagnóstico / clone).', 'info');
      emit({ type: 'pipe', name: 'shannon', state: 'skip' });
    } else if (!githubClonedItems.length) {
      log(
        'Shannon: nenhum clone local neste run — activa o módulo GitHub + clone (GHOSTRECON_GITHUB_CLONE_ENABLED) para analisar código.',
        'warn',
      );
      emit({ type: 'pipe', name: 'shannon', state: 'skip' });
    } else {
      pipe('shannon', 'active');
      const max = shannonMaxClonesPerRun();
      const slice = githubClonedItems.slice(0, max);
      log(`Shannon: a correr até ${slice.length} scan(s) (máx. por run = ${max})…`, 'info');
      for (const item of slice) {
        try {
          const out = await runShannonOnClone({
            ghostRoot: ROOT,
            domain,
            clonePath: item.local_path,
            repoFullName: item.full_name,
            log,
            emit,
          });
          if (out.ok && out.report?.ok) {
            const excerpt = String(out.report.content || '')
              .replace(/\s+/g, ' ')
              .trim()
              .slice(0, 480);
            addFinding(
              {
                type: 'intel',
                prio: 'high',
                score: 72,
                value: `Shannon white-box: ${item.full_name}`,
                meta: `workspace=${out.workspaceId} • report=${out.report.path} • excerpt=${excerpt}`,
                url: `https://github.com/${item.full_name}`,
              },
              null,
            );
          } else {
            const hint = out.detail || out.logTail || out.note || JSON.stringify({ phase: out.phase, exitCode: out.exitCode });
            log(`Shannon falhou (${item.full_name}): ${String(hint).slice(0, 600)}`, 'warn');
            addFinding(
              {
                type: 'intel',
                prio: 'med',
                score: 48,
                value: `Shannon falhou: ${item.full_name}`,
                meta: `workspace=${out.workspaceId || '—'} • phase=${out.phase || '—'} • ${String(hint).slice(0, 400)}`,
                url: `https://github.com/${item.full_name}`,
              },
              null,
            );
          }
        } catch (e) {
          log(`Shannon: excepção (${item.full_name}): ${e.message}`, 'error');
        }
      }
      pipe('shannon', 'done');
      applyPrioritizationV2(findings, bountyCtx);
    }
  }

  const modulesForDb = kaliMode ? [...modules, '__kali_scan__'] : modules;

  let pentestgptSummary = null;
  progress(98);
  if (modules.includes('pentestgpt_validate')) {
    pipe('pentestgpt', 'active');
    try {
      const pgPayload = buildPipelineExportPayloadForAi({
        target: domain,
        projectName: String(projectNameRaw || '').trim(),
        stats,
        findings,
        correlation: corr,
        reportTemplates,
        runId: null,
        storage: storageLabel(),
        intelMerge: null,
        kaliMode: Boolean(kaliMode),
        modules: modulesForDb,
        bountyContext: bountyCtx,
        auth,
      });
      const pg = await runPentestGptValidation(pgPayload, { log, urlOverride: pentestgptUrlOverride });
      pentestgptSummary = pg.summary || null;
      if (pg.findings?.length) {
        for (const f of pg.findings) addFinding(f, null);
      } else if (pg.summary && !pg.skipped) {
        addFinding(
          {
            type: 'intel',
            prio: 'med',
            score: 44,
            value: 'PentestGPT (resumo)',
            meta: String(pg.summary).slice(0, 900),
          },
          null,
        );
      }
    } catch (e) {
      log(`PentestGPT: ${e.message}`, 'warn');
    }
    pipe('pentestgpt', 'done');
  } else {
    emit({ type: 'pipe', name: 'pentestgpt', state: 'skip' });
  }

  progress(100);
  stats.high = findings.filter((f) => f.prio === 'high').length;
  emit({ type: 'stats', stats: { ...stats } });

  applyOwaspTagsToFindings(findings);
  applyMitreTagsToFindings(findings);
  emit({ type: 'findings_rescore', findings: [...findings] });
  log('OWASP Top 10 (2025): etiquetas heurísticas aplicadas a cada achado', 'info');
  log('MITRE ATT&CK (recon): mapa fixo aplicado quando recon-bundle.json existe', 'info');

  const findingsSnapshotJson = serializeFindingsForRunSnapshot(findings);
  const saved = await saveRun({
    target: domain,
    exactMatch,
    modules: modulesForDb,
    stats: { ...stats },
    findings,
    correlation: corr,
    localProjectName: String(projectNameRaw || '').trim(),
    findingsJson: findingsSnapshotJson,
  });
  let runId = null;
  let intelMerge = null;
  if (saved != null) {
    runId = saved.runId;
    intelMerge = saved.intelMerge;
    log(`Recon gravado — run #${runId} → ${storageLabel()}`, 'success');
    const eid = engagementIdRaw != null ? String(engagementIdRaw).trim() : '';
    if (eid && runId != null) {
      try {
        await attachRunToEngagement(eid, {
          runId,
          target: domain,
          by: engagementOperatorRaw != null ? String(engagementOperatorRaw).trim() || null : null,
        });
      } catch (e) {
        log(`Engagement: falha ao anexar run — ${e?.message || e}`, 'warn');
      }
      try {
        await recordAction({
          operator: engagementOperatorRaw != null ? String(engagementOperatorRaw).trim() || 'api' : 'api',
          target: domain,
          action: 'run-complete',
          runId,
          metadata: { engagementId: eid },
        });
      } catch (e) {
        log(`Team trail: falha ao registar — ${e?.message || e}`, 'warn');
      }
    }
    const sqlitePath = saved.localMirrorPath || saved.dbPath;
    if (sqlitePath) {
      log(`SQLite no disco: ${sqlitePath}`, 'success');
    }
    if (saved.remoteSaveFailed) {
      log('Aviso: gravação na cloud falhou — este run ficou no SQLite local acima.', 'warn');
    }
    if (intelMerge?.newArtifacts > 0) {
      log(
        `Corpus do alvo: +${intelMerge.newArtifacts} artefacto(s) novo(s) na base; ${intelMerge.alreadyKnown} já existiam; total único para ${domain}: ${intelMerge.totalKnownForTarget}`,
        'success',
      );
    } else if (findings.length > 0 && intelMerge) {
      log(
        `Corpus do alvo: sem linhas novas (todos os ${intelMerge.alreadyKnown} achados deste run já estavam na base). Total único: ${intelMerge.totalKnownForTarget}`,
        'info',
      );
    }
    if (saved.projectSecretDuplicates?.length) {
      emit({ type: 'project_secret_peers', duplicates: saved.projectSecretDuplicates });
      log(
        `Correlação de segredos (mesmo projeto): ${saved.projectSecretDuplicates.length} valor(es) aparecem em 2+ alvos — Ghostmap / GET /api/project-secret-peers`,
        'warn',
      );
    }
    try {
      const runs = await listRuns(120);
      const nt = domain.trim().toLowerCase();
      const prev = runs.find((r) => String(r.target).trim().toLowerCase() === nt && r.id < runId);
      if (prev) {
        const diff = await compareRuns(prev.id, runId);
        if (!diff.error) {
          const hotAdded = diff.added.filter((x) => {
            const t = String(x.type || '').toLowerCase();
            const v = String(x.value || '').toLowerCase();
            return ['xss', 'sqli', 'open_redirect', 'idor', 'lfi', 'secret', 'exploit', 'nuclei', 'takeover'].includes(t)
              || /\/(admin|api|graphql|internal|debug)|token|key|secret/.test(v);
          });
          if (hotAdded.length) {
            emit({
              type: 'delta_hot',
              baselineRunId: prev.id,
              newerRunId: runId,
              hotAddedCount: hotAdded.length,
              sample: hotAdded.slice(0, 12).map((x) => ({
                type: x.type,
                prio: x.prio,
                value: String(x.value || '').slice(0, 180),
              })),
            });
            log(`Delta hot: ${hotAdded.length} novidade(s) crítica(s) vs run #${prev.id}`, 'warn');
          }
        }
      }
    } catch {
      /* ignore delta hot */
    }
  } else {
    log(`Não foi possível gravar na base (${storageLabel()}) — ver consola do servidor`, 'warn');
  }

  emit({
    type: 'done',
    target: domain,
    findings,
    stats,
    correlation: corr,
    runId,
    intelMerge,
    kaliMode: Boolean(kaliMode),
    storage: storageLabel(),
    reportTemplates,
    localSqlitePath: saved?.localMirrorPath || saved?.dbPath || null,
    reconCoverage: reconCoverageSnapshot,
  });

  if (autoAiReports && aiAutoReportsServerAllowed() && aiKeysConfigured().any) {
    emit({ type: 'ai_report', phase: 'start', target: domain });
    const pri =
      String(aiPrimaryCloud || '').toLowerCase() === 'openrouter' || normalizeOpenrouterOnlyFlag(aiOpenrouterOnly)
        ? 'OpenRouter'
        : 'Gemini';
    const alt = pri === 'OpenRouter' ? 'Gemini' : 'OpenRouter';
    const iaOrder =
      aiUseOpenrouter === false
        ? 'Gemini (sem OpenRouter) → LM Studio → Claude se configurado'
        : `${pri} (primeiro) → LM Studio → ${alt} → Claude se configurado`;
    log(`IA: recon concluído — a gerar relatórios (${iaOrder}) com o JSON deste run…`, 'info');
    const pn = String(projectNameRaw || '').trim();
    const aiPayload = buildPipelineExportPayloadForAi({
      target: domain,
      projectName: pn,
      stats,
      findings,
      correlation: corr,
      reportTemplates,
      runId,
      storage: storageLabel(),
      intelMerge,
      kaliMode: Boolean(kaliMode),
      modules: modulesForDb,
      bountyContext: bountyCtx,
      auth,
    });
    try {
      const aiOut = await runDualAiReports(aiPayload, {
        projectName: pn,
        targetDomain: domain,
        aiProviderMode,
        aiUseOpenrouter,
        aiOpenrouterOnly,
        aiPrimaryCloud,
        onStatus: (message, level = 'info') => log(message, level),
      });
      pipelineAiOut = aiOut;
      emit({
        type: 'ai_report',
        phase: 'done',
        target: domain,
        outputDir: aiOut.outputDir,
        pipelineJsonPath: aiOut.pipelineJsonPath,
        gemini: { ok: Boolean(aiOut.gemini?.ok), error: aiOut.gemini?.error || null },
        openrouter: { ok: Boolean(aiOut.openrouter?.ok), error: aiOut.openrouter?.error || null },
        claude: { ok: Boolean(aiOut.claude?.ok), error: aiOut.claude?.error || null },
        lmstudio: { ok: Boolean(aiOut.lmstudio?.ok), error: aiOut.lmstudio?.error || null },
      });
      emitIaProximosPassosToLog(aiOut, log);
    } catch (e) {
      emit({
        type: 'ai_report',
        phase: 'error',
        target: domain,
        message: e?.message || String(e),
      });
      log(`IA: ${e?.message || e}`, 'error');
    }
  }

  let reconDeltaForWebhook = null;
  try {
    if (runId != null) {
      const runs = await listRuns(120);
      const nt = domain.trim().toLowerCase();
      const prev = runs.find((r) => String(r.target).trim().toLowerCase() === nt && r.id < runId);
      if (prev) {
        const diff = await compareRuns(prev.id, runId);
        if (!diff.error) {
          reconDeltaForWebhook = {
            baselineId: diff.baselineId,
            baselineCreatedAt: diff.baselineCreatedAt,
            newerCreatedAt: diff.newerCreatedAt,
            added: diff.added,
            removedCount: diff.removedCount,
            removedSample: diff.removed.slice(0, 10).map((x) => ({
              type: x.type,
              prio: x.prio,
              value: String(x.value ?? '').slice(0, 240),
            })),
          };
        }
      }
    }
  } catch (e) {
    console.warn('[GHOSTRECON webhook diff]', e?.message || e);
  }

  const whUrl = process.env.GHOSTRECON_WEBHOOK_URL?.trim();
  if (whUrl && runId != null) {
    const findingsByType = {};
    for (const f of findings) {
      const t = f?.type || 'unknown';
      findingsByType[t] = (findingsByType[t] || 0) + 1;
    }
    let runDiffSummary = null;
    if (reconDeltaForWebhook) {
      const d = reconDeltaForWebhook;
      runDiffSummary = {
        baselineId: d.baselineId,
        newerId: runId,
        baselineCreatedAt: d.baselineCreatedAt,
        newerCreatedAt: d.newerCreatedAt,
        addedCount: d.added.length,
        removedCount: d.removedCount,
        addedSample: d.added.slice(0, 10).map((x) => ({
          type: x.type,
          prio: x.prio,
          value: String(x.value ?? '').slice(0, 240),
        })),
        removedSample: d.removedSample || [],
      };
    }
    const shannonSummary =
      findings
        .filter((f) => f?.type === 'intel' && /shannon/i.test(`${f.value || ''} ${f.meta || ''}`))
        .map((f) => `${String(f.value || '').slice(0, 140)} — ${String(f.meta || '').slice(0, 120)}`)
        .slice(0, 4)
        .join(' | ') || null;

    void postReconWebhook(whUrl, {
      target: domain,
      runId,
      stats,
      intelMerge,
      kaliMode: Boolean(kaliMode),
      modules: modulesForDb,
      highCount: findings.filter((f) => f.prio === 'high').length,
      findingsByType,
      runDiffSummary,
      shannonSummary,
      pentestgptSummary,
    });
  }

  const whAi = process.env.GHOSTRECON_WEBHOOK_URL?.trim();
  if (whAi) {
    const picked = pickAiReportForWebhook(pipelineAiOut);
    if (picked) {
      void postAiReportWebhook(whAi, {
        target: domain,
        runId,
        provider: picked.provider,
        relatorio: picked.relatorio,
        proximos_passos: picked.proximos_passos,
      });
      if (reconDeltaForWebhook) {
        void postReconDeltaFullWebhook(whAi, {
          target: domain,
          runId,
          baselineId: reconDeltaForWebhook.baselineId,
          baselineCreatedAt: reconDeltaForWebhook.baselineCreatedAt,
          newerCreatedAt: reconDeltaForWebhook.newerCreatedAt,
          added: reconDeltaForWebhook.added,
          removedCount: reconDeltaForWebhook.removedCount,
        });
      }
    } else if (reconDeltaForWebhook) {
      void postReconDeltaFullWebhook(whAi, {
        target: domain,
        runId,
        baselineId: reconDeltaForWebhook.baselineId,
        baselineCreatedAt: reconDeltaForWebhook.baselineCreatedAt,
        newerCreatedAt: reconDeltaForWebhook.newerCreatedAt,
        added: reconDeltaForWebhook.added,
        removedCount: reconDeltaForWebhook.removedCount,
      });
    }
  }
}

app.post('/api/recon/stream', requireScope('recon.run', { intrusiveCheck: (req) => reconBodyIsIntrusive(req.body) }), async (req, res) => {
  res.setHeader('Content-Type', 'application/x-ndjson; charset=utf-8');
  res.setHeader('Cache-Control', 'no-cache, no-transform');
  res.setHeader('X-Accel-Buffering', 'no');

  const send = (obj) => {
    res.write(`${JSON.stringify(obj)}\n`);
  };

  if (!validateCsrfToken(req)) {
    send({ type: 'error', message: 'CSRF token inválido/ausente' });
    res.end();
    return;
  }

  if (!allowReconRequest(req)) {
    send({ type: 'error', message: 'Rate limit — aguarde antes de novo recon' });
    res.end();
    return;
  }

  const domainRaw = req.body?.domain;
  const modules = Array.isArray(req.body?.modules) ? req.body.modules : [];
  const exactMatch = Boolean(req.body?.exactMatch);
  const kaliMode = Boolean(req.body?.kaliMode);
  const profile = String(req.body?.profile || 'standard')
    .trim()
    .toLowerCase();
  const auth =
    req.body?.auth && typeof req.body.auth === 'object'
      ? {
          headers: req.body.auth.headers && typeof req.body.auth.headers === 'object' ? req.body.auth.headers : {},
          cookie: req.body.auth.cookie ? String(req.body.auth.cookie) : '',
        }
      : null;

  const parsed = parseReconTarget(domainRaw);
  if (!parsed.ok) {
    send({ type: 'error', message: parsed.message || 'Alvo inválido' });
    res.end();
    return;
  }

  const domain = parsed.target;

  const engagementIdRaw = req.body?.engagementId != null ? String(req.body.engagementId).trim() : '';
  const operatorRaw = req.body?.operator != null ? String(req.body.operator).trim() : '';
  const confirmActive = Boolean(req.body?.confirmActive);
  const rawOpsec = String(req.body?.opsecProfile || process.env.GHOSTRECON_OPSEC_PROFILE || 'standard')
    .trim()
    .toLowerCase();
  const allowedOpsec = new Set(['passive', 'stealth', 'standard', 'aggressive']);
  const opsecProfile = allowedOpsec.has(rawOpsec) ? rawOpsec : 'standard';
  const playbookNameForCheck =
    req.body?.playbook != null ? String(req.body.playbook).trim() : '';

  let engagement = null;
  if (engagementIdRaw) {
    try {
      engagement = await getEngagement(engagementIdRaw);
    } catch (e) {
      send({ type: 'error', message: `engagement: ${e?.message || e}` });
      res.end();
      return;
    }
    if (!engagement) {
      send({ type: 'error', message: `engagement "${engagementIdRaw}" não encontrado` });
      res.end();
      return;
    }
  }

  const checklist = preRunChecklist({
    engagement,
    target: domain,
    modules,
    playbook: playbookNameForCheck || null,
  });
  if (!checklist.ok) {
    send({
      type: 'error',
      message: 'Pré-checklist (engagement / escopo) falhou — ver campo checklist',
      checklist,
    });
    res.end();
    return;
  }
  for (const w of checklist.warnings || []) {
    send({ type: 'log', msg: `[engagement] ${w}`, level: 'warn' });
  }

  let gate;
  try {
    gate = gateModules({
      modules,
      profile: opsecProfile,
      confirm: confirmActive || process.env.GHOSTRECON_CONFIRM_ACTIVE === '1',
      engagement,
    });
  } catch (e) {
    send({ type: 'error', message: `OPSEC: ${e?.message || e}` });
    res.end();
    return;
  }
  if (!gate.ok) {
    send({
      type: 'error',
      message: gate.reason || 'Módulos bloqueados por perfil OPSEC',
      opsec: { blocked: gate.blocked, needsConfirm: gate.needsConfirm, profile: gate.profile },
    });
    res.end();
    return;
  }

  let authForPipeline = auth;
  if (engagementIdRaw) {
    const baseHeaders = { ...(auth?.headers && typeof auth.headers === 'object' ? auth.headers : {}) };
    authForPipeline = {
      headers: applyWatermarkHeaders(baseHeaders, {
        engagementId: engagementIdRaw,
        operator: operatorRaw || undefined,
      }),
      cookie: auth?.cookie ? String(auth.cookie) : '',
    };
  }

  const shannonPrecheck = req.body?.shannonPrecheck !== false;
  const shannonSkipDepsVerify = Boolean(req.body?.shannonSkipDepsVerify);
  if (modules.includes('shannon_whitebox') && shannonPrecheck && !shannonSkipDepsVerify) {
    try {
      const sc = await getShannonCapabilities({ ghostRoot: ROOT });
      if (!sc.ok) {
        send({
          type: 'error',
          message: `Shannon: dependências incompletas — ${sc.message}`,
        });
        res.end();
        return;
      }
    } catch (e) {
      send({ type: 'error', message: `Shannon: falha ao verificar dependências — ${e?.message || e}` });
      res.end();
      return;
    }
  }

  const extraPathRaw = typeof req.body?.extraPath === 'string' ? req.body.extraPath : '';
  let savedEnvPath = null;
  if (extraPathRaw.trim()) {
    savedEnvPath = process.env.PATH;
    process.env.PATH = prependExtraPathToEnvPath(extraPathRaw, savedEnvPath);
  }

  // ── Tor enforcement ────────────────────────────────────────────────────
  // Body shape:
  //   tor: {
  //     required: true,            // aborta o run se o tunnel não validar
  //     strict: true,              // exige tor-strict prereqs (proxychains, DNS lockdown…)
  //     newnymBeforeRun: true,     // sinaliza NEWNYM antes do pipeline iniciar
  //     perTargetCircuit: true,    // injeta isolation user/pass no SOCKS5 (IsolateSOCKSAuth)
  //     dnsLeakHost: 'check.tor…' // host usado para o DNS leak test (opt)
  //   }
  // Default: se GHOSTRECON_TOR_REQUIRED=1 ou GHOSTRECON_TOR_STRICT=1, força.
  const torOpts = req.body?.tor && typeof req.body.tor === 'object' ? req.body.tor : {};
  const torStrictWanted =
    torOpts.strict === true ||
    String(process.env.GHOSTRECON_TOR_STRICT || '').trim() === '1';
  const torRequired =
    torOpts.required === true ||
    torStrictWanted ||
    String(process.env.GHOSTRECON_TOR_REQUIRED || '').trim() === '1';
  let cleanupTorStrictScope = null;

  // STRICT prereq check — se faltar algo (proxychains, DNS lockdown, SOCKS,
  // ControlPort, conf), abortamos antes do pipeline para evitar leaks parciais.
  if (torStrictWanted) {
    cleanupTorStrictScope = beginTorStrictScope();
    const refusal = torRefuseToRun();
    if (refusal) {
      if (cleanupTorStrictScope) cleanupTorStrictScope();
      auditAuth(req, req.principal, 'deny', {
        action: 'recon.stream.tor_strict_prereqs',
        target: domain,
        reason: 'strict_prereqs_failed',
        missing: refusal.missing,
      });
      send({
        type: 'error',
        message: 'tor.strict: pré-requisitos em falta — ver `missing`',
        missing: refusal.missing,
        checks: refusal.checks,
      });
      res.end();
      return;
    }
  }
  let torValidation = null;
  if (torRequired) {
    send({ type: 'log', msg: '[tor] enforcement activo — a validar tunnel antes do recon', level: 'info' });
    try {
      torValidation = await quickValidateTor({ timeoutMs: 12_000 });
    } catch (e) {
      torValidation = { validated: false, error: e?.message || String(e) };
    }
    if (!torValidation.validated) {
      if (cleanupTorStrictScope) cleanupTorStrictScope();
      auditAuth(req, req.principal, 'deny', {
        action: 'recon.stream.tor_required',
        target: domain,
        reason: 'tor_validation_failed',
        torValidation,
      });
      send({
        type: 'error',
        message: 'Tor enforcement: tunnel não validado — ver detalhes em torValidation',
        torValidation,
      });
      res.end();
      return;
    }
    send({
      type: 'log',
      msg: `[tor] OK — exitIp=${torValidation.tor?.ip} bootstrap=${torValidation.control?.bootstrap?.tag} (${torValidation.durationMs}ms)`,
      level: 'info',
    });
    if (torOpts.newnymBeforeRun === true) {
      try {
        await torNewnym({ timeoutMs: 5_000 });
        send({ type: 'log', msg: '[tor] NEWNYM sinalizado', level: 'info' });
      } catch (e) {
        send({ type: 'log', msg: `[tor] NEWNYM falhou: ${e?.message || e}`, level: 'warn' });
      }
    }
  }

  const identityOpts = normalizeIdentityOptions(modules, req.body?.identity);
  // ID temporário para telemetria do tor-strict (correlacionável com runId
  // depois que saveRun emitir um). Emitimos no stream para o cliente saber.
  const requestRunId = `req-${Date.now().toString(36)}-${randomBytes(4).toString('hex')}`;
  identityOpts.runId = requestRunId;
  identityOpts.target = domain;
  // Quando torRequired + perTargetCircuit, propagamos para identity-controller
  // ativar IsolateSOCKSAuth com user/pass únicos (circuit dedicado por target).
  if (torRequired && torOpts.perTargetCircuit !== false) {
    identityOpts.isolate = true;
    identityOpts.isolationKey = `${domain}-${Date.now().toString(36)}`;
  }
  const identityCtrl = createIdentityController({ ...identityOpts, modules });
  send({ type: 'meta', requestRunId, torStrict: torStrictWanted, torRequired });
  recordReconHttpHistory({
    requestRunId,
    target: domain,
    source: 'browser',
    method: 'POST',
    url: '/api/recon/stream',
    requestHeaders: normalizeHeadersForHistory(req.headers),
    requestBody: safeJsonBodyForHistory(req.body),
    status: 200,
    statusText: 'stream',
    ok: true,
    durationMs: 0,
    emit: send,
  });

  // Auditoria operacional do início do pipeline (após CSRF/rate-limit/escopo).
  auditAuth(req, req.principal, 'allow', {
    action: 'recon.stream.start',
    target: domain,
    modules,
    kaliMode,
    opsecProfile,
    profile,
    intrusive: reconBodyIsIntrusive(req.body),
    engagementId: engagementIdRaw || null,
    tor: torRequired
      ? {
          required: true,
          exitIp: torValidation?.tor?.ip || null,
          bootstrap: torValidation?.control?.bootstrap?.tag || null,
          perTargetCircuit: torOpts.perTargetCircuit !== false,
          newnymBefore: Boolean(torOpts.newnymBeforeRun),
        }
      : { required: false },
  });

  try {
    await reconHttpContext.run({ requestRunId, target: domain, emit: send }, async () => {
      await runPipeline({
        domain,
        exactMatch,
        modules,
        emit: send,
        kaliMode,
        auth: authForPipeline,
        profile,
        outOfScope: req.body?.outOfScope,
        projectName: req.body?.projectName,
        autoAiReports: Boolean(req.body?.autoAiReports),
        aiProviderMode: String(req.body?.aiProviderMode || 'auto'),
        aiUseOpenrouter: req.body?.aiUseOpenrouter !== false,
        aiOpenrouterOnly: normalizeOpenrouterOnlyFlag(req.body?.aiOpenrouterOnly),
        aiPrimaryCloud:
          typeof req.body?.aiPrimaryCloud === 'string'
            ? req.body.aiPrimaryCloud
            : typeof req.body?.aiPrimaryReport === 'string'
              ? req.body.aiPrimaryReport
              : null,
        shannonPrecheck,
        shannonSkipDepsVerify,
        shannonGithubRepos: req.body?.shannonGithubRepos,
        pentestgptUrl: req.body?.pentestgptUrl != null ? String(req.body.pentestgptUrl) : null,
        bountyContext:
          req.body?.bountyContext && typeof req.body.bountyContext === 'object' ? req.body.bountyContext : null,
        engagementId: engagementIdRaw || null,
        engagementOperator: operatorRaw || null,
        identityCtrl,
        navegation: req.body?.navegation && typeof req.body.navegation === 'object' ? req.body.navegation : null,
      });
    });
  } catch (e) {
    send({ type: 'error', message: e?.message || String(e) });
  } finally {
    if (savedEnvPath !== null) process.env.PATH = savedEnvPath;
    if (cleanupTorStrictScope) cleanupTorStrictScope();
  }
  res.end();
});

app.get('/api/csrf-token', (req, res) => {
  const token = issueCsrfToken(req);
  res.setHeader('Cache-Control', 'no-store');
  res.json({ token, expiresInMs: CSRF_TTL_MS });
});

app.get('/api/history/recon', requireScope('recon.read'), (req, res) => {
  const limitRaw = Number(req.query.limit || 500);
  const limit = Number.isFinite(limitRaw) ? Math.max(1, Math.min(1000, Math.floor(limitRaw))) : 500;
  const target = String(req.query.target || '').trim().toLowerCase();
  const afterRaw = Number(req.query.after || 0);
  const after = Number.isFinite(afterRaw) ? Math.max(0, Math.floor(afterRaw)) : 0;
  let rows = reconHttpHistory;
  if (target) rows = rows.filter((x) => String(x.target || '').toLowerCase() === target);
  if (after > 0) rows = rows.filter((x) => Number(x.id) > after);
  res.setHeader('Cache-Control', 'no-store');
  res.json({ ok: true, count: rows.length, items: rows.slice(-limit) });
});

// ── PROXY CAPTURE API ──────────────────────────────────────────────────────
app.get('/api/proxy/status', requireScope('recon.read'), (_req, res) => {
  res.json({ ok: true, ...ghostProxy.status() });
});

app.post('/api/proxy/start', requireScope('recon.run'), async (req, res) => {
  if (!validateCsrfToken(req)) { res.status(403).json({ ok: false, error: 'CSRF inválido' }); return; }
  try {
    const result = await ghostProxy.start();
    res.json({ ok: true, ...result, ...ghostProxy.status() });
  } catch (e) {
    res.status(500).json({ ok: false, error: e?.message || String(e) });
  }
});

app.post('/api/proxy/stop', requireScope('recon.run'), async (req, res) => {
  if (!validateCsrfToken(req)) { res.status(403).json({ ok: false, error: 'CSRF inválido' }); return; }
  try {
    await ghostProxy.stop();
    res.json({ ok: true, ...ghostProxy.status() });
  } catch (e) {
    res.status(500).json({ ok: false, error: e?.message || String(e) });
  }
});

app.post('/api/proxy/mitm', requireScope('recon.run'), (req, res) => {
  if (!validateCsrfToken(req)) { res.status(403).json({ ok: false, error: 'CSRF inválido' }); return; }
  const enabled = Boolean(req.body?.enabled !== false);
  ghostProxy.setMitm(enabled);
  res.json({ ok: true, mitmEnabled: enabled, ...ghostProxy.status() });
});

app.get('/api/proxy/ca.crt', (_req, res) => {
  const cert = ghostProxy.caCert;
  if (!cert) { res.status(404).json({ ok: false, error: 'CA não gerada — OpenSSL disponível?' }); return; }
  res.setHeader('Content-Type', 'application/x-x509-ca-cert');
  res.setHeader('Content-Disposition', 'attachment; filename="ghostrecon-ca.crt"');
  res.send(cert);
});

app.get('/api/tunnel/status', async (_req, res) => {
  try {
    const status = await getNavegationTunnelStatus(ROOT);
    res.json({ ok: true, ...status });
  } catch (e) {
    res.status(500).json({ ok: false, error: e?.message || String(e) });
  }
});

app.get('/api/tunnel/validate', async (_req, res) => {
  try {
    const report = await validateNavegationTorPath(ROOT);
    res.json(report);
  } catch (e) {
    res.status(500).json({ ok: false, error: e?.message || String(e) });
  }
});

app.post('/api/tunnel/enable', requireRole('admin'), async (req, res) => {
  if (!validateCsrfToken(req)) {
    res.status(403).json({ ok: false, error: 'CSRF token inválido/ausente' });
    return;
  }
  try {
    const dryRun = Boolean(req.body?.dryRun);
    const run = await executeNavegationPlaybook(ROOT, {
      action: 'up',
      dryRun,
      timeoutMs: Number(process.env.GHOSTRECON_NAVEGATION_TIMEOUT_MS || 900000),
    });
    const status = await getNavegationTunnelStatus(ROOT);
    res.json({ ok: run.ok, run, status });
  } catch (e) {
    res.status(500).json({ ok: false, error: e?.message || String(e) });
  }
});

app.get('/api/tunnel/health', requireScope('recon.read'), async (_req, res) => {
  try {
    const health = await torControlHealth();
    res.json({ ok: true, ...health, strict: { active: torIsStrict() } });
  } catch (e) {
    res.status(500).json({ ok: false, error: e?.message || String(e) });
  }
});

app.get('/api/tunnel/strict-check', requireScope('recon.read'), async (_req, res) => {
  try {
    const p = torStrictPrereqs();
    res.json({ ok: true, ...p });
  } catch (e) {
    res.status(500).json({ ok: false, error: e?.message || String(e) });
  }
});

app.get('/api/tunnel/telemetry/:runId', requireScope('recon.read'), (req, res) => {
  const t = torSnapshotTelemetry(String(req.params.runId));
  if (!t) return res.status(404).json({ ok: false, error: 'sem telemetria para esse runId' });
  res.json({ ok: true, runId: req.params.runId, ...t });
});

app.post('/api/tunnel/newnym', requireScope('recon.run'), async (req, res) => {
  if (!validateCsrfToken(req)) {
    res.status(403).json({ ok: false, error: 'CSRF token inválido/ausente' });
    return;
  }
  try {
    const r = await torNewnym({ timeoutMs: 5_000 });
    auditAuth(req, req.principal, 'allow', { action: 'tunnel.newnym', ok: r.ok });
    res.json({ ok: true, ...r });
  } catch (e) {
    res.status(500).json({ ok: false, error: e?.message || String(e) });
  }
});

app.post('/api/tunnel/disable', requireRole('admin'), async (req, res) => {
  if (!validateCsrfToken(req)) {
    res.status(403).json({ ok: false, error: 'CSRF token inválido/ausente' });
    return;
  }
  try {
    const dryRun = Boolean(req.body?.dryRun);
    const run = await executeNavegationPlaybook(ROOT, {
      action: 'down',
      dryRun,
      timeoutMs: Number(process.env.GHOSTRECON_NAVEGATION_TIMEOUT_MS || 900000),
    });
    const status = await getNavegationTunnelStatus(ROOT);
    res.json({ ok: run.ok, run, status });
  } catch (e) {
    res.status(500).json({ ok: false, error: e?.message || String(e) });
  }
});

app.post('/api/tool-path-refresh', requireRole('admin'), (req, res) => {
  if (!validateCsrfToken(req)) {
    res.status(403).json({ ok: false, error: 'CSRF' });
    return;
  }
  try {
    const added = augmentProcessPathFromCommonDirs();
    res.json({ ok: true, added });
  } catch (e) {
    res.status(500).json({ ok: false, error: e?.message || String(e) });
  }
});

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

/** Segredos com o mesmo value_fp em mais de um alvo (requer nome de projeto na UI e achados com value_fp no meta). */
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

app.get('/api/capabilities', async (_req, res) => {
  try {
    const cap = await getKaliCapabilities();
    let shannon = null;
    try {
      shannon = await getShannonCapabilities({ ghostRoot: ROOT });
    } catch (e) {
      shannon = { ok: false, home: '', checks: {}, message: e?.message || String(e), prepHints: {} };
    }
    let pentestgpt = null;
    try {
      pentestgpt = await getPentestGptCapabilities({ ghostRoot: ROOT });
    } catch (e) {
      pentestgpt = {
        ok: false,
        home: '',
        checks: {},
        message: e?.message || String(e),
        prepHints: {},
        http: { configured: false, preview: '' },
      };
    }
    res.json({
      ...cap,
      ai: aiKeysConfigured(),
      shannon,
      pentestgpt,
    });
  } catch (e) {
    res.status(500).json({
      kali: false,
      message: e.message,
      tools: {},
      ai: aiKeysConfigured(),
      shannon: null,
      pentestgpt: null,
    });
  }
});

app.post('/api/pentestgpt-ping', requireScope('ai.run'), async (req, res) => {
  if (!validateCsrfToken(req)) {
    res.status(403).json({ ok: false, error: 'CSRF token inválido ou ausente' });
    return;
  }
  const raw = req.body?.pentestgptUrl != null ? String(req.body.pentestgptUrl).trim() : '';
  const url = resolvePentestGptUrl(raw || null);
  if (!url) {
    res.status(400).json({
      ok: false,
      error: 'Sem URL de validação: define GHOSTRECON_PENTESTGPT_URL no .env ou envia pentestgptUrl no corpo.',
    });
    return;
  }
  const health = pentestGptHealthUrl(url);
  if (!health) {
    res.status(400).json({ ok: false, error: 'URL inválida (só http/https).' });
    return;
  }
  const ac = new AbortController();
  const timer = setTimeout(() => ac.abort(), 8000);
  try {
    const fr = await fetch(health, { method: 'GET', signal: ac.signal, redirect: 'manual' });
    const text = await fr.text();
    let parsed = null;
    try {
      parsed = JSON.parse(text);
    } catch {
      /* texto plano */
    }
    res.json({
      ok: fr.ok,
      healthUrl: health,
      validateUrlPreview: url.slice(0, 120),
      status: fr.status,
      body: parsed ?? text.slice(0, 400),
    });
  } catch (e) {
    res.json({
      ok: false,
      healthUrl: health,
      validateUrlPreview: url.slice(0, 120),
      error: e?.name === 'AbortError' ? 'Timeout ao contactar /health' : e?.message || String(e),
    });
  } finally {
    clearTimeout(timer);
  }
});

app.post('/api/shannon/prep', requireScope('shannon.run'), async (req, res) => {
  if (!validateCsrfToken(req)) {
    res.status(403).json({ ok: false, error: 'CSRF token inválido ou ausente' });
    return;
  }
  const pullUpstream = Boolean(req.body?.pullUpstream);
  if (!pullUpstream) {
    res.status(400).json({
      ok: false,
      error: 'Define pullUpstream: true para puxar keygraph/shannon:latest (opcional; modo local usa shannon-worker).',
    });
    return;
  }
  try {
    const out = await shannonPullUpstreamWorkerImage();
    if (!out.ok) {
      res.status(500).json({
        ok: false,
        error: out.note || 'docker pull falhou',
        dockerPullLog: out.dockerPullLog,
      });
      return;
    }
    const shannon = await getShannonCapabilities({ ghostRoot: ROOT });
    res.json({
      ok: true,
      note: out.note,
      dockerPullLog: out.dockerPullLog,
      shannon,
    });
  } catch (e) {
    res.status(500).json({ ok: false, error: e?.message || String(e) });
  }
});

app.post('/api/ai-reports', requireScope('ai.run'), async (req, res) => {
  if (!validateCsrfToken(req)) {
    res.status(403).json({ ok: false, error: 'CSRF token inválido ou ausente' });
    return;
  }
  const payload = req.body?.payload;
  if (!payload || typeof payload !== 'object' || Array.isArray(payload)) {
    res.status(400).json({ ok: false, error: 'Corpo inválido: falta object "payload" (export JSON do pipeline).' });
    return;
  }
  const projectName = String(req.body?.projectName ?? payload.projectName ?? '').trim();
  const targetDomain = String(req.body?.targetDomain ?? payload.target ?? '').trim();
  if (!targetDomain) {
    res.status(400).json({ ok: false, error: 'Define Target ($) ou inclui "target" no payload.' });
    return;
  }
  try {
    const out = await runDualAiReports(payload, {
      projectName,
      targetDomain,
      aiProviderMode: String(req.body?.aiProviderMode || 'auto'),
      aiUseOpenrouter: req.body?.aiUseOpenrouter !== false,
      aiOpenrouterOnly: normalizeOpenrouterOnlyFlag(req.body?.aiOpenrouterOnly),
      aiPrimaryCloud:
        typeof req.body?.aiPrimaryCloud === 'string'
          ? req.body.aiPrimaryCloud
          : typeof req.body?.aiPrimaryReport === 'string'
            ? req.body.aiPrimaryReport
            : null,
    });
    const whUrl = process.env.GHOSTRECON_WEBHOOK_URL?.trim();
    if (whUrl) {
      const picked = pickAiReportForWebhook(out);
      let reconDeltaApi = null;
      const rid = payload.runId != null ? Number(payload.runId) : null;
      if (Number.isFinite(rid)) {
        try {
          const runs = await listRuns(120);
          const nt = targetDomain.trim().toLowerCase();
          const prev = runs.find((r) => String(r.target).trim().toLowerCase() === nt && r.id < rid);
          if (prev) {
            const diff = await compareRuns(prev.id, rid);
            if (!diff.error) {
              reconDeltaApi = {
                baselineId: diff.baselineId,
                baselineCreatedAt: diff.baselineCreatedAt,
                newerCreatedAt: diff.newerCreatedAt,
                added: diff.added,
                removedCount: diff.removedCount,
              };
            }
          }
        } catch (e) {
          console.warn('[GHOSTRECON webhook diff ai-reports]', e?.message || e);
        }
      }
      if (picked) {
        void postAiReportWebhook(whUrl, {
          target: targetDomain,
          runId: payload.runId ?? null,
          provider: picked.provider,
          relatorio: picked.relatorio,
          proximos_passos: picked.proximos_passos,
        });
        if (reconDeltaApi) {
          void postReconDeltaFullWebhook(whUrl, {
            target: targetDomain,
            runId: rid,
            baselineId: reconDeltaApi.baselineId,
            baselineCreatedAt: reconDeltaApi.baselineCreatedAt,
            newerCreatedAt: reconDeltaApi.newerCreatedAt,
            added: reconDeltaApi.added,
            removedCount: reconDeltaApi.removedCount,
          });
        }
      } else if (reconDeltaApi) {
        void postReconDeltaFullWebhook(whUrl, {
          target: targetDomain,
          runId: rid,
          baselineId: reconDeltaApi.baselineId,
          baselineCreatedAt: reconDeltaApi.baselineCreatedAt,
          newerCreatedAt: reconDeltaApi.newerCreatedAt,
          added: reconDeltaApi.added,
          removedCount: reconDeltaApi.removedCount,
        });
      }
    }
    res.json({ ok: true, ...out });
  } catch (e) {
    res.status(500).json({ ok: false, error: e?.message || String(e) });
  }
});

app.get('/api/ai/lmstudio-check', async (_req, res) => {
  try {
    const out = await probeLmStudioConnection();
    res.json(out);
  } catch (e) {
    res.status(503).json({ ok: false, error: e?.message || String(e) });
  }
});

app.get('/api/runs', async (req, res) => {
  const lim = Number(req.query.limit) || 50;
  try {
    const runs = await listRuns(lim);
    res.json({ runs });
  } catch (e) {
    res.status(500).json({ error: e?.message || String(e) });
  }
});

app.get('/api/runs/:id', async (req, res) => {
  const id = Number(req.params.id);
  if (!Number.isFinite(id)) {
    res.status(400).json({ error: 'id inválido' });
    return;
  }
  try {
    const run = await getRunById(id);
    if (!run) {
      res.status(404).json({ error: 'run não encontrado' });
      return;
    }
    res.json(run);
  } catch (e) {
    res.status(500).json({ error: e?.message || String(e) });
  }
});

/** Diff entre dois runs do mesmo alvo (fingerprints como `bounty_intel`). */
app.get('/api/runs/:newerId/diff/:baselineId', async (req, res) => {
  const newerId = Number(req.params.newerId);
  const baselineId = Number(req.params.baselineId);
  if (!Number.isFinite(newerId) || !Number.isFinite(baselineId)) {
    res.status(400).json({ error: 'ids inválidos' });
    return;
  }
  try {
    const result = await compareRuns(baselineId, newerId);
    if (result.error) {
      res.status(result.error === 'run não encontrado' ? 404 : 400).json(result);
      return;
    }
    res.json(result);
  } catch (e) {
    res.status(500).json({ error: e?.message || String(e) });
  }
});

/** Corpus deduplicado por alvo (`bounty_intel` — SQLite ou Supabase). */
app.get('/api/intel/:target', async (req, res) => {
  const t = String(req.params.target || '')
    .trim()
    .toLowerCase();
  if (!t || !/^[a-z0-9][a-z0-9.-]*[a-z0-9]$/.test(t)) {
    res.status(400).json({ error: 'domínio inválido' });
    return;
  }
  try {
    const [totalUnique, items] = await Promise.all([
      intelCountForTarget(t),
      listIntelForTarget(t, 500),
    ]);
    res.json({
      target: t,
      totalUnique,
      items,
    });
  } catch (e) {
    res.status(500).json({ error: e?.message || String(e) });
  }
});

function isValidManualValidationTarget(t) {
  const s = String(t || '')
    .trim()
    .toLowerCase();
  return s && /^[a-z0-9][a-z0-9.-]*[a-z0-9]$/.test(s);
}

function isSha256FingerprintHex(fp) {
  return /^[a-f0-9]{64}$/.test(String(fp || '').trim().toLowerCase());
}

/** Categorias do modo cérebro (vulnerabilidade agregada); SQLite local com seeds iniciais. */
app.get('/api/brain/categories', async (_req, res) => {
  try {
    const items = await listBrainCategories();
    res.json({ items });
  } catch (e) {
    res.status(500).json({ error: e?.message || String(e) });
  }
});

app.post('/api/brain/categories', requireScope('brain.write'), async (req, res) => {
  if (!validateCsrfToken(req)) {
    res.status(403).json({ ok: false, error: 'CSRF token inválido ou ausente' });
    return;
  }
  const title = req.body?.title;
  const description = req.body?.description;
  try {
    const out = await createBrainCategory(title, description);
    res.json({ ok: true, ...out });
  } catch (e) {
    res.status(400).json({ ok: false, error: e?.message || String(e) });
  }
});

app.post('/api/brain/categories/:id/description', requireScope('brain.write'), async (req, res) => {
  if (!validateCsrfToken(req)) {
    res.status(403).json({ ok: false, error: 'CSRF token inválido ou ausente' });
    return;
  }
  const id = Number(req.params.id);
  const description = req.body?.description;
  try {
    const out = await updateBrainCategoryDescription(id, description);
    res.json({ ok: true, category: out });
  } catch (e) {
    res.status(400).json({ ok: false, error: e?.message || String(e) });
  }
});

app.post('/api/brain/link', requireScope('brain.write'), async (req, res) => {
  if (!validateCsrfToken(req)) {
    res.status(403).json({ ok: false, error: 'CSRF token inválido ou ausente' });
    return;
  }
  const target = String(req.body?.target || '')
    .trim()
    .toLowerCase();
  const fp = String(req.body?.fingerprint || '').trim().toLowerCase();
  const categoryId = req.body?.categoryId;
  try {
    const out = await upsertBrainLink({ target, fingerprint: fp, categoryId });
    let ghostKbSync = { ok: false, skipped: true, reason: 'not_attempted' };
    try {
      const category = await getBrainCategoryById(Number(categoryId));
      const validated = await listManualValidationsForTarget(target);
      const row = validated.find((x) => String(x.fingerprint || '').trim().toLowerCase() === fp);
      ghostKbSync = await syncValidatedCortexFindingToGhostKb({
        target,
        fingerprint: fp,
        snapshot: row?.snapshot || null,
        notes: row?.notes || '',
        brainCategoryTitle: category?.title || '',
      });
    } catch (e) {
      ghostKbSync = { ok: false, error: e?.message || String(e) };
    }
    res.json({ ok: true, ...out, ghostKbSync });
  } catch (e) {
    res.status(400).json({ ok: false, error: e?.message || String(e) });
  }
});

/** Uma categoria do cérebro + achados ligados (para a página Cortex). */
app.get('/api/brain/category/:id', async (req, res) => {
  const id = Number(req.params.id);
  if (!Number.isFinite(id) || id < 1) {
    res.status(400).json({ error: 'id inválido' });
    return;
  }
  try {
    const category = await getBrainCategoryById(id);
    if (!category) {
      res.status(404).json({ error: 'categoria não encontrada' });
      return;
    }
    const links = await listBrainLinksForCategory(id);
    res.json({ category, links });
  } catch (e) {
    res.status(500).json({ error: e?.message || String(e) });
  }
});

/** Pacote Reporte→Anotações (nova aba não partilha sessionStorage; one‑time na RAM). */
const ANOTACAO_HANDOFF_TTL_MS = 20 * 60 * 1000;
const anotacaoHandoffStore = new Map();

function pruneAnotacaoHandoffStore() {
  const now = Date.now();
  for (const [k, v] of anotacaoHandoffStore) {
    if (!v || v.exp <= now) anotacaoHandoffStore.delete(k);
  }
}

app.post('/api/anotacao-handoff', requireScope('notes.write'), (req, res) => {
  if (!validateCsrfToken(req)) {
    res.status(403).json({ ok: false, error: 'CSRF token inválido ou ausente' });
    return;
  }
  const payload = req.body?.payload;
  if (!payload || typeof payload !== 'object') {
    res.status(400).json({ ok: false, error: 'Indica { payload: { target, findings, … } } no corpo.' });
    return;
  }
  pruneAnotacaoHandoffStore();
  const id = randomBytes(16).toString('hex');
  anotacaoHandoffStore.set(id, { data: payload, exp: Date.now() + ANOTACAO_HANDOFF_TTL_MS });
  res.json({ ok: true, id });
});

app.get('/api/anotacao-handoff/:id', (req, res) => {
  pruneAnotacaoHandoffStore();
  const id = String(req.params.id || '')
    .trim()
    .toLowerCase()
    .replace(/[^a-f0-9]/g, '');
  if (!/^[a-f0-9]{32}$/.test(id)) {
    res.status(400).json({ error: 'id de handoff inválido' });
    return;
  }
  const row = anotacaoHandoffStore.get(id);
  if (!row || row.exp < Date.now()) {
    res.status(404).json({ error: 'Pacote expirado ou já consumido. Volta ao Reporte e clica ANOTAÇÃO de novo.' });
    return;
  }
  anotacaoHandoffStore.delete(id);
  res.json(row.data);
});

/** Lista achados marcados como validados manualmente para o alvo (SQLite). */
app.get('/api/manual-validations/:target', async (req, res) => {
  const t = String(req.params.target || '')
    .trim()
    .toLowerCase();
  if (!isValidManualValidationTarget(t)) {
    res.status(400).json({ error: 'domínio inválido' });
    return;
  }
  try {
    const items = await listManualValidationsForTarget(t);
    res.json({ target: t, items });
  } catch (e) {
    res.status(500).json({ error: e?.message || String(e) });
  }
});

/** Marca ou desmarca validação manual (persistência por fingerprint = mesmo achado em recons futuros). */
app.post('/api/manual-validations', requireScope('validation.write'), async (req, res) => {
  if (!validateCsrfToken(req)) {
    res.status(403).json({ ok: false, error: 'CSRF token inválido ou ausente' });
    return;
  }
  const target = String(req.body?.target || '')
    .trim()
    .toLowerCase();
  const fp = String(req.body?.fingerprint || '').trim().toLowerCase();
  const validated = req.body?.validated !== false && req.body?.validated !== 0 && req.body?.validated !== 'false';
  if (!isValidManualValidationTarget(target)) {
    res.status(400).json({ ok: false, error: 'domínio inválido' });
    return;
  }
  if (!isSha256FingerprintHex(fp)) {
    res.status(400).json({ ok: false, error: 'fingerprint inválido' });
    return;
  }
  try {
    if (validated) {
      const snap = req.body?.snapshot && typeof req.body.snapshot === 'object' ? req.body.snapshot : null;
      const notes = req.body?.notes != null ? String(req.body.notes) : '';
      await upsertManualValidation({ target, fingerprint: fp, snapshot: snap, notes });
      res.json({ ok: true, target, fingerprint: fp, validated: true });
    } else {
      await deleteManualValidation(target, fp);
      res.json({ ok: true, target, fingerprint: fp, validated: false });
    }
  } catch (e) {
    res.status(400).json({ ok: false, error: e?.message || String(e) });
  }
});

/** Gera relatório por IA só com achados já validados manualmente (subset do recon). */
app.post('/api/manual-validations/ai-report', requireScope('ai.run'), async (req, res) => {
  if (!validateCsrfToken(req)) {
    res.status(403).json({ ok: false, error: 'CSRF token inválido ou ausente' });
    return;
  }
  const target = String(req.body?.target || '')
    .trim()
    .toLowerCase();
  const findingsIn = Array.isArray(req.body?.findings) ? req.body.findings : null;
  if (!isValidManualValidationTarget(target)) {
    res.status(400).json({ ok: false, error: 'domínio inválido' });
    return;
  }
  if (!findingsIn || !findingsIn.length) {
    res.status(400).json({ ok: false, error: 'Indica pelo menos um achado validado (array findings).' });
    return;
  }
  const known = new Set(
    (await listManualValidationsForTarget(target)).map((x) => String(x.fingerprint || '').toLowerCase()),
  );
  const findings = [];
  for (const f of findingsIn) {
    if (!f || typeof f !== 'object') continue;
    const fp = String(f.fingerprint || '').trim().toLowerCase();
    if (!isSha256FingerprintHex(fp) || !known.has(fp)) continue;
    findings.push({
      type: f.type,
      prio: f.prio,
      score: f.score,
      value: f.value,
      meta: f.meta,
      url: f.url,
      fingerprint: fp,
    });
  }
  if (!findings.length) {
    res.status(400).json({
      ok: false,
      error: 'Nenhum achado coincide com validações manuais gravadas na base para este alvo.',
    });
    return;
  }
  const projectName = String(req.body?.projectName ?? '').trim();
  const stats =
    req.body?.stats && typeof req.body.stats === 'object'
      ? req.body.stats
      : { subs: 0, endpoints: 0, params: 0, secrets: 0, dorks: 0, high: 0 };
  const payload = {
    schemaVersion: 1,
    source: 'ghostrecon-manual-validation-report',
    exportedAt: new Date().toISOString(),
    target,
    projectName: projectName || undefined,
    stats,
    findings,
    correlation: null,
    reportTemplates: {},
    runId: null,
    storage: storageLabel(),
    modules: ['manual_validation'],
    bountyContext: {
      note: 'Relatório pedido a partir de achados já confirmados manualmente no checklist Reporte.',
    },
  };
  const aiPrimaryRaw =
    typeof req.body?.aiPrimaryCloud === 'string'
      ? req.body.aiPrimaryCloud
      : typeof req.body?.aiPrimaryReport === 'string'
        ? req.body.aiPrimaryReport
        : null;
  try {
    const out = await runDualAiReports(payload, {
      projectName,
      targetDomain: target,
      aiProviderMode: 'auto',
      aiUseOpenrouter: req.body?.aiUseOpenrouter !== false,
      aiOpenrouterOnly: normalizeOpenrouterOnlyFlag(req.body?.aiOpenrouterOnly),
      aiPrimaryCloud: aiPrimaryRaw,
      onStatus: () => {},
      /** Reporte: OpenRouter → Gemini → LM Studio (não LM entre as duas clouds). */
      aiOpenrouterThenGeminiBeforeLm: true,
    });
    res.json({ ok: true, ...out });
  } catch (e) {
    res.status(500).json({ ok: false, error: e?.message || String(e) });
  }
});

const ANNOTATIONS_AI_SYSTEM_PT = [
  'És um redactor técnico de relatórios de segurança ofensiva (pentest / red team).',
  'Recebes anotações de campo em Markdown (português). Gera um relatório formal em Markdown, em português de Portugal, com:',
  '- Título e metadados (alvo, data se existir na entrada).',
  '- Resumo executivo (2–5 frases).',
  '- Achados e riscos (tabela ou lista) com severidade estimada quando possível a partir do texto.',
  '- Detalhe técnico por tema (portas/serviços, web, vetores, testes, exploração, impacto).',
  '- Recomendações de mitigação concretas.',
  '- Secção «Referências» só com OWASP/MITRE que apareçam nas anotações (não inventes códigos).',
  'Regras: não inventes factos, URLs, portas, CVEs ou resultados de testes que não estejam nas anotações; se algo for incerto, indica-o explicitamente como hipótese ou «não documentado nas notas».',
  'Responde apenas com o corpo Markdown do relatório (sem JSON).',
].join(' ');

/** Relatório Markdown só via OpenRouter a partir do texto das anotações do Reporte. */
app.post('/api/manual-validations/annotations-ai', requireScope('ai.run'), async (req, res) => {
  if (!validateCsrfToken(req)) {
    res.status(403).json({ ok: false, error: 'CSRF token inválido ou ausente' });
    return;
  }
  const markdown = String(req.body?.markdown || '').trim();
  if (!markdown) {
    res.status(400).json({ ok: false, error: 'Indica o campo markdown com as anotações.' });
    return;
  }
  const targetOpt = String(req.body?.target || '')
    .trim()
    .toLowerCase();
  if (targetOpt && !isValidManualValidationTarget(targetOpt)) {
    res.status(400).json({ ok: false, error: 'domínio inválido' });
    return;
  }
  const openrouterKey = process.env.OPENROUTER_API_KEY?.trim();
  if (!openrouterKey) {
    res.status(503).json({ ok: false, error: 'OPENROUTER_API_KEY não configurada no servidor.' });
    return;
  }
  const openrouterModel =
    process.env.GHOSTRECON_OPENROUTER_MODEL?.trim() || 'google/gemma-4-31b-it';
  const maxIn = Math.max(4000, Math.min(200000, Number(process.env.GHOSTRECON_ANNOTATIONS_AI_MAX_CHARS || 120000)));
  const slice = markdown.length > maxIn ? `${markdown.slice(0, maxIn)}\n\n[… texto truncado …]` : markdown;
  const userBlock = [
    targetOpt ? `Alvo (referência): ${targetOpt}` : '',
    '',
    '---',
    '',
    'Anotações do analista:',
    '',
    slice,
  ]
    .filter(Boolean)
    .join('\n');
  try {
    const out = await callOpenRouter(userBlock, openrouterKey, openrouterModel, {
      systemPrompt: ANNOTATIONS_AI_SYSTEM_PT,
      jsonObject: false,
    });
    res.json({ ok: true, markdown: String(out || '').trim() });
  } catch (e) {
    res.status(500).json({ ok: false, error: e?.message || String(e) });
  }
});

// === Extensões produzidas pelo roadmap (CLI/scheduler/playbooks/CVE/inbound/projects) ===
// Inbound webhooks: POST /api/inbound/:source e GET /api/inbound/:source/:target
registerInboundWebhooks(app);
// Rotas auxiliares (playbooks list, cve enrich on-demand, projects CRUD, evidence trigger)
registerNewApiRoutes(app, { validateCsrfToken });

app.use(express.static(ROOT, { index: false }));
app.get('/', (_req, res) => {
  res.sendFile(path.join(ROOT, 'index.html'));
});

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
