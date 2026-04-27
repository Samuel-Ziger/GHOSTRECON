/**
 * lovable-fingerprint.js
 *
 * Detecta se um target é uma aplicação gerada pela plataforma Lovable
 * (vibe-coded), extrai endpoint Supabase + anon key embutida no bundle e
 * roda probes leves de RLS contra a REST API do Supabase para sinalizar
 * apps com policies ausentes/quebradas (CVE-2025-48757).
 *
 * Saída: array de findings padrão GHOSTRECON ({ type, value, score, prio,
 * url, meta, owasp, mitre }).
 *
 * Uso:
 *   import { fingerprintLovable } from './lovable-fingerprint.js';
 *   const findings = await fingerprintLovable('https://alvo.lovable.app', { fetch });
 *
 * Segurança: o módulo só faz GETs com `?limit=0` e `?limit=1`, evitando
 * dump real de dados. NÃO escreve, não tenta INSERT/UPDATE/DELETE — quem
 * confirma write é o operador via PoC manual (ver playbooks/lovable-checklist.md).
 */

const COMMON_TABLES = [
  'users',
  'profiles',
  'orders',
  'payments',
  'tickets',
  'messages',
  'posts',
  'comments',
  'subscriptions',
  'api_keys',
  'tokens',
  'sessions',
  'invoices',
  'leads',
];

// Caminhos típicos de exposição (A05) — auto-deploy do Vite/Lovable às vezes empurra dotfiles.
const COMMON_DOTFILES = [
  { path: '/.env', severity: 'critical', label: 'dotenv' },
  { path: '/.env.production', severity: 'critical', label: 'dotenv-prod' },
  { path: '/.env.local', severity: 'critical', label: 'dotenv-local' },
  { path: '/.env.development', severity: 'high', label: 'dotenv-dev' },
  { path: '/.git/config', severity: 'high', label: 'git-config' },
  { path: '/.git/HEAD', severity: 'high', label: 'git-head' },
  { path: '/package.json', severity: 'medium', label: 'package-json' },
  { path: '/package-lock.json', severity: 'low', label: 'package-lock' },
  { path: '/yarn.lock', severity: 'low', label: 'yarn-lock' },
  { path: '/pnpm-lock.yaml', severity: 'low', label: 'pnpm-lock' },
  { path: '/composer.json', severity: 'medium', label: 'composer-json' },
  { path: '/composer.lock', severity: 'low', label: 'composer-lock' },
  { path: '/.DS_Store', severity: 'low', label: 'ds-store' },
];

// Rotas comuns que costumam responder sem auth quando o LLM "esquece" middleware.
const COMMON_AUTHLESS_ENDPOINTS = [
  '/api/admin',
  '/api/admin/users',
  '/api/users',
  '/api/users/list',
  '/api/me',
  '/api/private',
  '/api/internal',
  '/api/debug',
  '/api/stats',
  '/api/export',
  '/api/account',
  '/api/config',
  '/api/health/secrets',
];

// Headers obrigatórios pra postura mínima de segurança (A02/A05).
const REQUIRED_SECURITY_HEADERS = [
  { name: 'content-security-policy', severity: 'medium', owasp: 'A05:2021' },
  { name: 'strict-transport-security', severity: 'medium', owasp: 'A02:2021' },
  { name: 'x-frame-options', severity: 'low', owasp: 'A05:2021' },
  { name: 'x-content-type-options', severity: 'low', owasp: 'A05:2021' },
  { name: 'referrer-policy', severity: 'info', owasp: 'A05:2021' },
];

const SECRET_PATTERNS = [
  // Stripe live/test secret
  { name: 'stripe_secret', re: /\bsk_(?:live|test)_[A-Za-z0-9]{20,}\b/g, severity: 'critical' },
  // Supabase service role / anon (JWT)
  { name: 'supabase_jwt', re: /\beyJ[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}\b/g, severity: 'high' },
  // Resend
  { name: 'resend_key', re: /\bre_[A-Za-z0-9]{20,}\b/g, severity: 'high' },
  // OpenAI
  { name: 'openai_key', re: /\bsk-[A-Za-z0-9_-]{32,}\b/g, severity: 'high' },
  // Google API
  { name: 'google_api_key', re: /\bAIza[0-9A-Za-z_-]{30,}\b/g, severity: 'high' },
  // GitHub
  { name: 'github_pat', re: /\bghp_[A-Za-z0-9]{36}\b/g, severity: 'high' },
  // GitLab
  { name: 'gitlab_pat', re: /\bglpat-[A-Za-z0-9_-]{20,}\b/g, severity: 'high' },
  // Slack bot
  { name: 'slack_bot_token', re: /\bxoxb-[A-Za-z0-9-]{20,}\b/g, severity: 'high' },
];

const SUPABASE_URL_RE = /https?:\/\/([a-z0-9]{8,30})\.supabase\.co/gi;
const JS_BUNDLE_RE = /(?:src|href)\s*=\s*["']([^"']+\.(?:js|mjs))(?:\?[^"']*)?["']/gi;
const LOVABLE_HINTS = [
  /<meta\s+name=["']lovable["']/i,
  /lovable\.(app|dev|tagger|cdn)/i,
  /__LOVABLE__/,
  /data-lovable[-=]/i,
];

function decodeJwtPayload(jwt) {
  try {
    const parts = jwt.split('.');
    if (parts.length !== 3) return null;
    const pad = '='.repeat((4 - (parts[1].length % 4)) % 4);
    const b64 = parts[1].replace(/-/g, '+').replace(/_/g, '/') + pad;
    const json = typeof Buffer !== 'undefined'
      ? Buffer.from(b64, 'base64').toString('utf8')
      : atob(b64);
    return JSON.parse(json);
  } catch {
    return null;
  }
}

async function safeFetch(url, opts, fetchImpl) {
  const f = fetchImpl || globalThis.fetch;
  if (!f) throw new Error('fetch indisponível — passe opts.fetch');
  const ac = new AbortController();
  const timeout = setTimeout(() => ac.abort(), opts?.timeout ?? 12_000);
  try {
    const res = await f(url, { ...(opts || {}), signal: ac.signal });
    return res;
  } finally {
    clearTimeout(timeout);
  }
}

async function fetchText(url, fetchImpl, headers) {
  try {
    const res = await safeFetch(url, { headers: headers || {} }, fetchImpl);
    if (!res.ok) return { status: res.status, text: '' };
    const text = await res.text();
    return { status: res.status, text };
  } catch {
    return { status: 0, text: '' };
  }
}

function extractMatches(text, regex) {
  const out = new Set();
  let m;
  // reset
  regex.lastIndex = 0;
  while ((m = regex.exec(text)) !== null) {
    out.add(m[1] || m[0]);
    if (regex.lastIndex === m.index) regex.lastIndex++;
  }
  return [...out];
}

function isLovableMarkup(html) {
  for (const re of LOVABLE_HINTS) if (re.test(html)) return true;
  return false;
}

function isLovableHost(targetUrl) {
  try {
    const u = new URL(targetUrl);
    return /\.lovable\.(app|dev)$/i.test(u.hostname);
  } catch {
    return false;
  }
}

function makeFinding({ type, value, score = 50, url, meta, owasp, mitre }) {
  const prio =
    score >= 85 ? 'critical' :
    score >= 70 ? 'high' :
    score >= 50 ? 'medium' :
    score >= 30 ? 'low' : 'info';
  return {
    type,
    value,
    score,
    prio,
    url,
    meta,
    owasp: owasp || undefined,
    mitre: mitre || undefined,
    source: 'lovable-fingerprint',
  };
}

/**
 * Probe REST API do Supabase com anon key — somente leitura, limit=0/1.
 * Retorna lista de tabelas que respondem 200 sem auth (= RLS quebrado).
 */
async function probeSupabaseTables({ supabaseUrl, anonKey, fetchImpl, tables }) {
  const out = [];
  const list = tables || COMMON_TABLES;
  for (const table of list) {
    const url = `${supabaseUrl}/rest/v1/${encodeURIComponent(table)}?select=*&limit=1`;
    try {
      const res = await safeFetch(url, {
        headers: {
          apikey: anonKey,
          Authorization: `Bearer ${anonKey}`,
          'Accept-Profile': 'public',
        },
      }, fetchImpl);
      if (res.status === 200) {
        let rowCount = 0;
        let sample = null;
        try {
          const data = await res.json();
          if (Array.isArray(data)) {
            rowCount = data.length;
            // não vazar PII em finding — só os nomes de coluna
            if (data[0] && typeof data[0] === 'object') {
              sample = Object.keys(data[0]);
            }
          }
        } catch {
          /* ignore */
        }
        out.push({ table, status: 200, rowCount, sampleKeys: sample });
      } else if (res.status === 401 || res.status === 403) {
        // tabela existe ou não, mas RLS bloqueou → ok
      } else if (res.status === 404) {
        // tabela não existe — ignora
      }
    } catch {
      /* ignore */
    }
  }
  return out;
}

/**
 * Probe de dotfiles / lockfiles / config files expostos. Só sinaliza 200
 * com um shape mínimo coerente (evita falso positivo em SPA que devolve
 * o `index.html` em qualquer rota).
 */
async function probeDotfiles({ targetUrl, fetchImpl }) {
  const out = [];
  for (const entry of COMMON_DOTFILES) {
    let url;
    try {
      url = new URL(entry.path, targetUrl).href;
    } catch {
      continue;
    }
    try {
      const res = await safeFetch(url, { headers: { Accept: '*/*' } }, fetchImpl);
      if (res.status !== 200) continue;
      const ct = (res.headers?.get?.('content-type') || '').toLowerCase();
      const body = await res.text();
      const looksLikeHtml = /<html[\s>]/i.test(body) || /<!doctype html/i.test(body);
      if (looksLikeHtml) continue; // SPA fallback — descarta

      const valid =
        (entry.label === 'package-json' && /"dependencies"|"name"\s*:/.test(body)) ||
        (entry.label === 'composer-json' && /"require"\s*:/.test(body)) ||
        (entry.label.startsWith('dotenv') && /^[A-Z][A-Z0-9_]+\s*=/m.test(body)) ||
        (entry.label === 'git-config' && /\[core\]/i.test(body)) ||
        (entry.label === 'git-head' && /^ref:\s*refs\//i.test(body)) ||
        (entry.label === 'package-lock' && /"lockfileVersion"/.test(body)) ||
        (entry.label === 'yarn-lock' && /^# THIS IS AN AUTOGENERATED FILE/m.test(body)) ||
        (entry.label === 'pnpm-lock' && /^lockfileVersion:/m.test(body)) ||
        (entry.label === 'composer-lock' && /"_readme"|"packages"/.test(body)) ||
        (entry.label === 'ds-store' && body.length > 16) ||
        (ct.includes('json') && body.startsWith('{'));

      if (!valid) continue;

      // Extrair tech versions de package.json para feeding em cve-hints
      let extra = {};
      if (entry.label === 'package-json') {
        try {
          const pkg = JSON.parse(body);
          const deps = { ...(pkg.dependencies || {}), ...(pkg.devDependencies || {}) };
          extra.deps = Object.entries(deps).slice(0, 80).map(([n, v]) => `${n}@${v}`);
          extra.depCount = Object.keys(deps).length;
        } catch {
          /* ignore */
        }
      }

      // Mascarar conteúdo .env — só nomes das chaves
      if (entry.label.startsWith('dotenv')) {
        const keys = [...body.matchAll(/^([A-Z][A-Z0-9_]+)\s*=/gm)].map((m) => m[1]).slice(0, 30);
        extra.envKeyNames = keys;
      }

      out.push({ ...entry, url, contentType: ct, bodySize: body.length, extra });
    } catch {
      /* ignore */
    }
  }
  return out;
}

/**
 * Probe de source maps a partir dos bundles JS encontrados — bundles em prod
 * frequentemente vêm com `.map` companheiro pelo build do Vite.
 */
async function probeSourceMaps({ targetUrl, bundleUrls, fetchImpl }) {
  const out = [];
  for (const js of bundleUrls.slice(0, 6)) {
    let mapUrl;
    try {
      mapUrl = new URL(js, targetUrl).href + '.map';
    } catch {
      continue;
    }
    try {
      const res = await safeFetch(mapUrl, {}, fetchImpl);
      if (res.status !== 200) continue;
      const body = await res.text();
      if (!/"version"\s*:\s*\d/.test(body) || !/"sources"\s*:/.test(body)) continue;
      let sourceCount = 0;
      try {
        const j = JSON.parse(body);
        sourceCount = Array.isArray(j.sources) ? j.sources.length : 0;
      } catch {
        /* ignore */
      }
      out.push({ url: mapUrl, sourceCount, bodySize: body.length });
    } catch {
      /* ignore */
    }
  }
  return out;
}

/**
 * Probe CORS — manda Origin atacante e checa se servidor reflete.
 */
async function probeCorsPermissive({ targetUrl, fetchImpl }) {
  const attackerOrigin = 'https://attacker-cors-test.invalid';
  try {
    const res = await safeFetch(targetUrl, {
      method: 'GET',
      headers: { Origin: attackerOrigin },
    }, fetchImpl);
    const aco = res.headers?.get?.('access-control-allow-origin') || '';
    const acc = res.headers?.get?.('access-control-allow-credentials') || '';
    if (!aco) return null;
    const reflects = aco === attackerOrigin || aco === '*';
    if (!reflects) return null;
    return {
      acao: aco,
      acac: acc,
      criticalCombo: aco === attackerOrigin && acc.toLowerCase() === 'true',
    };
  } catch {
    return null;
  }
}

/**
 * Probe de rotas comuns sem `Authorization`. 200 sem auth = `api_no_auth`.
 */
async function probeAuthlessEndpoints({ targetUrl, fetchImpl }) {
  const out = [];
  for (const path of COMMON_AUTHLESS_ENDPOINTS) {
    let url;
    try {
      url = new URL(path, targetUrl).href;
    } catch {
      continue;
    }
    try {
      const res = await safeFetch(url, { method: 'GET' }, fetchImpl);
      if (res.status !== 200) continue;
      const body = await res.text();
      const ct = (res.headers?.get?.('content-type') || '').toLowerCase();
      const looksLikeHtml = /<html[\s>]/i.test(body) || /<!doctype html/i.test(body);
      if (looksLikeHtml) continue; // SPA fallback
      const looksJsonish = ct.includes('json') || /^[\[{]/.test(body.trim());
      if (!looksJsonish) continue;
      out.push({ path, url, bodySize: body.length, contentType: ct });
    } catch {
      /* ignore */
    }
  }
  return out;
}

/**
 * Avalia headers de segurança ausentes na resposta root.
 */
function analyzeSecurityHeadersFromResponse(rootHeaders) {
  const missing = [];
  if (!rootHeaders) return missing;
  const lower = new Map();
  if (typeof rootHeaders.entries === 'function') {
    for (const [k, v] of rootHeaders.entries()) lower.set(k.toLowerCase(), v);
  } else if (typeof rootHeaders === 'object') {
    for (const k of Object.keys(rootHeaders)) lower.set(k.toLowerCase(), rootHeaders[k]);
  }
  for (const h of REQUIRED_SECURITY_HEADERS) {
    if (!lower.has(h.name)) missing.push(h);
  }
  return missing;
}

async function fetchWithHeaders(url, fetchImpl, headers) {
  try {
    const res = await safeFetch(url, { headers: headers || {} }, fetchImpl);
    return { status: res.status, headers: res.headers, text: await res.text() };
  } catch {
    return { status: 0, headers: null, text: '' };
  }
}

/**
 * Pipeline principal: dado um target HTTP, devolve findings.
 *
 * @param {string} targetUrl - ex.: https://alvo.lovable.app
 * @param {object} [opts]
 * @param {Function} [opts.fetch] - fetch a usar (default: globalThis.fetch)
 * @param {boolean} [opts.probeRls=true] - rodar probes Supabase
 * @param {boolean} [opts.probeMisconfig=true] - rodar A05/A07/A02 (dotfiles, source maps, CORS, auth-less, headers)
 * @param {string[]} [opts.tables] - lista de tabelas a probar (default: comuns)
 * @param {number} [opts.maxJsBundles=8] - quantos bundles JS analisar
 * @returns {Promise<{ isLovable: boolean, findings: object[], context: object }>}
 */
export async function fingerprintLovable(targetUrl, opts = {}) {
  const fetchImpl = opts.fetch || globalThis.fetch;
  const probeRls = opts.probeRls !== false;
  const probeMisconfig = opts.probeMisconfig !== false;
  const maxBundles = Math.max(1, Math.min(20, opts.maxJsBundles ?? 8));

  const findings = [];
  const context = {
    targetUrl,
    isLovable: false,
    supabaseUrl: null,
    anonKey: null,
    anonKeyClaims: null,
    bundlesScanned: 0,
    secretsFound: [],
    rlsBrokenTables: [],
    dotfilesExposed: [],
    sourceMapsExposed: [],
    corsPermissive: null,
    authlessEndpoints: [],
    missingSecurityHeaders: [],
  };

  // 1) Buscar HTML root (com headers para análise A02/A05)
  const rootFull = await fetchWithHeaders(targetUrl, fetchImpl);
  const root = { status: rootFull.status, text: rootFull.text };
  if (!root.text && !isLovableHost(targetUrl)) {
    return { isLovable: false, findings, context };
  }

  // 2) Fingerprint Lovable
  const lovableFromHtml = isLovableMarkup(root.text);
  const lovableFromHost = isLovableHost(targetUrl);
  context.isLovable = lovableFromHtml || lovableFromHost;

  if (context.isLovable) {
    findings.push(makeFinding({
      type: 'tech_fingerprint',
      value: 'Lovable platform',
      score: 25,
      url: targetUrl,
      meta: {
        evidence: lovableFromHost ? 'hostname *.lovable.app/dev' : 'meta/markup hints',
        platform: 'lovable',
        framework_hint: 'react+vite+tailwind+supabase',
      },
    }));
  }

  // 3) Achar URL Supabase + bundles JS
  const allText = [root.text];
  const supabaseUrls = new Set(extractMatches(root.text, SUPABASE_URL_RE).map((m) => `https://${m}.supabase.co`));
  const bundles = extractMatches(root.text, JS_BUNDLE_RE).slice(0, maxBundles);

  // 4) Baixar bundles (parcial — apenas para grep de secret/URL Supabase)
  for (const rel of bundles) {
    let absUrl;
    try {
      absUrl = new URL(rel, targetUrl).href;
    } catch {
      continue;
    }
    const r = await fetchText(absUrl, fetchImpl);
    if (!r.text) continue;
    context.bundlesScanned++;
    allText.push(r.text);
    for (const m of extractMatches(r.text, SUPABASE_URL_RE)) {
      supabaseUrls.add(`https://${m}.supabase.co`);
    }
  }

  // 5) Pegar primeira URL Supabase como projeto canônico
  const supabaseUrl = [...supabaseUrls][0] || null;
  context.supabaseUrl = supabaseUrl;

  if (supabaseUrl) {
    findings.push(makeFinding({
      type: 'supabase_endpoint',
      value: supabaseUrl,
      score: 20,
      url: targetUrl,
      meta: { source: 'bundle/html grep' },
    }));
  }

  // 6) Caçar secrets em todo texto coletado
  const seenSecrets = new Set();
  for (const block of allText) {
    for (const pat of SECRET_PATTERNS) {
      for (const sec of extractMatches(block, pat.re)) {
        const key = `${pat.name}:${sec}`;
        if (seenSecrets.has(key)) continue;
        seenSecrets.add(key);

        // Heurística: para JWT, decodificar p/ saber se é supabase anon vs service_role
        let extra = {};
        let prioBoost = 0;
        if (pat.name === 'supabase_jwt') {
          const claims = decodeJwtPayload(sec);
          if (claims) {
            extra = {
              jwt_role: claims.role || null,
              jwt_iss: claims.iss || null,
              jwt_ref: claims.ref || null,
              jwt_exp: claims.exp || null,
            };
            // service_role no bundle é catastrófico
            if (claims.role === 'service_role') prioBoost = 40;
            // anon no bundle é esperado (mas habilita RLS attacks)
            if (claims.role === 'anon') {
              context.anonKey = sec;
              context.anonKeyClaims = claims;
            }
          }
        }

        const score =
          (pat.severity === 'critical' ? 90 : pat.severity === 'high' ? 75 : 50) + prioBoost;

        // Mascarar secret no value para evitar leak em log/UI (mostrar prefixo)
        const masked = sec.length > 16 ? `${sec.slice(0, 12)}…(${sec.length}c)` : sec;

        findings.push(makeFinding({
          type: pat.name === 'supabase_jwt' && extra.jwt_role === 'anon'
            ? 'supabase_anon_key_embedded'
            : 'secret_exposed_client',
          value: `${pat.name}: ${masked}`,
          score,
          url: targetUrl,
          meta: { pattern: pat.name, secret_masked: masked, ...extra },
          owasp: 'A07:2021',
          mitre: 'T1552.001',
        }));

        context.secretsFound.push({ pattern: pat.name, masked, ...extra });
      }
    }
  }

  // 7) Probe RLS — só se tivermos URL + anon key
  if (probeRls && supabaseUrl && context.anonKey) {
    const broken = await probeSupabaseTables({
      supabaseUrl,
      anonKey: context.anonKey,
      fetchImpl,
      tables: opts.tables,
    });
    context.rlsBrokenTables = broken;

    for (const b of broken) {
      findings.push(makeFinding({
        type: 'supabase_rls_missing',
        value: `Tabela ${b.table} acessível com anon key (${b.rowCount} row${b.rowCount === 1 ? '' : 's'} retornada${b.rowCount === 1 ? '' : 's'})`,
        score: 90,
        url: `${supabaseUrl}/rest/v1/${b.table}?select=*&limit=1`,
        meta: {
          table: b.table,
          rowCount: b.rowCount,
          columns: b.sampleKeys || [],
          cve: 'CVE-2025-48757',
          cvss: 8.26,
          remediation: 'Habilitar RLS na tabela e definir policies SELECT/INSERT/UPDATE/DELETE separadas. Confirmar via curl com a anon key embutida no bundle.',
        },
        owasp: 'A01:2021',
        mitre: 'T1190',
      }));
    }

    if (broken.length === 0) {
      findings.push(makeFinding({
        type: 'supabase_rls_probe_clean',
        value: `Probe de RLS em ${COMMON_TABLES.length} tabelas comuns não encontrou leitura aberta com anon key`,
        score: 10,
        url: supabaseUrl,
        meta: {
          probedTables: opts.tables || COMMON_TABLES,
          note: 'Probe heurístico — RLS pode ainda estar mal configurada em tabelas customizadas. Inspecionar JS bundle para `.from(...)` queries e re-probar.',
        },
      }));
    }
  } else if (probeRls && supabaseUrl && !context.anonKey) {
    findings.push(makeFinding({
      type: 'supabase_anon_key_not_found',
      value: 'Endpoint Supabase identificado mas anon key não foi extraída do bundle — probe de RLS pulado',
      score: 15,
      url: supabaseUrl,
      meta: { note: 'Tente analisar bundles dinâmicos / lazy chunks manualmente.' },
    }));
  }

  // ===========================================================================
  // 8) Probes de misconfiguration (A05/A07/A02/A06/A08)
  // ===========================================================================

  if (probeMisconfig) {
    // 8a) Dotfiles / lockfiles / config (A05/A06)
    const dot = await probeDotfiles({ targetUrl, fetchImpl });
    context.dotfilesExposed = dot;
    for (const f of dot) {
      const score =
        f.severity === 'critical' ? 92 :
        f.severity === 'high' ? 80 :
        f.severity === 'medium' ? 55 : 35;
      findings.push(makeFinding({
        type: 'expose_dotfile',
        value: `${f.label} acessível em ${new URL(f.url).pathname}`,
        score,
        url: f.url,
        meta: {
          path: new URL(f.url).pathname,
          contentType: f.contentType,
          bodySize: f.bodySize,
          ...(f.extra || {}),
          remediation:
            'Mover artefatos de build para fora do diretório servido publicamente (ex.: configurar `vite build` para emitir em `dist/` e servir só `dist/assets/*`). Adicionar `.env*` e `.git` no `.dockerignore` / config de hosting (Netlify, Vercel, Cloudflare Pages).',
        },
        owasp: 'A05:2021',
        mitre: 'T1083',
      }));
    }

    // 8b) Source maps em produção (A05)
    if (bundles.length) {
      const maps = await probeSourceMaps({ targetUrl, bundleUrls: bundles, fetchImpl });
      context.sourceMapsExposed = maps;
      for (const m of maps) {
        findings.push(makeFinding({
          type: 'expose_sourcemap',
          value: `Source map exposto em prod (${m.sourceCount} sources)`,
          score: 55,
          url: m.url,
          meta: {
            sourceCount: m.sourceCount,
            bodySize: m.bodySize,
            remediation:
              'Configurar `build.sourcemap: false` no Vite/Lovable para builds de produção, ou hospedar `.map` apenas em ambiente privado de monitoring (Sentry, Datadog).',
          },
          owasp: 'A05:2021',
          mitre: 'T1592.002',
        }));
      }
    }

    // 8c) CORS permissivo (A05)
    const cors = await probeCorsPermissive({ targetUrl, fetchImpl });
    context.corsPermissive = cors;
    if (cors) {
      findings.push(makeFinding({
        type: 'cors_permissive',
        value: cors.criticalCombo
          ? `CORS reflete Origin atacante com Allow-Credentials: true`
          : `CORS permissivo: ACAO=${cors.acao}`,
        score: cors.criticalCombo ? 78 : 45,
        url: targetUrl,
        meta: {
          accessControlAllowOrigin: cors.acao,
          accessControlAllowCredentials: cors.acac,
          remediation:
            'Allowlist explícito de origins; nunca refletir Origin recebido. `Allow-Credentials: true` exige origin específico (não `*`).',
        },
        owasp: 'A05:2021',
        mitre: 'T1190',
      }));
    }

    // 8d) Endpoints sem auth (A07)
    const authless = await probeAuthlessEndpoints({ targetUrl, fetchImpl });
    context.authlessEndpoints = authless;
    for (const a of authless) {
      findings.push(makeFinding({
        type: 'api_no_auth',
        value: `${a.path} responde 200 sem Authorization (${a.bodySize}b ${a.contentType || '?'})`,
        score: 80,
        url: a.url,
        meta: {
          path: a.path,
          contentType: a.contentType,
          bodySize: a.bodySize,
          remediation:
            'Aplicar middleware de autenticação/RLS em **todas** as rotas mutáveis. Default deny; allow-list para rotas públicas. Validar `Authorization` server-side mesmo se o front já o faz.',
        },
        owasp: 'A07:2021',
        mitre: 'T1078',
      }));
    }

    // 8e) Headers de segurança ausentes (A02/A05)
    const missing = analyzeSecurityHeadersFromResponse(rootFull.headers);
    context.missingSecurityHeaders = missing.map((h) => h.name);
    if (missing.length >= 3) {
      // só sinaliza quando faltam 3+ — 1-2 isolados é ruído.
      const score = missing.some((h) => h.name === 'content-security-policy' || h.name === 'strict-transport-security') ? 40 : 25;
      findings.push(makeFinding({
        type: 'security_headers_missing',
        value: `${missing.length} headers de segurança ausentes (${missing.map((h) => h.name).join(', ')})`,
        score,
        url: targetUrl,
        meta: {
          missing: missing.map((h) => h.name),
          remediation:
            'Adicionar CSP (mesmo `default-src \'self\'` é melhor que nada), HSTS (`max-age=31536000; includeSubDomains`), `X-Frame-Options: DENY`, `X-Content-Type-Options: nosniff`, `Referrer-Policy: strict-origin-when-cross-origin`.',
        },
        owasp: 'A05:2021',
        mitre: 'T1056',
      }));
    }
  }

  return { isLovable: context.isLovable, findings, context };
}

export const _internals = {
  COMMON_TABLES,
  COMMON_DOTFILES,
  COMMON_AUTHLESS_ENDPOINTS,
  REQUIRED_SECURITY_HEADERS,
  SECRET_PATTERNS,
  decodeJwtPayload,
  isLovableHost,
  isLovableMarkup,
  probeDotfiles,
  probeSourceMaps,
  probeCorsPermissive,
  probeAuthlessEndpoints,
  analyzeSecurityHeadersFromResponse,
};

export default fingerprintLovable;
      out.push({ path, url, bodySize: body.length, contentType: ct });
    } catch {
      /* ignore */
    }
  }
  return out;
}

/**
 * Avalia headers de segurança ausentes na resposta root.
 */
function analyzeSecurityHeadersFromResponse(rootHeaders) {
  const missing = [];
  if (!rootHeaders) return missing;
  const lower = new Map();
  if (typeof rootHeaders.entries === 'function') {
    for (const [k, v] of rootHeaders.entries()) lower.set(k.toLowerCase(), v);
  } else if (typeof rootHeaders === 'object') {
    for (const k of Object.keys(rootHeaders)) lower.set(k.toLowerCase(), rootHeaders[k]);
  }
  for (const h of REQUIRED_SECURITY_HEADERS) {
    if (!lower.has(h.name)) missing.push(h);
  }
  return missing;
}

async function fetchWithHeaders(url, fetchImpl, headers) {
  try {
    const res = await safeFetch(url, { headers: headers || {} }, fetchImpl);
    return { status: res.status, headers: res.headers, text: await res.text() };
  } catch {
    return { status: 0, headers: null, text: '' };
  }
}

/**
 * Pipeline principal: dado um target HTTP, devolve findings.
 *
 * @param {string} targetUrl
 * @param {object} [opts]
 * @param {Function} [opts.fetch]
 * @param {boolean} [opts.probeRls=true]
 * @param {boolean} [opts.probeMisconfig=true]
 * @param {string[]} [opts.tables]
 * @param {number} [opts.maxJsBundles=8]
 * @returns {Promise<{ isLovable: boolean, findings: object[], context: object }>}
 */
export async function fingerprintLovable(targetUrl, opts = {}) {
  const fetchImpl = opts.fetch || globalThis.fetch;
  const probeRls = opts.probeRls !== false;
  const probeMisconfig = opts.probeMisconfig !== false;
  const maxBundles = Math.max(1, Math.min(20, opts.maxJsBundles ?? 8));

  const findings = [];
  const context = {
    targetUrl,
    isLovable: false,
    supabaseUrl: null,
    anonKey: null,
    anonKeyClaims: null,
    bundlesScanned: 0,
    secretsFound: [],
    rlsBrokenTables: [],
    dotfilesExposed: [],
    sourceMapsExposed: [],
    corsPermissive: null,
    authlessEndpoints: [],
    missingSecurityHeaders: [],
  };

  // 1) Buscar HTML root
  const rootFull = await fetchWithHeaders(targetUrl, fetchImpl);
  const root = { status: rootFull.status, text: rootFull.text };
  if (!root.text && !isLovableHost(targetUrl)) {
    return { isLovable: false, findings, context };
  }

  // 2) Fingerprint Lovable
  const lovableFromHtml = isLovableMarkup(root.text);
  const lovableFromHost = isLovableHost(targetUrl);
  context.isLovable = lovableFromHtml || lovableFromHost;

  if (context.isLovable) {
    findings.push(makeFinding({
      type: 'tech_fingerprint',
      value: 'Lovable platform',
      score: 25,
      url: targetUrl,
      meta: {
        evidence: lovableFromHost ? 'hostname *.lovable.app/dev' : 'meta/markup hints',
        platform: 'lovable',
        framework_hint: 'react+vite+tailwind+supabase',
      },
    }));
  }

  // 3) Achar URL Supabase + bundles JS
  const allText = [root.text];
  const supabaseUrls = new Set(extractMatches(root.text, SUPABASE_URL_RE).map((m) => `https://${m}.supabase.co`));
  const bundles = extractMatches(root.text, JS_BUNDLE_RE).slice(0, maxBundles);

  // 4) Baixar bundles
  for (const rel of bundles) {
    let absUrl;
    try {
      absUrl = new URL(rel, targetUrl).href;
    } catch {
      continue;
    }
    const r = await fetchText(absUrl, fetchImpl);
    if (!r.text) continue;
    context.bundlesScanned++;
    allText.push(r.text);
    for (const m of extractMatches(r.text, SUPABASE_URL_RE)) {
      supabaseUrls.add(`https://${m}.supabase.co`);
    }
  }

  // 5) URL Supabase canônica
  const supabaseUrl = [...supabaseUrls][0] || null;
  context.supabaseUrl = supabaseUrl;

  if (supabaseUrl) {
    findings.push(makeFinding({
      type: 'supabase_endpoint',
      value: supabaseUrl,
      score: 20,
      url: targetUrl,
      meta: { source: 'bundle/html grep' },
    }));
  }

  // 6) Secrets
  const seenSecrets = new Set();
  for (const block of allText) {
    for (const pat of SECRET_PATTERNS) {
      for (const sec of extractMatches(block, pat.re)) {
        const key = `${pat.name}:${sec}`;
        if (seenSecrets.has(key)) continue;
        seenSecrets.add(key);

        let extra = {};
        let prioBoost = 0;
        if (pat.name === 'supabase_jwt') {
          const claims = decodeJwtPayload(sec);
          if (claims) {
            extra = {
              jwt_role: claims.role || null,
              jwt_iss: claims.iss || null,
              jwt_ref: claims.ref || null,
              jwt_exp: claims.exp || null,
            };
            if (claims.role === 'service_role') prioBoost = 40;
            if (claims.role === 'anon') {
              context.anonKey = sec;
              context.anonKeyClaims = claims;
            }
          }
        }

        const score =
          (pat.severity === 'critical' ? 90 : pat.severity === 'high' ? 75 : 50) + prioBoost;
        const masked = sec.length > 16 ? `${sec.slice(0, 12)}...(${sec.length}c)` : sec;

        findings.push(makeFinding({
          type: pat.name === 'supabase_jwt' && extra.jwt_role === 'anon'
            ? 'supabase_anon_key_embedded'
            : 'secret_exposed_client',
          value: `${pat.name}: ${masked}`,
          score,
          url: targetUrl,
          meta: { pattern: pat.name, secret_masked: masked, ...extra },
          owasp: 'A07:2021',
          mitre: 'T1552.001',
        }));

        context.secretsFound.push({ pattern: pat.name, masked, ...extra });
      }
    }
  }

  // 7) Probe RLS
  if (probeRls && supabaseUrl && context.anonKey) {
    const broken = await probeSupabaseTables({
      supabaseUrl,
      anonKey: context.anonKey,
      fetchImpl,
      tables: opts.tables,
    });
    context.rlsBrokenTables = broken;

    for (const b of broken) {
      findings.push(makeFinding({
        type: 'supabase_rls_missing',
        value: `Tabela ${b.table} acessivel com anon key (${b.rowCount} row${b.rowCount === 1 ? '' : 's'})`,
        score: 90,
        url: `${supabaseUrl}/rest/v1/${b.table}?select=*&limit=1`,
        meta: {
          table: b.table,
          rowCount: b.rowCount,
          columns: b.sampleKeys || [],
          cve: 'CVE-2025-48757',
          cvss: 8.26,
          remediation: 'Habilitar RLS na tabela e definir policies SELECT/INSERT/UPDATE/DELETE separadas.',
        },
        owasp: 'A01:2021',
        mitre: 'T1190',
      }));
    }

    if (broken.length === 0) {
      findings.push(makeFinding({
        type: 'supabase_rls_probe_clean',
        value: `Probe de RLS em ${COMMON_TABLES.length} tabelas comuns nao encontrou leitura aberta`,
        score: 10,
        url: supabaseUrl,
        meta: {
          probedTables: opts.tables || COMMON_TABLES,
          note: 'Probe heuristico - verificar tabelas customizadas via .from(...) no bundle.',
        },
      }));
    }
  } else if (probeRls && supabaseUrl && !context.anonKey) {
    findings.push(makeFinding({
      type: 'supabase_anon_key_not_found',
      value: 'Endpoint Supabase identificado mas anon key nao foi extraida do bundle',
      score: 15,
      url: supabaseUrl,
      meta: { note: 'Tente analisar bundles dinamicos / lazy chunks manualmente.' },
    }));
  }

  // 8) Misconfiguration probes (A05/A07/A02)
  if (probeMisconfig) {
    // 8a) Dotfiles
    const dot = await probeDotfiles({ targetUrl, fetchImpl });
    context.dotfilesExposed = dot;
    for (const f of dot) {
      const score =
        f.severity === 'critical' ? 92 :
        f.severity === 'high' ? 80 :
        f.severity === 'medium' ? 55 : 35;
      findings.push(makeFinding({
        type: 'expose_dotfile',
        value: `${f.label} acessivel em ${new URL(f.url).pathname}`,
        score,
        url: f.url,
        meta: {
          path: new URL(f.url).pathname,
          contentType: f.contentType,
          bodySize: f.bodySize,
          ...(f.extra || {}),
          remediation: 'Mover artefatos de build para fora do diretorio servido. Adicionar .env*/.git no .dockerignore / config de hosting.',
        },
        owasp: 'A05:2021',
        mitre: 'T1083',
      }));
    }

    // 8b) Source maps
    if (bundles.length) {
      const maps = await probeSourceMaps({ targetUrl, bundleUrls: bundles, fetchImpl });
      context.sourceMapsExposed = maps;
      for (const m of maps) {
        findings.push(makeFinding({
          type: 'expose_sourcemap',
          value: `Source map exposto em prod (${m.sourceCount} sources)`,
          score: 55,
          url: m.url,
          meta: {
            sourceCount: m.sourceCount,
            bodySize: m.bodySize,
            remediation: 'Configurar build.sourcemap: false em prod, ou mover .map para Sentry/Datadog privado.',
          },
          owasp: 'A05:2021',
          mitre: 'T1592.002',
        }));
      }
    }

    // 8c) CORS
    const cors = await probeCorsPermissive({ targetUrl, fetchImpl });
    context.corsPermissive = cors;
    if (cors) {
      findings.push(makeFinding({
        type: 'cors_permissive',
        value: cors.criticalCombo
          ? 'CORS reflete Origin atacante com Allow-Credentials: true'
          : `CORS permissivo: ACAO=${cors.acao}`,
        score: cors.criticalCombo ? 78 : 45,
        url: targetUrl,
        meta: {
          accessControlAllowOrigin: cors.acao,
          accessControlAllowCredentials: cors.acac,
          remediation: 'Allowlist de origins; nunca refletir Origin recebido. Allow-Credentials: true exige origin especifico.',
        },
        owasp: 'A05:2021',
        mitre: 'T1190',
      }));
    }

    // 8d) Auth-less endpoints
    const authless = await probeAuthlessEndpoints({ targetUrl, fetchImpl });
    context.authlessEndpoints = authless;
    for (const a of authless) {
      findings.push(makeFinding({
        type: 'api_no_auth',
        value: `${a.path} responde 200 sem Authorization (${a.bodySize}b ${a.contentType || '?'})`,
        score: 80,
        url: a.url,
        meta: {
          path: a.path,
          contentType: a.contentType,
          bodySize: a.bodySize,
          remediation: 'Aplicar middleware de auth/RLS em todas as rotas mutaveis. Default deny; allow-list para rotas publicas.',
        },
        owasp: 'A07:2021',
        mitre: 'T1078',
      }));
    }

    // 8e) Security headers
    const missing = analyzeSecurityHeadersFromResponse(rootFull.headers);
    context.missingSecurityHeaders = missing.map((h) => h.name);
    if (missing.length >= 3) {
      const score = missing.some((h) => h.name === 'content-security-policy' || h.name === 'strict-transport-security') ? 40 : 25;
      findings.push(makeFinding({
        type: 'security_headers_missing',
        value: `${missing.length} headers de seguranca ausentes (${missing.map((h) => h.name).join(', ')})`,
        score,
        url: targetUrl,
        meta: {
          missing: missing.map((h) => h.name),
          remediation: 'Adicionar CSP, HSTS, X-Frame-Options, X-Content-Type-Options, Referrer-Policy.',
        },
        owasp: 'A05:2021',
        mitre: 'T1056',
      }));
    }
  }

  return { isLovable: context.isLovable, findings, context };
}

export const _internals = {
  COMMON_TABLES,
  COMMON_DOTFILES,
  COMMON_AUTHLESS_ENDPOINTS,
  REQUIRED_SECURITY_HEADERS,
  SECRET_PATTERNS,
  decodeJwtPayload,
  isLovableHost,
  isLovableMarkup,
  probeDotfiles,
  probeSourceMaps,
  probeCorsPermissive,
  probeAuthlessEndpoints,
  analyzeSecurityHeadersFromResponse,
};

export default fingerprintLovable;
diation: 'Aplicar middleware de auth/RLS em todas as rotas mutaveis. Default deny; allow-list para rotas publicas.',
        },
        owasp: 'A07:2021',
        mitre: 'T1078',
      }));
    }

    // 8e) Security headers
    const missing = analyzeSecurityHeadersFromResponse(rootFull.headers);
    context.missingSecurityHeaders = missing.map((h) => h.name);
    if (missing.length >= 3) {
      const score = missing.some((h) => h.name === 'content-security-policy' || h.name === 'strict-transport-security') ? 40 : 25;
      findings.push(makeFinding({
        type: 'security_headers_missing',
        value: missing.length + ' headers de seguranca ausentes (' + missing.map((h) => h.name).join(', ') + ')',
        score,
        url: targetUrl,
        meta: {
          missing: missing.map((h) => h.name),
          remediation: 'Adicionar CSP, HSTS, X-Frame-Options, X-Content-Type-Options, Referrer-Policy.',
        },
        owasp: 'A05:2021',
        mitre: 'T1056',
      }));
    }
  }

  return { isLovable: context.isLovable, findings, context };
}

export const _internals = {
  COMMON_TABLES,
  COMMON_DOTFILES,
  COMMON_AUTHLESS_ENDPOINTS,
  REQUIRED_SECURITY_HEADERS,
  SECRET_PATTERNS,
  decodeJwtPayload,
  isLovableHost,
  isLovableMarkup,
  probeDotfiles,
  probeSourceMaps,
  probeCorsPermissive,
  probeAuthlessEndpoints,
  analyzeSecurityHeadersFromResponse,
};

export default fingerprintLovable;
= {
  COMMON_TABLES,
  COMMON_DOTFILES,
  COMMON_AUTHLESS_ENDPOINTS,
  REQUIRED_SECURITY_HEADERS,
  SECRET_PATTERNS,
  decodeJwtPayload,
  isLovableHost,
  isLovableMarkup,
  probeDotfiles,
  probeSourceMaps,
  probeCorsPermissive,
  probeAuthlessEndpoints,
  analyzeSecurityHeadersFromResponse,
};

export default fingerprintLovable;
