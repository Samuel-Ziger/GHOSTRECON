/**
 * firebase-audit.mjs
 *
 * Inventário e revisão de leituras anônimas de backends Firebase em escopo.
 * Acesso público observado não comprova exposição indevida nem impacto:
 *
 *  1. RTDB — leitura anônima superficial
 *  2. Firestore — leitura anônima em coleções observadas no cliente
 *  3. Storage — listagem pública limitada (sem download)
 *  4. RBAC client-side — inventário heurístico do router/frontend
 *
 * Este módulo é estritamente somente leitura. Probes mutáveis pertencem a uma
 * capacidade de laboratório separada e nunca são habilitados por esta API.
 */

import https from 'node:https';
import http from 'node:http';
import { AsyncLocalStorage } from 'node:async_hooks';
import {
  combineAbortSignals,
  isAbortError,
  throwIfAborted,
} from './http-utils.js';
import { readResponseSnippet } from './module-runner.mjs';
import { fetchScoped, urlAllowedOrSameOrigin } from './scoped-fetch.mjs';

const TIMEOUT_MS = 12_000;
const MAX_RESPONSE_BYTES = 64 * 1024;
const UA = 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36';
const FIRESTORE_COLLECTION_DENYLIST = new Set([
  'default', 'documents', 'firestore', 'firebase', 'undefined', 'null',
]);

const FIREBASE_CONFIG_RES = [
  { key: 'apiKey', re: /apiKey\s*[:=]\s*["'](AIza[0-9A-Za-z_-]{33,39})["']/gi },
  { key: 'projectId', re: /projectId\s*[:=]\s*["']([a-z0-9-]{3,64})["']/gi },
  { key: 'authDomain', re: /authDomain\s*[:=]\s*["']([^"']+\.firebaseapp\.com)["']/gi },
  { key: 'databaseURL', re: /databaseURL\s*[:=]\s*["'](https:\/\/[^"']+-default-rtdb\.firebaseio\.com)["']/gi },
  { key: 'storageBucket', re: /storageBucket\s*[:=]\s*["']([^"']+\.appspot\.com)["']/gi },
];

const RTDB_URL_RE = /https:\/\/([a-z0-9-]+)-default-rtdb\.firebaseio\.com/gi;
const FIRESTORE_PROJECT_RE = /firestore\.googleapis\.com\/v1\/projects\/([a-z0-9-]+)\/databases/gi;
const STORAGE_BUCKET_RE = /firebasestorage\.googleapis\.com\/v0\/b\/([^/"'\s]+)/gi;
const FIREBASE_API_KEY_RE = /\b(AIza[0-9A-Za-z_-]{35})\b/g;

function makeFinding({ type, value, score, url, meta, owasp, mitre, cvss }) {
  const prio = score >= 85 ? 'critical' : score >= 70 ? 'high' : score >= 50 ? 'med' : score >= 30 ? 'low' : 'info';
  return { type, value, score, prio, url, meta: meta || {}, owasp, mitre, cvss: cvss || null, source: 'firebase_audit' };
}

export function extractFirestoreCollectionCandidates(text, { limit = 40 } = {}) {
  const src = String(text || '').slice(0, 1_500_000);
  const out = new Set();
  const patterns = [
    /\bcollection\s*\(\s*(?:[^,]{0,100},\s*)?["']([a-zA-Z0-9_-]{1,80})["']/g,
    /\.collection\s*\(\s*["']([a-zA-Z0-9_-]{1,80})["']\s*\)/g,
    /\/documents\/([a-zA-Z0-9_-]{1,80})(?:\/|[?"'])/g,
    /\bdoc\s*\(\s*(?:[^,]{0,100},\s*)?["']([a-zA-Z0-9_-]{1,80})["']\s*,/g,
  ];
  for (const pattern of patterns) {
    pattern.lastIndex = 0;
    let match;
    while ((match = pattern.exec(src)) !== null) {
      const name = String(match[1] || '').trim();
      if (!name || FIRESTORE_COLLECTION_DENYLIST.has(name.toLowerCase())) continue;
      out.add(name);
      if (out.size >= Math.max(1, Math.min(100, Number(limit) || 40))) return [...out];
    }
  }
  return [...out];
}

const requestImplContext = new AsyncLocalStorage();

function abortReason(signal) {
  return signal?.reason || new DOMException('The operation was aborted', 'AbortError');
}

async function networkRequest(
  url,
  { method = 'GET', headers = {}, body = null, signal = null } = {},
) {
  throwIfAborted(signal);
  return new Promise((resolve, reject) => {
    let parsed;
    try { parsed = new URL(url); } catch { return resolve({ status: null, headers: {}, body: '', error: 'invalid_url' }); }
    if (!['https:', 'http:'].includes(parsed.protocol) || parsed.username || parsed.password) {
      return resolve({ status: null, headers: {}, body: '', error: 'invalid_url' });
    }

    const mod = parsed.protocol === 'https:' ? https : http;
    let settled = false;
    let req = null;
    const finishResolve = (value) => {
      if (settled) return;
      settled = true;
      signal?.removeEventListener('abort', onAbort);
      resolve(value);
    };
    const finishReject = (error) => {
      if (settled) return;
      settled = true;
      signal?.removeEventListener('abort', onAbort);
      reject(error);
    };
    const onAbort = () => {
      const reason = abortReason(signal);
      req?.destroy(reason);
      finishReject(reason);
    };
    signal?.addEventListener('abort', onAbort, { once: true });
    if (signal?.aborted) return onAbort();
    const opts = {
      hostname: parsed.hostname,
      port: parsed.port || (parsed.protocol === 'https:' ? 443 : 80),
      path: parsed.pathname + parsed.search,
      method,
      timeout: TIMEOUT_MS,
      headers: {
        'User-Agent': UA,
        Accept: 'application/json, */*',
        ...headers,
        ...(body ? { 'Content-Length': Buffer.byteLength(body) } : {}),
      },
    };

    req = mod.request(opts, (res) => {
      const resHeaders = {};
      for (const [k, v] of Object.entries(res.headers || {})) resHeaders[k.toLowerCase()] = v;
      let buf = '';
      let bytes = 0;
      res.setEncoding('utf8');
      res.on('data', (c) => {
        bytes += Buffer.byteLength(c, 'utf8');
        if (bytes > MAX_RESPONSE_BYTES) {
          finishResolve({ status: res.statusCode, headers: resHeaders, body: '', error: 'response_too_large' });
          res.destroy();
          req.destroy();
          return;
        }
        buf += c;
      });
      res.on('end', () => finishResolve({ status: res.statusCode, headers: resHeaders, body: buf, error: null }));
      res.on('error', () => finishResolve({ status: res.statusCode, headers: resHeaders, body: '', error: 'response_error' }));
      res.on('aborted', () => finishResolve({ status: res.statusCode, headers: resHeaders, body: '', error: 'response_aborted' }));
    });

    req.on('error', (e) => {
      if (isAbortError(e, signal)) finishReject(abortReason(signal));
      else finishResolve({ status: null, headers: {}, body: '', error: e.message });
    });
    req.on('timeout', () => {
      finishResolve({ status: null, headers: {}, body: '', error: 'timeout' });
      req.destroy();
    });
    if (body) req.write(body);
    req.end();
  });
}

async function rawRequest(url, options = {}) {
  const context = requestImplContext.getStore() || {};
  const requestImpl = typeof context === 'function' ? context : context.requestImpl;
  const parentSignal = options.signal && context.signal && options.signal !== context.signal
    ? AbortSignal.any([options.signal, context.signal])
    : options.signal || context.signal || null;
  const urlAllowed = context.urlAllowed || null;
  throwIfAborted(parentSignal);
  let parsed;
  try { parsed = new URL(url); } catch { return { status: null, headers: {}, body: '', error: 'invalid_url' }; }
  if (!['https:', 'http:'].includes(parsed.protocol) || parsed.username || parsed.password) {
    return { status: null, headers: {}, body: '', error: 'invalid_url' };
  }
  if (typeof urlAllowed === 'function' && urlAllowed(url) !== true) {
    return { status: null, headers: {}, body: '', error: 'out_of_scope' };
  }
  const signal = combineAbortSignals(parentSignal, context.requestTimeoutMs || TIMEOUT_MS);
  try {
    const result = typeof requestImpl === 'function'
      ? await requestImpl(url, { ...options, signal })
      : await networkRequest(url, { ...options, signal });
    throwIfAborted(parentSignal);
    if (signal.aborted) return { status: null, headers: {}, body: '', error: 'timeout' };
    if (!result || typeof result !== 'object') {
      return { status: null, headers: {}, body: '', error: 'invalid_response' };
    }
    if (result.url && typeof urlAllowed === 'function' && urlAllowed(result.url) !== true) {
      return { status: null, headers: {}, body: '', error: 'out_of_scope_redirect' };
    }
    if (result.truncated || Buffer.byteLength(String(result.body || ''), 'utf8') >= MAX_RESPONSE_BYTES
      || Number(result.headers?.['content-length']) > MAX_RESPONSE_BYTES) {
      return { status: result.status, headers: {}, body: '', error: 'response_too_large' };
    }
    return result;
  } catch (error) {
    throwIfAborted(parentSignal);
    return { status: null, headers: {}, body: '', error: signal.aborted || error?.name === 'TimeoutError' ? 'timeout' : 'network_error' };
  }
}

function withRequestImpl(requestImpl, signal, urlAllowed, requestTimeoutMs, fn) {
  throwIfAborted(signal);
  const timeout = Math.max(1, Math.min(TIMEOUT_MS, Number(requestTimeoutMs) || TIMEOUT_MS));
  return requestImplContext.run({ requestImpl, signal, urlAllowed, requestTimeoutMs: timeout }, fn);
}

function rethrowAbort(error) {
  const signal = requestImplContext.getStore()?.signal || null;
  if (isAbortError(error, signal)) throw error;
}

function collectMatches(re, text, group = 1) {
  const out = new Set();
  re.lastIndex = 0;
  let m;
  while ((m = re.exec(text)) !== null) {
    const v = m[group] || m[0];
    if (v) out.add(v);
  }
  return [...out];
}

/**
 * Extrai configuração Firebase de texto JS/HTML.
 * @returns {object|null}
 */
export function extractFirebaseConfig(text, { targetOrigin = null } = {}) {
  if (!text || typeof text !== 'string') return null;
  const cap = text.slice(0, 800_000);
  const configs = [];

  const blockRe = /firebaseConfig\s*[:=]\s*\{([^}]{20,800})\}/gi;
  let block;
  while ((block = blockRe.exec(cap)) !== null) {
    const chunk = block[1];
    const cfg = {};
    for (const { key, re } of FIREBASE_CONFIG_RES) {
      re.lastIndex = 0;
      const m = re.exec(chunk);
      if (m?.[1]) cfg[key] = m[1];
    }
    if (cfg.apiKey || cfg.projectId) configs.push(cfg);
  }

  const apiKeys = collectMatches(FIREBASE_API_KEY_RE, cap, 1);
  const projectIds = [
    ...collectMatches(FIRESTORE_PROJECT_RE, cap, 1),
    ...collectMatches(/projects\/([a-z0-9-]{3,64})\/databases/gi, cap, 1),
  ];
  const rtdbUrls = collectMatches(/https:\/\/[a-z0-9-]+-default-rtdb\.firebaseio\.com/gi, cap, 0);
  const storageBuckets = [
    ...collectMatches(STORAGE_BUCKET_RE, cap, 1),
    ...collectMatches(/storageBucket\s*[:=]\s*["']([^"']+)["']/gi, cap, 1),
  ];

  const merged = configs[0] || {};
  if (!merged.apiKey && apiKeys[0]) merged.apiKey = apiKeys[0];
  if (!merged.projectId && projectIds[0]) merged.projectId = projectIds[0];
  if (!merged.databaseURL && rtdbUrls[0]) merged.databaseURL = rtdbUrls[0];
  if (!merged.storageBucket && storageBuckets[0]) merged.storageBucket = storageBuckets[0];
  if (!merged.authDomain && merged.projectId) merged.authDomain = `${merged.projectId}.firebaseapp.com`;

  if (!merged.apiKey && !merged.projectId && !merged.databaseURL) return null;

  if (!merged.databaseURL && merged.projectId) {
    merged.databaseURL = `https://${merged.projectId}-default-rtdb.firebaseio.com`;
  }
  if (!merged.storageBucket && merged.projectId) {
    merged.storageBucket = `${merged.projectId}.appspot.com`;
  }

  merged.firestoreUrl = merged.projectId
    ? `https://firestore.googleapis.com/v1/projects/${merged.projectId}/databases/(default)/documents`
    : null;
  merged.storageUrl = merged.storageBucket
    ? `https://firebasestorage.googleapis.com/v0/b/${merged.storageBucket}/o`
    : null;
  merged.targetOrigin = targetOrigin || null;
  merged.firestoreCollections = extractFirestoreCollectionCandidates(cap);

  return merged;
}

function responseOutcome(res) {
  const status = Number.isInteger(res?.status) ? res.status : null;
  if (res?.error) {
    const reason = String(res.error);
    const state = reason === 'timeout' ? 'timeout'
      : reason.startsWith('out_of_scope') ? 'out_of_scope'
        : reason === 'response_too_large' ? 'response_too_large'
          : ['invalid_url', 'invalid_response'].includes(reason) ? reason : 'network_error';
    return { outcome: { state, status, conclusive: false } };
  }
  if (status === 401 || status === 403) {
    return { outcome: { state: 'access_denied', status, conclusive: true } };
  }
  if (status !== 200) {
    const state = status === 404 ? 'not_found' : status === 429 ? 'rate_limited' : 'http_error';
    return { outcome: { state, status, conclusive: false } };
  }
  const contentType = String(res.headers?.['content-type'] || '').toLowerCase();
  if (contentType.includes('text/html')) {
    return { outcome: { state: 'invalid_response', status, conclusive: false } };
  }
  let data;
  try {
    if (typeof res.body !== 'string' || !res.body.trim()) throw new Error('empty');
    data = JSON.parse(res.body);
  } catch {
    return { outcome: { state: 'invalid_response', status, conclusive: false } };
  }
  if (data && typeof data === 'object' && Object.hasOwn(data, 'error')) {
    const denied = data.error === 'Permission denied'
      || data.error?.status === 'PERMISSION_DENIED' || data.error?.code === 403;
    return { outcome: { state: denied ? 'access_denied' : 'api_error', status, conclusive: denied } };
  }
  return { data, status };
}

function completedRead(state, status, extra = {}) {
  return { state, status, conclusive: true, ...extra };
}

function publicReadMetadata(meta) {
  return {
    ...meta,
    evidenceStatus: 'public_read_observed',
    assessment: 'candidate_requires_owner_review',
    impactVerified: false,
    note: 'A leitura anônima pode ser intencional. A política esperada e a sensibilidade dos dados não foram verificadas.',
  };
}

async function probeRtdbRead(rtdbUrl, log) {
  const url = `${rtdbUrl.replace(/\/$/, '')}/.json?shallow=true`;
  log?.(`[firebase-audit] RTDB read: ${url}`, 'info');
  const res = await rawRequest(url);
  const parsed = responseOutcome(res);
  if (parsed.outcome) return { finding: null, outcome: parsed.outcome };
  const data = parsed.data;
  const hasData = data !== null && (typeof data !== 'object' || Object.keys(data).length > 0);
  if (hasData) {
    const bytes = Buffer.byteLength(res.body || '', 'utf8');
    return {
      finding: makeFinding({
        type: 'firebase_rtdb_public_read',
        value: `Leitura anônima superficial observada no Realtime Database (${bytes} bytes); revisar intenção`,
        score: 35,
        url,
        meta: publicReadMetadata({ bytes, status: res.status, rtdbUrl, shallow: true }),
      }),
      outcome: completedRead('public_data_observed', res.status, { bytes }),
    };
  }
  return { finding: null, outcome: completedRead('no_data_observed', res.status) };
}

async function probeFirestoreCollection(firestoreUrl, apiKey, collection, log) {
  const url = `${firestoreUrl}/${collection}?pageSize=1`;
  const res = await rawRequest(url, { headers: { 'X-Goog-Api-Key': apiKey } });
  const parsed = responseOutcome(res);
  if (parsed.outcome) return { finding: null, outcome: parsed.outcome };
  const data = parsed.data;
  if (!data || typeof data !== 'object' || Array.isArray(data)
    || (data.documents !== undefined && (!Array.isArray(data.documents)
      || data.documents.some((doc) => !doc || typeof doc.name !== 'string')))
    || (data.documents === undefined && Object.keys(data).length > 0)) {
    return { finding: null, outcome: { state: 'invalid_response', status: res.status, conclusive: false } };
  }
  if (data.documents?.length > 0) {
    const bytes = Buffer.byteLength(res.body || '', 'utf8');
    log?.(`[firebase-audit] Firestore ${collection}: leitura anônima observada (${bytes} bytes); impacto não verificado`, 'info');
    return {
      finding: makeFinding({
        type: 'firebase_firestore_public_read',
        value: `Leitura anônima observada na coleção Firestore "${collection}"; revisar intenção`,
        score: 40,
        url,
        meta: publicReadMetadata({ collection, bytes, status: res.status }),
      }),
      outcome: completedRead('public_data_observed', res.status, { bytes }),
    };
  }
  return { finding: null, outcome: completedRead('no_data_observed', res.status) };
}

async function probeStorageList(storageUrl, apiKey, log) {
  const url = `${storageUrl}?maxResults=3`;
  log?.(`[firebase-audit] Storage list: ${url}`, 'info');
  const res = await rawRequest(url, { headers: { 'X-Firebase-Storage-Key': apiKey } });
  const parsed = responseOutcome(res);
  if (parsed.outcome) return { finding: null, outcome: parsed.outcome };
  const data = parsed.data;
  if (!data || typeof data !== 'object' || Array.isArray(data)
    || (data.items !== undefined && (!Array.isArray(data.items)
      || data.items.some((item) => !item || typeof item.name !== 'string')))
    || (data.prefixes !== undefined && (!Array.isArray(data.prefixes)
      || data.prefixes.some((prefix) => typeof prefix !== 'string')))
    || (data.nextPageToken !== undefined && typeof data.nextPageToken !== 'string')
    || Object.keys(data).some((key) => !['items', 'prefixes', 'nextPageToken'].includes(key))) {
    return { finding: null, outcome: { state: 'invalid_response', status: res.status, conclusive: false } };
  }
  const itemCount = data.items?.length || 0;
  const prefixCount = data.prefixes?.length || 0;
  if (itemCount > 0 || prefixCount > 0) {
    return {
      finding: makeFinding({
        type: 'firebase_storage_public_list',
        value: `Listagem anônima observada no Firebase Storage (${itemCount} objeto(s), ${prefixCount} prefixo(s) nesta página); revisar intenção`,
        score: 35,
        url,
        meta: publicReadMetadata({ itemCount, prefixCount, status: res.status, listingOnly: true }),
      }),
      outcome: completedRead('public_data_observed', res.status, { itemCount, prefixCount }),
    };
  }
  return { finding: null, outcome: completedRead('no_data_observed', res.status) };
}

export function detectClientSideRbac(text) {
  if (!text || typeof text !== 'string') return null;
  const cap = text.slice(0, 500_000);
  const patterns = [
    /router\/permissions/i,
    /beforeEach\s*\([^)]*role/i,
    /\bhasRole\s*\(/i,
    /permissions\.js/i,
    /signInWithEmailAndPassword/i,
    /users\/\$\{?\s*(?:uid|userId|localId)/i,
  ];
  const hits = patterns.filter((re) => re.test(cap));
  if (hits.length >= 2) {
    return makeFinding({
      type: 'firebase_client_side_rbac',
      value: 'Inventário: controles Firebase/RBAC observados no frontend',
      score: 24,
      url: null,
      meta: {
        signals: hits.length,
        evidenceStatus: 'inventory',
        note: 'Não prova bypass; correlacionar apenas com rules efetivamente abertas',
      },
      owasp: 'A01:2021',
      mitre: 'T1552',
    });
  }
  return null;
}

/**
 * @param {object} context - { apiKey, projectId, databaseURL, firestoreUrl, storageUrl, authDomain, bundleText? }
 */
export async function runFirebaseAudit(context, opts = {}) {
  return withRequestImpl(opts.requestImpl, opts.signal, opts.urlAllowed, opts.requestTimeoutMs, async () => {
    const {
      apiKey, projectId, databaseURL, firestoreUrl, storageUrl, storageBucket,
      bundleText,
      firestoreCollections = [],
    } = context || {};
    const { log = null } = opts;
    if (opts.writeProbes === true) {
      log?.('[firebase-audit] writeProbes recusado: este módulo é somente leitura', 'warn');
    }

    if (!apiKey && !projectId && !databaseURL) {
      return { findings: [], summary: { skipped: 'sem config Firebase' } };
    }

    const key = apiKey || null;
    const rtdb = databaseURL || (projectId ? `https://${projectId}-default-rtdb.firebaseio.com` : null);
    const fsUrl = firestoreUrl || (projectId
      ? `https://firestore.googleapis.com/v1/projects/${projectId}/databases/(default)/documents`
      : null);
    const stUrl = storageUrl || (storageBucket
      ? `https://firebasestorage.googleapis.com/v0/b/${storageBucket}/o`
      : null);
    const networkTargets = [rtdb, fsUrl, stUrl].filter(Boolean);
    if (
      networkTargets.length > 0
      && typeof opts.urlAllowed === 'function'
      && networkTargets.every((url) => opts.urlAllowed(url) !== true)
    ) {
      log?.('[firebase-audit] Endpoints Firebase fora do escopo autorizado — probes ignorados', 'info');
      return {
        findings: [],
        summary: {
          skipped: 'firebase_out_of_scope',
          projectId: projectId || null,
          writeProbes: false,
        },
      };
    }

    log?.(`[firebase-audit] Projeto=${projectId || '?'} RTDB=${rtdb ? 'sim' : 'não'} Firestore=${fsUrl ? 'sim' : 'não'}`, 'info');

    const findings = [];
    const results = {};
    const outcomes = {};

    if (bundleText) {
      const rbac = detectClientSideRbac(bundleText);
      if (rbac) findings.push(rbac);
    }

    if (rtdb) {
      try {
        const { finding, outcome } = await probeRtdbRead(rtdb, log);
        if (finding) findings.push(finding);
        outcomes.rtdbRead = outcome;
      } catch (e) {
        rethrowAbort(e);
        log?.('[firebase-audit] RTDB read inconclusivo: erro interno', 'warn');
        outcomes.rtdbRead = { state: 'internal_error', conclusive: false };
      }
      results.rtdbRead = outcomes.rtdbRead.state;
    }

    if (fsUrl && key) {
      const observedCollections = [...new Set([
        ...(Array.isArray(firestoreCollections) ? firestoreCollections : []),
        ...extractFirestoreCollectionCandidates(bundleText),
      ].filter((collection) => typeof collection === 'string'
        && /^[a-zA-Z0-9_-]{1,80}$/.test(collection)
        && !FIRESTORE_COLLECTION_DENYLIST.has(collection.toLowerCase())))].slice(0, 40);
      const collectionOutcomes = [];
      for (const col of observedCollections) {
        try {
          const { finding, outcome } = await probeFirestoreCollection(fsUrl, key, col, log);
          if (finding) findings.push(finding);
          collectionOutcomes.push({ collection: col, ...outcome });
        } catch (error) {
          rethrowAbort(error);
          collectionOutcomes.push({ collection: col, state: 'internal_error', conclusive: false });
        }
      }
      const states = new Set(collectionOutcomes.map((outcome) => outcome.state));
      const state = !collectionOutcomes.length ? 'no_observed_collections'
        : states.size === 1 ? collectionOutcomes[0].state : 'mixed_outcomes';
      outcomes.firestoreRead = {
        state,
        conclusive: collectionOutcomes.length > 0 && collectionOutcomes.every((outcome) => outcome.conclusive),
        collections: collectionOutcomes,
      };
      results.firestoreRead = state;
    } else if (fsUrl) {
      results.firestoreRead = 'not_attempted_missing_api_key';
      outcomes.firestoreRead = { state: results.firestoreRead, conclusive: false };
    }

    if (stUrl && key) {
      try {
        const { finding, outcome } = await probeStorageList(stUrl, key, log);
        if (finding) findings.push(finding);
        outcomes.storage = outcome;
      } catch (e) {
        rethrowAbort(e);
        log?.('[firebase-audit] Storage inconclusivo: erro interno', 'warn');
        outcomes.storage = { state: 'internal_error', conclusive: false };
      }
      results.storage = outcomes.storage.state;
    } else if (stUrl) {
      results.storage = 'not_attempted_missing_api_key';
      outcomes.storage = { state: results.storage, conclusive: false };
    }

    const critical = findings.filter((f) => f.score >= 85).length;
    const high = findings.filter((f) => f.score >= 70 && f.score < 85).length;
    const inconclusive = Object.values(outcomes).some((outcome) => !outcome.conclusive);
    log?.(`[firebase-audit] Concluído: ${findings.length} observação(ões); impacto não verificado${inconclusive ? '; cobertura parcial/inconclusiva' : ''}`, 'info');

    return {
      findings,
      summary: {
        total: findings.length,
        critical,
        high,
        status: inconclusive ? 'partial' : 'completed',
        assessment: 'read_only_observations_not_vulnerability_confirmation',
        outcomes,
        results: {
          ...results,
          writeProbes: opts.writeProbes === true ? 'refused_read_only_module' : 'disabled',
        },
        projectId: projectId || null,
        writeProbes: false,
      },
    };
  });
}

/**
 * Busca homepage + bundles JS e extrai config Firebase.
 */
export async function discoverFirebaseFromTarget(
  targetUrl,
  {
    fetchImpl = null,
    log = null,
    signal = null,
    urlAllowed = null,
  } = {},
) {
  const fetchFn = fetchImpl || globalThis.fetch;
  if (!fetchFn) return { config: null, bundleText: '' };
  throwIfAborted(signal);
  if (typeof urlAllowed === 'function' && urlAllowed(targetUrl) !== true) {
    return { config: null, bundleText: '', jsUrls: [] };
  }

  let html = '';
  try {
    const res = await fetchScoped(targetUrl, {
      fetchImpl: fetchFn,
      urlAllowed: urlAllowedOrSameOrigin(targetUrl, urlAllowed),
      headers: { 'User-Agent': UA, Accept: 'text/html,*/*' },
      signal: combineAbortSignals(signal, TIMEOUT_MS),
    });
    html = await readResponseSnippet(res, 500_000);
  } catch (e) {
    if (isAbortError(e, signal)) throw e;
    log?.(`[firebase-audit] Falha ao buscar ${targetUrl}: ${e.message}`, 'warn');
    return { config: null, bundleText: html };
  }

  const origin = new URL(targetUrl).origin;
  const jsUrls = new Set();
  const jsRe = /(?:src|href)\s*=\s*["']([^"']+\.(?:js|mjs))(?:\?[^"']*)?["']/gi;
  let m;
  while ((m = jsRe.exec(html)) !== null && jsUrls.size < 8) {
    let u = m[1];
    if (u.startsWith('//')) u = `https:${u}`;
    else if (u.startsWith('/')) u = `${origin}${u}`;
    else if (!/^https?:\/\//i.test(u)) u = `${origin}/${u}`;
    jsUrls.add(u);
  }

  let bundleText = html;
  for (const jsUrl of jsUrls) {
    throwIfAborted(signal);
    if (typeof urlAllowed === 'function' && urlAllowed(jsUrl) !== true) continue;
    try {
      const r = await fetchScoped(jsUrl, {
        fetchImpl: fetchFn,
        urlAllowed: urlAllowedOrSameOrigin(targetUrl, urlAllowed),
        headers: { 'User-Agent': UA, Accept: '*/*' },
        signal: combineAbortSignals(signal, TIMEOUT_MS),
      });
      if (r.ok) bundleText += `\n${await readResponseSnippet(r, 800_000)}`;
    } catch (error) {
      if (isAbortError(error, signal)) throw error;
      /* skip */
    }
  }

  const config = extractFirebaseConfig(bundleText, { targetOrigin: origin });
  return { config, bundleText, jsUrls: [...jsUrls] };
}
