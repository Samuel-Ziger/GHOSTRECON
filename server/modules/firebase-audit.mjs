/**
 * firebase-audit.mjs
 *
 * Auditoria generalista de backends Firebase expostos via SPA.
 * Cobre classes de vulnerabilidade comuns em apps Vue/React + Firebase:
 *
 *  1. RTDB — leitura/escrita anônima (rules abertas)
 *  2. Firestore — leitura/escrita anônima em coleções sensíveis
 *  3. Storage — listagem/download público
 *  4. Auth — cadastro público habilitado (Identity Toolkit signUp)
 *  5. RBAC client-side — autorização só no router/frontend
 *  6. Escalação — Firestore aceita escrita em users/{uid} sem token
 *
 * Probes de escrita usam marcador AUDIT_MARKER e fazem cleanup automático.
 * Não cria contas persistentes nem altera dados de produção além do PoC efêmero.
 */

import https from 'node:https';
import http from 'node:http';

const TIMEOUT_MS = 12_000;
const UA = 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36';
const AUDIT_MARKER = 'ghostrecon_audit_poc';

const FIRESTORE_COLLECTIONS = [
  'users', 'profiles', 'user', 'accounts', 'admin', 'admin_users', 'roles',
  'totem', 'orders', 'products', 'settings', 'config', 'configuracao',
  'messages', 'notifications', 'subscriptions', 'payments', 'logs',
  'userFranqueado', 'compras', 'cupons', 'molduras',
];

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
  const prio = score >= 85 ? 'critical' : score >= 70 ? 'high' : score >= 50 ? 'medium' : score >= 30 ? 'low' : 'info';
  return { type, value, score, prio, url, meta: meta || {}, owasp, mitre, cvss: cvss || null, source: 'firebase_audit' };
}

async function rawRequest(url, { method = 'GET', headers = {}, body = null } = {}) {
  return new Promise((resolve) => {
    let parsed;
    try { parsed = new URL(url); } catch { return resolve({ status: null, headers: {}, body: '', error: 'invalid_url' }); }

    const mod = parsed.protocol === 'https:' ? https : http;
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

    const req = mod.request(opts, (res) => {
      const resHeaders = {};
      for (const [k, v] of Object.entries(res.headers || {})) resHeaders[k.toLowerCase()] = v;
      let buf = '';
      res.setEncoding('utf8');
      res.on('data', (c) => { buf += c; if (buf.length > 65536) req.destroy(); });
      res.on('end', () => resolve({ status: res.statusCode, headers: resHeaders, body: buf, error: null }));
    });

    req.on('error', (e) => resolve({ status: null, headers: {}, body: '', error: e.message }));
    req.on('timeout', () => { req.destroy(); resolve({ status: null, headers: {}, body: '', error: 'timeout' }); });
    if (body) req.write(body);
    req.end();
  });
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

  return merged;
}

function parseJsonSafe(body) {
  try { return JSON.parse(body); } catch { return null; }
}

function firestoreHasDocuments(body) {
  const j = parseJsonSafe(body);
  return Boolean(j?.documents?.length);
}

function rtdbLooksPublic(body, status) {
  if (status !== 200) return false;
  const trimmed = String(body || '').trim();
  if (!trimmed || trimmed === 'null') return false;
  const j = parseJsonSafe(trimmed);
  if (j?.error === 'Permission denied') return false;
  if (typeof j === 'object' && j !== null && Object.keys(j).length > 0) return true;
  return trimmed.length > 80;
}

async function probeRtdbRead(rtdbUrl, log) {
  const url = `${rtdbUrl.replace(/\/$/, '')}/.json?shallow=true`;
  log?.(`[firebase-audit] RTDB read: ${url}`, 'info');
  const res = await rawRequest(url);
  if (res.error) return { finding: null, detail: { error: res.error } };

  if (rtdbLooksPublic(res.body, res.status)) {
    const bytes = Buffer.byteLength(res.body || '', 'utf8');
    return {
      finding: makeFinding({
        type: 'firebase_rtdb_public_read',
        value: `Realtime Database legível sem autenticação (${bytes} bytes em shallow read)`,
        score: 92,
        url,
        meta: { bytes, status: res.status, rtdbUrl },
        owasp: 'A01:2021',
        mitre: 'T1190',
        cvss: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N',
      }),
      detail: { bytes, status: res.status },
    };
  }
  return { finding: null, detail: { status: res.status, blocked: true } };
}

async function probeRtdbWrite(rtdbUrl, log) {
  const path = `/${AUDIT_MARKER}.json`;
  const url = `${rtdbUrl.replace(/\/$/, '')}${path}`;
  const payload = JSON.stringify({ marker: AUDIT_MARKER, ts: new Date().toISOString() });
  log?.(`[firebase-audit] RTDB write probe: ${url}`, 'info');

  const put = await rawRequest(url, {
    method: 'PUT',
    headers: { 'Content-Type': 'application/json' },
    body: payload,
  });

  let finding = null;
  if (put.status === 200 && !String(put.body).includes('Permission denied')) {
    finding = makeFinding({
      type: 'firebase_rtdb_public_write',
      value: 'Realtime Database aceita escrita anônima (PUT sem Authorization)',
      score: 95,
      url,
      meta: { status: put.status, rtdbUrl },
      owasp: 'A01:2021',
      mitre: 'T1565',
      cvss: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:H',
    });
  }

  await rawRequest(url, { method: 'DELETE' });
  return { finding, detail: { status: put.status } };
}

async function probeFirestoreCollection(firestoreUrl, apiKey, collection, log) {
  const url = `${firestoreUrl}/${collection}?pageSize=1`;
  const res = await rawRequest(url, { headers: { 'X-Goog-Api-Key': apiKey } });
  if (res.error) return null;

  if (res.status === 200 && firestoreHasDocuments(res.body)) {
    const bytes = Buffer.byteLength(res.body || '', 'utf8');
    log?.(`[firebase-audit] Firestore ${collection}: leitura anônima (${bytes} bytes)`, 'warn');
    return makeFinding({
      type: 'firebase_firestore_public_read',
      value: `Firestore coleção "${collection}" legível sem autenticação`,
      score: collection === 'users' ? 94 : 88,
      url,
      meta: { collection, bytes, status: res.status },
      owasp: 'A01:2021',
      mitre: 'T1530',
      cvss: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N',
    });
  }
  return null;
}

async function probeFirestoreWrite(firestoreUrl, apiKey, log) {
  const url = `${firestoreUrl}/${AUDIT_MARKER}`;
  const body = JSON.stringify({ fields: { marker: { stringValue: AUDIT_MARKER } } });
  log?.(`[firebase-audit] Firestore write probe: ${url}`, 'info');

  const post = await rawRequest(url, {
    method: 'POST',
    headers: { 'X-Goog-Api-Key': apiKey, 'Content-Type': 'application/json' },
    body,
  });

  let finding = null;
  const j = parseJsonSafe(post.body);
  if (post.status === 200 && j?.name) {
    finding = makeFinding({
      type: 'firebase_firestore_public_write',
      value: 'Firestore aceita criação de documentos sem autenticação',
      score: 93,
      url,
      meta: { status: post.status, docName: j.name },
      owasp: 'A01:2021',
      mitre: 'T1565',
      cvss: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:L',
    });
    await rawRequest(`https://firestore.googleapis.com/v1/${j.name}`, {
      method: 'DELETE',
      headers: { 'X-Goog-Api-Key': apiKey },
    });
  } else {
    const patchUrl = `${firestoreUrl}/${AUDIT_MARKER}/probe-doc?updateMask.fieldPaths=marker`;
    const patch = await rawRequest(patchUrl, {
      method: 'PATCH',
      headers: { 'X-Goog-Api-Key': apiKey, 'Content-Type': 'application/json' },
      body: JSON.stringify({ fields: { marker: { stringValue: AUDIT_MARKER } } }),
    });
    if (patch.status === 200 && !parseJsonSafe(patch.body)?.error) {
      finding = makeFinding({
        type: 'firebase_firestore_public_write',
        value: 'Firestore aceita PATCH/upsert de documentos sem autenticação',
        score: 93,
        url: patchUrl,
        meta: { status: patch.status },
        owasp: 'A01:2021',
        mitre: 'T1565',
      });
      await rawRequest(`${firestoreUrl}/${AUDIT_MARKER}/probe-doc`, {
        method: 'DELETE',
        headers: { 'X-Goog-Api-Key': apiKey },
      });
    }
  }
  return finding;
}

async function probeFirestoreUsersWrite(firestoreUrl, apiKey, log) {
  const uid = `${AUDIT_MARKER}_uid`;
  const url = `${firestoreUrl}/users/${uid}?updateMask.fieldPaths=role&updateMask.fieldPaths=status`;
  const body = JSON.stringify({
    fields: {
      role: { arrayValue: { values: [{ stringValue: 'ADMIN' }] } },
      status: { stringValue: 'AUDIT_TEST' },
    },
  });
  log?.('[firebase-audit] Firestore users/{uid} write probe (escalação simulada)', 'info');

  const res = await rawRequest(url, {
    method: 'PATCH',
    headers: { 'X-Goog-Api-Key': apiKey, 'Content-Type': 'application/json' },
    body,
  });

  let finding = null;
  const j = parseJsonSafe(res.body);
  if (res.status === 200 && j?.fields && !j?.error) {
    finding = makeFinding({
      type: 'firebase_privilege_escalation_chain',
      value: 'Firestore permite gravar users/{uid} com role ADMIN sem autenticação — cadeia Auth+Firestore exposta',
      score: 96,
      url,
      meta: {
        uid,
        chain: 'signUp → PATCH users/{localId} com role admin → login no painel',
        note: 'PoC efêmero — documento removido após teste',
      },
      owasp: 'A01:2021',
      mitre: 'T1548',
      cvss: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N',
    });
  }

  await rawRequest(`${firestoreUrl}/users/${uid}`, {
    method: 'DELETE',
    headers: { 'X-Goog-Api-Key': apiKey },
  });
  return finding;
}

async function probeStorageList(storageUrl, apiKey, log) {
  const url = `${storageUrl}?maxResults=3`;
  log?.(`[firebase-audit] Storage list: ${url}`, 'info');
  const res = await rawRequest(url, { headers: { 'X-Firebase-Storage-Key': apiKey } });
  const j = parseJsonSafe(res.body);

  if (res.status === 200 && Array.isArray(j?.items) && j.items.length > 0) {
    return makeFinding({
      type: 'firebase_storage_public_list',
      value: `Firebase Storage listável sem autenticação (${j.items.length}+ objeto(s))`,
      score: 78,
      url,
      meta: { itemCount: j.items.length, sample: j.items.slice(0, 3).map((i) => i.name) },
      owasp: 'A01:2021',
      mitre: 'T1530',
    });
  }
  return null;
}

async function probePublicSignUp(apiKey, refererOrigin, log) {
  const email = `ghostrecon.audit.${Date.now()}@ghostrecon.invalid`;
  const url = `https://identitytoolkit.googleapis.com/v1/accounts:signUp?key=${apiKey}`;
  log?.('[firebase-audit] Auth signUp probe (e-mail descartável)', 'info');

  const headers = { 'Content-Type': 'application/json' };
  if (refererOrigin) {
    headers.Referer = `${refererOrigin}/`;
    headers.Origin = refererOrigin.replace(/\/$/, '');
  }

  const res = await rawRequest(url, {
    method: 'POST',
    headers,
    body: JSON.stringify({ email, password: 'GhostReconAudit!2026', returnSecureToken: true }),
  });

  const j = parseJsonSafe(res.body);
  if (j?.localId) {
    const idToken = j.idToken;
    if (idToken) {
      await rawRequest(`https://identitytoolkit.googleapis.com/v1/accounts:delete?key=${apiKey}`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', ...(refererOrigin ? { Referer: `${refererOrigin}/` } : {}) },
        body: JSON.stringify({ idToken }),
      });
    }
    return makeFinding({
      type: 'firebase_public_signup',
      value: 'Cadastro público Firebase Auth habilitado (accounts:signUp)',
      score: 72,
      url,
      meta: { note: 'Conta de teste criada e removida automaticamente' },
      owasp: 'A07:2021',
      mitre: 'T1078',
    });
  }

  const msg = j?.error?.message || '';
  if (/OPERATION_NOT_ALLOWED|ADMIN_ONLY/i.test(msg)) return null;

  if (/referer.*blocked/i.test(msg)) {
    return makeFinding({
      type: 'firebase_signup_referrer_gated',
      value: 'Cadastro Auth bloqueado por referrer na apiKey (mitigação parcial)',
      score: 35,
      url,
      meta: { message: msg.slice(0, 120) },
      owasp: 'A07:2021',
    });
  }
  return null;
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
      value: 'Autorização Firebase/RBAC aparenta depender só do frontend (router + Firestore read pós-login)',
      score: 58,
      url: null,
      meta: { signals: hits.length, hint: 'Combinar com rules abertas = bypass total via API direta' },
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
  const {
    apiKey, projectId, databaseURL, firestoreUrl, storageUrl, storageBucket,
    targetOrigin, bundleText,
  } = context || {};
  const { targetUrl = '', log = null, writeProbes = true } = opts;

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
  const origin = targetOrigin || (targetUrl ? new URL(targetUrl).origin : null);

  log?.(`[firebase-audit] Projeto=${projectId || '?'} RTDB=${rtdb ? 'sim' : 'não'} Firestore=${fsUrl ? 'sim' : 'não'}`, 'info');

  const findings = [];
  const results = {};

  if (bundleText) {
    const rbac = detectClientSideRbac(bundleText);
    if (rbac) findings.push(rbac);
  }

  if (rtdb) {
    try {
      const { finding } = await probeRtdbRead(rtdb, log);
      if (finding) findings.push(finding);
      results.rtdbRead = finding ? 'vulneravel' : 'ok';
    } catch (e) {
      log?.(`[firebase-audit] RTDB read erro: ${e.message}`, 'warn');
      results.rtdbRead = 'erro';
    }

    if (writeProbes) {
      try {
        const { finding } = await probeRtdbWrite(rtdb, log);
        if (finding) findings.push(finding);
        results.rtdbWrite = finding ? 'vulneravel' : 'ok';
      } catch (e) {
        log?.(`[firebase-audit] RTDB write erro: ${e.message}`, 'warn');
        results.rtdbWrite = 'erro';
      }
    }
  }

  if (fsUrl && key) {
    const exposedCollections = [];
    for (const col of FIRESTORE_COLLECTIONS) {
      try {
        const f = await probeFirestoreCollection(fsUrl, key, col, log);
        if (f) {
          findings.push(f);
          exposedCollections.push(col);
        }
      } catch { /* skip */ }
    }
    results.firestoreRead = exposedCollections.length ? exposedCollections.join(',') : 'ok';

    if (writeProbes) {
      try {
        const fw = await probeFirestoreWrite(fsUrl, key, log);
        if (fw) findings.push(fw);
        results.firestoreWrite = fw ? 'vulneravel' : 'ok';
      } catch (e) {
        log?.(`[firebase-audit] Firestore write erro: ${e.message}`, 'warn');
      }

      try {
        const pe = await probeFirestoreUsersWrite(fsUrl, key, log);
        if (pe) findings.push(pe);
        results.privilegeEscalation = pe ? 'vulneravel' : 'ok';
      } catch (e) {
        log?.(`[firebase-audit] Privilege escalation probe erro: ${e.message}`, 'warn');
      }
    }
  }

  if (stUrl && key) {
    try {
      const f = await probeStorageList(stUrl, key, log);
      if (f) findings.push(f);
      results.storage = f ? 'vulneravel' : 'ok';
    } catch (e) {
      log?.(`[firebase-audit] Storage erro: ${e.message}`, 'warn');
    }
  }

  if (key) {
    try {
      const su = await probePublicSignUp(key, origin, log);
      if (su) findings.push(su);
      results.signUp = su?.type || 'ok';
    } catch (e) {
      log?.(`[firebase-audit] signUp probe erro: ${e.message}`, 'warn');
    }
  }

  const critical = findings.filter((f) => f.score >= 85).length;
  const high = findings.filter((f) => f.score >= 70 && f.score < 85).length;
  log?.(`[firebase-audit] Concluído: ${findings.length} achado(s) — ${critical} crítico(s), ${high} alto(s)`, findings.length ? 'warn' : 'info');

  return {
    findings,
    summary: { total: findings.length, critical, high, results, projectId: projectId || null },
  };
}

/**
 * Busca homepage + bundles JS e extrai config Firebase.
 */
export async function discoverFirebaseFromTarget(targetUrl, { fetchImpl = null, log = null } = {}) {
  const fetchFn = fetchImpl || globalThis.fetch;
  if (!fetchFn) return { config: null, bundleText: '' };

  let html = '';
  try {
    const res = await fetchFn(targetUrl, {
      headers: { 'User-Agent': UA, Accept: 'text/html,*/*' },
      signal: AbortSignal.timeout(TIMEOUT_MS),
    });
    html = await res.text();
  } catch (e) {
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
    try {
      const r = await fetchFn(jsUrl, {
        headers: { 'User-Agent': UA, Accept: '*/*' },
        signal: AbortSignal.timeout(TIMEOUT_MS),
      });
      if (r.ok) bundleText += `\n${await r.text()}`;
    } catch { /* skip */ }
  }

  const config = extractFirebaseConfig(bundleText, { targetOrigin: origin });
  return { config, bundleText, jsUrls: [...jsUrls] };
}
