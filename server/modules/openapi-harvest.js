import { limits } from '../config.js';
import { urlInReconScope } from './scope.js';
import { stealthPause, pickStealthUserAgent } from './request-policy.js';
import { readResponseSnippet } from './module-runner.mjs';

const SPEC_PATHS = [
  '/openapi.json',
  '/swagger.json',
  '/v2/api-docs',
  '/v3/api-docs',
  '/api-docs/swagger.json',
  '/swagger/v1/swagger.json',
];

function collectParamsFromOpenApi3(doc) {
  const names = new Set();
  const paths = doc?.paths && typeof doc.paths === 'object' ? doc.paths : {};
  for (const [, methods] of Object.entries(paths)) {
    if (!methods || typeof methods !== 'object') continue;
    for (const def of Object.values(methods)) {
      if (!def || typeof def !== 'object') continue;
      const params = def.parameters;
      if (!Array.isArray(params)) continue;
      for (const p of params) {
        const n = p?.name;
        if (typeof n === 'string' && n.length < 120) names.add(n);
      }
    }
  }
  return [...names];
}

function collectParamsFromSwagger2(doc) {
  const names = new Set();
  const paths = doc?.paths && typeof doc.paths === 'object' ? doc.paths : {};
  for (const [, methods] of Object.entries(paths)) {
    if (!methods || typeof methods !== 'object') continue;
    for (const def of Object.values(methods)) {
      if (!def || typeof def !== 'object') continue;
      const params = def.parameters;
      if (!Array.isArray(params)) continue;
      for (const p of params) {
        const n = p?.name;
        if (typeof n === 'string' && n.length < 120) names.add(n);
      }
    }
  }
  return [...names];
}

/**
 * @returns {{ type:'endpoint'|'param', value, meta, url?, prio, score }[]}
 */
export async function harvestOpenApiFromOrigins(
  origins,
  domain,
  outOfScopeList,
  modules,
  log,
  scopePolicy = null,
) {
  const out = [];
  const cap = Math.max(1, Number(limits.openapiMaxOrigins ?? 10));
  const list = [...new Set(origins.map((o) => String(o).replace(/\/$/, '')))].slice(0, cap);
  const ua = pickStealthUserAgent(modules);
  const timeoutMs = Math.min(14000, limits.probeTimeoutMs || 12000);

  for (const base of list) {
    for (const sp of SPEC_PATHS) {
      await stealthPause(modules);
      let u;
      try {
        u = new URL(sp, base + '/');
      } catch {
        continue;
      }
      if (!urlInReconScope(u.href, domain, outOfScopeList, scopePolicy)) continue;
      try {
        const res = await fetch(u.href, {
          method: 'GET',
          redirect: 'manual',
          signal: AbortSignal.timeout(timeoutMs),
          headers: {
            Accept: 'application/json,*/*;q=0.8',
            'User-Agent': ua,
          },
        });
        if (!res.ok) continue;
        const ct = (res.headers.get('content-type') || '').toLowerCase();
        if (!ct.includes('json') && !ct.includes('text')) continue;
        const text = await res.text();
        if (text.length > 2_000_000) continue;
        let doc;
        try {
          doc = JSON.parse(text);
        } catch {
          continue;
        }
        const isOas3 = doc.openapi && String(doc.openapi).startsWith('3');
        const paramNames = isOas3 ? collectParamsFromOpenApi3(doc) : collectParamsFromSwagger2(doc);
        if (!paramNames.length && !doc.paths) continue;

        out.push({
          type: 'endpoint',
          prio: 'med',
          score: 64,
          value: u.href,
          meta: `OpenAPI/Swagger leak • ${isOas3 ? 'OAS3' : 'Swagger2'} • params=${paramNames.length}`,
          url: u.href,
        });
        for (const name of paramNames.slice(0, 40)) {
          out.push({
            type: 'param',
            prio: 'med',
            score: 66,
            value: `?${name}=`,
            meta: `openapi_spec • source=${u.pathname}`,
            url: u.href,
          });
        }
        if (typeof log === 'function') {
          log(`OpenAPI: ${u.href} → ${paramNames.length} parâmetro(s) em spec`, 'success');
        }
        break;
      } catch {
        /* next path */
      }
    }
  }

  return out;
}

const GQL_INTRO = JSON.stringify({
  query: 'query IntrospectionQuery { __schema { queryType { name } } }',
});
const GQL_TYPENAME = JSON.stringify({ query: 'query GhostReconTypeName { __typename }' });

async function graphqlJsonRequest(url, body, {
  fetchImpl,
  signal,
  timeoutMs,
  userAgent,
  urlAllowed,
}) {
  if (signal?.aborted) throw signal.reason || new DOMException('The operation was aborted', 'AbortError');
  if (urlAllowed && !urlAllowed(url)) return null;
  const timeoutSignal = AbortSignal.timeout(timeoutMs);
  const requestSignal = signal ? AbortSignal.any([signal, timeoutSignal]) : timeoutSignal;
  const res = await fetchImpl(url, {
    method: 'POST',
    redirect: 'manual',
    signal: requestSignal,
    headers: {
      'Content-Type': 'application/json',
      Accept: 'application/json',
      'User-Agent': userAgent,
    },
    body,
  });
  const finalUrl = res.url || url;
  if (urlAllowed && !urlAllowed(finalUrl)) return null;
  if (res.status < 200 || res.status >= 300) return { status: res.status, json: null };
  const contentLength = Number(res.headers?.get?.('content-length') || 0);
  if (contentLength > 128 * 1024) {
    await res.body?.cancel?.();
    return { status: res.status, json: null, outcome: 'response_too_large' };
  }
  const text = await readResponseSnippet(res, 128 * 1024);
  try {
    return { status: res.status, json: JSON.parse(text), url: finalUrl };
  } catch {
    return { status: res.status, json: null, url: finalUrl };
  }
}

/**
 * Um POST de introspecção mínima em /graphql (só se já existir pista no corpus).
 */
export async function tryGraphqlMinimalProbe(
  graphqlUrls,
  domain,
  outOfScopeList,
  modules,
  log,
  scopePolicy = null,
  opts = {},
) {
  const ua = pickStealthUserAgent(modules);
  const timeoutMs = Math.min(12000, limits.probeTimeoutMs || 12000);
  const seen = new Set();
  const fetchImpl = opts.fetchImpl || globalThis.fetch;
  const signal = opts.signal || null;
  const urlAllowed = opts.urlAllowed || ((url) => urlInReconScope(url, domain, outOfScopeList, scopePolicy));
  if (signal?.aborted) throw signal.reason || new DOMException('The operation was aborted', 'AbortError');
  if (typeof fetchImpl !== 'function') return [];
  for (const raw of graphqlUrls.slice(0, 4)) {
    let u;
    try {
      u = new URL(raw);
    } catch {
      continue;
    }
    if (!urlInReconScope(u.href, domain, outOfScopeList, scopePolicy)) continue;
    const key = u.origin + u.pathname;
    if (seen.has(key)) continue;
    seen.add(key);
    await stealthPause(modules);
    try {
      const common = { fetchImpl, signal, timeoutMs, userAgent: ua, urlAllowed };
      const typename = await graphqlJsonRequest(u.href, GQL_TYPENAME, common);
      const rootType = typename?.json?.data?.__typename;
      if (typeof rootType !== 'string' || !/^[_A-Za-z][_0-9A-Za-z]{0,127}$/.test(rootType)) continue;

      const introspection = await graphqlJsonRequest(u.href, GQL_INTRO, common);
      const queryType = introspection?.json?.data?.__schema?.queryType?.name;
      if (typeof queryType === 'string' && queryType === rootType) {
        log?.(`GraphQL: endpoint e introspecção observados em ${u.href}`, 'success');
        return [{
          type: 'graphql_introspection_inventory',
          prio: 'info',
          score: 28,
          value: `GraphQL introspection disponível @ ${u.pathname}`,
          meta: {
            engine: 'graphql_probe',
            status: introspection.status,
            queryType,
            evidenceStatus: 'observed_inventory',
            partialResponse: Array.isArray(introspection.json.errors) && introspection.json.errors.length > 0,
            impactVerified: false,
            note: 'Introspecção pública não é vulnerabilidade por si só.',
          },
          url: introspection.url || u.href,
        }];
      }

      if (rootType) {
        log?.(`GraphQL: endpoint respondeu a consulta inócua em ${u.href}`, 'info');
        return [{
          type: 'graphql_endpoint_inventory',
          prio: 'info',
          score: 18,
          value: `Endpoint GraphQL confirmado @ ${u.pathname}`,
          meta: {
            engine: 'graphql_probe',
            status: typename.status,
            introspection: 'not_observed',
            queryType: rootType,
            introspectionOutcome: introspection?.json ? 'not_observed' : 'inconclusive',
            impactVerified: false,
            evidenceStatus: 'observed_inventory',
          },
          url: typename.url || u.href,
        }];
      }
    } catch (error) {
      if (signal?.aborted || error?.name === 'AbortError') throw signal?.reason || error;
      log?.('GraphQL: request/parse inconclusivo; não equivale a endpoint ausente.', 'warn');
    }
  }
  return [];
}
