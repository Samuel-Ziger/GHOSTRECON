import { createHash } from 'node:crypto';
import { limits } from '../config.js';
import { urlInReconScope } from './scope.js';
import { pickStealthUserAgent, stealthPause } from './request-policy.js';
import { readResponseSnippet } from './module-runner.mjs';

export const moduleManifest = {
  id: 'api_contract_diff',
  name: 'API Contract Diff',
  category: 'surface',
  intrusive: false,
  requiresAuth: false,
  requiresKali: false,
  timeoutMs: 30_000,
  concurrency: 2,
  outputs: ['finding'],
};

const SPEC_PATHS = [
  '/openapi.json',
  '/swagger.json',
  '/v2/api-docs',
  '/v3/api-docs',
  '/api-docs/swagger.json',
  '/swagger/v1/swagger.json',
];

const HTTP_METHODS = new Set(['get', 'post', 'put', 'patch', 'delete', 'options', 'head', 'trace']);

function stableJson(value) {
  if (Array.isArray(value)) return `[${value.map(stableJson).join(',')}]`;
  if (value && typeof value === 'object') {
    return `{${Object.keys(value).sort().map((k) => `${JSON.stringify(k)}:${stableJson(value[k])}`).join(',')}}`;
  }
  return JSON.stringify(value);
}

function sha256(value) {
  return createHash('sha256').update(String(value)).digest('hex');
}

function getSecuritySchemes(doc) {
  const a = doc?.components?.securitySchemes;
  const b = doc?.securityDefinitions;
  const src = a && typeof a === 'object' ? a : b && typeof b === 'object' ? b : {};
  return Object.entries(src).map(([name, def]) => ({
    name,
    type: String(def?.type || ''),
    scheme: String(def?.scheme || ''),
    in: String(def?.in || ''),
  })).sort((x, y) => x.name.localeCompare(y.name));
}

function paramKey(p) {
  if (!p || typeof p !== 'object') return '';
  const name = String(p.name || '').trim();
  if (!name) return '';
  return `${String(p.in || 'query')}:${name}`;
}

export function collectOpenApiSummary(doc, { url = '' } = {}) {
  const paths = doc?.paths && typeof doc.paths === 'object' ? doc.paths : {};
  const operations = [];
  const params = new Set();
  const securitySchemes = getSecuritySchemes(doc);
  const globalSecurity = Array.isArray(doc?.security) && doc.security.length > 0;
  let operationsWithoutSecurity = 0;

  for (const [pathName, pathItem] of Object.entries(paths)) {
    if (!pathItem || typeof pathItem !== 'object') continue;
    const pathParams = Array.isArray(pathItem.parameters) ? pathItem.parameters.map(paramKey).filter(Boolean) : [];
    for (const [methodRaw, op] of Object.entries(pathItem)) {
      const method = String(methodRaw).toLowerCase();
      if (!HTTP_METHODS.has(method) || !op || typeof op !== 'object') continue;
      const opParams = Array.isArray(op.parameters) ? op.parameters.map(paramKey).filter(Boolean) : [];
      for (const p of [...pathParams, ...opParams]) params.add(p);
      const opSecurity = Array.isArray(op.security) ? op.security : null;
      const hasSecurity = opSecurity ? opSecurity.length > 0 : globalSecurity;
      if (!hasSecurity) operationsWithoutSecurity += 1;
      operations.push({
        id: `${method.toUpperCase()} ${pathName}`,
        method: method.toUpperCase(),
        path: pathName,
        operationId: String(op.operationId || ''),
        tags: Array.isArray(op.tags) ? op.tags.map(String).sort() : [],
        params: [...new Set([...pathParams, ...opParams])].sort(),
        requestBody: Boolean(op.requestBody),
        responses: op.responses && typeof op.responses === 'object' ? Object.keys(op.responses).sort() : [],
        hasSecurity,
      });
    }
  }

  operations.sort((a, b) => a.id.localeCompare(b.id));
  const summary = {
    schemaVersion: 1,
    url,
    version: String(doc?.openapi || doc?.swagger || 'unknown'),
    title: String(doc?.info?.title || ''),
    apiVersion: String(doc?.info?.version || ''),
    pathCount: Object.keys(paths).length,
    operationCount: operations.length,
    paramCount: params.size,
    securitySchemes,
    operationsWithoutSecurity,
    operations,
  };
  summary.hash = sha256(stableJson({
    version: summary.version,
    title: summary.title,
    apiVersion: summary.apiVersion,
    securitySchemes,
    operations,
  }));
  return summary;
}

function setDiff(a, b) {
  const bSet = new Set(b);
  return a.filter((x) => !bSet.has(x));
}

export function diffOpenApiSummaries(previous, current) {
  if (!previous || !current) return null;
  const prevOps = (previous.operations || []).map((o) => o.id).sort();
  const curOps = (current.operations || []).map((o) => o.id).sort();
  const prevParams = new Set();
  const curParams = new Set();
  for (const op of previous.operations || []) for (const p of op.params || []) prevParams.add(`${op.id}:${p}`);
  for (const op of current.operations || []) for (const p of op.params || []) curParams.add(`${op.id}:${p}`);
  const prevSchemes = (previous.securitySchemes || []).map((s) => s.name).sort();
  const curSchemes = (current.securitySchemes || []).map((s) => s.name).sort();
  return {
    changed: previous.hash !== current.hash,
    previousHash: previous.hash,
    currentHash: current.hash,
    addedOperations: setDiff(curOps, prevOps),
    removedOperations: setDiff(prevOps, curOps),
    addedParams: setDiff([...curParams].sort(), [...prevParams].sort()),
    removedParams: setDiff([...prevParams].sort(), [...curParams].sort()),
    addedSecuritySchemes: setDiff(curSchemes, prevSchemes),
    removedSecuritySchemes: setDiff(prevSchemes, curSchemes),
    operationsWithoutSecurityDelta:
      Number(current.operationsWithoutSecurity || 0) - Number(previous.operationsWithoutSecurity || 0),
  };
}

function prioFor(score) {
  if (score >= 72) return 'high';
  if (score >= 50) return 'med';
  if (score >= 30) return 'low';
  return 'info';
}

function snapshotFinding(summary) {
  return {
    type: 'api_contract_snapshot',
    prio: 'info',
    score: 22,
    value: `OpenAPI snapshot: ${summary.operationCount} ops / ${summary.pathCount} paths`,
    meta: `source=api_contract_diff - hash=${summary.hash} - ops=${summary.operationCount} - paths=${summary.pathCount}`,
    url: summary.url,
    verification: {
      classification: 'noisy',
      confidenceScore: 1,
      verifiedAt: new Date().toISOString(),
      evidence: {
        evidenceHash: summary.hash,
        apiContractSummary: summary,
      },
    },
  };
}

function diffFinding(diff, current, previousMeta = {}) {
  const score =
    diff.removedSecuritySchemes.length || diff.operationsWithoutSecurityDelta > 0
      ? 74
      : diff.removedOperations.length
        ? 62
        : 44;
  return {
    type: 'api_contract_diff',
    prio: prioFor(score),
    score,
    value: `OpenAPI contract mudou: +${diff.addedOperations.length} / -${diff.removedOperations.length} operacoes`,
    meta: [
      'source=api_contract_diff',
      previousMeta.runId ? `previous_run=${previousMeta.runId}` : '',
      `prev=${diff.previousHash}`,
      `cur=${diff.currentHash}`,
      `added_ops=${diff.addedOperations.length}`,
      `removed_ops=${diff.removedOperations.length}`,
      `removed_security=${diff.removedSecuritySchemes.join(',') || '-'}`,
      `no_security_delta=${diff.operationsWithoutSecurityDelta}`,
    ].filter(Boolean).join(' - '),
    url: current.url,
    owasp: 'A05:2021',
    verification: {
      classification: 'probable',
      confidenceScore: 0.85,
      verifiedAt: new Date().toISOString(),
      evidence: {
        evidenceHash: current.hash,
        apiContractDiff: {
          previousRunId: previousMeta.runId || null,
          previousCreatedAt: previousMeta.createdAt || null,
          previousHash: diff.previousHash,
          currentHash: diff.currentHash,
          addedOperations: diff.addedOperations.slice(0, 100),
          removedOperations: diff.removedOperations.slice(0, 100),
          addedParams: diff.addedParams.slice(0, 100),
          removedParams: diff.removedParams.slice(0, 100),
          addedSecuritySchemes: diff.addedSecuritySchemes,
          removedSecuritySchemes: diff.removedSecuritySchemes,
          operationsWithoutSecurityDelta: diff.operationsWithoutSecurityDelta,
        },
      },
    },
  };
}

async function fetchSpec(url, { fetchImpl = fetch, timeoutMs = 10_000, headers = {} } = {}) {
  const res = await fetchImpl(url, {
    method: 'GET',
    redirect: 'follow',
    signal: AbortSignal.timeout(timeoutMs),
    headers: {
      Accept: 'application/json,*/*;q=0.8',
      ...headers,
    },
  });
  if (!res.ok) return null;
  const ct = String(res.headers?.get?.('content-type') || '').toLowerCase();
  if (ct && !/json|text|javascript/.test(ct)) return null;
  const text = await readResponseSnippet(res, 2_000_000);
  let doc;
  try { doc = JSON.parse(text); } catch { return null; }
  if (!doc?.paths || typeof doc.paths !== 'object') return null;
  return { doc, url: res.url || url };
}

export async function fetchOpenApiContracts({
  origins = [],
  domain = '',
  outOfScopeList = [],
  modules = [],
  fetchImpl = fetch,
  log = () => {},
} = {}) {
  const out = [];
  const ua = pickStealthUserAgent(modules);
  const timeoutMs = Math.min(14_000, limits.probeTimeoutMs || 12_000);
  const originList = [...new Set((origins || []).map((o) => String(o).replace(/\/$/, '')))]
    .slice(0, Math.max(1, limits.openapiMaxOrigins || 10));

  for (const origin of originList) {
    for (const p of SPEC_PATHS) {
      let u;
      try { u = new URL(p, `${origin}/`).href; } catch { continue; }
      if (!urlInReconScope(u, domain, outOfScopeList)) continue;
      await stealthPause(modules);
      const fetched = await fetchSpec(u, {
        fetchImpl,
        timeoutMs,
        headers: { 'User-Agent': ua },
      }).catch(() => null);
      if (!fetched) continue;
      const summary = collectOpenApiSummary(fetched.doc, { url: fetched.url });
      out.push(summary);
      log(`API contract: snapshot ${summary.operationCount} ops em ${fetched.url}`, 'success');
      break;
    }
  }
  return out;
}

export function extractApiContractSnapshots(run) {
  const out = [];
  for (const f of run?.findings || []) {
    if (f?.type !== 'api_contract_snapshot') continue;
    const summary =
      f.verification?.evidence?.apiContractSummary ||
      (f.meta && typeof f.meta === 'object' ? f.meta.summary : null);
    if (summary?.hash && Array.isArray(summary.operations)) {
      out.push({ runId: run.id, createdAt: run.created_at, summary });
    }
  }
  return out;
}

export async function findPreviousApiContractSnapshots({
  target,
  listRunsFn,
  getRunByIdFn,
  limit = 80,
} = {}) {
  if (typeof listRunsFn !== 'function' || typeof getRunByIdFn !== 'function') return [];
  const rows = await listRunsFn(limit);
  const t = String(target || '').trim().toLowerCase();
  for (const row of rows || []) {
    if (String(row?.target || '').trim().toLowerCase() !== t) continue;
    const run = await getRunByIdFn(row.id);
    const snapshots = extractApiContractSnapshots(run);
    if (snapshots.length) return snapshots;
  }
  return [];
}

function previousFor(current, previousSnapshots) {
  const list = Array.isArray(previousSnapshots) ? previousSnapshots : [];
  return (
    list.find((p) => p.summary?.url === current.url) ||
    list.find((p) => {
      try { return new URL(p.summary?.url).origin === new URL(current.url).origin; } catch { return false; }
    }) ||
    list[0] ||
    null
  );
}

export async function runApiContractDiff({
  origins = [],
  domain = '',
  outOfScopeList = [],
  modules = [],
  previousSnapshots = [],
  fetchImpl = fetch,
  log = () => {},
} = {}) {
  const summaries = await fetchOpenApiContracts({ origins, domain, outOfScopeList, modules, fetchImpl, log });
  const findings = [];
  for (const current of summaries) {
    findings.push(snapshotFinding(current));
    const previous = previousFor(current, previousSnapshots);
    if (!previous?.summary) continue;
    const diff = diffOpenApiSummaries(previous.summary, current);
    if (diff?.changed) findings.push(diffFinding(diff, current, previous));
  }
  return { findings, summaries };
}
