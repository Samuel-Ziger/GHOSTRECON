import { createHash } from 'node:crypto';
import { auditCookieSession } from './cookie-session-audit.mjs';
import { auditCsrfFlows } from './csrf-flow-audit.mjs';
import { auditHttp3QuicSurface } from './http3-quic-surface.mjs';
import { runJwtJwksAudit } from './jwt-jwks-audit.mjs';
import { auditNginxHttp3Cve202642530 } from './nginx-http3-cve-2026-42530.mjs';
import { runCveCorrelation } from './cve-correlation.mjs';
import { runPanelExposureAudit } from './panel-exposure-audit.mjs';
import { runServiceWorkerAudit } from './service-worker-audit.mjs';
import {
  findPreviousApiContractSnapshots,
  moduleManifest as apiContractManifest,
  runApiContractDiff,
} from './api-contract-diff.mjs';
import { runWebSocketRecon } from './websocket-recon.mjs';
import { auditHppParamPollution } from './hpp-param-pollution.mjs';
import { runDomClobberingAudit } from './dom-clobbering-audit.mjs';
import { runEmailSecurityDeep } from './email-security-deep.mjs';
import { runHexstrikeOrchestrator } from './hexstrike-orchestrator.mjs';
import { rankSecretFindings } from './secrets-context-ranker.mjs';
import { runPastebinIntel } from './pastebin-intel.mjs';
import { runSqliDeepVerification } from './sqli-deep-verify.mjs';
import { runSafeXssVibesAudit } from './xss-vibes-safe.mjs';
import { runCloudDebugEnvAudit } from './cloud-debug-env-audit.mjs';
import { runRuntimeEndpointPivot } from './runtime-endpoint-pivot.mjs';
import { runDeterministicVoucherAudit } from './deterministic-voucher-audit.mjs';
import { runJwtClaimAuthzDiff } from './jwt-claim-authz-diff.mjs';
import { runAuthzObjectMatrix } from './authz-object-matrix-v2.mjs';
import { runArtifactSafetyAudit } from './artifact-safety-audit.mjs';
import { runApiExcessiveDataAudit } from './api-excessive-data-audit.mjs';
import { runBoundedObjectKeyDiscovery } from './bounded-object-key-discovery.mjs';
import { runCloudObjectProxyAuthz } from './cloud-object-proxy-authz.mjs';
import { runSensitivePaymentData } from './sensitive-payment-data.mjs';
import { runFinancialIntegrityAudit } from './financial-integrity-audit.mjs';
import { runSqliTargetedVerify } from './sqli-targeted-verify.mjs';
import {
  getRunByStorageRef,
  listRuns,
  listRunsForTarget,
} from './db.js';
import { combineAbortSignals } from './http-utils.js';
import { readResponseSnippet } from './module-runner.mjs';

function activeOriginsFromState(s) {
  const map = s.originByHost;
  if (!map || typeof map.values !== 'function') return [];
  return [...map.values()].map((v) => v.origin);
}

function htmlAuditBodiesFromProbe(s) {
  return (s.probeResults || [])
    .map(({ r }) => (r?.ok && r.htmlSample ? { url: r.url, body: r.htmlSample } : null))
    .filter(Boolean);
}

function passiveObservationsFromState(s) {
  const rows = [];
  for (const item of s.probeResults || []) {
    const r = item?.r || item;
    const body = r?.htmlSample || r?.body || '';
    if (!body) continue;
    rows.push({
      url: r?.url || item?.url || '',
      status: r?.status || 0,
      headers: r?.headers || r?.responseHeaders || null,
      body,
    });
  }
  for (const item of s._jsAuditBodies || []) {
    const body = item?.body || item?.source || item?.text || '';
    if (body) rows.push({ url: item?.url || '', status: 200, body });
  }
  for (const item of s._cloudDebugMetadataObservations || []) rows.push(item);
  return rows.slice(0, 256);
}

function structuredApiObservationsFromState(s) {
  const explicit = Array.isArray(s.apiResponseObservations) ? s.apiResponseObservations : [];
  const parsed = [];
  for (const observation of passiveObservationsFromState(s)) {
    const text = String(observation?.body || '').trim();
    if (!/^[{[]/.test(text)) continue;
    try {
      parsed.push({ ...observation, json: JSON.parse(text), authTrust: observation.authTrust || 'anonymous' });
    } catch { /* non-JSON evidence */ }
  }
  return [...explicit, ...parsed].slice(0, 128);
}

function evidenceCapabilityAllowed(s, moduleId = null) {
  if (typeof s.allowsPipelineCapability !== 'function') return false;
  return s.allowsPipelineCapability('evidence_verification')
    || Boolean(moduleId && s.allowsPipelineCapability(moduleId));
}

function boundedHeaders(value) {
  const headers = {};
  if (!value || typeof value !== 'object') return headers;
  for (const [rawName, rawValue] of Object.entries(value).slice(0, 64)) {
    const name = String(rawName || '').trim();
    if (!/^[A-Za-z0-9!#$%&'*+.^_`|~-]{1,80}$/.test(name)) continue;
    if (['host', 'content-length', 'transfer-encoding', 'connection'].includes(name.toLowerCase())) continue;
    const text = String(rawValue ?? '').replace(/[\r\n]+/g, ' ').slice(0, 8_192);
    if (text) headers[name] = text;
  }
  return headers;
}

function buildReadOnlyAuthTransport(s, config = {}) {
  if (typeof config.transport === 'function') return config.transport;
  const contexts = config.authContexts && typeof config.authContexts === 'object'
    ? config.authContexts : null;
  if (!contexts) return null;
  return async ({ url, method = 'GET', authRef = null, signal = null }) => {
    const verb = String(method || 'GET').toUpperCase();
    if (!['GET', 'HEAD'].includes(verb)) throw new Error('read_only_auth_transport_method_rejected');
    if (s.urlInScope(url) !== true) throw new Error('read_only_auth_transport_out_of_scope');
    const authContext = authRef == null ? null : contexts[String(authRef)];
    if (authRef != null && (!authContext || typeof authContext !== 'object')) {
      throw new Error('read_only_auth_transport_unknown_ref');
    }
    const headers = {
      Accept: 'application/json,text/plain,*/*;q=0.5',
      ...boundedHeaders(config.headers),
      ...boundedHeaders(authContext?.headers),
    };
    if (authContext?.cookie) headers.Cookie = String(authContext.cookie).replace(/[\r\n]+/g, ' ').slice(0, 8_192);
    const response = await (s.fetchImpl || globalThis.fetch)(url, {
      method: verb,
      headers,
      redirect: 'manual',
      signal: combineAbortSignals(signal || s.signal || null, 12_000),
    });
    const text = await readResponseSnippet(response, 512_000);
    let json = null;
    try { json = JSON.parse(text); } catch { /* non-JSON control */ }
    return {
      status: response.status,
      json,
      text,
      errorCode: json?.Code || json?.code || json?.errorCode || '',
      bodyFingerprint: createHash('sha256').update(text).digest('hex'),
    };
  };
}

function materializeObjectProxyCases(config, candidates = []) {
  const direct = Array.isArray(config?.cases) ? config.cases : [];
  const template = config?.caseTemplate && typeof config.caseTemplate === 'object'
    ? config.caseTemplate : null;
  if (!template) return direct;
  const urlFields = ['ownerUrl', 'crossUrl', 'missingControlUrl', 'urlShapedControlUrl'];
  const derived = candidates.slice(0, 16).map((candidate, index) => {
    const row = { ...template, id: template.id ? `${template.id}:${index + 1}` : `derived:${index + 1}` };
    for (const field of urlFields) {
      if (typeof row[field] === 'string') {
        row[field] = row[field].replaceAll('{{objectKey}}', encodeURIComponent(candidate.key));
      }
    }
    return row;
  });
  return [...direct, ...derived];
}

function valueAtPath(value, selector) {
  if (!selector) return undefined;
  return String(selector).split('.').filter(Boolean).reduce((current, key) => current?.[key], value);
}

function renderTemplate(value, variables) {
  if (Array.isArray(value)) return value.map((child) => renderTemplate(child, variables));
  if (value && typeof value === 'object') {
    return Object.fromEntries(Object.entries(value).map(([key, child]) => [key, renderTemplate(child, variables)]));
  }
  if (typeof value !== 'string') return value;
  const exact = value.match(/^\{\{(amount|marker|accountRef|receiptRef)\}\}$/);
  if (exact) return variables[exact[1]];
  return value.replace(/\{\{(amount|marker|accountRef|receiptRef)\}\}/g, (_match, key) => (
    encodeURIComponent(String(variables[key] ?? ''))
  ));
}

function buildFinancialHttpAdapters(s, config = {}) {
  if (typeof config.transport === 'function' && typeof config.cleanup === 'function') {
    return { transport: config.transport, cleanup: config.cleanup };
  }
  const request = config.request && typeof config.request === 'object' ? config.request : null;
  const cleanupSpec = config.cleanupRequest && typeof config.cleanupRequest === 'object'
    ? config.cleanupRequest : null;
  if (!request || !cleanupSpec || request.bodyTemplate == null || !cleanupSpec.urlTemplate) return null;
  const auth = config.authContext && typeof config.authContext === 'object' ? config.authContext : {};
  const commonHeaders = { Accept: 'application/json,*/*;q=0.8', ...boundedHeaders(auth.headers) };
  if (auth.cookie) commonHeaders.Cookie = String(auth.cookie).replace(/[\r\n]+/g, ' ').slice(0, 8_192);

  const execute = async ({ url, method, bodyTemplate, variables, signal, contentType }) => {
    if (s.urlInScope(url) !== true) throw new Error('financial_http_adapter_out_of_scope');
    const rendered = renderTemplate(bodyTemplate, variables);
    const normalizedType = String(contentType || 'application/json').toLowerCase();
    const body = normalizedType.includes('json')
      ? JSON.stringify(rendered)
      : new URLSearchParams(rendered && typeof rendered === 'object' ? rendered : {}).toString();
    const response = await (s.fetchImpl || globalThis.fetch)(url, {
      method,
      headers: {
        ...commonHeaders,
        'Content-Type': normalizedType.includes('json')
          ? 'application/json' : 'application/x-www-form-urlencoded',
      },
      body,
      redirect: 'manual',
      signal: combineAbortSignals(signal || s.signal || null, 12_000),
    });
    const text = await readResponseSnippet(response, 256_000);
    let json = null;
    try { json = JSON.parse(text); } catch { /* explicit non-JSON */ }
    return { response, json };
  };

  return {
    async transport({ url, requestedAmount, accountRef, marker, signal }) {
      const method = String(request.method || 'POST').toUpperCase();
      if (!['POST', 'PUT', 'PATCH'].includes(method)) throw new Error('financial_http_adapter_method_rejected');
      const { response, json } = await execute({
        url,
        method,
        bodyTemplate: request.bodyTemplate,
        variables: { amount: requestedAmount, marker, accountRef, receiptRef: '' },
        signal,
        contentType: request.contentType,
      });
      const acceptedStatuses = Array.isArray(request.acceptedStatuses)
        ? request.acceptedStatuses.map(Number) : [200, 201, 202];
      const accepted = acceptedStatuses.includes(response.status)
        && (request.acceptedPath ? valueAtPath(json, request.acceptedPath) === true : true);
      const receiptRef = valueAtPath(json, request.receiptRefPath);
      const persisted = request.persistedPath
        ? valueAtPath(json, request.persistedPath) === true
        : Boolean(receiptRef);
      return {
        status: response.status,
        accepted,
        persisted,
        acceptedAmount: request.acceptedAmountPath
          ? valueAtPath(json, request.acceptedAmountPath) : requestedAmount,
        receiptRef: receiptRef == null ? null : String(receiptRef),
      };
    },
    async cleanup({ receiptRef, marker, accountRef, signal }) {
      const url = renderTemplate(String(cleanupSpec.urlTemplate), { receiptRef, marker, accountRef, amount: '' });
      const method = String(cleanupSpec.method || 'DELETE').toUpperCase();
      if (!['DELETE', 'POST'].includes(method) || s.urlInScope(url) !== true) return { confirmed: false };
      const { response, json } = await execute({
        url,
        method,
        bodyTemplate: cleanupSpec.bodyTemplate ?? {},
        variables: { receiptRef, marker, accountRef, amount: '' },
        signal,
        contentType: cleanupSpec.contentType,
      });
      const statuses = Array.isArray(cleanupSpec.confirmedStatuses)
        ? cleanupSpec.confirmedStatuses.map(Number) : [200, 202, 204];
      const semantic = cleanupSpec.confirmedPath
        ? valueAtPath(json, cleanupSpec.confirmedPath) === true
        : response.status === 204;
      return { confirmed: statuses.includes(response.status) && semantic };
    },
  };
}

/** Adaptadores `run(state)` — lote 1 (manifests existentes). */
export const moduleRunners = {
  async pastebin(s) {
    const env = s.env || process.env;
    return runPastebinIntel({
      target: s.domain,
      apiKey: env.GOOGLE_CSE_KEY,
      cx: env.GOOGLE_CSE_CX,
      signal: s.signal || null,
      log: s.log,
    });
  },

  async verify_sqli_deep(s) {
    return runSqliDeepVerification({
      findings: s.findings || [],
      auth: s.auth || null,
      log: s.log,
      signal: s.signal || null,
      urlAllowed: (url) => s.urlInScope(url),
      fetchImpl: s.fetchImpl || globalThis.fetch,
      identityCtrl: s.identityCtrl || null,
    });
  },

  async kali_xss_vibes(s) {
    const urls = [
      ...(Array.isArray(s.paramUrlsForKali) ? s.paramUrlsForKali : []),
      ...(s.findings || []).flatMap((finding) => [finding?.url, finding?.value]),
    ].filter((value) => typeof value === 'string' && /^https?:\/\//i.test(value));
    return runSafeXssVibesAudit({
      urls,
      auth: s.auth || null,
      signal: s.signal || null,
      urlAllowed: (url) => s.urlInScope(url),
      fetchImpl: s.fetchImpl || globalThis.fetch,
      identityCtrl: s.identityCtrl || null,
      log: s.log,
    });
  },

  async cookie_session_audit(s) {
    const findings = auditCookieSession(s.probeResults, { target: s.domain });
    return {
      findings,
      logOk: findings.length
        ? `Cookie/session audit: ${findings.length} achado(s)`
        : 'Cookie/session audit: sem achados relevantes',
      logLevel: findings.length ? 'warn' : 'info',
    };
  },

  async csrf_flow_audit(s) {
    const findings = auditCsrfFlows(s.probeResults, { target: s.domain });
    return {
      findings,
      logOk: findings.length
        ? `CSRF flow audit: ${findings.length} achado(s)`
        : 'CSRF flow audit: sem forms mutáveis suspeitos',
      logLevel: findings.length ? 'warn' : 'info',
    };
  },

  async jwt_jwks_audit(s) {
    const findings = await runJwtJwksAudit({
      origins: activeOriginsFromState(s),
      modules: s.modules,
      log: s.log,
      fetchImpl: s.fetchImpl || globalThis.fetch,
      signal: s.signal || null,
      urlAllowed: (url) => s.urlInScope(url),
      onSecret: typeof s.storeSensitiveEvidence === 'function'
        ? async (entry) => {
            const stored = await s.storeSensitiveEvidence(entry);
            s.latestJwtSecretRef = stored.secretRef;
            return stored;
          }
        : null,
    });
    return {
      findings,
      logOk: findings.length
        ? `JWT/JWKS audit: ${findings.length} achado(s)`
        : 'JWT/JWKS audit: sem JWKS suspeito nas origens vivas',
      logLevel: findings.length ? 'warn' : 'info',
    };
  },

  async http3_quic_surface(s) {
    const findings = auditHttp3QuicSurface({
      probeResults: s.probeResults,
      nmapFindings: (s.findings || []).filter((f) => f.type === 'nmap'),
    });
    return {
      findings,
      logOk: findings.length
        ? `HTTP/3/QUIC surface: ${findings.length} exposicao(oes)`
        : 'HTTP/3/QUIC surface: sem Alt-Svc h3 observado',
      logLevel: findings.length ? 'info' : 'info',
    };
  },

  async nginx_http3_cve_2026_42530(s) {
    const findings = auditNginxHttp3Cve202642530({
      probeResults: s.probeResults,
    });
    return {
      findings,
      logOk: findings.length
        ? `NGINX HTTP/3 ${findings.length} achado(s)/candidato(s) para CVE-2026-42530`
        : 'NGINX HTTP/3 CVE-2026-42530: sem versao vulneravel confirmada',
      logLevel: findings.some((f) => f.prio === 'high') ? 'warn' : 'info',
    };
  },

  async cve_correlation(s) {
    return runCveCorrelation({
      findings: s.findings || [],
      probeResults: s.probeResults || [],
      fetchImpl: s.fetchImpl || globalThis.fetch,
      env: s.env || process.env,
      signal: s.signal || null,
    });
  },

  async panel_exposure_audit(s) {
    const findings = await runPanelExposureAudit({
      origins: activeOriginsFromState(s),
      modules: s.modules,
      log: s.log,
      fetchImpl: s.fetchImpl || globalThis.fetch,
      signal: s.signal || null,
      urlAllowed: (url) => s.urlInScope(url),
    });
    return {
      findings,
      logOk: findings.length ? `Panel exposure: ${findings.length} achado(s)` : 'Panel exposure: sem painéis comuns expostos',
      logLevel: findings.length ? 'warn' : 'info',
    };
  },

  async service_worker_audit(s) {
    const findings = await runServiceWorkerAudit({
      probeResults: s.probeResults,
      origins: activeOriginsFromState(s),
      modules: s.modules,
      log: s.log,
      urlAllowed: (url) => s.urlInScope(url),
    });
    return {
      findings,
      logOk: findings.length
        ? `Service Worker audit: ${findings.length} achado(s)`
        : 'Service Worker audit: sem service worker relevante',
      logLevel: findings.length ? 'warn' : 'info',
    };
  },

  async api_contract_diff(s) {
    const requestedTimeoutMs = Number(s.apiContractTimeoutMs);
    const timeoutMs = Math.max(1, Math.min(
      120_000,
      Math.floor(
        Number.isFinite(requestedTimeoutMs) && requestedTimeoutMs > 0
          ? requestedTimeoutMs
          : apiContractManifest.timeoutMs,
      ),
    ));
    const startedAt = Date.now();
    const deadlineAt = startedAt + timeoutMs;
    const runSignal = combineAbortSignals(s.signal || null, timeoutMs);
    const targetedListFn = s.listRunsForTargetFn
      || (s.listRunsFn
        ? null
        : (target, limit, options = {}) => listRunsForTarget(target, limit, {
            ...options,
            localProjectName: s.projectNameRaw,
          }));
    const targetedGetRunFn = s.getRunByIdFn
      || ((id, options = {}) => getRunByStorageRef(id, {
        ...options,
        localProjectName: s.projectNameRaw,
      }));
    const previousSnapshots = await findPreviousApiContractSnapshots({
      target: s.domain,
      listRunsFn: s.listRunsFn || listRuns,
      listRunsForTargetFn: targetedListFn,
      getRunByIdFn: targetedGetRunFn,
      signal: runSignal,
    });
    const remainingTimeoutMs = deadlineAt - Date.now();
    if (remainingTimeoutMs <= 0) {
      throw new DOMException('API contract baseline deadline exhausted', 'TimeoutError');
    }
    const {
      findings,
      summaries,
      status,
      outcomes,
      reason,
      metrics: apiContractMetrics,
    } = await runApiContractDiff({
      origins: activeOriginsFromState(s),
      domain: s.domain,
      outOfScopeList: s.outOfScopeList,
      scopePolicy: s.scopePolicy,
      modules: s.modules,
      previousSnapshots,
      fetchImpl: s.fetchImpl || globalThis.fetch,
      log: s.log,
      signal: s.signal || null,
      timeoutMs: Math.max(1, Math.floor(remainingTimeoutMs)),
    });
    const materializedSnapshots = findings.filter(
      (finding) => finding.type === 'api_contract_snapshot',
    ).length;
    const diffs = findings.filter((f) => f.type === 'api_contract_diff').length;
    let logOk = 'API contract diff: nenhuma spec OpenAPI encontrada';
    let logLevel = 'info';
    if (diffs) {
      logOk = `API contract diff: ${diffs} mudança(s) detectada(s)`;
      logLevel = 'warn';
    } else if (summaries.length && previousSnapshots.length) {
      logOk = 'API contract diff: snapshots sem mudanças relevantes';
    } else if (summaries.length) {
      logOk = 'API contract diff: snapshot inicial gravado para próximos runs';
    }
    if (status === 'partial') {
      logOk = `API contract diff: cobertura parcial; ${summaries.length} contrato(s) válido(s), consulte outcomes`;
      logLevel = 'warn';
    } else if (status === 'timeout') {
      logOk = `API contract diff: deadline atingido; ${materializedSnapshots} snapshot(s) preservado(s), consulte outcomes`;
      logLevel = 'warn';
    }
    const outcomeMetrics = outcomes.reduce((metrics, outcome) => {
      const key = `state_${String(outcome?.state || 'unknown').replace(/[^a-z0-9_]/gi, '_').toLowerCase()}`;
      metrics[key] = (metrics[key] || 0) + 1;
      return metrics;
    }, {
      contracts: apiContractMetrics?.contracts ?? summaries.length,
      snapshotsMaterialized:
        apiContractMetrics?.snapshotsMaterialized ?? materializedSnapshots,
      changes: apiContractMetrics?.changes ?? diffs,
      snapshotSchemaVersion: apiContractMetrics?.snapshotSchemaVersion,
      canonicalizationVersion: apiContractMetrics?.canonicalizationVersion,
      baselineBytesRead: apiContractMetrics?.baselineBytesRead,
      baselineBytesRetained: apiContractMetrics?.baselineBytesRetained,
      baselineByteLimit: apiContractMetrics?.baselineByteLimit,
      baselineByteLimitReached: apiContractMetrics?.baselineByteLimitReached,
      attempts: apiContractMetrics?.coverage?.candidatesEvaluated ?? outcomes.length,
      outcomes: outcomes.length,
      ...(apiContractMetrics?.coverage || {}),
    });
    return {
      findings,
      logOk,
      logLevel,
      status,
      partial: status === 'timeout',
      reason: status === 'partial'
        ? reason || 'api_contract_collection_incomplete'
        : reason,
      attempted: apiContractMetrics?.coverage?.candidatesEvaluated ?? outcomes.length,
      resultCount: findings.length,
      outcomeMetrics,
      metrics: apiContractMetrics,
    };
  },

  async hpp_param_pollution(s) {
    const corpus = s.urlCorpus?.length ? s.urlCorpus : s.interesting;
    const findings = auditHppParamPollution(corpus, { paramRows: s.paramRows });
    return {
      findings,
      logOk: findings.length ? `HPP audit: ${findings.length} candidato(s) priorizado(s)` : null,
      logLevel: 'success',
    };
  },

  async websocket_recon(s) {
    const htmlBodies = htmlAuditBodiesFromProbe(s);
    const { findings, urls } = runWebSocketRecon({
      urlCorpus: s.urlCorpus,
      jsBodies: s._jsAuditBodies || [],
      htmlBodies,
      target: s.domain,
    });
    return {
      findings,
      logOk: urls?.length
        ? `WebSocket recon: ${urls.length} endpoint(s) observado(s)`
        : null,
      logLevel: findings.length ? 'success' : 'info',
    };
  },

  async dom_clobbering_audit(s) {
    const htmlBodies = htmlAuditBodiesFromProbe(s);
    const { findings } = runDomClobberingAudit({
      htmlBodies,
      jsBodies: s._jsAuditBodies || [],
    });
    return {
      findings,
      logOk: findings.length ? `DOM clobbering audit: ${findings.length} achado(s)` : null,
      logLevel: 'success',
    };
  },

  async email_security_deep(s) {
    const { findings: emailFindings } = await runEmailSecurityDeep(s.domain, {
      log: s.log,
      hostAllowed: (host) => s.hostInScope(host),
      signal: s.signal || null,
    });
    return {
      findings: emailFindings,
      logOk: emailFindings.length
        ? `Email security deep: ${emailFindings.length} achado(s)`
        : 'Email security deep: sem achados relevantes',
      logLevel: emailFindings.length ? 'warn' : 'info',
    };
  },

  async hexstrike_orchestrator(s) {
    return runHexstrikeOrchestrator({
      target: s.domain,
      domain: s.domain,
      objective: process.env.GHOSTRECON_HEXSTRIKE_OBJECTIVE || 'comprehensive',
      timeoutMs: Number(process.env.GHOSTRECON_HEXSTRIKE_TIMEOUT_MS || 60_000),
      log: s.log,
    });
  },

  async secrets_context_ranker(s) {
    const rankedSecretFindings = rankSecretFindings(s.findings);
    return {
      findings: rankedSecretFindings,
      logOk: rankedSecretFindings.length
        ? `Secrets context ranker: ${rankedSecretFindings.length} prioridade(s) calculada(s)`
        : null,
      logLevel: 'success',
    };
  },

  async cloud_debug_env_audit(s) {
    const result = await runCloudDebugEnvAudit({
      observations: passiveObservationsFromState(s),
      origins: activeOriginsFromState(s),
      // Selecting this module explicitly authorizes its bounded same-origin
      // GET /debug probe; the module performs a soft-404 control first.
      probeOrigins: true,
      fetchImpl: s.fetchImpl || globalThis.fetch,
      urlAllowed: (url) => s.urlInScope(url),
      signal: s.signal || null,
    });
    s._cloudDebugMetadataObservations = result.analyses.map((analysis) => ({
      url: analysis.url,
      status: 200,
      body: JSON.stringify(analysis.metadata),
    }));
    return {
      findings: result.findings,
      status: result.status,
      reason: result.reason || (result.status === 'partial' ? 'cloud_debug_probe_partial' : undefined),
      attempted: result.metrics.requestsAttempted + result.metrics.passiveObservations,
      resultCount: result.findings.length,
      outcomeMetrics: {
        attempts: result.metrics.observations,
        completed: result.metrics.confirmed,
        outcomes: result.outcomes.length,
      },
      logOk: result.findings.length
        ? `Cloud debug/env audit: ${result.findings.length} achado(s)`
        : 'Cloud debug/env audit: nenhuma exposição confirmada',
      logLevel: result.findings.some((finding) => finding.prio === 'high') ? 'warn' : 'info',
    };
  },

  async runtime_endpoint_pivot(s) {
    const result = await runRuntimeEndpointPivot({ observations: passiveObservationsFromState(s) });
    s.runtimeEndpointCandidates = result.candidates;
    return {
      findings: result.findings,
      status: result.status,
      reason: result.reason,
      attempted: result.metrics.observations,
      resultCount: result.findings.length,
      outcomeMetrics: { attempts: result.metrics.observations, completed: result.metrics.candidates },
      logOk: result.findings.length
        ? `Runtime endpoint pivot: ${result.findings.length} candidato(s) de escopo; nenhum seguido automaticamente`
        : null,
      logLevel: 'info',
    };
  },

  async deterministic_voucher_audit(s) {
    const result = await runDeterministicVoucherAudit({
      sources: s._jsAuditBodies || [],
      probeResults: s.probeResults || [],
    });
    return {
      findings: result.findings,
      status: result.status,
      reason: result.reason,
      attempted: result.metrics.sources,
      resultCount: result.findings.length,
      outcomeMetrics: {
        attempts: result.metrics.sources,
        completed: result.metrics.confirmed,
        outcomes: result.metrics.candidates + result.metrics.confirmed,
      },
      logOk: result.findings.length
        ? `Deterministic voucher audit: ${result.metrics.confirmed} confirmado(s), ${result.metrics.candidates} candidato(s)`
        : null,
      logLevel: result.metrics.confirmed ? 'warn' : 'info',
    };
  },

  async jwt_claim_authz_diff(s) {
    const config = s.jwtClaimAuthzConfig;
    if (!config) return { findings: [], status: 'skipped', reason: 'missing_explicit_claim_test_config' };
    const capabilityAllowed = evidenceCapabilityAllowed(s, 'jwt_claim_authz_diff');
    const result = await runJwtClaimAuthzDiff({
      ...config,
      secretRef: config.secretRef || s.latestJwtSecretRef,
      resolveSecret: typeof config.resolveSecret === 'function'
        ? config.resolveSecret
        : s.resolveSensitiveEvidence,
      allowActive: config.allowActive === true && capabilityAllowed,
      fetchImpl: s.fetchImpl || globalThis.fetch,
      urlAllowed: (url) => s.urlInScope(url),
      signal: s.signal || null,
    });
    return {
      findings: result.findings || [],
      status: result.state === 'skipped_ineligible' ? 'skipped' : 'done',
      reason: result.reason,
      attempted: result.metrics?.requestsAttempted || 0,
      resultCount: result.findings?.length || 0,
      outcomeMetrics: {
        attempts: result.metrics?.requestsAttempted || 0,
        outcomes: result.outcomes?.length || 0,
      },
    };
  },

  async authz_object_matrix_v2(s) {
    const config = s.authzObjectMatrixConfig;
    if (!config) return { findings: [], status: 'skipped', reason: 'missing_explicit_object_matrix_config' };
    const capabilityAllowed = evidenceCapabilityAllowed(s, 'authz_object_matrix_v2');
    const transport = buildReadOnlyAuthTransport(s, config);
    if (typeof transport !== 'function') {
      return { findings: [], status: 'skipped', reason: 'missing_auth_context_transport' };
    }
    const result = await runAuthzObjectMatrix({
      ...config,
      transport,
      allowActive: config.allowActive === true && capabilityAllowed,
      urlAllowed: (url) => s.urlInScope(url),
      signal: s.signal || null,
      onConfirmedCrossResponse: async ({ url, response, accessFinding }) => {
        if (!response?.json || !accessFinding) return;
        s.sensitivePaymentObservations.push({
          url,
          data: response.json,
          accessFinding,
        });
      },
    });
    return {
      findings: result.findings || [],
      status: result.state === 'skipped_ineligible' ? 'skipped' : 'done',
      reason: result.reason,
      attempted: result.metrics?.requestsAttempted || 0,
      resultCount: result.findings?.length || 0,
      outcomeMetrics: {
        attempts: result.metrics?.requestsAttempted || 0,
        outcomes: result.outcomes?.length || 0,
      },
    };
  },

  async artifact_safety_audit(s) {
    const paths = Array.isArray(s.artifactPaths) ? s.artifactPaths : [];
    if (!paths.length || !s.artifactRoot) {
      return { findings: [], status: 'skipped', reason: 'no_artifacts_declared' };
    }
    const result = await runArtifactSafetyAudit({ paths, allowedRoot: s.artifactRoot });
    // Sinal consumido pelo finalize para impedir saídas externas (IA/webhooks)
    // quando um artefato explicitamente declarado ainda contém material sensível.
    // A evidência detalhada continua privada no resultado do runner.
    s.artifactPublicationAllowed = result.publicationAllowed === true;
    return {
      findings: [],
      status: result.publicationAllowed ? 'done' : 'partial',
      reason: result.publicationAllowed ? undefined : 'sensitive_artifact_publication_blocked',
      attempted: result.filesAudited,
      resultCount: result.leakCount,
      outcomeMetrics: { attempts: result.filesAudited, failed: result.leakCount },
      artifactSafety: result,
      logOk: result.publicationAllowed
        ? `Artifact safety: ${result.filesAudited} arquivo(s) sem sentinelas sensíveis`
        : `Artifact safety: publicação bloqueada em ${result.filesAudited} arquivo(s)`,
      logLevel: result.publicationAllowed ? 'info' : 'warn',
    };
  },

  async api_excessive_data_audit(s) {
    const result = await runApiExcessiveDataAudit({ observations: structuredApiObservationsFromState(s) });
    return {
      findings: result.findings,
      status: result.status,
      reason: result.reason,
      attempted: result.metrics.observations,
      resultCount: result.findings.length,
      outcomeMetrics: { attempts: result.metrics.observations, completed: result.metrics.probable },
      logOk: result.findings.length ? `API excessive data: ${result.findings.length} exposição(ões) provável(is)` : null,
      logLevel: result.findings.length ? 'warn' : 'info',
    };
  },

  async bounded_object_key_discovery(s) {
    const result = await runBoundedObjectKeyDiscovery({
      observations: passiveObservationsFromState(s),
      knownObjectKeys: s.knownObjectKeys || [],
      budget: s.objectKeyDiscoveryBudget ?? 8,
      signal: s.signal || null,
    });
    s.objectKeyCandidates = result.candidates;
    return {
      findings: [],
      status: result.status,
      reason: result.reason,
      attempted: result.metrics.inputsAnalyzed,
      resultCount: result.metrics.candidates,
      outcomeMetrics: { attempts: result.metrics.inputsAnalyzed, completed: result.metrics.candidates },
      logOk: result.metrics.candidates
        ? `Object key discovery: ${result.metrics.candidates} chave(s) derivada(s), sem brute force`
        : null,
      logLevel: 'info',
    };
  },

  async sqli_targeted_verify(s) {
    const config = s.sqliTargetedConfig;
    if (!config) return { findings: [], status: 'skipped', reason: 'missing_explicit_sqli_target' };
    const result = await runSqliTargetedVerify({
      ...config,
      allowActive: config.allowActive === true && evidenceCapabilityAllowed(s, 'sqli_targeted_verify'),
      allowNonGetReplay: config.allowNonGetReplay === true
        && typeof s.allowsPipelineCapability === 'function'
        && s.allowsPipelineCapability('payload_mutator'),
      fetchImpl: s.fetchImpl || globalThis.fetch,
      urlAllowed: (url) => s.urlInScope(url),
      signal: s.signal || null,
    });
    return {
      findings: result.findings || [],
      status: result.status,
      reason: result.reason,
      attempted: result.metrics?.requestsAttempted || 0,
      resultCount: result.findings?.length || 0,
      outcomeMetrics: { attempts: result.metrics?.requestsAttempted || 0, outcomes: result.outcomes?.length || 0 },
    };
  },

  async cloud_object_proxy_authz(s) {
    const config = s.cloudObjectProxyAuthzConfig;
    if (!config) return { findings: [], status: 'skipped', reason: 'missing_explicit_object_proxy_config' };
    const transport = buildReadOnlyAuthTransport(s, config);
    if (typeof transport !== 'function') {
      return { findings: [], status: 'skipped', reason: 'missing_auth_context_transport' };
    }
    const result = await runCloudObjectProxyAuthz({
      ...config,
      cases: materializeObjectProxyCases(config, s.objectKeyCandidates || []),
      transport,
      allowActive: config.allowActive === true && evidenceCapabilityAllowed(s, 'cloud_object_proxy_authz'),
      urlAllowed: (url) => s.urlInScope(url),
      signal: s.signal || null,
    });
    return {
      findings: result.findings || [],
      status: result.status,
      reason: result.reason,
      attempted: result.metrics?.requestsAttempted || 0,
      resultCount: result.findings?.length || 0,
      outcomeMetrics: { attempts: result.metrics?.requestsAttempted || 0, outcomes: result.outcomes?.length || 0 },
    };
  },

  async sensitive_payment_data(s) {
    const observations = Array.isArray(s.sensitivePaymentObservations) ? s.sensitivePaymentObservations : [];
    if (!observations.length) return { findings: [], status: 'skipped', reason: 'no_confirmed_authz_payment_observations' };
    const result = await runSensitivePaymentData({ observations });
    s.sensitivePaymentObservations = [];
    return {
      findings: result.findings,
      attempted: result.metrics.observations,
      resultCount: result.findings.length,
      outcomeMetrics: { attempts: result.metrics.observations, completed: result.metrics.confirmed },
    };
  },

  async financial_integrity_audit(s) {
    const config = s.financialIntegrityConfig;
    if (!config) return { findings: [], status: 'skipped', reason: 'missing_explicit_financial_test_config' };
    const adapters = buildFinancialHttpAdapters(s, config);
    if (!adapters) {
      return { findings: [], status: 'skipped', reason: 'missing_declarative_transport_and_cleanup' };
    }
    const autoAllowed = s.autoModeExecution !== true
      || (typeof s.allowsPipelineCapability === 'function' && s.allowsPipelineCapability('payload_mutator'));
    const result = await runFinancialIntegrityAudit({
      ...config,
      transport: adapters.transport,
      cleanup: adapters.cleanup,
      allowMutatingActions: config.allowMutatingActions === true && autoAllowed,
      urlAllowed: (url) => s.urlInScope(url),
      signal: s.signal || null,
    });
    return {
      findings: result.findings || [],
      status: result.status,
      reason: result.reason,
      attempted: result.metrics?.requestsAttempted || 0,
      resultCount: result.findings?.length || 0,
      outcomeMetrics: { attempts: result.metrics?.requestsAttempted || 0, outcomes: result.outcomes?.length || 0 },
    };
  },
};
