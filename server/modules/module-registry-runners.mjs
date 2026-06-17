import { auditCookieSession } from './cookie-session-audit.mjs';
import { auditCsrfFlows } from './csrf-flow-audit.mjs';
import { runJwtJwksAudit } from './jwt-jwks-audit.mjs';
import { runServiceWorkerAudit } from './service-worker-audit.mjs';
import {
  findPreviousApiContractSnapshots,
  runApiContractDiff,
} from './api-contract-diff.mjs';
import { runWebSocketRecon } from './websocket-recon.mjs';
import { auditHppParamPollution } from './hpp-param-pollution.mjs';
import { runDomClobberingAudit } from './dom-clobbering-audit.mjs';
import { runEmailSecurityDeep } from './email-security-deep.mjs';
import { rankSecretFindings } from './secrets-context-ranker.mjs';
import { getRunById, listRuns } from './db.js';

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

/** Adaptadores `run(state)` — lote 1 (manifests existentes). */
export const moduleRunners = {
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
    });
    return {
      findings,
      logOk: findings.length
        ? `JWT/JWKS audit: ${findings.length} achado(s)`
        : 'JWT/JWKS audit: sem JWKS suspeito nas origens vivas',
      logLevel: findings.length ? 'warn' : 'info',
    };
  },

  async service_worker_audit(s) {
    const findings = await runServiceWorkerAudit({
      probeResults: s.probeResults,
      origins: activeOriginsFromState(s),
      modules: s.modules,
      log: s.log,
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
    const previousSnapshots = await findPreviousApiContractSnapshots({
      target: s.domain,
      listRunsFn: listRuns,
      getRunByIdFn: getRunById,
    });
    const { findings, summaries } = await runApiContractDiff({
      origins: activeOriginsFromState(s),
      domain: s.domain,
      outOfScopeList: s.outOfScopeList,
      modules: s.modules,
      previousSnapshots,
      log: s.log,
    });
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
    return { findings, logOk, logLevel };
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
    const { findings: emailFindings } = await runEmailSecurityDeep(s.domain, { log: s.log });
    return {
      findings: emailFindings,
      logOk: emailFindings.length
        ? `Email security deep: ${emailFindings.length} achado(s)`
        : 'Email security deep: sem achados relevantes',
      logLevel: emailFindings.length ? 'warn' : 'info',
    };
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
};
