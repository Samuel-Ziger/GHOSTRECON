import { moduleManifest as apiContractDiff } from './api-contract-diff.mjs';
import { moduleManifest as cookieSessionAudit } from './cookie-session-audit.mjs';
import { moduleManifest as csrfFlowAudit } from './csrf-flow-audit.mjs';
import { moduleManifest as domClobberingAudit } from './dom-clobbering-audit.mjs';
import { moduleManifest as emailSecurityDeep } from './email-security-deep.mjs';
import { moduleManifest as hppParamPollution } from './hpp-param-pollution.mjs';
import { moduleManifest as hexstrikeOrchestrator } from './hexstrike-orchestrator.mjs';
import { moduleManifest as http3QuicSurface } from './http3-quic-surface.mjs';
import { moduleManifest as jwtJwksAudit } from './jwt-jwks-audit.mjs';
import { moduleManifest as nginxHttp3Cve202642530 } from './nginx-http3-cve-2026-42530.mjs';
import { moduleManifest as cveCorrelation } from './cve-correlation.mjs';
import { moduleManifest as panelExposureAudit } from './panel-exposure-audit.mjs';
import { moduleManifest as pastebinIntel } from './pastebin-intel.mjs';
import { moduleManifest as riskExplainer } from './risk-explainer.mjs';
import { moduleManifest as secretsContextRanker } from './secrets-context-ranker.mjs';
import { moduleManifest as serviceWorkerAudit } from './service-worker-audit.mjs';
import { moduleManifest as websocketRecon } from './websocket-recon.mjs';
import { moduleManifest as vigoliumDast } from './vigolium-dast.mjs';
import { moduleManifest as vigoliumAudit } from './vigolium-audit.mjs';
import { moduleManifest as vigoliumSwarm } from './vigolium-swarm.mjs';
import { moduleManifest as sqliDeepVerify } from './sqli-deep-verify.mjs';
import { moduleManifest as xssVibesSafe } from './xss-vibes-safe.mjs';
import { moduleManifest as cloudDebugEnvAudit } from './cloud-debug-env-audit.mjs';
import { moduleManifest as runtimeEndpointPivot } from './runtime-endpoint-pivot.mjs';
import { moduleManifest as deterministicVoucherAudit } from './deterministic-voucher-audit.mjs';
import { moduleManifest as jwtClaimAuthzDiff } from './jwt-claim-authz-diff.mjs';
import { moduleManifest as authzObjectMatrixV2 } from './authz-object-matrix-v2.mjs';
import { moduleManifest as artifactSafetyAudit } from './artifact-safety-audit.mjs';
import { moduleManifest as apiExcessiveDataAudit } from './api-excessive-data-audit.mjs';
import { moduleManifest as boundedObjectKeyDiscovery } from './bounded-object-key-discovery.mjs';
import { moduleManifest as cloudObjectProxyAuthz } from './cloud-object-proxy-authz.mjs';
import { moduleManifest as sensitivePaymentData } from './sensitive-payment-data.mjs';
import { moduleManifest as financialIntegrityAudit } from './financial-integrity-audit.mjs';
import { moduleManifest as sqliTargetedVerify } from './sqli-targeted-verify.mjs';
import { moduleRunners } from './module-registry-runners.mjs';
import { normalizeModuleId } from './module-ids.mjs';

export const moduleManifests = [
  cookieSessionAudit,
  csrfFlowAudit,
  jwtJwksAudit,
  http3QuicSurface,
  nginxHttp3Cve202642530,
  cveCorrelation,
  panelExposureAudit,
  pastebinIntel,
  serviceWorkerAudit,
  apiContractDiff,
  websocketRecon,
  hppParamPollution,
  hexstrikeOrchestrator,
  domClobberingAudit,
  emailSecurityDeep,
  secretsContextRanker,
  riskExplainer,
  vigoliumDast,
  vigoliumAudit,
  vigoliumSwarm,
  sqliDeepVerify,
  xssVibesSafe,
  cloudDebugEnvAudit,
  runtimeEndpointPivot,
  deterministicVoucherAudit,
  jwtClaimAuthzDiff,
  authzObjectMatrixV2,
  artifactSafetyAudit,
  apiExcessiveDataAudit,
  boundedObjectKeyDiscovery,
  cloudObjectProxyAuthz,
  sensitivePaymentData,
  financialIntegrityAudit,
  sqliTargetedVerify,
];

const registry = new Map(
  moduleManifests.map((manifest) => [
    manifest.id,
    {
      manifest,
      run: moduleRunners[manifest.id] || null,
    },
  ]),
);

export function listModuleManifests() {
  return moduleManifests.map((m) => ({ ...m, outputs: [...(m.outputs || [])] }));
}

export function getRegistryEntry(moduleId) {
  const id = normalizeModuleId(moduleId);
  return registry.get(id) || null;
}

export function getModulesForCategory(category) {
  const cat = String(category || '').trim().toLowerCase();
  return moduleManifests.filter((m) => String(m.category || '').toLowerCase() === cat);
}

export async function runModule(moduleId, state) {
  const entry = getRegistryEntry(moduleId);
  if (!entry?.run) {
    throw new Error(`módulo não registado ou sem run(): ${moduleId}`);
  }
  return entry.run(state);
}

export { registry as moduleRegistry };
