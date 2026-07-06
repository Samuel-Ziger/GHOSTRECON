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
import { moduleManifest as panelExposureAudit } from './panel-exposure-audit.mjs';
import { moduleManifest as riskExplainer } from './risk-explainer.mjs';
import { moduleManifest as secretsContextRanker } from './secrets-context-ranker.mjs';
import { moduleManifest as serviceWorkerAudit } from './service-worker-audit.mjs';
import { moduleManifest as websocketRecon } from './websocket-recon.mjs';
import { moduleManifest as vigoliumDast } from './vigolium-dast.mjs';
import { moduleManifest as vigoliumAudit } from './vigolium-audit.mjs';
import { moduleManifest as vigoliumSwarm } from './vigolium-swarm.mjs';
import { moduleRunners } from './module-registry-runners.mjs';
import { normalizeModuleId } from './module-ids.mjs';

export const moduleManifests = [
  cookieSessionAudit,
  csrfFlowAudit,
  jwtJwksAudit,
  http3QuicSurface,
  nginxHttp3Cve202642530,
  panelExposureAudit,
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
