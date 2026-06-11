import { moduleManifest as apiContractDiff } from './api-contract-diff.mjs';
import { moduleManifest as cookieSessionAudit } from './cookie-session-audit.mjs';
import { moduleManifest as csrfFlowAudit } from './csrf-flow-audit.mjs';
import { moduleManifest as jwtJwksAudit } from './jwt-jwks-audit.mjs';
import { moduleManifest as serviceWorkerAudit } from './service-worker-audit.mjs';

export const moduleManifests = [
  cookieSessionAudit,
  csrfFlowAudit,
  jwtJwksAudit,
  serviceWorkerAudit,
  apiContractDiff,
];

export function listModuleManifests() {
  return moduleManifests.map((m) => ({ ...m, outputs: [...(m.outputs || [])] }));
}
