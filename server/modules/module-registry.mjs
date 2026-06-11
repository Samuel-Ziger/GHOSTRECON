import { moduleManifest as apiContractDiff } from './api-contract-diff.mjs';
import { moduleManifest as cookieSessionAudit } from './cookie-session-audit.mjs';
import { moduleManifest as csrfFlowAudit } from './csrf-flow-audit.mjs';
import { moduleManifest as domClobberingAudit } from './dom-clobbering-audit.mjs';
import { moduleManifest as emailSecurityDeep } from './email-security-deep.mjs';
import { moduleManifest as hppParamPollution } from './hpp-param-pollution.mjs';
import { moduleManifest as jwtJwksAudit } from './jwt-jwks-audit.mjs';
import { moduleManifest as secretsContextRanker } from './secrets-context-ranker.mjs';
import { moduleManifest as serviceWorkerAudit } from './service-worker-audit.mjs';
import { moduleManifest as websocketRecon } from './websocket-recon.mjs';

export const moduleManifests = [
  cookieSessionAudit,
  csrfFlowAudit,
  jwtJwksAudit,
  serviceWorkerAudit,
  apiContractDiff,
  websocketRecon,
  hppParamPollution,
  domClobberingAudit,
  emailSecurityDeep,
  secretsContextRanker,
];

export function listModuleManifests() {
  return moduleManifests.map((m) => ({ ...m, outputs: [...(m.outputs || [])] }));
}
