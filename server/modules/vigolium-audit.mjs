/** Manifest UI — execução em go-agent.mjs via bridge/agent-bridge.mjs */
export const moduleManifest = {
  id: 'vigolium_audit',
  name: 'Vigolium code audit (SAST agent)',
  category: 'whitebox',
  intrusive: false,
  requiresAuth: false,
  requiresKali: false,
  timeoutMs: 3_600_000,
  concurrency: 1,
  outputs: ['finding'],
};
