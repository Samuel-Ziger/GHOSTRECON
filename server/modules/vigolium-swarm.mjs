/** Manifest UI — execução em go-agent.mjs via bridge/agent-bridge.mjs */
export const moduleManifest = {
  id: 'vigolium_swarm',
  name: 'Vigolium agent swarm (IA + DAST)',
  category: 'active',
  intrusive: true,
  requiresAuth: false,
  requiresKali: false,
  timeoutMs: 3_600_000,
  concurrency: 1,
  outputs: ['finding'],
};
