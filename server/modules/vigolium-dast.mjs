/** Manifest do módulo UI — execução real em server/pipeline/phases/go-engine.mjs */
export const moduleManifest = {
  id: 'vigolium_dast',
  name: 'Vigolium DAST (motor Go)',
  category: 'active',
  intrusive: true,
  requiresAuth: false,
  requiresKali: false,
  timeoutMs: 600_000,
  concurrency: 1,
  outputs: ['finding'],
};
