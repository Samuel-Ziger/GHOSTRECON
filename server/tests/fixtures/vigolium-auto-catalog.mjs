/** Catálogo sintético para testes Auto sem fonte vigolium/ no worktree. */

export const FIXTURE_VIGOLIUM_MODULES = Object.freeze([
  Object.freeze({
    id: 'headers',
    name: 'headers',
    short: 'security headers',
    descriptionSummary: 'Passive header checks',
    kind: 'passive',
    tags: Object.freeze(['headers', 'passive']),
  }),
  Object.freeze({
    id: 'audit',
    name: 'audit',
    short: 'surface audit',
    descriptionSummary: 'Active surface audit',
    kind: 'active',
    tags: Object.freeze(['audit', 'active']),
  }),
  Object.freeze({
    id: 'xss_light_scanner',
    name: 'xss light',
    short: 'xss',
    descriptionSummary: 'Active XSS probe',
    kind: 'active',
    tags: Object.freeze(['xss', 'dast']),
  }),
  Object.freeze({
    id: 'sqli_error_based',
    name: 'sqli',
    short: 'sqli',
    descriptionSummary: 'SQL injection error based',
    kind: 'active',
    tags: Object.freeze(['sqli', 'dast']),
  }),
  Object.freeze({
    id: 'upload_probe',
    name: 'upload probe',
    short: 'upload',
    descriptionSummary: 'Attempts file upload write probe',
    kind: 'active',
    tags: Object.freeze(['upload', 'write']),
  }),
  Object.freeze({
    id: 'credential_spray',
    name: 'credential spray',
    short: 'creds',
    descriptionSummary: 'Login credential spray',
    kind: 'active',
    tags: Object.freeze(['credential', 'login']),
  }),
]);

export async function listFixtureVigoliumModules(opts = {}) {
  let modules = [...FIXTURE_VIGOLIUM_MODULES];
  if (opts.kind) modules = modules.filter((m) => m.kind === opts.kind);
  if (opts.tag) {
    const tag = String(opts.tag).toLowerCase();
    modules = modules.filter((m) => m.tags.some((t) => t === tag));
  }
  if (opts.q) {
    const q = String(opts.q).toLowerCase();
    modules = modules.filter((m) => JSON.stringify(m).toLowerCase().includes(q));
  }
  return {
    ok: true,
    root: opts.root || process.cwd(),
    counts: {
      total: FIXTURE_VIGOLIUM_MODULES.length,
      filtered: modules.length,
      active: FIXTURE_VIGOLIUM_MODULES.filter((m) => m.kind === 'active').length,
      passive: FIXTURE_VIGOLIUM_MODULES.filter((m) => m.kind === 'passive').length,
    },
    tags: [...new Set(FIXTURE_VIGOLIUM_MODULES.flatMap((m) => m.tags))].sort(),
    modules,
    errors: [],
  };
}
