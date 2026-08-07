/**
 * Expansão determinística dos módulos internos do Vigolium para o plano efetivo.
 * Fail-closed: seleção vazia, ambígua ou inexistente nunca vira "all".
 */

import { createHash } from 'node:crypto';
import { listVigoliumModules } from './vigolium-catalog.mjs';

/** Classes de risco usadas no plano Auto / hash. */
export const VIGOLIUM_MODULE_RISK = Object.freeze({
  PASSIVE: 'passive',
  ACTIVE: 'active',
  INTRUSIVE: 'intrusive',
  CREDENTIAL: 'credential',
  WRITE: 'write',
  DESTRUCTIVE: 'destructive',
});

/**
 * IDs/tags/padrões proibidos no Auto até existir consentimento dedicado.
 * Cobertura heurística + IDs conhecidos; o catálogo real reforça via tags.
 */
export const AUTO_VIGOLIUM_BLOCKED_PATTERNS = Object.freeze([
  /upload/i,
  /stored[-_]?xss/i,
  /stored[-_]?payload/i,
  /credential/i,
  /cred[-_]?spray/i,
  /password[-_]?spray/i,
  /bruteforce/i,
  /brute[-_]?force/i,
  /default[-_]?login/i,
  /default[-_]?cred/i,
  /login[-_]?attempt/i,
  /signup/i,
  /register[-_]?account/i,
  /\bwrite\b/i,
  /mutable[-_]?verb/i,
  /http[-_]?put/i,
  /http[-_]?delete/i,
  /http[-_]?patch/i,
  /\bstor\b/i,
]);

export const AUTO_VIGOLIUM_BLOCKED_TAGS = Object.freeze([
  'credential',
  'credentials',
  'upload',
  'write',
  'destructive',
  'stored-xss',
  'stored_payload',
  'auth-bruteforce',
  'login-spray',
]);

function normalizeId(value) {
  return String(value || '').trim().toLowerCase();
}

function uniqueSorted(values) {
  return [...new Set((values || []).map(normalizeId).filter(Boolean))].sort();
}

export function classifyVigoliumModuleRisk(module = {}) {
  const hay = [
    module.id,
    module.name,
    module.short,
    module.descriptionSummary,
    module.kind,
    ...(module.tags || []),
  ].join(' ').toLowerCase();
  if (/destruct|wipe|drop|truncate|ransom/i.test(hay)) return VIGOLIUM_MODULE_RISK.DESTRUCTIVE;
  if (
    AUTO_VIGOLIUM_BLOCKED_PATTERNS.some((re) => re.test(hay))
    || (module.tags || []).some((tag) => AUTO_VIGOLIUM_BLOCKED_TAGS.includes(normalizeId(tag)))
  ) {
    if (/upload|stored|write|put|delete|patch|stor|mutable/i.test(hay)) {
      return VIGOLIUM_MODULE_RISK.WRITE;
    }
    return VIGOLIUM_MODULE_RISK.CREDENTIAL;
  }
  if (module.kind === 'passive') return VIGOLIUM_MODULE_RISK.PASSIVE;
  if (/dast|sqli|xss|ssrf|rce|inject/i.test(hay)) return VIGOLIUM_MODULE_RISK.INTRUSIVE;
  return VIGOLIUM_MODULE_RISK.ACTIVE;
}

export function isVigoliumModuleBlockedInAuto(module = {}) {
  const risk = classifyVigoliumModuleRisk(module);
  return risk === VIGOLIUM_MODULE_RISK.WRITE
    || risk === VIGOLIUM_MODULE_RISK.CREDENTIAL
    || risk === VIGOLIUM_MODULE_RISK.DESTRUCTIVE;
}

function expandOnlyToken(only, catalogModules) {
  const token = String(only || '').trim().toLowerCase();
  if (!token) return [];
  if (token === 'all' || token === '*') {
    throw Object.assign(new Error('Vigolium --only=all é proibido no Auto'), {
      code: 'VIGOLIUM_ONLY_ALL_FORBIDDEN',
    });
  }
  const byId = catalogModules.filter((m) => normalizeId(m.id) === token);
  if (byId.length) return byId;
  const byKind = catalogModules.filter((m) => m.kind === token);
  if (byKind.length) return byKind;
  const byTag = catalogModules.filter((m) => (m.tags || []).some((t) => normalizeId(t) === token));
  if (byTag.length) return byTag;
  throw Object.assign(new Error(`Vigolium --only desconhecido ou vazio: ${token}`), {
    code: 'VIGOLIUM_ONLY_UNRESOLVED',
  });
}

function resolveByFilter(filters, catalogModules) {
  const wanted = uniqueSorted(filters);
  if (!wanted.length) return [];
  const byId = new Map(catalogModules.map((m) => [normalizeId(m.id), m]));
  const resolved = [];
  const missing = [];
  const ambiguous = [];
  for (const id of wanted) {
    if (id === 'all' || id === '*') {
      throw Object.assign(new Error('Filtro Vigolium "all" é proibido no Auto'), {
        code: 'VIGOLIUM_FILTER_ALL_FORBIDDEN',
      });
    }
    if (byId.has(id)) {
      resolved.push(byId.get(id));
      continue;
    }
    const fuzzy = catalogModules.filter((m) => {
      const mid = normalizeId(m.id);
      return mid.includes(id) || id.includes(mid);
    });
    if (fuzzy.length === 1) {
      resolved.push(fuzzy[0]);
    } else if (fuzzy.length > 1) {
      ambiguous.push({ filter: id, matches: fuzzy.map((m) => m.id) });
    } else {
      missing.push(id);
    }
  }
  if (ambiguous.length) {
    throw Object.assign(
      new Error(
        `Filtro Vigolium ambíguo: ${ambiguous.map((a) => `${a.filter}→[${a.matches.join(',')}]`).join('; ')}`,
      ),
      { code: 'VIGOLIUM_FILTER_AMBIGUOUS', ambiguous },
    );
  }
  if (missing.length) {
    throw Object.assign(
      new Error(`Módulos Vigolium inexistentes no catálogo: ${missing.join(', ')}`),
      { code: 'VIGOLIUM_FILTER_MISSING', missing },
    );
  }
  return resolved;
}

function resolveByTags(tags, catalogModules) {
  const wanted = uniqueSorted(tags);
  if (!wanted.length) return [];
  const availableTags = new Set(
    catalogModules.flatMap((m) => (m.tags || []).map((t) => normalizeId(t))),
  );
  for (const tag of wanted) {
    if (!availableTags.has(tag)) {
      throw Object.assign(new Error(`Tag Vigolium inexistente: ${tag}`), {
        code: 'VIGOLIUM_TAG_MISSING',
        tag,
      });
    }
  }
  const matched = catalogModules.filter((m) =>
    wanted.every((tag) => (m.tags || []).some((t) => normalizeId(t) === tag)));
  if (!matched.length) {
    throw Object.assign(new Error(`Nenhum módulo Vigolium corresponde às tags: ${wanted.join(',')}`), {
      code: 'VIGOLIUM_TAG_EMPTY',
    });
  }
  return matched;
}

/**
 * Expande a seleção Vigolium para IDs concretos.
 * @param {object} opts
 * @param {string[]} [opts.modules]
 * @param {string[]} [opts.moduleTags]
 * @param {string|null} [opts.only]
 * @param {string} [opts.root]
 * @param {Function} [opts.listModulesImpl] — injetável para testes
 * @param {boolean} [opts.forAuto=true]
 */
export async function expandVigoliumEffectiveModules({
  modules = [],
  moduleTags = [],
  only = null,
  root = process.cwd(),
  listModulesImpl = listVigoliumModules,
  forAuto = true,
} = {}) {
  const catalog = await listModulesImpl({ root });
  const catalogModules = Array.isArray(catalog?.modules) ? catalog.modules : [];
  if (!catalogModules.length) {
    throw Object.assign(
      new Error(
        'Catálogo interno Vigolium indisponível: impossível expandir módulos antes dos gates',
      ),
      { code: 'VIGOLIUM_CATALOG_UNAVAILABLE' },
    );
  }

  let selected = [];
  const hasModules = uniqueSorted(modules).length > 0;
  const hasTags = uniqueSorted(moduleTags).length > 0;
  const hasOnly = Boolean(String(only || '').trim());

  if (!hasModules && !hasTags && !hasOnly) {
    throw Object.assign(
      new Error(
        'Seleção Vigolium vazia é proibida no Auto (nunca expande para all)',
      ),
      { code: 'VIGOLIUM_EMPTY_SELECTION' },
    );
  }

  if (hasOnly) {
    selected = expandOnlyToken(only, catalogModules);
  }
  if (hasModules) {
    const byFilter = resolveByFilter(modules, catalogModules);
    selected = selected.length
      ? selected.filter((m) => byFilter.some((x) => x.id === m.id))
      : byFilter;
    if (hasOnly && !selected.length) {
      throw Object.assign(
        new Error('Interseção --only ∩ módulos resultou vazia'),
        { code: 'VIGOLIUM_SELECTION_EMPTY' },
      );
    }
  }
  if (hasTags) {
    const byTags = resolveByTags(moduleTags, catalogModules);
    selected = selected.length
      ? selected.filter((m) => byTags.some((x) => x.id === m.id))
      : byTags;
    if (!selected.length) {
      throw Object.assign(
        new Error('Interseção tags ∩ filtros resultou vazia'),
        { code: 'VIGOLIUM_SELECTION_EMPTY' },
      );
    }
  }

  if (!selected.length) {
    throw Object.assign(new Error('Resolução Vigolium resultou em zero módulos'), {
      code: 'VIGOLIUM_SELECTION_EMPTY',
    });
  }

  const blocked = [];
  const allowed = [];
  for (const mod of selected) {
    const risk = classifyVigoliumModuleRisk(mod);
    const row = Object.freeze({
      id: normalizeId(mod.id),
      kind: mod.kind || null,
      risk,
      tags: Object.freeze([...(mod.tags || [])].map(normalizeId).sort()),
      blockedInAuto: isVigoliumModuleBlockedInAuto(mod),
    });
    if (forAuto && row.blockedInAuto) blocked.push(row);
    else allowed.push(row);
  }

  if (forAuto && blocked.length) {
    throw Object.assign(
      new Error(
        `Vigolium Auto bloqueia writes/credenciais/destrutivos: ${blocked.map((b) => b.id).join(', ')}`,
      ),
      { code: 'VIGOLIUM_AUTO_BLOCKED_MODULES', blocked },
    );
  }

  if (!allowed.length) {
    throw Object.assign(new Error('Nenhum módulo Vigolium permitado após filtros de risco'), {
      code: 'VIGOLIUM_SELECTION_EMPTY',
    });
  }

  const ids = uniqueSorted(allowed.map((m) => m.id));
  return Object.freeze({
    schemaVersion: 1,
    strategy: null,
    moduleIds: Object.freeze(ids),
    modules: Object.freeze(allowed),
    catalogCount: catalogModules.length,
    catalogHash: hashCatalogIds(catalogModules),
  });
}

function hashCatalogIds(modules) {
  return createHash('sha256')
    .update(uniqueSorted(modules.map((m) => m.id)).join('\n'))
    .digest('hex');
}

/**
 * Aplica a expansão ao snapshot público/runtime do Auto.
 */
export function applyVigoliumExpansionToRuntime(runtime, expansion) {
  if (!runtime || !expansion) return runtime;
  return Object.freeze({
    ...runtime,
    vigoliumModules: Object.freeze([...expansion.moduleIds]),
    vigoliumResolvedModules: expansion.modules,
    vigoliumCatalogHash: expansion.catalogHash,
    vigoliumCatalogCount: expansion.catalogCount,
  });
}
