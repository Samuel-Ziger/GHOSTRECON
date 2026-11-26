/**
 * Playbooks — perfis nomeados que pré-selecionam módulos e parâmetros de pipeline.
 *
 * Formato: JSON em `playbooks/*.json` ou YAML-ish (subset simples) em `playbooks/*.yaml`.
 * Não queremos puxar dependência de YAML — usamos JSON como fonte canônica.
 * Ficheiros .yaml são tolerados por um parser minimalista (key: value / listas "- ").
 *
 * Campos suportados em cada playbook:
 *   name         string  (obrigatório, único)
 *   description  string
 *   modules      string[]
 *   profile      "standard" | "stealth" | "aggressive"
 *   limits       object   (merge em config.js no server — futuro)
 *   tags         string[]
 *   targetHint   string   (regex/glob sugerido, apenas documental)
 */

import fs from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { AUTO_LEGACY_CAPABILITIES, AUTO_ENGINE_CAPABILITIES } from '../../auto-agent/pipeline-capabilities.mjs';
import { listModuleManifests } from '../module-registry.mjs';
import { normalizeModuleId } from '../module-ids.mjs';
import { findRetiredModuleIds } from '../retired-modules.mjs';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const DEFAULT_DIR = path.resolve(__dirname, '..', '..', '..', 'playbooks');

/** Migrações históricas explícitas. Expansões 1:N nunca são silenciosas. */
export const PLAYBOOK_MODULE_MIGRATIONS = new Map([
  ['crtsh', ['subdomains']],
  ['http', ['http_probe']],
  ['openapi_harvest', ['openapi_specs']],
  ['graphql', ['graphql_probe', 'graphql_recon']],
  ['param_discovery', ['active_param_discovery']],
  ['verify', ['evidence_verification']],
  ['js_analyze', ['js_intel']],
  ['js_crawler', ['js_intel']],
  // O probe TLS legado vive hoje na mesma fase/capacidade que audita headers.
  ['tls', ['security_headers']],
  ['html_surface', ['client_surface_audit']],
  ['takeover', ['asset_discovery']],
  ['github_clone', ['github']],
  // A recolha atual combina análise de bundles e priorização contextual.
  ['secrets', ['js_intel', 'secrets_context_ranker']],
  ['commoncrawl', ['common_crawl']],
  ['well_known', ['wellknown_security_txt', 'wellknown_openid']],
  ['dns_enrich', ['dns_enrichment']],
  ['kali_subdomains', ['subfinder', 'amass']],
  ['wpscan', ['kali_wpscan']],
  ['xss_vibes', ['kali_xss_vibes']],
]);

function executableModuleIds() {
  return new Set([
    ...AUTO_LEGACY_CAPABILITIES.map((capability) => normalizeModuleId(capability.id)),
    ...AUTO_ENGINE_CAPABILITIES.map((capability) => normalizeModuleId(capability.id)),
    ...listModuleManifests().map((manifest) => normalizeModuleId(manifest.id)),
  ].filter(Boolean));
}

/**
 * Resolve aliases históricos e prova que cada ID tem capacidade executável.
 * Retorna o plano canónico e metadados para UI/CLI; não executa nada.
 */
export function validatePlaybookModules(modules = []) {
  const executable = executableModuleIds();
  const canonicalModules = [];
  const migrations = [];
  const unknownModules = [];
  const retiredModules = findRetiredModuleIds(modules);

  for (const input of Array.isArray(modules) ? modules : []) {
    const raw = String(input || '').trim().toLowerCase();
    if (!raw) continue;
    const normalized = normalizeModuleId(raw);
    if (retiredModules.includes(normalized)) continue;
    const migrated = PLAYBOOK_MODULE_MIGRATIONS.get(raw)
      || PLAYBOOK_MODULE_MIGRATIONS.get(normalized);
    const resolved = migrated || [normalized];
    if (migrated) migrations.push(Object.freeze({ from: raw, to: [...resolved] }));
    for (const id of resolved) {
      const canonical = normalizeModuleId(id);
      if (!executable.has(canonical)) {
        unknownModules.push(raw);
        continue;
      }
      if (!canonicalModules.includes(canonical)) canonicalModules.push(canonical);
    }
  }

  return Object.freeze({
    ok: unknownModules.length === 0 && retiredModules.length === 0,
    modules: Object.freeze(canonicalModules),
    migrations: Object.freeze(migrations),
    unknownModules: Object.freeze([...new Set(unknownModules)]),
    retiredModules: Object.freeze(retiredModules),
  });
}

function playbookDirs() {
  const extras = (process.env.GHOSTRECON_PLAYBOOKS_DIR || '')
    .split(/[;:]/)
    .map((s) => s.trim())
    .filter(Boolean);
  return [DEFAULT_DIR, ...extras];
}

export async function listPlaybooks() {
  const out = new Map(); // name → playbook (primeira ocorrência vence)
  const loadErrors = [];
  for (const dir of playbookDirs()) {
    let files;
    try {
      files = await fs.readdir(dir);
    } catch {
      continue;
    }
    for (const f of files) {
      if (!/\.(json|ya?ml)$/i.test(f)) continue;
      try {
        const pb = await loadPlaybookFile(path.join(dir, f));
        const normalized = finalizePlaybook(pb, { strict: false });
        if (normalized?.name && !out.has(normalized.name)) out.set(normalized.name, normalized);
      } catch (error) {
        loadErrors.push(`${path.join(dir, f)}: ${error?.message || error}`);
      }
    }
  }
  if (loadErrors.length) {
    const error = new Error(`playbook(s) inválido(s): ${loadErrors.join('; ')}`);
    error.code = 'PLAYBOOK_LOAD_FAILED';
    error.details = loadErrors;
    throw error;
  }
  return [...out.values()].sort((a, b) => a.name.localeCompare(b.name));
}

export async function resolvePlaybook(name) {
  const n = String(name || '').trim().toLowerCase();
  if (!n) throw new Error('playbook vazio');
  for (const dir of playbookDirs()) {
    for (const ext of ['json', 'yaml', 'yml']) {
      const candidate = path.join(dir, `${n}.${ext}`);
      try {
        const pb = await loadPlaybookFile(candidate);
        if (pb) return finalizePlaybook(pb, { strict: true });
      } catch (error) {
        if (error?.code === 'ENOENT') continue;
        throw error;
      }
    }
  }
  // fallback: procura por name interno
  const all = await listPlaybooks();
  const match = all.find((p) => p.name.toLowerCase() === n);
  if (match) {
    if (!match.validation?.ok) {
      if (match.validation?.retiredModules?.length) {
        throw invalidPlaybookRetiredModulesError(match.name, match.validation.retiredModules);
      }
      throw invalidPlaybookModulesError(match.name, match.validation?.unknownModules || []);
    }
    return match;
  }
  throw new Error(`playbook não encontrado: ${name}`);
}

async function loadPlaybookFile(file) {
  const raw = await fs.readFile(file, 'utf8');
  if (/\.json$/i.test(file)) return JSON.parse(raw);
  return parseMinimalYaml(raw);
}

function normalize(pb) {
  return {
    name: String(pb.name || '').trim(),
    description: String(pb.description || '').trim(),
    modules: Array.isArray(pb.modules) ? pb.modules.map(String) : [],
    profile: pb.profile ? String(pb.profile) : 'standard',
    limits: pb.limits && typeof pb.limits === 'object' ? pb.limits : {},
    tags: Array.isArray(pb.tags) ? pb.tags.map(String) : [],
    targetHint: pb.targetHint ? String(pb.targetHint) : '',
  };
}

function invalidPlaybookModulesError(name, unknownModules) {
  const unknown = [...new Set((unknownModules || []).map(String).filter(Boolean))];
  const error = new Error(
    `playbook "${name}" contém módulos desconhecidos: ${unknown.join(', ')}`,
  );
  error.code = 'PLAYBOOK_MODULES_INVALID';
  error.playbook = name;
  error.unknownModules = unknown;
  return error;
}

function invalidPlaybookRetiredModulesError(name, retiredModules) {
  const retired = [...new Set((retiredModules || []).map(normalizeModuleId).filter(Boolean))];
  const error = new Error(
    `playbook "${name}" contém módulos removidos permanentemente: ${retired.join(', ')}`,
  );
  error.code = 'MODULE_RETIRED';
  error.statusCode = 410;
  error.playbook = name;
  error.retiredModules = retired;
  return error;
}

function finalizePlaybook(pb, { strict = true } = {}) {
  const normalized = normalize(pb);
  if (!normalized.name) throw new Error('playbook sem name');
  const validation = validatePlaybookModules(normalized.modules);
  const finalized = {
    ...normalized,
    modules: [...validation.modules],
    validation: {
      ok: validation.ok,
      migrations: validation.migrations.map((row) => ({ from: row.from, to: [...row.to] })),
      unknownModules: [...validation.unknownModules],
      retiredModules: [...validation.retiredModules],
    },
  };
  if (strict && !validation.ok) {
    if (validation.retiredModules.length) {
      throw invalidPlaybookRetiredModulesError(normalized.name, validation.retiredModules);
    }
    throw invalidPlaybookModulesError(normalized.name, validation.unknownModules);
  }
  return finalized;
}

/**
 * Parser YAML mínimo — suficiente para playbooks triviais:
 *   name: api-first
 *   modules:
 *     - crtsh
 *     - http
 *
 * Não suporta indentação aninhada complexa, multilinhas, âncoras, etc.
 * Exportado para testes.
 */
export function parseMinimalYaml(text) {
  const lines = String(text || '').split(/\r?\n/);
  const out = {};
  let currentList = null;
  for (const line of lines) {
    const raw = line.replace(/#.*$/, '');
    const trimmed = raw.trim();
    if (!trimmed) continue;

    if (trimmed.startsWith('- ')) {
      if (currentList) currentList.push(parseScalar(trimmed.slice(2).trim()));
      continue;
    }
    const m = /^([A-Za-z_][A-Za-z0-9_-]*)\s*:\s*(.*)$/.exec(trimmed);
    if (!m) continue;
    const key = m[1];
    const rest = m[2];
    if (!rest) {
      out[key] = [];
      currentList = out[key];
      continue;
    }
    currentList = null;
    if (rest.startsWith('[') && rest.endsWith(']')) {
      out[key] = rest
        .slice(1, -1)
        .split(',')
        .map((s) => parseScalar(s.trim()))
        .filter((v) => v !== '');
    } else {
      out[key] = parseScalar(rest);
    }
  }
  return out;
}

function parseScalar(v) {
  if (v == null) return v;
  const s = String(v).trim();
  if (/^['"].*['"]$/.test(s)) return s.slice(1, -1);
  if (/^-?\d+$/.test(s)) return Number(s);
  if (/^-?\d+\.\d+$/.test(s)) return Number(s);
  if (s === 'true') return true;
  if (s === 'false') return false;
  if (s === 'null') return null;
  return s;
}
