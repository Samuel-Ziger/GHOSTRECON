import fs from 'node:fs';
import path from 'node:path';
import { spawn } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import {
  shouldSkipVigoliumExternalHarvest,
  shouldUseVigoliumVpsProfile,
  vigoliumVpsDefaultStrategy,
} from './vigolium-vps-profile.mjs';
import { assertVigoliumSourceIdentityShape } from './vigolium-source-integrity.mjs';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = path.resolve(__dirname, '..');

const ENGINE_MODES = new Set(['node', 'go', 'both']);
const STRATEGIES = new Set(['lite', 'balanced', 'deep']);
const PATH_LOOKUP_TIMEOUT_MS = 3_000;
const TRUTHY = new Set(['1', 'true', 'yes', 'y', 'on']);
const VIGOLIUM_RUNTIME_CONFIG_VERSION = 1;
const VIGOLIUM_CHILD_ENV_KEYS = Object.freeze([
  // Necessárias para localizar subprocessos e diretórios temporários sem
  // encaminhar o restante do ambiente da API (tokens, DB, JWT, cookies etc.).
  'PATH',
  'HOME',
  'USERPROFILE',
  'TMPDIR',
  'TMP',
  'TEMP',
  'SYSTEMROOT',
  'WINDIR',
  'COMSPEC',
  'PATHEXT',
  // Localidade/terminal não carregam credenciais e evitam diferenças de parse.
  'LANG',
  'LC_ALL',
  'LC_CTYPE',
  'TZ',
  'TERM',
  'NO_COLOR',
]);

function hasOwn(value, key) {
  return Boolean(value && Object.prototype.hasOwnProperty.call(value, key));
}

function isFrozenRuntimeConfig(ctx) {
  return ctx?.vigoliumRuntimeConfigFrozen === true;
}

function cleanList(values) {
  return (Array.isArray(values) ? values : [])
    .map(String)
    .map((value) => value.trim())
    .filter(Boolean);
}

function freezeList(values) {
  return Object.freeze(cleanList(values));
}

function runtimeConfigError(message) {
  const error = new Error(`snapshot Vigolium inválido: ${message}`);
  error.code = 'VIGOLIUM_RUNTIME_CONFIG_INVALID';
  return error;
}

export function assertVigoliumRuntimeConfig(value) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) {
    throw runtimeConfigError('objeto ausente');
  }
  if (
    value.vigoliumRuntimeConfigFrozen !== true
    || value.vigoliumRuntimeConfigVersion !== VIGOLIUM_RUNTIME_CONFIG_VERSION
  ) {
    throw runtimeConfigError('versão ou marcador incompatível');
  }
  if (!ENGINE_MODES.has(value.engineMode) || value.engine !== value.engineMode) {
    throw runtimeConfigError('engineMode inválido');
  }
  if (!STRATEGIES.has(value.vigoliumStrategy)) {
    throw runtimeConfigError('strategy inválida');
  }
  if (![...AGENT_MODES, 'none'].includes(value.vigoliumAgentMode)
    || value.vigoliumAgent !== value.vigoliumAgentMode) {
    throw runtimeConfigError('agentMode inválido');
  }
  for (const key of [
    'vigoliumModules',
    'vigoliumModuleTags',
    'vigoliumAuthFiles',
    'vigoliumAuthEntries',
  ]) {
    if (!Array.isArray(value[key]) || value[key].some((item) => typeof item !== 'string')) {
      throw runtimeConfigError(`${key} precisa ser array de strings`);
    }
  }
  for (const key of [
    'vigoliumHtmlReport',
    'vigoliumPreferPath',
    'vigoliumUseCodex',
    'vigoliumVpsProfile',
    'vigoliumSkipExternalHarvest',
  ]) {
    if (typeof value[key] !== 'boolean') {
      throw runtimeConfigError(`${key} precisa ser boolean`);
    }
  }
  for (const key of ['vigoliumTimeoutMs', 'vigoliumAgentTimeoutMs']) {
    if (!Number.isFinite(value[key]) || value[key] <= 0) {
      throw runtimeConfigError(`${key} precisa ser deadline positivo`);
    }
  }
  for (const key of [
    'vigoliumSource',
    'vigoliumInputFile',
    'vigoliumInputType',
    'vigoliumOnly',
  ]) {
    if (value[key] !== null && typeof value[key] !== 'string') {
      throw runtimeConfigError(`${key} precisa ser string ou null`);
    }
  }
  if (typeof value.vigoliumReportOnly !== 'string'
    || typeof value.vigoliumAuditMode !== 'string') {
    throw runtimeConfigError('reportOnly/auditMode inválidos');
  }
  if (
    value.vigoliumChildEnv != null
    && (
      typeof value.vigoliumChildEnv !== 'object'
      || Array.isArray(value.vigoliumChildEnv)
    )
  ) {
    throw runtimeConfigError('childEnv inválido');
  }
  const sourceIsExecutable = Boolean(
    value.vigoliumSource && value.vigoliumAgentMode !== 'none',
  );
  if (sourceIsExecutable) {
    try {
      assertVigoliumSourceIdentityShape(value.vigoliumExpectedSourceIdentity);
    } catch {
      throw runtimeConfigError('identidade da fonte local ausente ou inválida');
    }
    if (
      !Array.isArray(value.vigoliumSourceAllowedRoots)
      || value.vigoliumSourceAllowedRoots.length === 0
      || value.vigoliumSourceAllowedRoots.some(
        (root) => typeof root !== 'string' || !path.isAbsolute(root),
      )
    ) {
      throw runtimeConfigError('raízes permitidas da fonte local inválidas');
    }
  } else if (!value.vigoliumSource && value.vigoliumExpectedSourceIdentity != null) {
    throw runtimeConfigError('identidade de fonte presente sem vigoliumSource');
  }
  return value;
}

/** Raiz do monorepo (onde vive vigolium/). */
export function ghostreconRoot(sourceEnv = process.env) {
  return sourceEnv?.GHOSTRECON_ROOT?.trim() || REPO_ROOT;
}

/**
 * @param {{ engine?: string, modules?: string[] }} ctx
 * @returns {'node'|'go'|'both'}
 */
export function resolveEngineMode(ctx = {}, sourceEnv = process.env) {
  const fromCtx = String(ctx.engine || '').trim().toLowerCase();
  const fromEnv = String(sourceEnv?.GHOSTRECON_ENGINE || 'node').trim().toLowerCase();
  let mode = ENGINE_MODES.has(fromCtx) ? fromCtx : fromEnv;
  if (!ENGINE_MODES.has(mode)) mode = 'node';
  if (ctx.modules?.includes('vigolium_dast') && mode === 'node') return 'both';
  return mode;
}

export function shouldRunGoEngine(engineMode, modules = []) {
  if (modules.includes('vigolium_dast')) return true;
  return engineMode === 'go' || engineMode === 'both';
}

export function resolveVigoliumStrategy(ctx = {}, sourceEnv = process.env) {
  const raw = String(
    ctx.vigoliumStrategy || ctx.strategy || sourceEnv?.GHOSTRECON_VIGOLIUM_STRATEGY || '',
  )
    .trim()
    .toLowerCase();
  if (STRATEGIES.has(raw)) return raw;
  const vpsDefault = vigoliumVpsDefaultStrategy(ctx, sourceEnv);
  if (vpsDefault && STRATEGIES.has(vpsDefault)) return vpsDefault;
  return 'lite';
}

export { shouldUseVigoliumVpsProfile, shouldSkipVigoliumExternalHarvest };

export function resolveVigoliumModuleFilter(ctx = {}, sourceEnv = process.env) {
  const fromCtx = Array.isArray(ctx.vigoliumModules) ? ctx.vigoliumModules : [];
  if (fromCtx.length || (isFrozenRuntimeConfig(ctx) && hasOwn(ctx, 'vigoliumModules'))) {
    return cleanList(fromCtx);
  }
  const env = String(sourceEnv?.GHOSTRECON_VIGOLIUM_MODULES || '').trim();
  if (!env) return [];
  return env
    .split(',')
    .map((s) => s.trim())
    .filter(Boolean);
}

export function resolveVigoliumModuleTags(ctx = {}, sourceEnv = process.env) {
  const fromCtx = Array.isArray(ctx.vigoliumModuleTags) ? ctx.vigoliumModuleTags : [];
  if (fromCtx.length || (isFrozenRuntimeConfig(ctx) && hasOwn(ctx, 'vigoliumModuleTags'))) {
    return cleanList(fromCtx);
  }
  const single = String(ctx.vigoliumModuleTag || '').trim();
  if (single) return [single];
  const env = String(
    sourceEnv?.GHOSTRECON_VIGOLIUM_MODULE_TAGS
      || sourceEnv?.GHOSTRECON_VIGOLIUM_MODULE_TAG
      || '',
  ).trim();
  if (!env) return [];
  return env
    .split(',')
    .map((s) => s.trim())
    .filter(Boolean);
}

export function resolveVigoliumAuthFiles(ctx = {}, sourceEnv = process.env) {
  const fromCtx = Array.isArray(ctx.vigoliumAuthFiles) ? ctx.vigoliumAuthFiles : [];
  if (fromCtx.length || (isFrozenRuntimeConfig(ctx) && hasOwn(ctx, 'vigoliumAuthFiles'))) {
    return cleanList(fromCtx);
  }
  const single = String(ctx.vigoliumAuthFile || '').trim();
  if (single) return [single];
  const env = String(
    sourceEnv?.GHOSTRECON_VIGOLIUM_AUTH_FILES
      || sourceEnv?.GHOSTRECON_VIGOLIUM_AUTH_FILE
      || '',
  ).trim();
  if (!env) return [];
  return env
    .split(',')
    .map((s) => s.trim())
    .filter(Boolean);
}

function splitLooseList(value) {
  const raw = String(value || '').trim();
  if (!raw) return [];
  return raw
    .split(/[\n|,]+/)
    .map((s) => s.trim())
    .filter(Boolean);
}

function truthy(value) {
  if (typeof value === 'boolean') return value;
  return TRUTHY.has(String(value || '').trim().toLowerCase());
}

export function shouldPreferVigoliumPath(ctx = {}, sourceEnv = process.env) {
  if (ctx.vigoliumPreferPath === true) return true;
  if (ctx.vigoliumPreferPath === false && isFrozenRuntimeConfig(ctx)) return false;
  return Boolean(
    ctx.kaliMode === true ||
      truthy(sourceEnv?.GHOSTRECON_VIGOLIUM_PREFER_PATH) ||
      truthy(sourceEnv?.GHOSTRECON_VIGOLIUM_PATH_MODE),
  );
}

export function resolveVigoliumInputFile(ctx = {}) {
  // Nunca reabra esta capacidade pelo ambiente. Um arquivo `-T` pode conter
  // múltiplos alvos (por exemplo `servers` OpenAPI) e precisa de um contrato
  // selado/validado antes de voltar a ser executável.
  const raw = String(ctx.vigoliumInputFile || '').trim();
  return raw || null;
}

export function resolveVigoliumInputType(ctx = {}) {
  const raw = String(ctx.vigoliumInputType || '').trim();
  return raw || null;
}

export function resolveVigoliumOnly(ctx = {}, sourceEnv = process.env) {
  const frozen = isFrozenRuntimeConfig(ctx) && hasOwn(ctx, 'vigoliumOnly');
  const raw = String(
    frozen ? (ctx.vigoliumOnly || '') : (ctx.vigoliumOnly || sourceEnv?.GHOSTRECON_VIGOLIUM_ONLY || ''),
  ).trim();
  return raw || null;
}

export function resolveVigoliumAuthEntries(ctx = {}, sourceEnv = process.env) {
  const fromCtx = Array.isArray(ctx.vigoliumAuthEntries) ? ctx.vigoliumAuthEntries : [];
  const entries = fromCtx.length || (isFrozenRuntimeConfig(ctx) && hasOwn(ctx, 'vigoliumAuthEntries'))
    ? fromCtx
    : [
        ...splitLooseList(ctx.vigoliumAuth),
        ...splitLooseList(
          sourceEnv?.GHOSTRECON_VIGOLIUM_AUTHS || sourceEnv?.GHOSTRECON_VIGOLIUM_AUTH,
        ),
      ];
  return cleanList(entries);
}

export function shouldWriteVigoliumHtmlReport(ctx = {}, sourceEnv = process.env) {
  if (ctx.vigoliumHtmlReport === true) return true;
  if (ctx.vigoliumHtmlReport === false) return false;
  if (shouldUseVigoliumVpsProfile(ctx, sourceEnv)) return true;
  return truthy(sourceEnv?.GHOSTRECON_VIGOLIUM_HTML_REPORT);
}

export function resolveVigoliumReportOnly(ctx = {}, sourceEnv = process.env) {
  const frozen = isFrozenRuntimeConfig(ctx) && hasOwn(ctx, 'vigoliumReportOnly');
  const raw = String(
    frozen
      ? (ctx.vigoliumReportOnly || '')
      : (ctx.vigoliumReportOnly || sourceEnv?.GHOSTRECON_VIGOLIUM_REPORT_ONLY || ''),
  ).trim();
  return raw || 'discovery';
}

export function shouldUseVigoliumCodex(ctx = {}, sourceEnv = process.env) {
  // Uma escolha explícita no plano selado prevalece inclusive sobre o
  // ambiente do servidor. Isso impede que uma variável de boot reative o
  // provider depois de o operador/Auto ter aprovado `false`.
  if (ctx.vigoliumUseCodex === true) return true;
  if (ctx.vigoliumUseCodex === false) return false;
  return truthy(sourceEnv?.GHOSTRECON_VIGOLIUM_USE_CODEX);
}

/**
 * Ambiente mínimo entregue ao binário Vigolium e aos subprocessos do agente.
 * A configuração que muda o plano continua em argv/estado selado; o ambiente
 * filho não herda chaves, cookies, URLs de banco, JWTs ou tokens da API.
 */
export function buildVigoliumChildEnv(ctx = {}, sourceEnv = process.env) {
  const child = {};
  for (const key of VIGOLIUM_CHILD_ENV_KEYS) {
    const value = sourceEnv?.[key];
    if (value == null || String(value).includes('\0')) continue;
    child[key] = String(value);
  }
  if (shouldUseVigoliumCodex(ctx, sourceEnv)) {
    child.GHOSTRECON_VIGOLIUM_USE_CODEX = '1';
    // O provider faz parte da opção explícita "usar Codex"; não aceite um
    // provider diferente injetado pelo ambiente após a aprovação.
    child.VIGOLIUM_PROVIDER = 'openai-codex-oauth';
  }
  if (shouldUseVigoliumVpsProfile(ctx, sourceEnv)) {
    if (shouldSkipVigoliumExternalHarvest(ctx, sourceEnv)) {
      child.SKIP_EXTERNAL_HARVEST = '1';
    }
    child.VIGOLIUM_STRATEGY = resolveVigoliumStrategy(ctx, sourceEnv);
  }
  return child;
}

export function vigoliumTimeoutMs(sourceEnv = process.env) {
  const n = Number(sourceEnv?.GHOSTRECON_VIGOLIUM_TIMEOUT_MS);
  if (Number.isFinite(n) && n > 0) return Math.min(n, 3_600_000);
  return 600_000;
}

function fileExecutable(p) {
  if (!p) return false;
  try {
    const st = fs.statSync(p);
    return st.isFile() || st.isSymbolicLink();
  } catch {
    return false;
  }
}

function homeDir(sourceEnv = process.env) {
  return sourceEnv?.HOME || sourceEnv?.USERPROFILE || '';
}

function withExecutableVariants(p) {
  const base = String(p || '').trim();
  if (!base) return [];
  if (/\.exe$/i.test(base)) return [base];
  return [base, `${base}.exe`];
}

/** Candidatos ao binário vigolium (ordem de preferência). */
export function vigoliumBinaryCandidates(
  root = ghostreconRoot(),
  sourceEnv = process.env,
) {
  const list = [];
  const envBin = String(sourceEnv?.GHOSTRECON_VIGOLIUM_BIN || '').trim();
  if (envBin) list.push(...withExecutableVariants(envBin));
  const home = homeDir(sourceEnv);
  for (const p of [
    path.join(root, 'engines', 'vigolium'),
    path.join(root, 'vigolium', 'bin', 'vigolium'),
    home ? path.join(home, 'go', 'bin', 'vigolium') : '',
    home ? path.join(home, '.local', 'bin', 'vigolium') : '',
  ]) {
    list.push(...withExecutableVariants(p));
  }
  return [...new Set(list.filter(Boolean))];
}

export async function resolvePathVigoliumBinary(sourceEnv = process.env) {
  const which = await new Promise((resolve) => {
    const finder = process.platform === 'win32' ? 'where' : 'which';
    const lookupEnv = {};
    for (const key of ['PATH', 'PATHEXT', 'SYSTEMROOT', 'WINDIR', 'COMSPEC']) {
      if (sourceEnv?.[key] != null) lookupEnv[key] = String(sourceEnv[key]);
    }
    const p = spawn(finder, ['vigolium'], {
      stdio: ['ignore', 'pipe', 'pipe'],
      env: lookupEnv,
    });
    let out = '';
    let settled = false;
    const finish = (value) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      resolve(value);
    };
    const timer = setTimeout(() => {
      try { p.kill('SIGKILL'); } catch {}
      finish(null);
    }, PATH_LOOKUP_TIMEOUT_MS);
    p.stdout?.on('data', (d) => {
      out += String(d);
    });
    p.on('error', () => finish(null));
    p.on('close', (code) => {
      if (code !== 0) finish(null);
      else {
        const line = out.split(/\r?\n/).map((s) => s.trim()).find(Boolean);
        finish(line || null);
      }
    });
  });
  if (which && fileExecutable(which)) return { bin: which, source: 'path' };
  return { bin: null, source: null };
}

export async function resolveVigoliumBinary(root = ghostreconRoot(), opts = {}) {
  const sourceEnv = opts.env && typeof opts.env === 'object' ? opts.env : process.env;
  const candidates = vigoliumBinaryCandidates(root, sourceEnv);
  const envBin = String(sourceEnv?.GHOSTRECON_VIGOLIUM_BIN || '').trim();
  if (envBin) {
    for (const p of withExecutableVariants(envBin)) {
      if (fileExecutable(p)) return { bin: p, source: 'env' };
    }
  }
  if (opts.preferPath) {
    const pathBin = await resolvePathVigoliumBinary(sourceEnv);
    if (pathBin.bin) return pathBin;
  }
  for (const p of candidates) {
    if (fileExecutable(p)) return { bin: p, source: p.includes(`${path.sep}engines${path.sep}`) ? 'engine' : 'local' };
  }
  const pathBin = await resolvePathVigoliumBinary(sourceEnv);
  if (pathBin.bin) return pathBin;
  return { bin: null, source: null };
}

/**
 * URL alvo para `vigolium scan -t`.
 * @param {{ domain: string, probeResults?: unknown[], urlCorpus?: string[], originByHost?: Map }} s
 */
export function resolveVigoliumTarget(s) {
  const { domain, probeResults, urlCorpus, originByHost } = s;
  if (originByHost && typeof originByHost.values === 'function') {
    for (const v of originByHost.values()) {
      const o = v?.origin;
      if (o && /^https?:\/\//i.test(o)) return o.replace(/\/$/, '') || o;
    }
  }
  if (Array.isArray(probeResults)) {
    for (const row of probeResults) {
      const url = row?.r?.url;
      if (row?.r?.ok && url && /^https?:\/\//i.test(url)) {
        return String(url).replace(/\/$/, '') || url;
      }
    }
  }
  if (Array.isArray(urlCorpus)) {
    const https = urlCorpus.find((u) => /^https:\/\//i.test(String(u)));
    if (https) return String(https).replace(/\/$/, '');
    const http = urlCorpus.find((u) => /^http:\/\//i.test(String(u)));
    if (http) return String(http).replace(/\/$/, '');
  }
  const d = String(domain || '').trim();
  if (/^https?:\/\//i.test(d)) return d.replace(/\/$/, '');
  return `https://${d}`;
}

const AGENT_MODES = new Set(['audit', 'swarm', 'query', 'autopilot']);

/**
 * @param {{ modules?: string[], vigoliumAgent?: string }} ctx
 * @returns {'none'|'audit'|'swarm'|'query'|'autopilot'}
 */
export function resolveVigoliumAgentMode(ctx = {}) {
  const fromCtx = String(ctx.vigoliumAgent || '').trim().toLowerCase();
  if (AGENT_MODES.has(fromCtx)) return fromCtx;
  if (isFrozenRuntimeConfig(ctx) && fromCtx === 'none') return 'none';
  const mods = ctx.modules || [];
  if (mods.includes('vigolium_autopilot')) return 'autopilot';
  if (mods.includes('vigolium_swarm')) return 'swarm';
  if (mods.includes('vigolium_audit')) return 'audit';
  return 'none';
}

export function shouldRunGoAgent(agentMode, modules = []) {
  if (agentMode !== 'none') return true;
  return modules.includes('vigolium_audit') || modules.includes('vigolium_swarm') || modules.includes('vigolium_autopilot');
}

export function resolveVigoliumSource(ctx = {}, sourceEnv = process.env) {
  const frozen = isFrozenRuntimeConfig(ctx) && hasOwn(ctx, 'vigoliumSource');
  const raw = String(
    frozen
      ? (ctx.vigoliumSource || '')
      : (ctx.vigoliumSource || sourceEnv?.GHOSTRECON_VIGOLIUM_SOURCE || ''),
  ).trim();
  return raw || null;
}

export function resolveVigoliumAuditMode(ctx = {}, sourceEnv = process.env) {
  const frozen = isFrozenRuntimeConfig(ctx) && hasOwn(ctx, 'vigoliumAuditMode');
  const raw = String(
    frozen
      ? (ctx.vigoliumAuditMode || '')
      : (ctx.vigoliumAuditMode || sourceEnv?.GHOSTRECON_VIGOLIUM_AUDIT_MODE || ''),
  ).trim();
  return raw || 'lite';
}

export function vigoliumAgentTimeoutMs(sourceEnv = process.env) {
  const n = Number(sourceEnv?.GHOSTRECON_VIGOLIUM_AGENT_TIMEOUT_MS);
  if (Number.isFinite(n) && n > 0) return Math.min(n, 7_200_000);
  return 3_600_000;
}

/**
 * Resolve uma única vez toda configuração Vigolium que pode alterar o plano
 * efetivo do RUN. O objeto retornado contém somente valores já normalizados,
 * arrays copiados/congelados e decisões booleanas explícitas; assim, helpers
 * chamados depois não voltam a consultar variáveis de ambiente divergentes.
 *
 * Credenciais permanecem no objeto privado de runtime (`vigoliumAuthEntries` e
 * `vigoliumAuthFiles`) e não devem ser serializadas em logs/NDJSON/relatórios.
 * A rota é responsável por representar apenas contagens/digests no plano
 * público e por selar a identidade dos arquivos.
 */
export function resolveVigoliumEffectiveConfig(
  ctx = {},
  { env = process.env } = {},
) {
  const vpsProfile = shouldUseVigoliumVpsProfile(ctx, env);
  const resolvedCtx = {
    ...ctx,
    vigoliumVpsProfile: vpsProfile,
    vigoliumRuntimeConfigFrozen: true,
  };
  const engineMode = resolveEngineMode(ctx, env);
  const agentMode = resolveVigoliumAgentMode(ctx);

  return Object.freeze({
    vigoliumRuntimeConfigVersion: VIGOLIUM_RUNTIME_CONFIG_VERSION,
    vigoliumRuntimeConfigFrozen: true,
    engine: engineMode,
    engineMode,
    vigoliumStrategy: resolveVigoliumStrategy(resolvedCtx, env),
    vigoliumModules: freezeList(resolveVigoliumModuleFilter(ctx, env)),
    vigoliumModuleTags: freezeList(resolveVigoliumModuleTags(ctx, env)),
    vigoliumAgent: agentMode,
    vigoliumAgentMode: agentMode,
    vigoliumSource: resolveVigoliumSource(ctx, env),
    vigoliumAuthFiles: freezeList(resolveVigoliumAuthFiles(ctx, env)),
    vigoliumAuthEntries: freezeList(resolveVigoliumAuthEntries(ctx, env)),
    vigoliumInputFile: resolveVigoliumInputFile(ctx),
    vigoliumInputType: resolveVigoliumInputType(ctx),
    vigoliumOnly: resolveVigoliumOnly(ctx, env),
    vigoliumHtmlReport: shouldWriteVigoliumHtmlReport(resolvedCtx, env),
    vigoliumReportOnly: resolveVigoliumReportOnly(ctx, env),
    vigoliumPreferPath: shouldPreferVigoliumPath(resolvedCtx, env),
    vigoliumUseCodex: shouldUseVigoliumCodex(ctx, env),
    vigoliumVpsProfile: vpsProfile,
    vigoliumSkipExternalHarvest:
      vpsProfile && shouldSkipVigoliumExternalHarvest(resolvedCtx, env),
    vigoliumAuditMode: resolveVigoliumAuditMode(ctx, env),
    vigoliumTimeoutMs: vigoliumTimeoutMs(env),
    vigoliumAgentTimeoutMs: vigoliumAgentTimeoutMs(env),
  });
}
