import fs from 'node:fs';
import path from 'node:path';
import { spawn } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import {
  shouldUseVigoliumVpsProfile,
  vigoliumVpsDefaultStrategy,
} from './vigolium-vps-profile.mjs';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = path.resolve(__dirname, '..');

const ENGINE_MODES = new Set(['node', 'go', 'both']);
const STRATEGIES = new Set(['lite', 'balanced', 'deep']);
const PATH_LOOKUP_TIMEOUT_MS = 3_000;
const TRUTHY = new Set(['1', 'true', 'yes', 'y', 'on']);
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

/** Raiz do monorepo (onde vive vigolium/). */
export function ghostreconRoot() {
  return process.env.GHOSTRECON_ROOT?.trim() || REPO_ROOT;
}

/**
 * @param {{ engine?: string, modules?: string[] }} ctx
 * @returns {'node'|'go'|'both'}
 */
export function resolveEngineMode(ctx = {}) {
  const fromCtx = String(ctx.engine || '').trim().toLowerCase();
  const fromEnv = String(process.env.GHOSTRECON_ENGINE || 'node').trim().toLowerCase();
  let mode = ENGINE_MODES.has(fromCtx) ? fromCtx : fromEnv;
  if (!ENGINE_MODES.has(mode)) mode = 'node';
  if (ctx.modules?.includes('vigolium_dast') && mode === 'node') return 'both';
  return mode;
}

export function shouldRunGoEngine(engineMode, modules = []) {
  if (modules.includes('vigolium_dast')) return true;
  return engineMode === 'go' || engineMode === 'both';
}

export function resolveVigoliumStrategy(ctx = {}) {
  const raw = String(
    ctx.vigoliumStrategy || ctx.strategy || process.env.GHOSTRECON_VIGOLIUM_STRATEGY || '',
  )
    .trim()
    .toLowerCase();
  if (STRATEGIES.has(raw)) return raw;
  const vpsDefault = vigoliumVpsDefaultStrategy(ctx);
  if (vpsDefault && STRATEGIES.has(vpsDefault)) return vpsDefault;
  return 'lite';
}

export { shouldUseVigoliumVpsProfile, shouldSkipVigoliumExternalHarvest } from './vigolium-vps-profile.mjs';

export function resolveVigoliumModuleFilter(ctx = {}) {
  const fromCtx = Array.isArray(ctx.vigoliumModules) ? ctx.vigoliumModules : [];
  if (fromCtx.length) return fromCtx.map(String);
  const env = String(process.env.GHOSTRECON_VIGOLIUM_MODULES || '').trim();
  if (!env) return [];
  return env
    .split(',')
    .map((s) => s.trim())
    .filter(Boolean);
}

export function resolveVigoliumModuleTags(ctx = {}) {
  const fromCtx = Array.isArray(ctx.vigoliumModuleTags) ? ctx.vigoliumModuleTags : [];
  if (fromCtx.length) return fromCtx.map(String).map((s) => s.trim()).filter(Boolean);
  const single = String(ctx.vigoliumModuleTag || '').trim();
  if (single) return [single];
  const env = String(process.env.GHOSTRECON_VIGOLIUM_MODULE_TAGS || process.env.GHOSTRECON_VIGOLIUM_MODULE_TAG || '').trim();
  if (!env) return [];
  return env
    .split(',')
    .map((s) => s.trim())
    .filter(Boolean);
}

export function resolveVigoliumAuthFiles(ctx = {}) {
  const fromCtx = Array.isArray(ctx.vigoliumAuthFiles) ? ctx.vigoliumAuthFiles : [];
  if (fromCtx.length) return fromCtx.map(String).map((s) => s.trim()).filter(Boolean);
  const single = String(ctx.vigoliumAuthFile || '').trim();
  if (single) return [single];
  const env = String(process.env.GHOSTRECON_VIGOLIUM_AUTH_FILES || process.env.GHOSTRECON_VIGOLIUM_AUTH_FILE || '').trim();
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

export function shouldPreferVigoliumPath(ctx = {}) {
  return Boolean(
    ctx.vigoliumPreferPath === true ||
      ctx.kaliMode === true ||
      truthy(process.env.GHOSTRECON_VIGOLIUM_PREFER_PATH) ||
      truthy(process.env.GHOSTRECON_VIGOLIUM_PATH_MODE),
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

export function resolveVigoliumOnly(ctx = {}) {
  const raw = String(ctx.vigoliumOnly || process.env.GHOSTRECON_VIGOLIUM_ONLY || '').trim();
  return raw || null;
}

export function resolveVigoliumAuthEntries(ctx = {}) {
  const fromCtx = Array.isArray(ctx.vigoliumAuthEntries) ? ctx.vigoliumAuthEntries : [];
  const entries = fromCtx.length
    ? fromCtx
    : [
        ...splitLooseList(ctx.vigoliumAuth),
        ...splitLooseList(process.env.GHOSTRECON_VIGOLIUM_AUTHS || process.env.GHOSTRECON_VIGOLIUM_AUTH),
      ];
  return entries.map(String).map((s) => s.trim()).filter(Boolean);
}

export function shouldWriteVigoliumHtmlReport(ctx = {}) {
  if (ctx.vigoliumHtmlReport === true) return true;
  if (ctx.vigoliumHtmlReport === false) return false;
  if (shouldUseVigoliumVpsProfile(ctx)) return true;
  return truthy(process.env.GHOSTRECON_VIGOLIUM_HTML_REPORT);
}

export function resolveVigoliumReportOnly(ctx = {}) {
  const raw = String(ctx.vigoliumReportOnly || process.env.GHOSTRECON_VIGOLIUM_REPORT_ONLY || '').trim();
  return raw || 'discovery';
}

export function shouldUseVigoliumCodex(ctx = {}) {
  // Uma escolha explícita no plano selado prevalece inclusive sobre o
  // ambiente do servidor. Isso impede que uma variável de boot reative o
  // provider depois de o operador/Auto ter aprovado `false`.
  if (ctx.vigoliumUseCodex === true) return true;
  if (ctx.vigoliumUseCodex === false) return false;
  return truthy(process.env.GHOSTRECON_VIGOLIUM_USE_CODEX);
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
  if (shouldUseVigoliumCodex(ctx)) {
    child.GHOSTRECON_VIGOLIUM_USE_CODEX = '1';
    // O provider faz parte da opção explícita "usar Codex"; não aceite um
    // provider diferente injetado pelo ambiente após a aprovação.
    child.VIGOLIUM_PROVIDER = 'openai-codex-oauth';
  }
  if (shouldUseVigoliumVpsProfile(ctx)) {
    child.SKIP_EXTERNAL_HARVEST = '1';
    child.VIGOLIUM_STRATEGY = resolveVigoliumStrategy(ctx);
  }
  return child;
}

export function vigoliumTimeoutMs() {
  const n = Number(process.env.GHOSTRECON_VIGOLIUM_TIMEOUT_MS);
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

function homeDir() {
  return process.env.HOME || process.env.USERPROFILE || '';
}

function withExecutableVariants(p) {
  const base = String(p || '').trim();
  if (!base) return [];
  if (/\.exe$/i.test(base)) return [base];
  return [base, `${base}.exe`];
}

/** Candidatos ao binário vigolium (ordem de preferência). */
export function vigoliumBinaryCandidates(root = ghostreconRoot()) {
  const list = [];
  const envBin = String(process.env.GHOSTRECON_VIGOLIUM_BIN || '').trim();
  if (envBin) list.push(...withExecutableVariants(envBin));
  const home = homeDir();
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

export async function resolvePathVigoliumBinary() {
  const which = await new Promise((resolve) => {
    const finder = process.platform === 'win32' ? 'where' : 'which';
    const p = spawn(finder, ['vigolium'], { stdio: ['ignore', 'pipe', 'pipe'] });
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
  const candidates = vigoliumBinaryCandidates(root);
  const envBin = String(process.env.GHOSTRECON_VIGOLIUM_BIN || '').trim();
  if (envBin) {
    for (const p of withExecutableVariants(envBin)) {
      if (fileExecutable(p)) return { bin: p, source: 'env' };
    }
  }
  if (opts.preferPath) {
    const pathBin = await resolvePathVigoliumBinary();
    if (pathBin.bin) return pathBin;
  }
  for (const p of candidates) {
    if (fileExecutable(p)) return { bin: p, source: p.includes(`${path.sep}engines${path.sep}`) ? 'engine' : 'local' };
  }
  const pathBin = await resolvePathVigoliumBinary();
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

export function resolveVigoliumSource(ctx = {}) {
  const raw = String(ctx.vigoliumSource || process.env.GHOSTRECON_VIGOLIUM_SOURCE || '').trim();
  return raw || null;
}

export function vigoliumAgentTimeoutMs() {
  const n = Number(process.env.GHOSTRECON_VIGOLIUM_AGENT_TIMEOUT_MS);
  if (Number.isFinite(n) && n > 0) return Math.min(n, 7_200_000);
  return 3_600_000;
}
