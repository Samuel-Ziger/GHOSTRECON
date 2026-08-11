/**
 * ghostrecon ghostwatch - VPS sentinel mode.
 *
 * Discovers known targets from the run history / domains.txt, runs one target
 * at a time (full-recon + Vigolium/Codex + FrameSeven), compares against the
 * previous run, and sends Discord/Slack/generic alerts only when relevant
 * changes appear.
 */

import fs from 'node:fs/promises';
import path from 'node:path';
import { spawn } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { parseArgs, parseDuration } from '../args.mjs';
import { GhostClient, GLOBAL_OPTS } from '../client.mjs';
import { resolvePlaybook } from '../../playbooks/loader.mjs';
import { summarizeDiff, shouldAlert } from '../../diff-engine.mjs';
import { postAlert } from '../../alerting.mjs';
import { parseReconTarget } from '../../recon-target.js';
import { ensureCveWebDb } from '../../../../scripts/ensure-cve-web-db.mjs';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const ROOT = path.resolve(__dirname, '..', '..', '..', '..');
const SYNC_SCRIPT = path.join(ROOT, 'server', 'scripts', 'sync-sqlite-to-postgres.mjs');

const DEFAULT_STATE_DIR = '.ghostrecon-ghostwatch';
const DEFAULT_PLAYBOOK = process.env.GHOSTWATCH_PLAYBOOK || 'full-recon';
const DEFAULT_WEBHOOK =
  process.env.GHOSTWATCH_WEBHOOK ||
  process.env.GHOSTRECON_WEBHOOK_URL ||
  process.env.DISCORD_WEBHOOK ||
  '';
const DEFAULT_DOMAINS_FILE =
  process.env.GHOSTWATCH_DOMAINS_FILE || path.join(ROOT, 'domains.txt');
const DEFAULT_ENGINE = String(process.env.GHOSTRECON_ENGINE || 'both').trim().toLowerCase() || 'both';
const DEFAULT_STRATEGY = String(process.env.GHOSTRECON_VIGOLIUM_STRATEGY || 'deep').trim().toLowerCase() || 'deep';
const DEFAULT_TIMEOUT_SEC = Number(process.env.GHOSTWATCH_TIMEOUT || 3600);

/** Only strip modules unsafe / useless for unattended VPS (Tor/Navigator). */
const FORBIDDEN_MODULES = new Set([
  'navegation',
  'navigator',
  'tor',
  'tor_strict',
  'tor-strict',
  'kali_proxychains',
  'proxychains',
]);

const COMMON_SPEC = [
  ...GLOBAL_OPTS,
  { name: 'state-dir', type: 'string', default: process.env.GHOSTWATCH_STATE_DIR || DEFAULT_STATE_DIR },
  { name: 'target', type: 'string', alias: 't' },
  { name: 'format', type: 'string', default: 'table' },
];

const REGISTER_SPEC = [
  ...COMMON_SPEC,
  { name: 'modules', type: 'csv', default: [] },
  { name: 'playbook', type: 'string', default: DEFAULT_PLAYBOOK },
  { name: 'profile', type: 'string', default: process.env.GHOSTWATCH_PROFILE || 'aggressive' },
  { name: 'kali', type: 'bool', default: true },
  { name: 'out-of-scope', type: 'csv', default: [] },
];

const SYNC_DOMAINS_SPEC = [
  ...COMMON_SPEC,
  { name: 'file', type: 'string', default: DEFAULT_DOMAINS_FILE },
  { name: 'playbook', type: 'string', default: DEFAULT_PLAYBOOK },
  { name: 'profile', type: 'string', default: process.env.GHOSTWATCH_PROFILE || 'aggressive' },
  { name: 'kali', type: 'bool', default: true },
  { name: 'bootstrap', type: 'bool', default: false },
  { name: 'out-of-scope', type: 'csv', default: [] },
];

const SYNC_SPEC = [
  { name: 'limit', type: 'int', default: 200 },
  { name: 'dry-run', type: 'bool', default: false },
  { name: 'sqlite', type: 'string' },
  { name: 'help', type: 'bool', default: false, alias: 'h' },
];

const RUN_SPEC = [
  ...COMMON_SPEC,
  { name: 'modules', type: 'csv', default: [] },
  { name: 'playbook', type: 'string', default: DEFAULT_PLAYBOOK },
  { name: 'profile', type: 'string', default: process.env.GHOSTWATCH_PROFILE || 'aggressive' },
  { name: 'opsec-profile', type: 'string', default: process.env.GHOSTWATCH_OPSEC_PROFILE || 'aggressive' },
  { name: 'webhook', type: 'string', default: DEFAULT_WEBHOOK },
  { name: 'min-severity', type: 'string', default: process.env.GHOSTWATCH_MIN_SEVERITY || 'medium' },
  { name: 'only-new', type: 'bool', default: true },
  { name: 'once', type: 'bool', default: false },
  { name: 'interval', type: 'string', default: process.env.GHOSTWATCH_INTERVAL || '12h' },
  { name: 'max-targets', type: 'int', default: 0 },
  { name: 'limit-runs', type: 'int', default: 200 },
  { name: 'timeout', type: 'int', default: Number.isFinite(DEFAULT_TIMEOUT_SEC) ? DEFAULT_TIMEOUT_SEC : 3600 },
  { name: 'kali', type: 'bool', default: true },
  { name: 'reuse-modules', type: 'bool', default: false },
  { name: 'dry-run', type: 'bool', default: false },
  { name: 'out-of-scope', type: 'csv', default: [] },
  {
    name: 'confirm-active',
    type: 'bool',
    default: envFlagTrue(process.env.GHOSTWATCH_CONFIRM_ACTIVE),
  },
  { name: 'domains-file', type: 'string', default: '' },
  { name: 'sync-domains', type: 'bool', default: envFlagTrue(process.env.GHOSTWATCH_SYNC_DOMAINS, true) },
  { name: 'update-cve', type: 'bool', default: envFlagTrue(process.env.GHOSTWATCH_CVE_UPDATE, true) },
  { name: 'bootstrap', type: 'bool', default: envFlagTrue(process.env.GHOSTWATCH_BOOTSTRAP_MISSING) },
  { name: 'engine', type: 'string', default: DEFAULT_ENGINE },
  { name: 'strategy', type: 'string', default: DEFAULT_STRATEGY },
  {
    name: 'vigolium-use-codex',
    type: 'bool',
    default: envFlagTrue(process.env.GHOSTRECON_VIGOLIUM_USE_CODEX, true),
  },
  {
    name: 'include-frameseven',
    type: 'bool',
    default: envFlagTrue(process.env.GHOSTWATCH_INCLUDE_FRAMESEVEN, true),
  },
];

export async function ghostwatchCommand(argv) {
  const sub = argv[0] && !argv[0].startsWith('-') ? argv[0] : 'run';
  const rest = sub === argv[0] ? argv.slice(1) : argv;

  if (sub === 'help' || ((rest.includes('--help') || rest.includes('-h')) && sub !== 'sync-vps' && sub !== 'sync')) {
    printHelp();
    return 0;
  }

  switch (sub) {
    case 'register':
    case 'add':
      return registerCommand(rest);
    case 'disable':
      return setEnabledCommand(rest, false);
    case 'enable':
      return setEnabledCommand(rest, true);
    case 'list':
      return listCommand(rest);
    case 'sync-domains':
      return syncDomainsCommand(rest);
    case 'sync-vps':
    case 'sync':
      return syncVpsCommand(rest);
    case 'run':
    case 'once':
      return runGhostwatch(rest, { forceOnce: sub === 'once' });
    default:
      process.stderr.write(`ghostwatch: comando desconhecido "${sub}"\n`);
      printHelp();
      return 2;
  }
}

function envFlagTrue(value, defaultTrue = false) {
  if (value == null || value === '') return Boolean(defaultTrue);
  return !/^(0|false|no|off)$/i.test(String(value).trim());
}

async function syncVpsCommand(argv) {
  let opts;
  try {
    ({ opts } = parseArgs(argv, SYNC_SPEC));
  } catch (e) {
    process.stderr.write(`ghostwatch sync-vps: ${e.message}\n`);
    return 2;
  }
  if (opts.help) {
    printSyncHelp();
    return 0;
  }

  const args = [SYNC_SCRIPT, '--limit', String(opts.limit)];
  if (opts['dry-run']) args.push('--dry-run');
  if (opts.sqlite) args.push('--sqlite', String(opts.sqlite));
  return spawnInherit(process.execPath, args, { cwd: ROOT });
}

export async function parseDomainsFile(filePath) {
  const raw = await fs.readFile(filePath, 'utf8');
  const out = [];
  const seen = new Set();
  for (const line of raw.split(/\r?\n/)) {
    const trimmed = String(line || '').trim();
    if (!trimmed || trimmed.startsWith('#')) continue;
    const parsed = parseReconTarget(trimmed);
    if (!parsed.ok) continue;
    const target = String(parsed.target || '').toLowerCase();
    if (!target || seen.has(target)) continue;
    seen.add(target);
    out.push(target);
  }
  return out;
}

export async function applyDomainsToWatchlist({
  state,
  domains,
  playbook = DEFAULT_PLAYBOOK,
  profile = 'aggressive',
  kali = true,
  outOfScope = [],
} = {}) {
  const now = new Date().toISOString();
  const enabledSet = new Set(domains);
  const registered = [];
  const disabled = [];

  // Lista vazia (só comentários / arquivo novo) não desliga a watchlist inteira.
  if (!domains.length) {
    return { registered, disabled, enabled: [], skippedEmpty: true };
  }

  for (const target of domains) {
    const prev = state.targets[target] || {};
    const wasEnabled = prev.enabled !== false && Boolean(prev.registeredAt);
    state.targets[target] = {
      ...prev,
      target,
      enabled: true,
      playbook: playbook || prev.playbook || DEFAULT_PLAYBOOK,
      modules: Array.isArray(prev.modules) ? prev.modules : [],
      profile: profile || prev.profile || 'aggressive',
      kali: Boolean(kali || prev.kali),
      outOfScope: outOfScope?.length ? outOfScope : prev.outOfScope || [],
      registeredAt: prev.registeredAt || now,
      updatedAt: now,
      source: 'domains.txt',
    };
    if (!wasEnabled || !prev.registeredAt) registered.push(target);
  }

  for (const [target, cfg] of Object.entries(state.targets || {})) {
    if (enabledSet.has(target)) continue;
    if (cfg?.enabled === false) continue;
    state.targets[target] = {
      ...cfg,
      target,
      enabled: false,
      updatedAt: now,
    };
    disabled.push(target);
  }

  return { registered, disabled, enabled: [...enabledSet], skippedEmpty: false };
}

async function syncDomainsCommand(argv) {
  let opts;
  try {
    ({ opts } = parseArgs(argv, SYNC_DOMAINS_SPEC));
  } catch (e) {
    process.stderr.write(`ghostwatch sync-domains: ${e.message}\n`);
    return 2;
  }

  const filePath = path.resolve(String(opts.file || DEFAULT_DOMAINS_FILE));
  let domains;
  try {
    domains = await parseDomainsFile(filePath);
  } catch (e) {
    process.stderr.write(`ghostwatch sync-domains: nao leu ${filePath}: ${e.message}\n`);
    return 2;
  }

  const state = await loadState(opts['state-dir']);
  const result = await applyDomainsToWatchlist({
    state,
    domains,
    playbook: opts.playbook,
    profile: opts.profile,
    kali: opts.kali,
    outOfScope: opts['out-of-scope'],
  });
  await saveState(opts['state-dir'], state);

  if (result.skippedEmpty) {
    process.stdout.write(
      `ghostwatch sync-domains: file=${filePath} vazio (so comentarios?) — watchlist inalterada\n`,
    );
    return 0;
  }

  process.stdout.write(
    `ghostwatch sync-domains: file=${filePath} enabled=${result.enabled.length} `
    + `registered=${result.registered.length} disabled=${result.disabled.length}\n`,
  );
  for (const t of result.registered) process.stdout.write(`  + ${t}\n`);
  for (const t of result.disabled) process.stdout.write(`  - ${t}\n`);

  if (opts.bootstrap && result.enabled.length) {
    return runGhostwatch([
      '--once',
      '--bootstrap',
      '--confirm-active',
      '--state-dir', opts['state-dir'],
      '--playbook', opts.playbook || DEFAULT_PLAYBOOK,
      '--profile', opts.profile || 'aggressive',
      ...(opts.kali ? ['--kali'] : []),
      ...(opts.server ? ['--server', opts.server] : []),
      ...(opts['start-server'] ? ['--start-server'] : []),
    ], { forceOnce: true });
  }
  return 0;
}

async function registerCommand(argv) {
  let opts;
  try {
    ({ opts } = parseArgs(argv, REGISTER_SPEC));
  } catch (e) {
    process.stderr.write(`ghostwatch register: ${e.message}\n`);
    return 2;
  }
  if (!opts.target) {
    process.stderr.write('ghostwatch register: informe --target\n');
    return 2;
  }

  const parsed = parseReconTarget(opts.target);
  if (!parsed.ok) {
    process.stderr.write(`ghostwatch register: ${parsed.message || 'target invalido'}\n`);
    return 2;
  }

  const state = await loadState(opts['state-dir']);
  const target = parsed.target;
  const prev = state.targets[target] || {};
  state.targets[target] = {
    ...prev,
    target,
    enabled: true,
    playbook: opts.playbook || prev.playbook || DEFAULT_PLAYBOOK,
    modules: opts.modules?.length ? opts.modules : prev.modules || [],
    profile: opts.profile || prev.profile || 'aggressive',
    kali: Boolean(opts.kali || prev.kali),
    outOfScope: opts['out-of-scope']?.length ? opts['out-of-scope'] : prev.outOfScope || [],
    registeredAt: prev.registeredAt || new Date().toISOString(),
    updatedAt: new Date().toISOString(),
    source: 'manual',
  };
  await saveState(opts['state-dir'], state);
  process.stdout.write(`ghostwatch: ${target} registrado\n`);
  return 0;
}

async function setEnabledCommand(argv, enabled) {
  let opts;
  try {
    ({ opts } = parseArgs(argv, COMMON_SPEC));
  } catch (e) {
    process.stderr.write(`ghostwatch ${enabled ? 'enable' : 'disable'}: ${e.message}\n`);
    return 2;
  }
  if (!opts.target) {
    process.stderr.write(`ghostwatch ${enabled ? 'enable' : 'disable'}: informe --target\n`);
    return 2;
  }
  const parsed = parseReconTarget(opts.target);
  if (!parsed.ok) {
    process.stderr.write(`ghostwatch ${enabled ? 'enable' : 'disable'}: ${parsed.message || 'target invalido'}\n`);
    return 2;
  }
  const state = await loadState(opts['state-dir']);
  const target = parsed.target;
  state.targets[target] = {
    ...(state.targets[target] || { target, registeredAt: new Date().toISOString(), source: 'manual' }),
    target,
    enabled,
    updatedAt: new Date().toISOString(),
  };
  await saveState(opts['state-dir'], state);
  process.stdout.write(`ghostwatch: ${target} ${enabled ? 'habilitado' : 'desabilitado'}\n`);
  return 0;
}

async function listCommand(argv) {
  let opts;
  try {
    ({ opts } = parseArgs(argv, COMMON_SPEC));
  } catch (e) {
    process.stderr.write(`ghostwatch list: ${e.message}\n`);
    return 2;
  }
  const state = await loadState(opts['state-dir']);
  const rows = Object.values(state.targets || {}).sort((a, b) => a.target.localeCompare(b.target));
  if (opts.format === 'json') {
    process.stdout.write(`${JSON.stringify(rows, null, 2)}\n`);
    return 0;
  }
  if (!rows.length) {
    process.stdout.write('(watchlist vazia; ghostwatch run tambem usa targets conhecidos em /api/runs)\n');
    return 0;
  }
  for (const r of rows) {
    process.stdout.write(
      `${r.enabled === false ? 'off' : 'on '}  ${r.target}  playbook=${r.playbook || '-'} modules=${(r.modules || []).join(',') || '-'} outOfScope=${(r.outOfScope || []).join(',') || '-'}\n`,
    );
  }
  return 0;
}

async function runGhostwatch(argv, { forceOnce = false } = {}) {
  let opts;
  try {
    ({ opts } = parseArgs(argv, RUN_SPEC));
  } catch (e) {
    process.stderr.write(`ghostwatch run: ${e.message}\n`);
    return 2;
  }
  opts.once = forceOnce || Boolean(opts.once);
  if (opts.target) {
    const parsed = parseReconTarget(opts.target);
    if (!parsed.ok) {
      process.stderr.write(`ghostwatch run: ${parsed.message || 'target invalido'}\n`);
      return 2;
    }
    opts.target = parsed.target;
  }

  const intervalMs = parseDuration(opts.interval);
  const stateDir = opts['state-dir'];
  const log = (...a) => {
    if (!opts.quiet) process.stderr.write(`[ghostwatch] ${a.join(' ')}\n`);
  };

  const client = new GhostClient({ server: opts.server });
  try {
    await client.ensureServer({ autoStart: opts['start-server'], quiet: opts.quiet });
  } catch (e) {
    process.stderr.write(`${e.message}\n`);
    return 3;
  }

  let shuttingDown = false;
  const onSignal = () => {
    shuttingDown = true;
    log('shutdown solicitado');
  };
  process.on('SIGINT', onSignal);
  process.on('SIGTERM', onSignal);

  let iterations = 0;
  while (!shuttingDown) {
    iterations++;
    const code = await runOneSweep({ client, opts, stateDir, log });
    if (code !== 0) return code;
    if (opts.once || shuttingDown) break;
    log(`aguardando ${Math.round(intervalMs / 1000)}s para proxima varredura`);
    await interruptibleSleep(intervalMs, () => shuttingDown);
  }

  log(`terminou apos ${iterations} varredura(s)`);
  return 0;
}

export function isLoopbackServerUrl(serverUrl) {
  try {
    const u = new URL(String(serverUrl || 'http://127.0.0.1:3847'));
    const host = String(u.hostname || '').toLowerCase();
    return host === '127.0.0.1' || host === 'localhost' || host === '::1';
  } catch {
    return false;
  }
}

export function resolveApiKeyRole(env = process.env) {
  const apiKey = String(env.GHOSTRECON_API_KEY || '').trim();
  const raw = String(env.AUTH_API_KEYS || '').trim();
  if (!apiKey || !raw) return null;
  for (const entry of raw.split(/[|\n]/)) {
    const parts = entry.trim().split(':');
    if (parts.length < 2) continue;
    if (parts[0] === apiKey) return String(parts[1] || '').toLowerCase();
  }
  return null;
}

export function canTrustedApprove({
  env = process.env,
  serverUrl = '',
  target = '',
  watchlist = {},
  confirmActive = false,
} = {}) {
  if (!envFlagTrue(env.GHOSTWATCH_TRUSTED_OPERATOR)) {
    return { ok: false, reason: 'GHOSTWATCH_TRUSTED_OPERATOR desligado' };
  }
  if (!confirmActive) {
    return { ok: false, reason: 'confirmActive obrigatorio para trusted-operator' };
  }
  if (!isLoopbackServerUrl(serverUrl)) {
    return { ok: false, reason: 'API deve estar em loopback (127.0.0.1/localhost)' };
  }
  const role = resolveApiKeyRole(env);
  if (role !== 'red' && role !== 'admin') {
    return { ok: false, reason: `API key precisa role red/admin (atual=${role || 'desconhecida'})` };
  }
  const normalized = normalizeTargetForGhostwatch(target);
  const cfg = watchlist?.[normalized];
  if (!cfg || cfg.enabled === false) {
    return { ok: false, reason: `alvo ${normalized || '(vazio)'} fora da watchlist/domains.txt` };
  }
  return { ok: true, reason: 'trusted_operator' };
}

export function buildGhostwatchRunBody({
  target,
  modules,
  runCfg,
  opts,
  outOfScope = [],
} = {}) {
  const engine = String(opts.engine || DEFAULT_ENGINE).trim().toLowerCase() || 'both';
  const strategy = String(opts.strategy || DEFAULT_STRATEGY).trim().toLowerCase() || 'deep';
  const body = {
    domain: target,
    modules: [...modules],
    kaliMode: Boolean(runCfg?.kali),
    profile: runCfg?.profile || opts.profile || 'aggressive',
    opsecProfile: opts['opsec-profile'] || 'aggressive',
    confirmActive: Boolean(opts['confirm-active']),
    outOfScope: outOfScope.join(','),
    playbook: runCfg?.playbook || undefined,
    projectName: `ghostwatch-${target}`,
    autoAiReports: false,
    navigatorMode: false,
    navegation: { enabled: false },
    tor: { required: false, strict: false },
    engine,
    strategy,
    vigoliumUseCodex: Boolean(opts['vigolium-use-codex']),
    includeFrameSeven: Boolean(opts['include-frameseven']),
    frameSevenAuth: false,
  };
  if (outOfScope.length && !body.modules.includes('out_of_scope')) body.modules.push('out_of_scope');
  return body;
}

export async function runOneSweep({
  client,
  opts,
  stateDir,
  log,
  env = process.env,
  ensureCve = ensureCveWebDb,
} = {}) {
  let state = await loadState(stateDir);

  if (opts['sync-domains']) {
    const domainsFile = path.resolve(String(opts['domains-file'] || DEFAULT_DOMAINS_FILE));
    try {
      const domains = await parseDomainsFile(domainsFile);
      const syncResult = await applyDomainsToWatchlist({
        state,
        domains,
        playbook: opts.playbook || DEFAULT_PLAYBOOK,
        profile: opts.profile || 'aggressive',
        kali: opts.kali !== false,
        outOfScope: opts['out-of-scope'] || [],
      });
      await saveState(stateDir, state);
      if (syncResult.skippedEmpty) {
        log(`sync-domains ${domainsFile}: vazio — watchlist inalterada`);
      } else {
        log(
          `sync-domains ${domainsFile}: enabled=${syncResult.enabled.length} `
          + `+${syncResult.registered.length} -${syncResult.disabled.length}`,
        );
      }
    } catch (e) {
      if (e?.code !== 'ENOENT') {
        log(`sync-domains avisou: ${e.message}`);
      } else {
        log(`domains.txt ausente (${domainsFile}); usando watchlist/runs`);
      }
    }
    state = await loadState(stateDir);
  }

  if (opts['update-cve']) {
    try {
      const cve = await ensureCve({
        env,
        logImpl: (msg) => log(`cve: ${msg}`),
        warnImpl: (msg) => log(`cve-warn: ${msg}`),
      });
      log(`cve status=${cve?.status || 'unknown'} detail=${cve?.detail || '-'}`);
    } catch (e) {
      log(`cve update falhou (seguindo): ${e.message}`);
    }
  }

  let runs;
  try {
    runs = await client.listRuns({ limit: opts['limit-runs'] });
  } catch (e) {
    process.stderr.write(`ghostwatch: listRuns falhou: ${e.message}\n`);
    return 4;
  }

  const latest = latestRunsByTarget(runs);
  let targets = selectGhostwatchTargets({
    latestRuns: latest,
    watchlist: state.targets,
    onlyTarget: opts.target,
    maxTargets: opts['max-targets'],
  });

  if (!targets.length) {
    log('nenhum alvo conhecido para monitorar');
    return 0;
  }

  log(`varredura: ${targets.length} alvo(s), sequencial`);
  const sweep = {
    at: new Date().toISOString(),
    targets: [],
  };
  let approvalBlocked = false;

  for (const item of targets) {
    const target = item.target;
    const cfg = item.config || {};
    const baseline = latest.get(target) || null;
    const isBootstrap = !baseline?.id && Boolean(opts.bootstrap);

    if (!baseline?.id && !isBootstrap) {
      log(`${target}: sem baseline, pulando (use --bootstrap ou sync-domains --bootstrap)`);
      continue;
    }

    const runCfg = await resolveRunConfig({ cfg, opts, baseline, client });
    if (!runCfg.modules.length) {
      log(`${target}: sem modulos/playbook resolvidos, pulando`);
      continue;
    }

    const outOfScope = resolveOutOfScope({ cfg, opts, baseline });

    if (opts['dry-run']) {
      log(`${target}: dry-run baseline=#${baseline?.id || 'none'} modules=${runCfg.modules.join(',')} outOfScope=${outOfScope.join(',') || '-'}`);
      sweep.targets.push({
        target,
        baselineId: baseline?.id || null,
        dryRun: true,
        modules: runCfg.modules,
        outOfScope,
        bootstrap: isBootstrap,
      });
      continue;
    }

    const body = buildGhostwatchRunBody({
      target,
      modules: runCfg.modules,
      runCfg,
      opts,
      outOfScope,
    });

    log(
      `${target}: recon baseline=#${baseline?.id || 'bootstrap'} modules=${body.modules.length} `
      + `engine=${body.engine} frameseven=${body.includeFrameSeven} codex=${body.vigoliumUseCodex} `
      + `outOfScope=${outOfScope.length}`,
    );

    let newRunId = null;
    let errors = [];
    let targetApprovalRequired = null;
    let preflightCompleted = false;
    let targetPreflightFailed = false;
    let trustedApproved = false;

    try {
      const preflight = await client.postJson('/api/recon/preflight', body);
      preflightCompleted = true;
      if (preflight?.requiresApproval) {
        const planHash = String(preflight.plan?.hash || '').trim();
        const approvalId = String(preflight.approval?.approvalId || '').trim();
        const intrusiveModules = Array.isArray(preflight.plan?.intrusiveModules)
          ? preflight.plan.intrusiveModules.map(String).filter(Boolean)
          : [];
        targetApprovalRequired = {
          planHash: planHash || null,
          target: String(preflight.plan?.target || target),
          intrusiveModules,
        };

        const gate = canTrustedApprove({
          env,
          serverUrl: client.baseUrl || opts.server,
          target,
          watchlist: state.targets,
          confirmActive: Boolean(opts['confirm-active']),
        });

        if (gate.ok && planHash && approvalId) {
          const decision = await client.postJson('/api/recon/approval', {
            approvalId,
            planHash,
            approved: true,
          });
          if (decision?.approval?.status !== 'approved') {
            throw new Error('servidor nao confirmou aprovacao trusted-operator');
          }
          body.manualApproval = { approvalId, planHash };
          trustedApproved = true;
          log(`${target}: trusted_operator_approved hash=${planHash}`);
          await client.streamRecon(
            body,
            (evt) => {
              if (evt?.runId) newRunId = evt.runId;
              if (evt?.type === 'error') errors.push(evt.message || 'erro desconhecido');
            },
            { timeoutMs: Math.max(60_000, Number(opts.timeout || 3600) * 1000) },
          );
        } else {
          approvalBlocked = true;
          errors.push(
            `approval_required: plano ${planHash || '(sem hash)'} exige confirmacao; `
            + `trusted-operator recusado (${gate.reason})`,
          );
          log(
            `${target}: bloqueado — ${gate.reason} `
            + `hash=${planHash || '-'} intrusivos=${intrusiveModules.join(',') || '-'}`,
          );
        }
      } else {
        await client.streamRecon(
          body,
          (evt) => {
            if (evt?.runId) newRunId = evt.runId;
            if (evt?.type === 'error') errors.push(evt.message || 'erro desconhecido');
          },
          { timeoutMs: Math.max(60_000, Number(opts.timeout || 3600) * 1000) },
        );
      }
    } catch (e) {
      errors.push(e.message);
      if (!preflightCompleted) {
        approvalBlocked = true;
        targetPreflightFailed = true;
        log(`${target}: bloqueado com segurança — preflight falhou antes do stream`);
      }
      log(`${target}: recon falhou: ${e.message}`);
    }

    if (!targetApprovalRequired && !targetPreflightFailed && !newRunId) {
      try {
        const afterRuns = await client.listRuns({ limit: opts['limit-runs'] });
        const afterLatest = latestRunsByTarget(afterRuns).get(target);
        if (afterLatest?.id && afterLatest.id !== baseline?.id) newRunId = afterLatest.id;
      } catch {
        // ignore fallback failure
      }
    } else if (trustedApproved && !newRunId) {
      try {
        const afterRuns = await client.listRuns({ limit: opts['limit-runs'] });
        const afterLatest = latestRunsByTarget(afterRuns).get(target);
        if (afterLatest?.id && afterLatest.id !== baseline?.id) newRunId = afterLatest.id;
      } catch {
        // ignore
      }
    }

    const result = {
      target,
      baselineId: baseline?.id || null,
      newerId: newRunId,
      errors,
      bootstrap: isBootstrap,
      ...(trustedApproved ? { trustedApproved: true } : {}),
      ...(targetApprovalRequired && !trustedApproved ? { approvalRequired: targetApprovalRequired } : {}),
      ...(targetPreflightFailed ? { preflightFailed: true } : {}),
    };

    // Bootstrap / first run: never Discord-spam; only diff when baseline existed.
    if (baseline?.id && newRunId && newRunId !== baseline.id) {
      try {
        const diff = normalizeDiffForGhostwatch(await client.diffRuns(baseline.id, newRunId));
        if (!diff.error) {
          const summary = summarizeDiff(diff, {
            minSeverity: opts['min-severity'],
            onlyNew: opts['only-new'],
          });
          const seen = new Set(state.seenFingerprints?.[target] || []);
          const alert = shouldAlert(summary, { seenFingerprints: seen });
          result.summary = summary;
          result.alert = alert;
          log(`${target}: diff #${baseline.id}->#${newRunId} +${summary.addedCount} alert=${alert}`);
          if (alert) {
            state.seenFingerprints[target] = [...seen, summary.fingerprint].slice(-200);
            if (opts.webhook) {
              await postAlert(opts.webhook, buildGhostwatchAlertPayload(target, summary));
            } else {
              writeAlertStdout(target, summary);
            }
          }
        }
      } catch (e) {
        errors.push(`diff: ${e.message}`);
        log(`${target}: diff falhou: ${e.message}`);
      }
    } else if (isBootstrap) {
      log(`${target}: baseline gravada (sem alerta Discord)`);
    } else {
      log(`${target}: sem novo run salvo`);
    }

    sweep.targets.push(result);
    state.lastRunByTarget[target] = {
      baselineId: baseline?.id || null,
      newerId: newRunId,
      at: new Date().toISOString(),
      errors,
      outOfScope,
      trustedApproved,
    };
    await saveState(stateDir, state);
  }

  state.history.push(sweep);
  state.history = state.history.slice(-40);
  await saveState(stateDir, state);

  if (opts.format === 'json') process.stdout.write(`${JSON.stringify(sweep, null, 2)}\n`);
  else writeSweepSummary(sweep);
  return approvalBlocked ? 5 : 0;
}

async function resolveRunConfig({ cfg, opts, baseline, client }) {
  let modules = [];
  let playbook = opts.playbook || cfg.playbook || DEFAULT_PLAYBOOK;
  let profile = opts.profile || cfg.profile || 'stealth';

  if (opts.modules?.length) {
    modules = sanitizeGhostwatchModules(opts.modules);
    playbook = '';
  } else if (cfg.modules?.length) {
    modules = sanitizeGhostwatchModules(cfg.modules);
    playbook = cfg.playbook || '';
  } else if (opts['reuse-modules'] && baseline?.id) {
    try {
      const full = await client.getRun(baseline.id);
      if (Array.isArray(full?.modules)) modules = sanitizeGhostwatchModules(full.modules.filter((m) => m !== '__kali_scan__'));
    } catch {
      // fall back to playbook below
    }
  }

  if (!modules.length && playbook) {
    const pb = await resolvePlaybook(playbook);
    modules = sanitizeGhostwatchModules(pb.modules || []);
    if (profile === 'standard' && pb.profile) profile = pb.profile;
  }

  return {
    modules: unique(modules),
    playbook,
    profile,
    kali: Boolean(opts.kali || cfg.kali),
  };
}

export function sanitizeGhostwatchModules(modules) {
  return unique(modules).filter((m) => {
    const id = String(m || '').trim().toLowerCase();
    return id && !FORBIDDEN_MODULES.has(id);
  });
}

export function resolveOutOfScope({ cfg = {}, opts = {}, baseline = null } = {}) {
  return unique([
    ...(Array.isArray(baseline?.stats?.outOfScope) ? baseline.stats.outOfScope : []),
    ...(Array.isArray(cfg?.outOfScope) ? cfg.outOfScope : []),
    ...(Array.isArray(opts?.['out-of-scope']) ? opts['out-of-scope'] : []),
  ]);
}

export function latestRunsByTarget(runs) {
  const out = new Map();
  for (const run of runs || []) {
    const target = String(run?.target || '').trim().toLowerCase();
    const id = Number(run?.id);
    if (!target || !Number.isFinite(id)) continue;
    const prev = out.get(target);
    if (!prev || id > Number(prev.id || 0)) out.set(target, run);
  }
  return out;
}

export function selectGhostwatchTargets({ latestRuns, watchlist = {}, onlyTarget = '', maxTargets = 0 } = {}) {
  const out = [];
  const disabled = new Set(
    Object.values(watchlist || {})
      .filter((x) => x?.enabled === false)
      .map((x) => String(x.target || '').toLowerCase()),
  );
  const only = normalizeTargetForGhostwatch(onlyTarget);
  const seen = new Set();

  for (const [target, run] of latestRuns || new Map()) {
    if (only && target !== only) continue;
    if (disabled.has(target)) continue;
    seen.add(target);
    out.push({ target, latestRun: run, config: watchlist?.[target] || null });
  }

  for (const item of Object.values(watchlist || {})) {
    const target = String(item?.target || '').trim().toLowerCase();
    if (!target || seen.has(target) || item?.enabled === false) continue;
    if (only && target !== only) continue;
    out.push({ target, latestRun: null, config: item });
  }

  out.sort((a, b) => a.target.localeCompare(b.target));
  const n = Number(maxTargets || 0);
  return n > 0 ? out.slice(0, n) : out;
}

export function normalizeTargetForGhostwatch(target) {
  const raw = String(target || '').trim();
  if (!raw) return '';
  const parsed = parseReconTarget(raw);
  return (parsed.ok ? parsed.target : raw).toLowerCase();
}

export function normalizeDiffForGhostwatch(diff) {
  const normalizeFinding = (f) => ({
    ...f,
    severity: f?.severity || f?.prio || 'info',
    title: f?.title || f?.value || f?.type || 'finding',
    category: f?.category || f?.type || 'finding',
    evidence: {
      ...(f?.evidence || {}),
      target: f?.evidence?.target || f?.url || f?.value || diff?.target || '',
      url: f?.evidence?.url || f?.url || '',
    },
  });
  return {
    ...diff,
    added: (diff?.added || []).map(normalizeFinding),
    removed: (diff?.removed || []).map(normalizeFinding),
  };
}

export function buildGhostwatchAlertPayload(target, summary) {
  const lines = [
    `**GhostWatch** - alteracao detectada em \`${target}\``,
    `Run \`#${summary.baselineId}\` -> \`#${summary.newerId}\``,
    `Novos: **${summary.addedCount}** (critical=${summary.addedBySeverity.critical ?? 0}, high=${summary.addedBySeverity.high ?? 0}, medium=${summary.addedBySeverity.medium ?? 0}, low=${summary.addedBySeverity.low ?? 0})`,
  ];
  if (summary.newHosts?.length) {
    lines.push(`Novos hosts: ${summary.newHosts.slice(0, 8).map((h) => `\`${h}\``).join(', ')}`);
  }
  if (summary.notableAdded?.length) {
    lines.push('', 'Notaveis:');
    for (const f of summary.notableAdded.slice(0, 6)) {
      lines.push(`- [${String(f.severity || 'n/a').toUpperCase()}] ${f.title || f.category || '?'}`);
    }
  }
  return { content: lines.join('\n'), target, summary, source: 'ghostwatch' };
}

async function loadState(stateDir) {
  const file = stateFilePath(stateDir);
  try {
    const state = JSON.parse(await fs.readFile(file, 'utf8'));
    return {
      version: 1,
      targets: state.targets && typeof state.targets === 'object' ? state.targets : {},
      seenFingerprints: state.seenFingerprints && typeof state.seenFingerprints === 'object' ? state.seenFingerprints : {},
      lastRunByTarget: state.lastRunByTarget && typeof state.lastRunByTarget === 'object' ? state.lastRunByTarget : {},
      history: Array.isArray(state.history) ? state.history : [],
    };
  } catch {
    return { version: 1, targets: {}, seenFingerprints: {}, lastRunByTarget: {}, history: [] };
  }
}

async function saveState(stateDir, state) {
  const file = stateFilePath(stateDir);
  await fs.mkdir(path.dirname(file), { recursive: true });
  await fs.writeFile(file, JSON.stringify(state, null, 2), 'utf8');
}

function stateFilePath(stateDir) {
  return path.join(path.resolve(process.cwd(), stateDir || DEFAULT_STATE_DIR), 'ghostwatch.json');
}

function unique(items) {
  const seen = new Set();
  const out = [];
  for (const item of items || []) {
    const key = String(item || '').trim();
    if (!key || seen.has(key)) continue;
    seen.add(key);
    out.push(key);
  }
  return out;
}

async function interruptibleSleep(totalMs, shouldStop) {
  let left = totalMs;
  while (left > 0) {
    if (shouldStop()) return;
    const step = Math.min(1000, left);
    await new Promise((r) => setTimeout(r, step));
    left -= step;
  }
}

function writeAlertStdout(target, summary) {
  process.stdout.write(`\n[GhostWatch] ${target}: +${summary.addedCount} novos findings\n`);
  for (const f of summary.notableAdded.slice(0, 10)) {
    process.stdout.write(`  [${String(f.severity || 'n/a').toUpperCase()}] ${f.title || f.category || '?'}\n`);
  }
}

function writeSweepSummary(sweep) {
  const rows = sweep.targets || [];
  process.stdout.write(`GhostWatch sweep ${sweep.at} - ${rows.length} alvo(s)\n`);
  for (const r of rows) {
    const suffix = r.dryRun
      ? 'dry-run'
      : r.summary
        ? `+${r.summary.addedCount} alert=${Boolean(r.alert)}`
        : r.errors?.length
          ? `erro=${r.errors[0]}`
          : r.bootstrap
            ? 'baseline'
            : 'sem diff';
    process.stdout.write(`  ${r.target}: #${r.baselineId || '-'} -> #${r.newerId || '-'} ${suffix}\n`);
  }
}

function spawnInherit(cmd, args, opts = {}) {
  return new Promise((resolve) => {
    const child = spawn(cmd, args, {
      stdio: 'inherit',
      env: { ...process.env },
      cwd: opts.cwd || process.cwd(),
      shell: false,
    });
    child.on('error', (e) => {
      process.stderr.write(`ghostwatch sync-vps: ${e.message}\n`);
      resolve(3);
    });
    child.on('exit', (code) => resolve(typeof code === 'number' ? code : 1));
  });
}

function printHelp() {
  process.stdout.write(`ghostrecon ghostwatch - modo sentinela para VPS.

Comandos:
  ghostwatch run [opcoes]              Roda todos os alvos conhecidos, um por vez.
  ghostwatch once [opcoes]             Alias de run --once.
  ghostwatch sync-domains --file FILE  Sync watchlist a partir de domains.txt.
  ghostwatch sync-vps                  Envia runs SQLite pendentes para Postgres/VPS.
  ghostwatch register -t alvo          Adiciona/ajusta alvo na watchlist local da VPS.
  ghostwatch disable -t alvo           Desabilita alvo.
  ghostwatch enable -t alvo            Habilita alvo.
  ghostwatch list                      Lista watchlist manual.

Uso recomendado na VPS:
  ghostrecon ghostwatch sync-domains --file domains.txt --bootstrap
  ghostrecon ghostwatch run --once --confirm-active

Por padrao: sync domains.txt, atualiza CVE (TTL), full-recon + Vigolium deep/Codex +
FrameSeven (sem auth-browser), remove Tor/Navigator. Planos intrusivos so seguem com
GHOSTWATCH_TRUSTED_OPERATOR=1 + confirm-active + API key red/admin + alvo na watchlist
+ API em loopback.

Opcoes de run:
  --playbook NAME               Default: ${DEFAULT_PLAYBOOK}
  --modules CSV                 Usa modulos fixos em vez de playbook.
  --engine MODE                 Default: ${DEFAULT_ENGINE}
  --strategy NAME               Default: ${DEFAULT_STRATEGY}
  --vigolium-use-codex          Liga Codex no Vigolium (default on via env).
  --include-frameseven          Liga FrameSeven offensive_v1 (default on).
  --update-cve                  Atualiza CVE DB no inicio (default on; desliga: GHOSTWATCH_CVE_UPDATE=0).
  --sync-domains                Sync domains.txt no inicio (default on; desliga: GHOSTWATCH_SYNC_DOMAINS=0).
  --domains-file PATH           Override do arquivo de dominios.
  --bootstrap                   Roda alvos sem baseline (sem alerta Discord).
  --confirm-active              Necessario para planos intrusivos / trusted.
  --reuse-modules               Reusa modulos do ultimo run do alvo.
  --out-of-scope CSV            Exclusoes extras.
  --min-severity LEVEL          Default: medium.
  --only-new                    Evita alerta repetido por fingerprint.
  --max-targets N               Limita quantidade por varredura.
  --timeout SEC                 Default: ${Number.isFinite(DEFAULT_TIMEOUT_SEC) ? DEFAULT_TIMEOUT_SEC : 3600}.
  --dry-run                     Mostra o plano sem rodar recon.
  --interval 12h                Usado apenas sem --once.
  --start-server                Auto-inicia API local se necessario.
`);
}

function printSyncHelp() {
  process.stdout.write(`ghostrecon ghostwatch sync-vps

Atalho para server/scripts/sync-sqlite-to-postgres.mjs.

Requer no .env:
  GHOSTRECON_SYNC_DATABASE_URL=postgresql://...
ou:
  DATABASE_URL=postgresql://...

Opcoes:
  --limit N       Quantidade maxima de runs pendentes. Default: 200.
  --sqlite FILE   SQLite local especifico.
  --dry-run       Mostra o que seria enviado.
`);
}
