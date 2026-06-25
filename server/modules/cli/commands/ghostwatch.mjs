/**
 * ghostrecon ghostwatch - VPS sentinel mode.
 *
 * Discovers known targets from the run history, runs one target at a time,
 * compares against the previous run, and sends Discord/Slack/generic alerts
 * only when relevant changes appear.
 */

import fs from 'node:fs/promises';
import path from 'node:path';
import { parseArgs, parseDuration } from '../args.mjs';
import { GhostClient, GLOBAL_OPTS } from '../client.mjs';
import { resolvePlaybook } from '../../playbooks/loader.mjs';
import { summarizeDiff, shouldAlert } from '../../diff-engine.mjs';
import { postAlert } from '../../alerting.mjs';
import { parseReconTarget } from '../../recon-target.js';

const DEFAULT_STATE_DIR = '.ghostrecon-ghostwatch';
const DEFAULT_PLAYBOOK = process.env.GHOSTWATCH_PLAYBOOK || 'full-recon';
const DEFAULT_WEBHOOK =
  process.env.GHOSTWATCH_WEBHOOK ||
  process.env.GHOSTRECON_WEBHOOK_URL ||
  process.env.DISCORD_WEBHOOK ||
  '';
const FORBIDDEN_MODULES = new Set([
  'navegation',
  'navigator',
  'tor',
  'tor_strict',
  'tor-strict',
  'kali_proxychains',
  'proxychains',
  'shannon_whitebox',
  'shannon-whitebox',
  'pentestgpt_validate',
  'pentestgpt-validate',
  'vigolium_audit',
  'vigolium-audit',
  'vigolium_swarm',
  'vigolium-swarm',
  'vigolium_agent',
  'vigolium-agent',
  'vigolium_autopilot',
  'vigolium-autopilot',
  'vigolium_codex',
  'vigolium-codex',
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
  { name: 'timeout', type: 'int', default: 1800 },
  { name: 'kali', type: 'bool', default: true },
  { name: 'reuse-modules', type: 'bool', default: false },
  { name: 'dry-run', type: 'bool', default: false },
  { name: 'out-of-scope', type: 'csv', default: [] },
  { name: 'confirm-active', type: 'bool', default: true },
];

export async function ghostwatchCommand(argv) {
  const sub = argv[0] && !argv[0].startsWith('-') ? argv[0] : 'run';
  const rest = sub === argv[0] ? argv.slice(1) : argv;

  if (sub === 'help' || rest.includes('--help') || rest.includes('-h')) {
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
    case 'run':
    case 'once':
      return runGhostwatch(rest, { forceOnce: sub === 'once' });
    default:
      process.stderr.write(`ghostwatch: comando desconhecido "${sub}"\n`);
      printHelp();
      return 2;
  }
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

async function runOneSweep({ client, opts, stateDir, log }) {
  const state = await loadState(stateDir);
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

  for (const item of targets) {
    const target = item.target;
    const cfg = item.config || {};
    const baseline = latest.get(target) || null;
    if (!baseline?.id) {
      log(`${target}: sem baseline, pulando`);
      continue;
    }

    const runCfg = await resolveRunConfig({ cfg, opts, baseline, client });
    if (!runCfg.modules.length) {
      log(`${target}: sem modulos/playbook resolvidos, pulando`);
      continue;
    }

    const outOfScope = resolveOutOfScope({ cfg, opts, baseline });

    if (opts['dry-run']) {
      log(`${target}: dry-run baseline=#${baseline.id} modules=${runCfg.modules.join(',')} outOfScope=${outOfScope.join(',') || '-'}`);
      sweep.targets.push({ target, baselineId: baseline.id, dryRun: true, modules: runCfg.modules, outOfScope });
      continue;
    }

    const body = {
      domain: target,
      modules: runCfg.modules,
      kaliMode: Boolean(runCfg.kali),
      profile: runCfg.profile,
      opsecProfile: opts['opsec-profile'],
      confirmActive: Boolean(opts['confirm-active']) || process.env.GHOSTRECON_CONFIRM_ACTIVE === '1',
      outOfScope: outOfScope.join(','),
      playbook: runCfg.playbook || undefined,
      projectName: `ghostwatch-${target}`,
      autoAiReports: false,
      navigatorMode: false,
      navegation: { enabled: false },
      tor: { required: false, strict: false },
      vigoliumUseCodex: false,
    };
    if (outOfScope.length && !body.modules.includes('out_of_scope')) body.modules.push('out_of_scope');

    log(`${target}: recon baseline=#${baseline.id} modules=${body.modules.length} outOfScope=${outOfScope.length}`);
    let newRunId = null;
    let errors = [];
    try {
      await client.streamRecon(
        body,
        (evt) => {
          if (evt?.runId) newRunId = evt.runId;
          if (evt?.type === 'error') errors.push(evt.message || 'erro desconhecido');
        },
        { timeoutMs: Math.max(60_000, Number(opts.timeout || 1800) * 1000) },
      );
    } catch (e) {
      errors.push(e.message);
      log(`${target}: recon falhou: ${e.message}`);
    }

    if (!newRunId) {
      try {
        const afterRuns = await client.listRuns({ limit: opts['limit-runs'] });
        const afterLatest = latestRunsByTarget(afterRuns).get(target);
        if (afterLatest?.id && afterLatest.id !== baseline.id) newRunId = afterLatest.id;
      } catch {
        // ignore fallback failure
      }
    }

    const result = { target, baselineId: baseline.id, newerId: newRunId, errors };
    if (newRunId && newRunId !== baseline.id) {
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
    } else {
      log(`${target}: sem novo run salvo`);
    }
    sweep.targets.push(result);
    state.lastRunByTarget[target] = {
      baselineId: baseline.id,
      newerId: newRunId,
      at: new Date().toISOString(),
      errors,
      outOfScope,
    };
    await saveState(stateDir, state);
  }

  state.history.push(sweep);
  state.history = state.history.slice(-40);
  await saveState(stateDir, state);

  if (opts.format === 'json') process.stdout.write(`${JSON.stringify(sweep, null, 2)}\n`);
  else writeSweepSummary(sweep);
  return 0;
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
  } else if (opts['reuse-modules']) {
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
  const only = String(onlyTarget || '').trim().toLowerCase();
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
          : 'sem diff';
    process.stdout.write(`  ${r.target}: #${r.baselineId || '-'} -> #${r.newerId || '-'} ${suffix}\n`);
  }
}

function printHelp() {
  process.stdout.write(`ghostrecon ghostwatch - modo sentinela para VPS.

Comandos:
  ghostwatch run [opcoes]       Roda todos os alvos conhecidos, um por vez.
  ghostwatch once [opcoes]      Alias de run --once.
  ghostwatch register -t alvo   Adiciona/ajusta alvo na watchlist local da VPS.
  ghostwatch disable -t alvo    Desabilita alvo.
  ghostwatch enable -t alvo     Habilita alvo.
  ghostwatch list               Lista watchlist manual.

Uso recomendado na VPS:
  ghostrecon ghostwatch run --once

Por padrao le o .env do GHOSTRECON, usa GHOSTRECON_WEBHOOK_URL, roda full-recon
em modo agressivo/Kali e remove Tor/Navigator, Shannon, PentestGPT e Vigolium
agent/code-review/Codex antes de chamar o pipeline.

Opcoes de run:
  --playbook NAME               Default: ${DEFAULT_PLAYBOOK}
  --modules CSV                 Usa modulos fixos em vez de playbook.
  --reuse-modules               Reusa modulos do ultimo run do alvo.
  --out-of-scope CSV            Exclusoes extras; tambem reaplica stats.outOfScope do baseline.
  --min-severity LEVEL          Default: medium.
  --only-new                    Evita alerta repetido por fingerprint.
  --max-targets N               Limita quantidade por varredura.
  --limit-runs N                Quantos runs recentes consultar (max efetivo da API: 200).
  --dry-run                     Mostra o plano sem rodar recon.
  --interval 12h                Usado apenas sem --once.
  --start-server                Auto-inicia API local se necessario.
`);
}
