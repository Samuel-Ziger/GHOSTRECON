/**
 * ghostrecon schedule — scheduler com interval, diff automático e alerta new-only.
 *
 * Guarda estado entre execuções em .ghostrecon-schedule/<target>.json:
 *   - lastRunId, lastFingerprint, history
 *
 * O alerta é enviado via webhook (Slack/Discord compatível) se --webhook for passado,
 * caso contrário apenas stdout.
 */

import fs from 'node:fs/promises';
import path from 'node:path';
import { parseArgs, parseDuration, kvListToObject } from '../args.mjs';
import { GhostClient, GLOBAL_OPTS } from '../client.mjs';
import { summarizeDiff, shouldAlert } from '../../diff-engine.mjs';
import { resolvePlaybook } from '../../playbooks/loader.mjs';
import { postAlert } from '../../alerting.mjs';

const SPEC = [
  ...GLOBAL_OPTS,
  { name: 'target', type: 'string', required: true, alias: 't' },
  { name: 'interval', type: 'string', default: '6h' },
  { name: 'modules', type: 'csv', default: [] },
  { name: 'playbook', type: 'string' },
  { name: 'profile', type: 'string', default: 'standard' },
  { name: 'webhook', type: 'string' },
  { name: 'min-severity', type: 'string', default: 'high' },
  { name: 'only-new', type: 'bool', default: true },
  { name: 'max-runs', type: 'int', default: 0 },
  { name: 'once', type: 'bool', default: false },
  { name: 'state-dir', type: 'string', default: '.ghostrecon-schedule' },
  { name: 'kali', type: 'bool', default: false },
  { name: 'out-of-scope', type: 'csv', default: [] },
  { name: 'auth-header', type: 'repeat', default: [] },
  { name: 'auth-cookie', type: 'string' },
];

export async function scheduleCommand(argv) {
  let opts;
  try {
    ({ opts } = parseArgs(argv, SPEC));
  } catch (e) {
    process.stderr.write(`schedule: ${e.message}\n`);
    return 2;
  }
  const intervalMs = parseDuration(opts.interval);

  const client = new GhostClient({ server: opts.server });
  try {
    await client.ensureServer({ autoStart: opts['start-server'], quiet: opts.quiet });
  } catch (e) {
    process.stderr.write(`${e.message}\n`);
    return 3;
  }

  let modules = [...opts.modules];
  if (opts.playbook) {
    const pb = await resolvePlaybook(opts.playbook);
    modules = uniqueMerge(modules, pb.modules);
    if (opts.profile === 'standard' && pb.profile) opts.profile = pb.profile;
  }
  if (!modules.length) {
    process.stderr.write('schedule: indique --modules ou --playbook\n');
    return 2;
  }

  const stateDir = path.resolve(process.cwd(), opts['state-dir']);
  await fs.mkdir(stateDir, { recursive: true });
  const stateFile = path.join(stateDir, `${slug(opts.target)}.json`);

  let state;
  try {
    state = JSON.parse(await fs.readFile(stateFile, 'utf8'));
  } catch {
    state = { target: opts.target, history: [], fingerprints: [] };
  }

  const log = (...a) => { if (!opts.quiet) process.stderr.write(`[schedule] ${a.join(' ')}\n`); };
  const headers = kvListToObject(opts['auth-header']);
  const body = {
    domain: opts.target,
    modules,
    kaliMode: opts.kali,
    profile: opts.profile,
    outOfScope: opts['out-of-scope'].join(','),
    auth: Object.keys(headers).length || opts['auth-cookie']
      ? { headers, cookie: opts['auth-cookie'] || '' }
      : null,
  };

  let iterations = 0;
  let shuttingDown = false;
  const onSignal = () => { shuttingDown = true; log('shutdown solicitado'); };
  process.on('SIGINT', onSignal);
  process.on('SIGTERM', onSignal);

  // Loop principal
  while (!shuttingDown) {
    iterations++;
    const t0 = Date.now();
    log(`iteração #${iterations} — ${opts.target}`);

    let thisRunId = null;
    try {
      await client.streamRecon(body, (evt) => {
        if (evt?.runId) thisRunId = evt.runId;
        if (evt?.type === 'run-saved' && evt.runId) thisRunId = evt.runId;
      }, { timeoutMs: Math.max(intervalMs - 5000, 60_000) });
    } catch (e) {
      log(`recon falhou: ${e.message}`);
    }

    if (!thisRunId) {
      try {
        const runs = await client.listRuns();
        const mine = (runs || []).filter((r) => String(r.target) === String(opts.target));
        thisRunId = mine[0]?.id || null;
      } catch { /* ignore */ }
    }

    const baselineId = state.history.length ? state.history[state.history.length - 1].runId : null;

    if (thisRunId && baselineId && thisRunId !== baselineId) {
      try {
        const diff = await client.diffRuns(baselineId, thisRunId);
        if (!diff.error) {
          const summary = summarizeDiff(diff, {
            minSeverity: opts['min-severity'],
            onlyNew: opts['only-new'],
          });
          const seen = new Set(state.fingerprints || []);
          const alert = shouldAlert(summary, { seenFingerprints: seen });
          log(
            `diff #${baselineId}→#${thisRunId}: +${summary.addedCount} (high=${summary.addedBySeverity.high ?? 0}) newHosts=${summary.newHosts.length} alert=${alert}`,
          );
          if (alert) {
            state.fingerprints = [...seen, summary.fingerprint].slice(-200);
            if (opts.webhook) {
              try {
                await postAlert(opts.webhook, buildAlertPayload(opts.target, summary));
              } catch (e) {
                log(`webhook falhou: ${e.message}`);
              }
            } else {
              writeAlertStdout(opts.target, summary);
            }
          }
        }
      } catch (e) {
        log(`diff falhou: ${e.message}`);
      }
    } else if (thisRunId && !baselineId) {
      log('primeira execução gravada — próxima iteração produzirá diff');
    }

    state.history.push({ runId: thisRunId, at: new Date().toISOString(), elapsedMs: Date.now() - t0 });
    state.history = state.history.slice(-50);
    await fs.writeFile(stateFile, JSON.stringify(state, null, 2), 'utf8');

    if (opts.once || shuttingDown) break;
    if (opts['max-runs'] > 0 && iterations >= opts['max-runs']) break;

    const wait = intervalMs - (Date.now() - t0);
    if (wait > 0) {
      log(`aguardando ${Math.round(wait / 1000)}s para próxima iteração`);
      await interruptibleSleep(wait, () => shuttingDown);
    }
  }

  log(`terminou após ${iterations} iteração(ões)`);
  return 0;
}

function slug(s) {
  return String(s || '').toLowerCase().replace(/[^a-z0-9._-]+/g, '_').slice(0, 120);
}

function uniqueMerge(a, b) {
  const seen = new Set();
  const out = [];
  for (const item of [...(a || []), ...(b || [])]) {
    const k = String(item).trim();
    if (!k || seen.has(k)) continue;
    seen.add(k);
    out.push(k);
  }
  return out;
}

async function interruptibleSleep(totalMs, shouldStop) {
  const step = Math.min(1000, totalMs);
  let left = totalMs;
  while (left > 0) {
    if (shouldStop()) return;
    const s = Math.min(step, left);
    await new Promise((r) => setTimeout(r, s));
    left -= s;
  }
}

function buildAlertPayload(target, summary) {
  const lines = [
    `**GHOSTRECON** — novos findings em \`${target}\``,
    `Run \`#${summary.baselineId}\` → \`#${summary.newerId}\``,
    `Added: **${summary.addedCount}** (high=${summary.addedBySeverity.high ?? 0}, medium=${summary.addedBySeverity.medium ?? 0}, low=${summary.addedBySeverity.low ?? 0})`,
    summary.newHosts.length
      ? `Novos hosts: ${summary.newHosts.slice(0, 8).map((h) => `\`${h}\``).join(', ')}${summary.newHosts.length > 8 ? '…' : ''}`
      : 'Sem novos hosts.',
  ];
  if (summary.notableAdded.length) {
    lines.push('', 'Notáveis:');
    for (const f of summary.notableAdded.slice(0, 5)) {
      lines.push(`• [${(f.severity || 'n/a').toUpperCase()}] ${f.title || f.category || '?'}`);
    }
  }
  return { content: lines.join('\n'), target, summary };
}

function writeAlertStdout(target, summary) {
  process.stdout.write(`\n[ALERT] ${target} — +${summary.addedCount} findings (high=${summary.addedBySeverity.high ?? 0})\n`);
  for (const f of summary.notableAdded.slice(0, 10)) {
    process.stdout.write(
      `  [${(f.severity || 'n/a').toUpperCase()}] ${f.title || f.category || '?'} ${String(f.evidence?.target || f.url || '').slice(0, 100)}\n`,
    );
  }
}
