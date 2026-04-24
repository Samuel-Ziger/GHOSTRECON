/**
 * ghostrecon engagement — ROE + metadata + op report.
 */
import { parseArgs } from '../args.mjs';
import { GLOBAL_OPTS } from '../client.mjs';
import {
  listEngagements, getEngagement, upsertEngagement, closeEngagement,
  preRunChecklist, buildOperationalReport,
} from '../../engagement.mjs';

const SPEC = [
  ...GLOBAL_OPTS,
  { name: 'add', type: 'bool', default: false },
  { name: 'close', type: 'bool', default: false },
  { name: 'show', type: 'string' },
  { name: 'report', type: 'string' }, // id → op report
  { name: 'checklist', type: 'bool', default: false },
  { name: 'id', type: 'string' },
  { name: 'client', type: 'string' },
  { name: 'scope-domain', type: 'repeat', default: [] },
  { name: 'scope-ip', type: 'repeat', default: [] },
  { name: 'exclude', type: 'repeat', default: [] },
  { name: 'source-ip', type: 'repeat', default: [] },
  { name: 'starts-at', type: 'string' },
  { name: 'ends-at', type: 'string' },
  { name: 'tz', type: 'string' },
  { name: 'escalation', type: 'string' }, // "Name <email> <phone>"
  { name: 'roe-url', type: 'string' },
  { name: 'roe-signed', type: 'bool', default: false },
  { name: 'note', type: 'string' },
  { name: 'reason', type: 'string' },
  { name: 'target', type: 'string' },
  { name: 'modules', type: 'csv', default: [] },
  { name: 'playbook', type: 'string' },
  { name: 'format', type: 'string', default: 'table' },
];

function parseEscalation(s) {
  if (!s) return null;
  const m = String(s).match(/^\s*(.+?)\s*<([^>]+)>\s*(?:<([^>]+)>)?\s*$/);
  if (!m) return { name: String(s), email: '', phone: '' };
  return { name: m[1], email: m[2], phone: m[3] || '' };
}

export async function engagementCommand(argv) {
  let opts;
  try { ({ opts } = parseArgs(argv, SPEC)); }
  catch (e) { process.stderr.write(`engagement: ${e.message}\n`); return 2; }

  if (opts.show) {
    const e = await getEngagement(opts.show);
    if (!e) { process.stderr.write(`engagement "${opts.show}" não encontrado\n`); return 4; }
    process.stdout.write(`${JSON.stringify(e, null, 2)}\n`);
    return 0;
  }

  if (opts.report) {
    const e = await getEngagement(opts.report);
    if (!e) { process.stderr.write(`engagement "${opts.report}" não encontrado\n`); return 4; }
    process.stdout.write(`${buildOperationalReport(e)}\n`);
    return 0;
  }

  if (opts.close) {
    if (!opts.id) { process.stderr.write('engagement --close requer --id\n'); return 2; }
    const e = await closeEngagement(opts.id, { reason: opts.reason });
    if (!e) { process.stderr.write(`engagement "${opts.id}" não encontrado\n`); return 4; }
    process.stdout.write(`[engagement] fechado: ${opts.id}\n`);
    return 0;
  }

  if (opts.checklist) {
    if (!opts.target) { process.stderr.write('engagement --checklist requer --target\n'); return 2; }
    const eng = opts.id ? await getEngagement(opts.id) : null;
    const res = preRunChecklist({
      engagement: eng, target: opts.target, modules: opts.modules, playbook: opts.playbook,
    });
    process.stdout.write(`[checklist] ok=${res.ok}\n`);
    for (const e of res.errors) process.stdout.write(`  ✗ ${e}\n`);
    for (const w of res.warnings) process.stdout.write(`  ⚠ ${w}\n`);
    return res.ok ? 0 : 3;
  }

  if (opts.add) {
    if (!opts.id) { process.stderr.write('engagement --add requer --id\n'); return 2; }
    const window = (opts['starts-at'] || opts['ends-at'] || opts.tz)
      ? { startsAt: opts['starts-at'] || null, endsAt: opts['ends-at'] || null, tz: opts.tz || null }
      : null;
    const eng = await upsertEngagement({
      id: opts.id,
      client: opts.client,
      scopeDomains: opts['scope-domain'],
      scopeIps: opts['scope-ip'],
      exclusions: opts.exclude,
      sourceIps: opts['source-ip'],
      window,
      escalationContact: parseEscalation(opts.escalation),
      roeUrl: opts['roe-url'] || null,
      roeSigned: !!opts['roe-signed'],
      notes: opts.note ? [{ at: new Date().toISOString(), text: opts.note }] : [],
    });
    process.stdout.write(`[engagement] criado/atualizado: ${eng.id}\n`);
    return 0;
  }

  // Lista padrão
  const list = await listEngagements();
  if (opts.format === 'json') {
    process.stdout.write(`${JSON.stringify(list, null, 2)}\n`);
    return 0;
  }
  if (!list.length) {
    process.stdout.write('(sem engagements — use --add --id ENG-001 --client acme)\n');
    return 0;
  }
  const idW = Math.max(2, ...list.map((e) => e.id.length));
  const clientW = Math.max(6, ...list.map((e) => (e.client || '').length));
  process.stdout.write('ID'.padEnd(idW) + '  ' + 'CLIENT'.padEnd(clientW) + '  STATUS   RUNS  UPDATED\n');
  for (const e of list) {
    process.stdout.write(
      `${e.id.padEnd(idW)}  ${(e.client || '').padEnd(clientW)}  ${(e.status || 'active').padEnd(7)}  ${String(e.runCount).padEnd(4)}  ${e.updatedAt || '-'}\n`,
    );
  }
  return 0;
}
