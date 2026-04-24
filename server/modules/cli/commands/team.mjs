/**
 * ghostrecon team — locks e operator trail.
 */
import { parseArgs } from '../args.mjs';
import { GLOBAL_OPTS } from '../client.mjs';
import {
  acquireLock, releaseLock, forceReleaseLock, listLocks,
  recordAction, listTrail, diffByOperator,
} from '../../team-concurrency.mjs';

const SPEC = [
  ...GLOBAL_OPTS,
  { name: 'lock', type: 'bool', default: false },
  { name: 'unlock', type: 'bool', default: false },
  { name: 'force-unlock', type: 'bool', default: false },
  { name: 'locks', type: 'bool', default: false },
  { name: 'record', type: 'bool', default: false },
  { name: 'trail', type: 'bool', default: false },
  { name: 'diff', type: 'bool', default: false },
  { name: 'target', type: 'string' },
  { name: 'operator', type: 'string', default: process.env.GHOSTRECON_OPERATOR || 'anon' },
  { name: 'token', type: 'string' },
  { name: 'ttl-ms', type: 'int', default: 600_000 },
  { name: 'purpose', type: 'string', default: 'scan' },
  { name: 'action', type: 'string' },
  { name: 'run-id', type: 'int' },
  { name: 'since', type: 'string' },
  { name: 'format', type: 'string', default: 'table' },
];

export async function teamCommand(argv) {
  let opts;
  try { ({ opts } = parseArgs(argv, SPEC)); }
  catch (e) { process.stderr.write(`team: ${e.message}\n`); return 2; }

  if (opts.locks) {
    const list = await listLocks();
    if (opts.format === 'json') { process.stdout.write(`${JSON.stringify(list, null, 2)}\n`); return 0; }
    if (!list.length) { process.stdout.write('(sem locks ativos)\n'); return 0; }
    process.stdout.write('TARGET\tOPERATOR\tPURPOSE\tACQUIRED\tEXPIRES\tEXPIRED\n');
    for (const l of list) process.stdout.write(`${l.target}\t${l.operator}\t${l.purpose}\t${l.acquiredAt}\t${l.expiresAt}\t${l.expired}\n`);
    return 0;
  }

  if (opts.lock) {
    if (!opts.target) { process.stderr.write('team --lock requer --target\n'); return 2; }
    const r = await acquireLock(opts.target, { operator: opts.operator, ttlMs: opts['ttl-ms'], purpose: opts.purpose });
    if (!r.ok) {
      process.stdout.write(`[team] LOCK OCUPADO por ${r.heldBy} (acquired=${new Date(r.acquiredAt).toISOString()})\n`);
      return 3;
    }
    process.stdout.write(`[team] lock ok · token=${r.token} · ttl=${r.ttlMs}ms\n`);
    return 0;
  }

  if (opts.unlock) {
    if (!opts.target || !opts.token) { process.stderr.write('team --unlock requer --target e --token\n'); return 2; }
    const ok = await releaseLock(opts.target, opts.token);
    process.stdout.write(ok ? '[team] unlocked\n' : '[team] token/target não bate\n');
    return ok ? 0 : 4;
  }

  if (opts['force-unlock']) {
    if (!opts.target) { process.stderr.write('team --force-unlock requer --target\n'); return 2; }
    const ok = await forceReleaseLock(opts.target);
    process.stdout.write(ok ? '[team] forçado\n' : '[team] nada para liberar\n');
    return 0;
  }

  if (opts.record) {
    if (!opts.target || !opts.action) { process.stderr.write('team --record requer --target e --action\n'); return 2; }
    const e = await recordAction({ operator: opts.operator, target: opts.target, action: opts.action, runId: opts['run-id'] });
    process.stdout.write(`[team] trail: ${JSON.stringify(e)}\n`);
    return 0;
  }

  if (opts.trail) {
    const list = await listTrail({ target: opts.target, operator: opts.operator, sinceIso: opts.since });
    if (opts.format === 'json') { process.stdout.write(`${JSON.stringify(list, null, 2)}\n`); return 0; }
    for (const e of list) process.stdout.write(`${e.at}\t${e.operator}\t${e.target}\t${e.action}\t${e.runId ?? '-'}\n`);
    return 0;
  }

  if (opts.diff) {
    if (!opts.target) { process.stderr.write('team --diff requer --target\n'); return 2; }
    const res = await diffByOperator({ target: opts.target, sinceIso: opts.since });
    process.stdout.write(`${JSON.stringify(res, null, 2)}\n`);
    return 0;
  }

  process.stderr.write('team: use --locks, --lock, --unlock, --record, --trail, --diff\n');
  return 2;
}
