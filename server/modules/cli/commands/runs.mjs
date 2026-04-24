/**
 * ghostrecon runs — lista runs.
 */

import { parseArgs } from '../args.mjs';
import { GhostClient, GLOBAL_OPTS } from '../client.mjs';

const SPEC = [
  ...GLOBAL_OPTS,
  { name: 'target', type: 'string' },
  { name: 'limit', type: 'int', default: 20 },
  { name: 'format', type: 'string', default: 'table' },
];

export async function runsCommand(argv) {
  let opts;
  try {
    ({ opts } = parseArgs(argv, SPEC));
  } catch (e) {
    process.stderr.write(`runs: ${e.message}\n`);
    return 2;
  }

  const client = new GhostClient({ server: opts.server });
  try {
    await client.ensureServer({ autoStart: opts['start-server'], quiet: opts.quiet });
  } catch (e) {
    process.stderr.write(`${e.message}\n`);
    return 3;
  }

  let runs;
  try {
    runs = await client.listRuns();
  } catch (e) {
    process.stderr.write(`list: ${e.message}\n`);
    return 4;
  }

  if (opts.target) {
    const t = String(opts.target).toLowerCase();
    runs = (runs || []).filter((r) => String(r.target || '').toLowerCase() === t);
  }
  if (opts.limit && Array.isArray(runs)) runs = runs.slice(0, opts.limit);

  if (opts.format === 'json') {
    process.stdout.write(`${JSON.stringify(runs, null, 2)}\n`);
    return 0;
  }

  // table
  const rows = (runs || []).map((r) => ({
    id: r.id,
    target: r.target,
    created: r.created_at,
    high: r.stats?.high ?? '?',
    subs: r.stats?.subs ?? '?',
    endpoints: r.stats?.endpoints ?? '?',
  }));

  if (!rows.length) {
    process.stdout.write('(sem runs)\n');
    return 0;
  }
  const widths = {
    id: Math.max(3, ...rows.map((r) => String(r.id).length)),
    target: Math.max(6, ...rows.map((r) => String(r.target || '').length)),
    created: 25,
    high: 4,
    subs: 4,
    endpoints: 9,
  };
  const pad = (s, w) => String(s ?? '').padEnd(w);
  process.stdout.write(
    `${pad('ID', widths.id)}  ${pad('TARGET', widths.target)}  ${pad('CREATED', widths.created)}  ${pad('HIGH', widths.high)}  ${pad('SUBS', widths.subs)}  ${pad('ENDPOINTS', widths.endpoints)}\n`,
  );
  for (const r of rows) {
    process.stdout.write(
      `${pad(r.id, widths.id)}  ${pad(r.target, widths.target)}  ${pad(r.created, widths.created)}  ${pad(r.high, widths.high)}  ${pad(r.subs, widths.subs)}  ${pad(r.endpoints, widths.endpoints)}\n`,
    );
  }
  return 0;
}
