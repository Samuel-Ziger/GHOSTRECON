/**
 * ghostrecon purple — export purple-team (findings + controle + Sigma).
 */
import fs from 'node:fs/promises';
import { parseArgs } from '../args.mjs';
import { GLOBAL_OPTS, GhostClient } from '../client.mjs';
import { exportPurpleTeamReport, annotateOrigin, filterByOrigin } from '../../purple-team.mjs';

const SPEC = [
  ...GLOBAL_OPTS,
  { name: 'run', type: 'int' },
  { name: 'file', type: 'string' },
  { name: 'out', type: 'string' },
  { name: 'min-severity', type: 'string', default: 'low' },
  { name: 'annotate-origin', type: 'string' }, // aplica origem a todos os findings
  { name: 'filter-origin', type: 'string' },   // filtra por origem
];

export async function purpleCommand(argv) {
  let opts;
  try { ({ opts } = parseArgs(argv, SPEC)); }
  catch (e) { process.stderr.write(`purple: ${e.message}\n`); return 2; }

  let run = null;
  if (opts.file) {
    run = JSON.parse(await fs.readFile(opts.file, 'utf8'));
  } else if (opts.run != null) {
    const client = new GhostClient({ server: opts.server });
    await client.ensureServer({ autoStart: !!opts['start-server'], quiet: !!opts.quiet });
    run = await client.getRun(opts.run);
  } else {
    process.stderr.write('purple requer --run <id> ou --file path.json\n');
    return 2;
  }

  // Anotar origem opcional
  if (opts['annotate-origin']) {
    run.findings = (run.findings || []).map((f) => annotateOrigin(f, { origin: opts['annotate-origin'] }));
  }
  if (opts['filter-origin']) {
    run.findings = filterByOrigin(run.findings, opts['filter-origin'].split(','));
  }

  const md = exportPurpleTeamReport(run, { minSeverity: opts['min-severity'] });
  if (opts.out) {
    await fs.writeFile(opts.out, md, 'utf8');
    process.stdout.write(`[purple] escrito em ${opts.out} (${md.length} bytes)\n`);
  } else {
    process.stdout.write(`${md}\n`);
  }
  return 0;
}
