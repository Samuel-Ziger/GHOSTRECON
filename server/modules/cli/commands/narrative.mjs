/**
 * ghostrecon narrative — kill-chain/MITRE narrative + cenários nomeados.
 */
import fs from 'node:fs/promises';
import { parseArgs } from '../args.mjs';
import { GLOBAL_OPTS, GhostClient } from '../client.mjs';
import { narrate, narrativeToMarkdown, matchScenarios, buildAttackPath } from '../../attack-narrative.mjs';

const SPEC = [
  ...GLOBAL_OPTS,
  { name: 'run', type: 'int' },
  { name: 'file', type: 'string' },
  { name: 'format', type: 'string', default: 'markdown' },
  { name: 'include-info', type: 'bool', default: false },
  { name: 'scenarios', type: 'bool', default: false },
];

export async function narrativeCommand(argv) {
  let opts;
  try { ({ opts } = parseArgs(argv, SPEC)); }
  catch (e) { process.stderr.write(`narrative: ${e.message}\n`); return 2; }

  let run = null;
  if (opts.file) {
    const raw = await fs.readFile(opts.file, 'utf8');
    run = JSON.parse(raw);
  } else if (opts.run != null) {
    const client = new GhostClient({ server: opts.server });
    await client.ensureServer({ autoStart: !!opts['start-server'], quiet: !!opts.quiet });
    run = await client.getRun(opts.run);
  } else {
    process.stderr.write('narrative requer --run <id> ou --file path.json\n');
    return 2;
  }

  const narrative = narrate(run, { includeInfo: !!opts['include-info'] });
  if (opts.scenarios) {
    const matched = matchScenarios(narrative);
    if (opts.format === 'json') {
      process.stdout.write(`${JSON.stringify({ narrative: buildAttackPath(narrative), scenarios: matched }, null, 2)}\n`);
      return 0;
    }
    process.stdout.write(`[scenarios] ${matched.length} match(es)\n`);
    for (const sc of matched) {
      process.stdout.write(`  • ${sc.id} — ${sc.label}\n`);
      process.stdout.write(`    ${sc.description}\n`);
      process.stdout.write(`    Próximos: ${sc.recommendedNext.join('; ')}\n`);
    }
    return 0;
  }

  if (opts.format === 'json') {
    process.stdout.write(`${JSON.stringify(buildAttackPath(narrative), null, 2)}\n`);
    return 0;
  }
  process.stdout.write(`${narrativeToMarkdown(narrative)}\n`);
  return 0;
}
