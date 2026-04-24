/**
 * ghostrecon replay — replay NDJSON gravado + tabletop rerank.
 */
import fs from 'node:fs/promises';
import { parseArgs } from '../args.mjs';
import { GLOBAL_OPTS } from '../client.mjs';
import { replayNdjson, tabletopRerank } from '../../replay-tabletop.mjs';

const SPEC = [
  ...GLOBAL_OPTS,
  { name: 'file', type: 'string' },
  { name: 'speed', type: 'int', default: 10 },
  { name: 'limit', type: 'int' },
  { name: 'tabletop', type: 'string' }, // path de run.json
  { name: 'context', type: 'string' },  // path de bountyContext.json
  { name: 'playbook', type: 'string' },
  { name: 'out', type: 'string' },
  { name: 'format', type: 'string', default: 'summary' },
];

export async function replayCommand(argv) {
  let opts;
  try { ({ opts } = parseArgs(argv, SPEC)); }
  catch (e) { process.stderr.write(`replay: ${e.message}\n`); return 2; }

  // Tabletop rerank
  if (opts.tabletop) {
    const run = JSON.parse(await fs.readFile(opts.tabletop, 'utf8'));
    let ctx = null;
    if (opts.context) ctx = JSON.parse(await fs.readFile(opts.context, 'utf8'));
    const result = tabletopRerank(run, { bountyContext: ctx, playbook: opts.playbook });
    if (opts.out) {
      await fs.writeFile(opts.out, JSON.stringify(result, null, 2), 'utf8');
      process.stdout.write(`[tabletop] ${result.kept}/${result.total} kept, ${result.dropped} dropped → ${opts.out}\n`);
    } else if (opts.format === 'json') {
      process.stdout.write(`${JSON.stringify(result, null, 2)}\n`);
    } else {
      process.stdout.write(`[tabletop] target=${result.target} · kept=${result.kept}/${result.total} · dropped=${result.dropped}\n`);
      for (const f of result.findings.slice(0, 20)) {
        process.stdout.write(`  [${(f.severity || 'info').toUpperCase()}] ${f.title || f.category} · score=${f.rerank.score}\n`);
      }
    }
    return 0;
  }

  // Replay
  if (!opts.file) { process.stderr.write('replay requer --file path.ndjson ou --tabletop path.json\n'); return 2; }
  let count = 0;
  await replayNdjson(opts.file, async (evt) => {
    count++;
    if (opts.format === 'ndjson') process.stdout.write(`${JSON.stringify(evt)}\n`);
    else if (!opts.quiet) {
      const t = evt.type || evt.step || evt.phase || '?';
      process.stdout.write(`[${count}] ${t}\n`);
    }
  }, { speed: opts.speed, limit: opts.limit });
  process.stdout.write(`[replay] total=${count} eventos\n`);
  return 0;
}
