/**
 * ghostrecon diff — mostra delta entre dois runs do mesmo alvo.
 */

import { parseArgs } from '../args.mjs';
import { GhostClient, GLOBAL_OPTS } from '../client.mjs';
import { summarizeDiff } from '../../diff-engine.mjs';

const SPEC = [
  ...GLOBAL_OPTS,
  { name: 'baseline', type: 'int', required: true },
  { name: 'newer', type: 'int', required: true },
  { name: 'format', type: 'string', default: 'summary' },
  { name: 'min-severity', type: 'string', default: 'low' },
  { name: 'only-new', type: 'bool', default: false },
];

export async function diffCommand(argv) {
  let opts;
  try {
    ({ opts } = parseArgs(argv, SPEC));
  } catch (e) {
    process.stderr.write(`diff: ${e.message}\n`);
    return 2;
  }
  const client = new GhostClient({ server: opts.server });
  try {
    await client.ensureServer({ autoStart: opts['start-server'], quiet: opts.quiet });
  } catch (e) {
    process.stderr.write(`${e.message}\n`);
    return 3;
  }

  let diff;
  try {
    diff = await client.diffRuns(opts.baseline, opts.newer);
  } catch (e) {
    process.stderr.write(`diff: ${e.message}\n`);
    return 4;
  }
  if (diff.error) {
    process.stderr.write(`diff: ${diff.error}\n`);
    return 5;
  }

  const summary = summarizeDiff(diff, { minSeverity: opts['min-severity'], onlyNew: opts['only-new'] });

  if (opts.format === 'json') {
    process.stdout.write(`${JSON.stringify(summary, null, 2)}\n`);
    return 0;
  }

  process.stdout.write(
    `diff run #${diff.baselineId} → #${diff.newerId} (${diff.target})\n` +
      `  +added=${summary.addedCount} (high=${summary.addedBySeverity.high ?? 0}, medium=${summary.addedBySeverity.medium ?? 0}, low=${summary.addedBySeverity.low ?? 0})\n` +
      `  -removed=${summary.removedCount}\n` +
      `  new-hosts=${summary.newHosts.length}${summary.newHosts.length ? ` [${summary.newHosts.slice(0, 5).join(', ')}${summary.newHosts.length > 5 ? '…' : ''}]` : ''}\n`,
  );
  if (summary.notableAdded.length) {
    process.stdout.write('  notáveis:\n');
    for (const f of summary.notableAdded.slice(0, 10)) {
      process.stdout.write(
        `    [${(f.severity || 'n/a').toUpperCase()}] ${f.title || f.category || '?'} — ${String(f.evidence?.target || f.url || '').slice(0, 100)}\n`,
      );
    }
  }
  return 0;
}
