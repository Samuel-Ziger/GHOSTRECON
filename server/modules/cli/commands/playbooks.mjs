/**
 * ghostrecon playbooks — lista playbooks disponíveis.
 */

import { parseArgs } from '../args.mjs';
import { GLOBAL_OPTS } from '../client.mjs';
import { listPlaybooks, resolvePlaybook } from '../../playbooks/loader.mjs';

const SPEC = [
  ...GLOBAL_OPTS,
  { name: 'show', type: 'string' },
  { name: 'format', type: 'string', default: 'table' },
];

export async function playbooksCommand(argv) {
  let opts;
  try {
    ({ opts } = parseArgs(argv, SPEC));
  } catch (e) {
    process.stderr.write(`playbooks: ${e.message}\n`);
    return 2;
  }

  if (opts.show) {
    try {
      const pb = await resolvePlaybook(opts.show);
      process.stdout.write(`${JSON.stringify(pb, null, 2)}\n`);
      return 0;
    } catch (e) {
      process.stderr.write(`playbook "${opts.show}": ${e.message}\n`);
      return 4;
    }
  }

  const list = await listPlaybooks();
  if (opts.format === 'json') {
    process.stdout.write(`${JSON.stringify(list, null, 2)}\n`);
    return 0;
  }
  if (!list.length) {
    process.stdout.write('(sem playbooks — veja playbooks/README.md)\n');
    return 0;
  }
  const nameW = Math.max(10, ...list.map((p) => p.name.length));
  process.stdout.write(`${'NAME'.padEnd(nameW)}  MODULES  PROFILE        DESCRIPTION\n`);
  for (const p of list) {
    process.stdout.write(
      `${p.name.padEnd(nameW)}  ${String(p.modules?.length ?? 0).padEnd(7)}  ${String(p.profile || 'standard').padEnd(13)}  ${String(p.description || '').slice(0, 80)}\n`,
    );
  }
  return 0;
}
