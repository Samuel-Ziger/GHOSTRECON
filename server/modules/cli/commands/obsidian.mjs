/**
 * ghostrecon obsidian — exporta engagement + runs para Obsidian vault.
 */
import fs from 'node:fs/promises';
import path from 'node:path';
import { parseArgs } from '../args.mjs';
import { GLOBAL_OPTS, GhostClient } from '../client.mjs';
import { exportToObsidian } from '../../ecosystem-export.mjs';
import { getEngagement } from '../../engagement.mjs';

const SPEC = [
  ...GLOBAL_OPTS,
  { name: 'engagement', type: 'string' },
  { name: 'runs', type: 'csv', default: [] },        // IDs de runs para incluir
  { name: 'file', type: 'string' },                  // OU arquivo com array de runs
  { name: 'out-dir', type: 'string', default: './obsidian-vault' },
  { name: 'vault-root', type: 'string', default: 'ghostrecon' },
];

export async function obsidianCommand(argv) {
  let opts;
  try { ({ opts } = parseArgs(argv, SPEC)); }
  catch (e) { process.stderr.write(`obsidian: ${e.message}\n`); return 2; }

  const engagement = opts.engagement ? await getEngagement(opts.engagement) : null;
  if (opts.engagement && !engagement) {
    process.stderr.write(`obsidian: engagement "${opts.engagement}" não encontrado\n`);
    return 4;
  }

  let runs = [];
  if (opts.file) {
    const raw = JSON.parse(await fs.readFile(opts.file, 'utf8'));
    runs = Array.isArray(raw) ? raw : [raw];
  } else if (opts.runs.length) {
    const client = new GhostClient({ server: opts.server });
    await client.ensureServer({ autoStart: !!opts['start-server'], quiet: !!opts.quiet });
    for (const id of opts.runs) {
      const n = Number(id);
      if (!Number.isFinite(n)) continue;
      try { runs.push(await client.getRun(n)); } catch (e) { process.stderr.write(`warn: run ${n}: ${e.message}\n`); }
    }
  } else {
    process.stderr.write('obsidian requer --runs 1,2,3 OU --file path.json\n');
    return 2;
  }

  const { files } = exportToObsidian({ engagement, runs, vaultRoot: opts['vault-root'] });
  for (const f of files) {
    const full = path.resolve(opts['out-dir'], f.path);
    await fs.mkdir(path.dirname(full), { recursive: true });
    await fs.writeFile(full, f.content, 'utf8');
  }
  process.stdout.write(`[obsidian] ${files.length} arquivos escritos em ${opts['out-dir']}\n`);
  return 0;
}
