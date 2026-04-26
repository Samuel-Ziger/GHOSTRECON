/**
 * ghostrecon chains — detecta cadeias de exploit num run e exporta.
 */
import fs from 'node:fs/promises';
import { parseArgs } from '../args.mjs';
import { GLOBAL_OPTS } from '../client.mjs';
import { detectChains, applyChains, chainsToMarkdown, summarizeChains } from '../../chaining.mjs';

const SPEC = [
  ...GLOBAL_OPTS,
  { name: 'file', type: 'string' },              // run.json local
  { name: 'format', type: 'string', default: 'summary' }, // summary|markdown|json
  { name: 'out', type: 'string' },
  { name: 'apply', type: 'bool', default: false }, // injeta chains no run e escreve back
];

export async function chainsCommand(argv) {
  let opts;
  try { ({ opts } = parseArgs(argv, SPEC)); }
  catch (e) { process.stderr.write(`chains: ${e.message}\n`); return 2; }

  if (!opts.file) { process.stderr.write('chains: --file <run.json> obrigatório\n'); return 2; }
  let run;
  try { run = JSON.parse(await fs.readFile(opts.file, 'utf8')); }
  catch (e) { process.stderr.write(`chains: erro lendo ${opts.file}: ${e.message}\n`); return 4; }

  const findings = run.findings || [];
  const chains = detectChains(findings);
  const summary = summarizeChains(chains);

  if (opts.apply) {
    const enriched = applyChains(run);
    const out = opts.out || opts.file;
    await fs.writeFile(out, JSON.stringify(enriched, null, 2));
    process.stdout.write(`[chains] ${chains.length} cadeia(s) injetada(s) em ${out}\n`);
    return 0;
  }

  if (opts.format === 'json') {
    const payload = JSON.stringify({ chains, summary }, null, 2);
    if (opts.out) await fs.writeFile(opts.out, payload);
    else process.stdout.write(payload + '\n');
    return 0;
  }
  if (opts.format === 'markdown') {
    const md = chainsToMarkdown(chains);
    if (opts.out) await fs.writeFile(opts.out, md);
    else process.stdout.write(md);
    return 0;
  }
  // summary
  process.stdout.write(`[chains] total=${summary.total} top=${summary.topSeverity}\n`);
  for (const [id, n] of Object.entries(summary.byId)) {
    process.stdout.write(`  ${id}: ${n}\n`);
  }
  return 0;
}
