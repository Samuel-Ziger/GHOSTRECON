/**
 * ghostrecon projects — CRUD de projetos (scope, notas, módulos default).
 */

import { parseArgs } from '../args.mjs';
import { GLOBAL_OPTS } from '../client.mjs';
import {
  listProjects,
  getProject,
  upsertProject,
  removeProject,
  addProjectScope,
  removeProjectScope,
} from '../../projects.mjs';

const SPEC = [
  ...GLOBAL_OPTS,
  { name: 'add', type: 'bool', default: false },
  { name: 'remove', type: 'bool', default: false },
  { name: 'show', type: 'string' },
  { name: 'name', type: 'string' },
  { name: 'description', type: 'string' },
  { name: 'scope-add', type: 'repeat', default: [] },
  { name: 'scope-remove', type: 'repeat', default: [] },
  { name: 'out-of-scope', type: 'csv', default: [] },
  { name: 'modules', type: 'csv', default: [] },
  { name: 'playbook', type: 'string' },
  { name: 'note', type: 'string' },
  { name: 'format', type: 'string', default: 'table' },
];

export async function projectsCommand(argv) {
  let opts;
  try {
    ({ opts } = parseArgs(argv, SPEC));
  } catch (e) {
    process.stderr.write(`projects: ${e.message}\n`);
    return 2;
  }

  if (opts.show) {
    const p = await getProject(opts.show);
    if (!p) { process.stderr.write(`projeto "${opts.show}" nao encontrado\n`); return 4; }
    process.stdout.write(`${JSON.stringify(p, null, 2)}\n`);
    return 0;
  }

  if (opts.remove) {
    if (!opts.name) { process.stderr.write('projects --remove requer --name\n'); return 2; }
    const ok = await removeProject(opts.name);
    process.stdout.write(ok ? `removido: ${opts.name}\n` : `nao encontrado: ${opts.name}\n`);
    return ok ? 0 : 4;
  }

  if (opts.add) {
    if (!opts.name) { process.stderr.write('projects --add requer --name\n'); return 2; }
    const created = await upsertProject({
      name: opts.name,
      description: opts.description || '',
      scope: opts['scope-add'],
      outOfScope: opts['out-of-scope'],
      defaultModules: opts.modules,
      defaultPlaybook: opts.playbook || null,
      notes: opts.note ? [{ at: new Date().toISOString(), text: opts.note }] : [],
    });
    for (const s of opts['scope-remove']) await removeProjectScope(opts.name, s);
    process.stdout.write(`[projects] criado/atualizado: ${created.name}\n`);
    return 0;
  }

  if (opts['scope-add'].length || opts['scope-remove'].length) {
    if (!opts.name) { process.stderr.write('projects scope requer --name\n'); return 2; }
    for (const s of opts['scope-add']) await addProjectScope(opts.name, s);
    for (const s of opts['scope-remove']) await removeProjectScope(opts.name, s);
    const p = await getProject(opts.name);
    const n = p && Array.isArray(p.scope) ? p.scope.length : 0;
    process.stdout.write(`[projects] ${opts.name} scope=${n}\n`);
    return 0;
  }

  const list = await listProjects();
  if (opts.format === 'json') {
    process.stdout.write(`${JSON.stringify(list, null, 2)}\n`);
    return 0;
  }
  if (!list.length) {
    process.stdout.write('(sem projetos — use --add --name foo)\n');
    return 0;
  }
  const nameW = Math.max(6, ...list.map((p) => p.name.length));
  process.stdout.write('NAME'.padEnd(nameW) + '  SCOPE  RUNS  UPDATED\n');
  for (const p of list) {
    const scope = String(p.scope ? p.scope.length : 0).padEnd(5);
    const runs = String(p.runCount || 0).padEnd(4);
    process.stdout.write(`${p.name.padEnd(nameW)}  ${scope}  ${runs}  ${p.updatedAt || '-'}\n`);
  }
  return 0;
}
