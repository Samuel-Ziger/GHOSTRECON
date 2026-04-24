/**
 * ghostrecon export — exporta findings de um run para Linear/Jira/GitHub/Markdown.
 */

import fs from 'node:fs/promises';
import path from 'node:path';
import { parseArgs } from '../args.mjs';
import { GhostClient, GLOBAL_OPTS } from '../client.mjs';
import { exportToMarkdown, exportToGithubIssues, exportToLinear, exportToJira } from '../../workflow-export.mjs';

const SPEC = [
  ...GLOBAL_OPTS,
  { name: 'run', type: 'int', required: true },
  { name: 'to', type: 'string', default: 'markdown' },
  { name: 'severity', type: 'string', default: 'medium' },
  { name: 'output', type: 'string' },
  { name: 'dry-run', type: 'bool', default: false },
  // GitHub
  { name: 'repo', type: 'string' },
  { name: 'github-token', type: 'string', default: process.env.GITHUB_TOKEN || '' },
  { name: 'labels', type: 'csv', default: [] },
  // Linear
  { name: 'linear-team', type: 'string' },
  { name: 'linear-token', type: 'string', default: process.env.LINEAR_API_KEY || '' },
  // Jira
  { name: 'jira-url', type: 'string' },
  { name: 'jira-project', type: 'string' },
  { name: 'jira-user', type: 'string', default: process.env.JIRA_USER || '' },
  { name: 'jira-token', type: 'string', default: process.env.JIRA_TOKEN || '' },
];

export async function exportCommand(argv) {
  let opts;
  try {
    ({ opts } = parseArgs(argv, SPEC));
  } catch (e) {
    process.stderr.write(`export: ${e.message}\n`);
    return 2;
  }
  const client = new GhostClient({ server: opts.server });
  try {
    await client.ensureServer({ autoStart: opts['start-server'], quiet: opts.quiet });
  } catch (e) {
    process.stderr.write(`${e.message}\n`);
    return 3;
  }

  let run;
  try {
    run = await client.getRun(opts.run);
  } catch (e) {
    process.stderr.write(`run ${opts.run}: ${e.message}\n`);
    return 4;
  }

  const opts2 = {
    minSeverity: opts.severity,
    labels: opts.labels,
    dryRun: opts['dry-run'],
  };

  switch (String(opts.to).toLowerCase()) {
    case 'markdown':
    case 'md': {
      const md = exportToMarkdown(run, opts2);
      if (opts.output) {
        await fs.writeFile(path.resolve(process.cwd(), opts.output), md, 'utf8');
        process.stderr.write(`gravado: ${opts.output}\n`);
      } else {
        process.stdout.write(md);
      }
      return 0;
    }
    case 'github': {
      if (!opts.repo) { process.stderr.write('export: --repo owner/name é obrigatório para github\n'); return 2; }
      if (!opts['github-token'] && !opts['dry-run']) { process.stderr.write('export: --github-token (ou env GITHUB_TOKEN) é necessário\n'); return 2; }
      const res = await exportToGithubIssues(run, {
        repo: opts.repo,
        token: opts['github-token'],
        ...opts2,
      });
      writeExportResult('github', res, opts.output);
      return res.errors.length ? 1 : 0;
    }
    case 'linear': {
      if (!opts['linear-team']) { process.stderr.write('export: --linear-team é obrigatório\n'); return 2; }
      if (!opts['linear-token'] && !opts['dry-run']) { process.stderr.write('export: --linear-token (ou LINEAR_API_KEY) é necessário\n'); return 2; }
      const res = await exportToLinear(run, {
        teamId: opts['linear-team'],
        token: opts['linear-token'],
        ...opts2,
      });
      writeExportResult('linear', res, opts.output);
      return res.errors.length ? 1 : 0;
    }
    case 'jira': {
      if (!opts['jira-url'] || !opts['jira-project']) {
        process.stderr.write('export: --jira-url e --jira-project obrigatórios\n');
        return 2;
      }
      if ((!opts['jira-user'] || !opts['jira-token']) && !opts['dry-run']) {
        process.stderr.write('export: --jira-user/--jira-token (ou JIRA_USER/JIRA_TOKEN) necessários\n');
        return 2;
      }
      const res = await exportToJira(run, {
        baseUrl: opts['jira-url'],
        project: opts['jira-project'],
        user: opts['jira-user'],
        token: opts['jira-token'],
        ...opts2,
      });
      writeExportResult('jira', res, opts.output);
      return res.errors.length ? 1 : 0;
    }
    default:
      process.stderr.write(`export: destino desconhecido "${opts.to}" (markdown|github|linear|jira)\n`);
      return 2;
  }
}

async function writeExportResult(label, res, output) {
  if (output) {
    await (await import('node:fs/promises')).writeFile(
      (await import('node:path')).resolve(process.cwd(), output),
      JSON.stringify(res, null, 2),
      'utf8',
    );
    process.stderr.write(`gravado: ${output}\n`);
  }
  process.stderr.write(`[${label}] criados=${res.created?.length ?? 0} pulados=${res.skipped?.length ?? 0} erros=${res.errors?.length ?? 0}\n`);
  if (res.dryRun) {
    process.stdout.write(`${JSON.stringify(res.preview, null, 2)}\n`);
  }
}
