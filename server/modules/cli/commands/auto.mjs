/**
 * ghostrecon auto — Modo Auto via stream NDJSON.
 */
import { parseArgs } from '../args.mjs';
import { GhostClient, GLOBAL_OPTS } from '../client.mjs';

const SPEC = [
  ...GLOBAL_OPTS,
  { name: 'target', type: 'string' },
  { name: 'domain', type: 'string' },
  { name: 'autonomy', type: 'string', default: 'observation' },
  { name: 'mode', type: 'string', default: 'balanced' },
  { name: 'engagement', type: 'string' },
  { name: 'modules', type: 'csv', default: [] },
  { name: 'commanders', type: 'csv', default: [] },
  { name: 'approval-mode', type: 'string', default: 'interactive' },
  { name: 'include-frameseven', type: 'bool', default: false },
  { name: 'include-vigolium', type: 'bool', default: false },
  { name: 'include-hexstrike', type: 'bool', default: false },
  { name: 'resume', type: 'string' },
  { name: 'timeout', type: 'number', default: 1800 },
  { name: 'format', type: 'string', default: 'summary' },
];

export async function autoCommand(argv) {
  let opts;
  try {
    ({ opts } = parseArgs(argv, SPEC));
  } catch (error) {
    process.stderr.write(`auto: ${error.message}\n`);
    return 2;
  }

  const target = String(opts.target || opts.domain || '').trim();
  if (!target) {
    process.stderr.write('auto: --target é obrigatório\n');
    return 2;
  }

  const approvalMode = String(opts['approval-mode'] || 'interactive').trim().toLowerCase();
  if (!['interactive', 'deny', 'auto'].includes(approvalMode)) {
    process.stderr.write('auto: --approval-mode deve ser interactive|deny|auto\n');
    return 2;
  }

  const client = new GhostClient({
    server: opts.server,
  });
  await client.ensureServer({ autoStart: opts['start-server'] });

  const body = {
    domain: target,
    mode: opts.mode,
    autonomyLevel: opts.autonomy,
    approvalMode,
    modules: opts.modules,
    commanders: opts.commanders,
    includeFrameSeven: opts['include-frameseven'] === true,
    includeVigolium: opts['include-vigolium'] === true,
    includeHexstrike: opts['include-hexstrike'] === true,
    engagementId: opts.engagement || null,
    resumeSessionId: opts.resume || null,
  };

  const events = [];
  let lastSession = null;
  const result = await client.streamAutoRecon(body, (event) => {
    events.push(event);
    if (opts.format === 'ndjson') {
      process.stdout.write(`${JSON.stringify(event)}\n`);
    }
    if (event?.type === 'auto_session') lastSession = event;
    if (event?.type === 'auto_approval_required' && approvalMode === 'interactive') {
      process.stderr.write(
        `auto: aprovação necessária session=${event.sessionId} approval=${event.approval?.approvalId}\n`
        + 'Use a UI ou POST /api/recon/auto/:sessionId/approval\n',
      );
    }
  }, {
    timeoutMs: Math.max(60_000, Number(opts.timeout || 1800) * 1000),
  });

  if (opts.format === 'json') {
    process.stdout.write(`${JSON.stringify({
      ok: true,
      events: events.length,
      lastSession,
      result,
    }, null, 2)}\n`);
    return 0;
  }

  if (opts.format !== 'ndjson') {
    const terminal = events.filter((e) => e.type === 'auto_session').at(-1);
    process.stdout.write(
      `auto: target=${target} autonomy=${opts.autonomy} events=${events.length}`
      + ` phase=${terminal?.phase || '?'} session=${terminal?.sessionId || lastSession?.sessionId || '?'}\n`,
    );
  }
  return 0;
}
