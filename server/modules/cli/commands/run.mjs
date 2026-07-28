/**
 * ghostrecon run — executa o pipeline via /api/recon/stream.
 */

import fs from 'node:fs/promises';
import path from 'node:path';
import { createInterface } from 'node:readline/promises';
import { parseArgs, kvListToObject } from '../args.mjs';
import { GhostClient, GLOBAL_OPTS } from '../client.mjs';
import { resolvePlaybook } from '../../playbooks/loader.mjs';
import { getEngagement, preRunChecklist } from '../../engagement.mjs';
import { gateModules, applyWatermarkHeaders, expandIntrusiveRunModules } from '../../opsec.mjs';
import { parseReconTarget } from '../../recon-target.js';

const SPEC = [
  ...GLOBAL_OPTS,
  { name: 'target', type: 'string', required: true, alias: 't' },
  { name: 'modules', type: 'csv', default: [] },
  { name: 'playbook', type: 'string' },
  { name: 'profile', type: 'string', default: 'standard' },
  { name: 'opsec-profile', type: 'string', default: 'standard' },
  { name: 'output', type: 'string', alias: 'o' },
  { name: 'format', type: 'string', default: 'json' },
  { name: 'exact-match', type: 'bool', default: false },
  { name: 'kali', type: 'bool', default: false },
  { name: 'out-of-scope', type: 'csv', default: [] },
  { name: 'project', type: 'string' },
  { name: 'engagement', type: 'string' },
  { name: 'operator', type: 'string' },
  { name: 'confirm-active', type: 'bool', default: false },
  { name: 'auth-header', type: 'repeat', default: [] },
  { name: 'auth-cookie', type: 'string' },
  { name: 'timeout', type: 'int', default: 1800 },
  { name: 'no-auto-reports', type: 'bool', default: false },
  { name: 'engine', type: 'string' },
  { name: 'strategy', type: 'string' },
  { name: 'vigolium-modules', type: 'csv', default: [] },
  { name: 'vigolium-module-tag', type: 'repeat', default: [] },
  { name: 'vigolium-auth-file', type: 'repeat', default: [] },
  { name: 'vigolium-auth', type: 'repeat', default: [] },
  { name: 'vigolium-input-file', type: 'string' },
  { name: 'vigolium-input-type', type: 'string' },
  { name: 'vigolium-only', type: 'string' },
  { name: 'vigolium-html-report', type: 'bool', default: false },
  { name: 'vigolium-report-only', type: 'string' },
  { name: 'vigolium-prefer-path', type: 'bool', default: false },
  { name: 'vigolium-use-codex', type: 'bool', default: false },
  { name: 'vigolium-source', type: 'string' },
  { name: 'vigolium-agent', type: 'string' },
  { name: 'vigolium-audit-mode', type: 'string' },
];

export async function runCommand(argv) {
  let opts;
  try {
    ({ opts } = parseArgs(argv, SPEC));
  } catch (e) {
    process.stderr.write(`run: ${e.message}\n`);
    return 2;
  }

  if (opts.help) {
    printHelp();
    return 0;
  }

  const parsedTarget = parseReconTarget(opts.target);
  if (!parsedTarget.ok) {
    process.stderr.write(`run: ${parsedTarget.message || 'target invalido'}\n`);
    return 2;
  }
  opts.target = parsedTarget.target;

  const verbose = Boolean(opts.verbose);
  const quiet = Boolean(opts.quiet);
  const log = (...a) => { if (!quiet) process.stderr.write(`${a.join(' ')}\n`); };

  const client = new GhostClient({ server: opts.server });
  try {
    await client.ensureServer({ autoStart: opts['start-server'], quiet });
  } catch (e) {
    process.stderr.write(`${e.message}\n`);
    return 3;
  }

  // Merge modules com playbook se especificado.
  let modules = [...opts.modules];
  let playbookProfile = null;
  if (opts.playbook) {
    try {
      const pb = await resolvePlaybook(opts.playbook);
      modules = mergeUnique(modules, pb.modules || []);
      if (pb.profile && opts.profile === 'standard') opts.profile = pb.profile;
      playbookProfile = pb;
      log(`[playbook] ${pb.name} — ${pb.description || ''} (+${pb.modules?.length || 0} módulos)`);
    } catch (e) {
      process.stderr.write(`playbook: ${e.message}\n`);
      return 2;
    }
  }

  if (!modules.length) {
    process.stderr.write('run: indique --modules ou --playbook\n');
    return 2;
  }

  const rawOpsec = String(opts['opsec-profile'] || process.env.GHOSTRECON_OPSEC_PROFILE || 'standard')
    .trim()
    .toLowerCase();
  const allowedOpsec = new Set(['passive', 'stealth', 'standard', 'aggressive']);
  const opsecProfile = allowedOpsec.has(rawOpsec) ? rawOpsec : 'standard';

  const engagementId = opts.engagement != null ? String(opts.engagement).trim() : '';
  let engagement = null;
  if (engagementId) {
    try {
      engagement = await getEngagement(engagementId);
    } catch (e) {
      process.stderr.write(`engagement: ${e.message}\n`);
      return 2;
    }
    if (!engagement) {
      process.stderr.write(`engagement "${engagementId}" não encontrado\n`);
      return 4;
    }
  }

  const playbookNameForCheck = opts.playbook != null ? String(opts.playbook).trim() : '';
  const checklist = preRunChecklist({
    engagement,
    target: opts.target,
    modules,
    playbook: playbookNameForCheck || null,
  });
  if (!checklist.ok) {
    process.stderr.write(`run: pré-checklist falhou:\n${(checklist.errors || []).map((x) => `  - ${x}`).join('\n')}\n`);
    return 5;
  }
  for (const w of checklist.warnings || []) {
    log(`[engagement] ${w}`);
  }

  let gate;
  try {
    const modulesForOpsecGate = expandIntrusiveRunModules({
      modules,
      engine: opts.engine,
      vigoliumAgent: opts['vigolium-agent'],
      includeManualImplicit: true,
      includeManualIntrusive: Boolean(opts['confirm-active']),
      kaliMode: Boolean(opts.kali),
    });
    gate = gateModules({
      modules: modulesForOpsecGate,
      profile: opsecProfile,
      confirm: Boolean(opts['confirm-active']),
      engagement,
    });
  } catch (e) {
    process.stderr.write(`OPSEC: ${e.message}\n`);
    return 5;
  }
  if (!gate.ok) {
    process.stderr.write(
        `run: OPSEC — ${gate.reason || 'bloqueado'}\n` +
        `  perfil=${gate.profile} blocked=${(gate.blocked || []).join(', ') || '—'}\n` +
        '  (use --confirm-active nesta invocação, com engagement/ROE válido)\n',
    );
    return 5;
  }

  const headers = kvListToObject(opts['auth-header']);
  if (engagementId) {
    applyWatermarkHeaders(headers, {
      engagementId,
      operator: opts.operator != null ? String(opts.operator).trim() || undefined : undefined,
    });
  }
  const body = {
    domain: opts.target,
    modules,
    exactMatch: opts['exact-match'],
    kaliMode: opts.kali,
    profile: opts.profile,
    opsecProfile,
    outOfScope: opts['out-of-scope'].join(','),
    projectName: opts.project,
    autoAiReports: !opts['no-auto-reports'],
    engagementId: engagementId || undefined,
    operator: opts.operator != null ? String(opts.operator).trim() || undefined : undefined,
    confirmActive: Boolean(opts['confirm-active']),
    playbook: playbookNameForCheck || undefined,
    auth:
      Object.keys(headers).length || opts['auth-cookie']
        ? { headers, cookie: opts['auth-cookie'] || '' }
        : engagementId
          ? { headers, cookie: '' }
          : null,
  };
  if (opts.engine) body.engine = String(opts.engine).trim().toLowerCase();
  if (opts.strategy) body.vigoliumStrategy = String(opts.strategy).trim().toLowerCase();
  if (opts['vigolium-modules']?.length) body.vigoliumModules = opts['vigolium-modules'];
  if (opts['vigolium-module-tag']?.length) body.vigoliumModuleTags = opts['vigolium-module-tag'].map(String);
  if (opts['vigolium-auth-file']?.length) body.vigoliumAuthFiles = opts['vigolium-auth-file'].map(String);
  if (opts['vigolium-auth']?.length) body.vigoliumAuthEntries = opts['vigolium-auth'].map(String);
  if (opts['vigolium-input-file']) body.vigoliumInputFile = String(opts['vigolium-input-file']).trim();
  if (opts['vigolium-input-type']) body.vigoliumInputType = String(opts['vigolium-input-type']).trim();
  if (opts['vigolium-only']) body.vigoliumOnly = String(opts['vigolium-only']).trim();
  if (opts['vigolium-html-report']) body.vigoliumHtmlReport = true;
  if (opts['vigolium-report-only']) body.vigoliumReportOnly = String(opts['vigolium-report-only']).trim();
  if (opts['vigolium-prefer-path']) body.vigoliumPreferPath = true;
  if (opts['vigolium-use-codex']) body.vigoliumUseCodex = true;
  if (opts['vigolium-source']) body.vigoliumSource = String(opts['vigolium-source']).trim();
  if (opts['vigolium-agent']) body.vigoliumAgent = String(opts['vigolium-agent']).trim().toLowerCase();
  if (opts['vigolium-audit-mode']) body.vigoliumAuditMode = String(opts['vigolium-audit-mode']).trim().toLowerCase();

  if (Array.isArray(gate.acknowledged) && gate.acknowledged.length > 0) {
    try {
      // O preflight recebe o mesmo contexto privado que será enviado ao stream.
      // O servidor retorna somente o plano público e conserva apenas o binding
      // efêmero desse contexto; valores de autenticação nunca são exibidos aqui.
      const preflight = await client.postJson('/api/recon/preflight', body);
      if (!preflight?.requiresApproval || !preflight?.approval?.approvalId || !preflight?.plan?.hash) {
        throw new Error('servidor não emitiu uma aprovação vinculada ao plano intrusivo');
      }
      const confirmation = await requestPlanSpecificApproval(preflight.plan);
      if (!confirmation.approved) {
        throw new Error(confirmation.reason);
      }
      const decision = await client.postJson('/api/recon/approval', {
        approvalId: preflight.approval.approvalId,
        planHash: preflight.plan.hash,
        approved: true,
      });
      if (decision?.approval?.status !== 'approved') {
        throw new Error('servidor não confirmou a aprovação do plano');
      }
      body.manualApproval = {
        approvalId: preflight.approval.approvalId,
        planHash: preflight.plan.hash,
      };
    } catch (error) {
      process.stderr.write(`run: aprovação do plano falhou: ${error?.message || error}\n`);
      return 5;
    }
  }

  log(`[run] target=${opts.target} modules=${modules.length} profile=${opts.profile}`);
  const collected = { events: [], runId: null, finalStats: null, errors: [] };

  const onEvent = (evt) => {
    collected.events.push(evt);
    if (evt?.type === 'run-saved' || evt?.type === 'run_saved' || evt?.runId) {
      if (evt.runId) collected.runId = evt.runId;
    }
    if (evt?.type === 'stats' && evt.stats) collected.finalStats = evt.stats;
    if (evt?.type === 'error') collected.errors.push(evt.message);

    if (opts.format === 'ndjson') {
      process.stdout.write(`${JSON.stringify(evt)}\n`);
    } else if (verbose) {
      const t = evt?.type || 'event';
      const m = evt?.message || evt?.line || '';
      process.stderr.write(`  · ${t} ${typeof m === 'string' ? m.slice(0, 140) : ''}\n`);
    }
  };

  let result;
  try {
    result = await client.streamRecon(body, onEvent, { timeoutMs: Math.max(60_000, opts.timeout * 1000) });
  } catch (e) {
    process.stderr.write(`stream falhou: ${e.message}\n`);
    return 4;
  }

  log(`[run] stream fechado — ${result.lines} linhas em ${(result.elapsedMs / 1000).toFixed(1)}s`);

  // Extrai runId do final (fallback: último evento com runId ou consulta API)
  let runId = collected.runId;
  if (!runId) {
    const last = result.lastEvent;
    runId = last?.runId || null;
  }
  if (!runId) {
    try {
      const runs = await client.listRuns();
      const mine = (runs || []).find((r) => String(r.target || '').toLowerCase() === String(opts.target).toLowerCase());
      if (mine) runId = mine.id;
    } catch { /* ignore */ }
  }

  // Puxa o run completo para serialização final.
  let fullRun = null;
  if (runId) {
    try {
      fullRun = await client.getRun(runId);
    } catch (e) {
      log(`[run] aviso: falha ao carregar run ${runId}: ${e.message}`);
    }
  }

  const output = {
    version: 1,
    target: opts.target,
    runId,
    playbook: playbookProfile ? { name: playbookProfile.name, modules: playbookProfile.modules } : null,
    modules,
    profile: opts.profile,
    stats: collected.finalStats,
    elapsedMs: result.elapsedMs,
    eventCount: collected.events.length,
    errors: collected.errors,
    run: fullRun,
  };

  if (opts.format === 'summary') {
    writeSummary(output, process.stdout);
  } else if (opts.output) {
    const target = path.resolve(process.cwd(), opts.output);
    await fs.writeFile(target, JSON.stringify(output, null, 2), 'utf8');
    log(`[run] saída gravada: ${target}`);
  } else if (opts.format === 'json') {
    process.stdout.write(`${JSON.stringify(output, null, 2)}\n`);
  }

  return collected.errors.length ? 1 : 0;
}

function safeTerminalText(value, maxLength = 240) {
  return String(value ?? '')
    .replace(/[\u0000-\u001f\u007f-\u009f]/g, ' ')
    .trim()
    .slice(0, maxLength);
}

function safePlanModuleList(value) {
  return (Array.isArray(value) ? value : [])
    .map((item) => safeTerminalText(item, 80))
    .filter(Boolean)
    .slice(0, 128);
}

export function formatPlanSpecificApproval(plan = {}) {
  const target = safeTerminalText(plan?.target || '(alvo ausente)');
  const hash = safeTerminalText(plan?.hash, 64).toLowerCase();
  const intrusiveModules = safePlanModuleList(plan?.intrusiveModules);
  const frameSeven = plan?.engines?.frameseven?.enabled === true
    ? `FrameSeven:${safeTerminalText(plan.engines.frameseven.profile || 'habilitado', 40)}`
    : null;
  const vigolium = plan?.engines?.vigolium?.enabled === true
    ? `Vigolium:${safeTerminalText(plan.engines.vigolium.agent || 'habilitado', 40)}`
    : null;
  const engines = [frameSeven, vigolium].filter(Boolean);
  return [
    '',
    'Plano intrusivo aguardando confirmação humana:',
    `  alvo: ${target}`,
    `  hash: ${hash || '(ausente)'}`,
    `  módulos intrusivos: ${intrusiveModules.join(', ') || '(nenhum declarado)'}`,
    `  motores: ${engines.join(', ') || '(nenhum adicional)'}`,
    '  credenciais e contexto autenticado foram omitidos desta exibição.',
  ].join('\n');
}

export async function requestPlanSpecificApproval(plan, {
  input = process.stdin,
  output = process.stderr,
  ask = null,
} = {}) {
  const hash = String(plan?.hash || '').trim().toLowerCase();
  if (!/^[a-f0-9]{64}$/.test(hash)) {
    return { approved: false, reason: 'plano intrusivo retornou hash inválido' };
  }
  if (input?.isTTY !== true || output?.isTTY !== true) {
    return {
      approved: false,
      reason:
        'plano intrusivo requer confirmação plan-specific em terminal interativo; '
        + 'use o cockpit/API de aprovação ou execute novamente em um TTY',
    };
  }

  const prefix = hash.slice(0, 12);
  output.write(`${formatPlanSpecificApproval(plan)}\n`);
  let readline = null;
  try {
    const question = ask || ((prompt) => {
      readline = createInterface({ input, output, terminal: true });
      return readline.question(prompt);
    });
    const answer = String(await question(
      `Digite os 12 primeiros caracteres do hash (${prefix}) para aprovar: `,
    ) || '').trim().toLowerCase();
    if (answer !== prefix) {
      return {
        approved: false,
        reason: 'confirmação plan-specific recusada ou não corresponde ao hash',
      };
    }
    return { approved: true, prefix };
  } finally {
    readline?.close();
  }
}

function mergeUnique(a, b) {
  const seen = new Set();
  const out = [];
  for (const item of [...(a || []), ...(b || [])]) {
    const key = String(item).trim();
    if (!key || seen.has(key)) continue;
    seen.add(key);
    out.push(key);
  }
  return out;
}

function writeSummary(out, stream) {
  const stats = out.stats || {};
  stream.write(`GHOSTRECON run #${out.runId ?? '—'} — ${out.target}\n`);
  stream.write(`  módulos: ${out.modules.join(', ')}\n`);
  if (out.playbook) stream.write(`  playbook: ${out.playbook.name}\n`);
  stream.write(
    `  high=${stats.high ?? 0} subs=${stats.subs ?? 0} endpoints=${stats.endpoints ?? 0} ` +
      `params=${stats.params ?? 0} secrets=${stats.secrets ?? 0}\n`,
  );
  stream.write(`  elapsed=${(out.elapsedMs / 1000).toFixed(1)}s eventos=${out.eventCount}\n`);
  if (out.errors?.length) stream.write(`  erros: ${out.errors.length}\n`);
}

function printHelp() {
  process.stdout.write(`ghostrecon run — executa o pipeline.

Obrigatório:
  --target DOMAIN
  --modules CSV | --playbook NAME

Opções principais:
  --profile standard|stealth|aggressive   Default: standard.
  --output FILE                           Grava JSON agregado final.
  --format json|ndjson|summary            Default: json.
  --exact-match                           Sub apenas do alvo.
  --kali                                  Ativa módulos Kali.
  --out-of-scope CSV                      Padrões fora de escopo.
  --auth-header K=V                       Repetível.
  --auth-cookie STRING
  --project NAME
  --engagement ID                         Opcional — ROE/escopo (store local).
  --operator NAME                         Registo no engagement + team trail.
  --opsec-profile passive|stealth|standard|aggressive   Gate de módulos intrusivos (default: standard).
  --confirm-active                        Habilita gate intrusivo; o plano ainda exige confirmação do hash em TTY.
  --timeout SEC                           Default: 1800.
  --server URL                            Default: http://127.0.0.1:3847
  --start-server                          Auto-spawn do server.
  --engine MODE                           node | go | both.
  --strategy NAME                         lite | balanced | deep.
  --vigolium-modules CSV                  Filtro -m do Vigolium.
  --vigolium-module-tag TAG               Filtro --module-tag do Vigolium (repetivel).
  --vigolium-auth-file FILE               YAML/JSON de sessao Vigolium (repetivel).
  --vigolium-auth ROLE:KIND:VALUE         Auth inline do Vigolium (repetivel), ex.: admin:Cookie:sid=abc.
  --vigolium-input-file FILE              Entrada -T (ex.: openapi.yaml).
  --vigolium-input-type TYPE              Entrada -I (ex.: openapi).
  --vigolium-only NAME                    Passa --only para o scan JSONL.
  --vigolium-html-report                  Gera report HTML Vigolium em .runtime/vigolium-reports.
  --vigolium-report-only NAME             --only do report HTML (default: discovery).
  --vigolium-prefer-path                  Prefere vigolium do PATH antes do fallback local.
  --vigolium-use-codex                    Usa provider Codex/OAuth para agent IA (requer plano/login).
  --vigolium-source PATH                  Caminho do repo para audit/swarm.
  --vigolium-agent MODE                   query | audit | swarm | autopilot.
  --vigolium-audit-mode MODE              lite | balanced | deep.
  --verbose / --quiet
`);
}
