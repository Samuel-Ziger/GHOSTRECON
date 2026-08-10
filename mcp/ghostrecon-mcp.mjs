#!/usr/bin/env node
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { GhostClient } from '../server/modules/cli/client.mjs';
import {
  listAutoRagMarkdown,
  readAutoRagMarkdown,
  searchAutoRagMarkdown,
  writeAutoLesson,
  writeAutoRagNote,
  loadAutoRagContext,
} from '../server/auto-agent/rag-memory.mjs';
import {
  AUTO_AUTONOMY_POLICIES,
  buildEffectiveAutoPlan,
  effectivePlanApprovalDetails,
} from '../server/auto-agent/effective-plan.mjs';
import { expandIntrusiveRunModules, gateModules } from '../server/modules/opsec.mjs';

const SERVER_NAME = 'ghostrecon';
const SERVER_VERSION = '0.1.0';
const DEFAULT_PROTOCOL_VERSION = '2024-11-05';
const MAX_TEXT_CHARS = Number(process.env.GHOSTRECON_MCP_MAX_TEXT_CHARS || 120_000);
const __dirname = path.dirname(fileURLToPath(import.meta.url));
const ROOT = path.resolve(__dirname, '..');

function jsonText(value) {
  const raw = JSON.stringify(value, null, 2);
  return raw.length > MAX_TEXT_CHARS
    ? `${raw.slice(0, MAX_TEXT_CHARS)}\n... truncated by GHOSTRECON_MCP_MAX_TEXT_CHARS ...`
    : raw;
}

function toolResult(value) {
  return {
    content: [
      {
        type: 'text',
        text: typeof value === 'string' ? value : jsonText(value),
      },
    ],
  };
}

function publicRagMemory(item) {
  if (!item || typeof item !== 'object') return item;
  const {
    path: _localPath,
    filePath: _filePath,
    baseDir: _baseDir,
    dir: _dir,
    ...safe
  } = item;
  return safe;
}

function errorResult(message, extra = {}) {
  return {
    isError: true,
    content: [
      {
        type: 'text',
        text: jsonText({ ok: false, error: String(message || 'erro'), ...extra }),
      },
    ],
  };
}

function makeClient() {
  return new GhostClient({
    server: process.env.GHOSTRECON_URL || process.env.GHOSTRECON_SERVER || 'http://127.0.0.1:3847',
    timeoutMs: Number(process.env.GHOSTRECON_MCP_HTTP_TIMEOUT_MS || 30_000),
  });
}

async function ensureReady(client) {
  const autoStart = /^(1|true|yes|on)$/i.test(String(process.env.GHOSTRECON_MCP_AUTOSTART || '').trim());
  return client.ensureServer({ autoStart, quiet: true });
}

function cleanArray(value) {
  return Array.isArray(value)
    ? value.map((x) => String(x).trim()).filter(Boolean)
    : String(value || '')
      .split(',')
      .map((x) => x.trim())
      .filter(Boolean);
}

export function normalizeAutoMcpOptions(args = {}) {
  const requestedAutonomy = String(args.autonomyLevel || '').trim().toLowerCase();
  const autonomyLevel = Object.hasOwn(AUTO_AUTONOMY_POLICIES, requestedAutonomy)
    ? requestedAutonomy
    : 'observation';
  const includeFrameSeven = args.includeFrameSeven === true;
  const includeVigolium = args.includeVigolium === true;

  if (args.frameSevenAuth === true && !includeFrameSeven) {
    throw new Error('FrameSeven autenticado exige includeFrameSeven=true');
  }
  if (args.vigoliumUseCodex === true && !includeVigolium) {
    throw new Error('Vigolium com Codex exige includeVigolium=true');
  }
  if (includeFrameSeven && autonomyLevel === 'observation') {
    throw new Error('FrameSeven envia requests ao alvo e exige autonomia assistida ou superior');
  }
  if (args.frameSevenAuth === true && !['authorized', 'authorized_opsec'].includes(autonomyLevel)) {
    throw new Error('FrameSeven autenticado exige autonomia autorizada e recon.intrusive');
  }
  if (includeVigolium && !['authorized', 'authorized_opsec'].includes(autonomyLevel)) {
    throw new Error('Vigolium DAST exige autonomia autorizada e recon.intrusive');
  }

  const body = {
    domain: String(args.target || '').trim(),
    mode: String(args.mode || 'balanced').trim().toLowerCase(),
    commanders: cleanArray(args.commanders),
    modules: cleanArray(args.modules),
    includeHexstrike: args.includeHexstrike === true,
    includeDeepPassive: args.includeDeepPassive !== false,
    autonomyLevel,
    includeFrameSeven,
    frameSevenAuth: includeFrameSeven && args.frameSevenAuth === true,
    includeVigolium,
    vigoliumUseCodex: includeVigolium && args.vigoliumUseCodex === true,
    // MCP stdio não possui hoje um canal bidirecional de aprovação ligado à
    // mesma chamada. O backend deve negar qualquer popup em vez de aguardar
    // até o timeout ou interpretar uma confirmação antecipada como consentimento
    // para um plano que ainda não existe.
    approvalMode: 'deny',
  };
  if (args.openrouterModel) body.openrouterModel = String(args.openrouterModel).trim();
  if (args.engagementId) body.engagementId = String(args.engagementId).trim();
  return body;
}

export function autoAutonomyToOpsecProfile(autonomyLevel) {
  const normalized = String(autonomyLevel || '').trim().toLowerCase();
  return AUTO_AUTONOMY_POLICIES[normalized]?.opsecProfile
    || AUTO_AUTONOMY_POLICIES.observation.opsecProfile;
}

async function loadAutoPlanningModules() {
  const [
    providerDetector,
    toolCatalog,
    planner,
  ] = await Promise.all([
    import('../server/auto-agent/provider-detector.mjs'),
    import('../server/auto-agent/tool-catalog.mjs'),
    import('../server/auto-agent/planner.mjs'),
  ]);
  return {
    detectAutoProviders: providerDetector.detectAutoProviders,
    buildAutoToolCatalog: toolCatalog.buildAutoToolCatalog,
    createAutoPlan: planner.createAutoPlan,
  };
}

async function loadHexstrikeModules() {
  const [capabilities, orchestrator] = await Promise.all([
    import('../server/modules/hexstrike-capabilities.mjs'),
    import('../server/modules/hexstrike-orchestrator.mjs'),
  ]);
  return {
    getHexstrikeCapabilities: capabilities.getHexstrikeCapabilities,
    runHexstrikeOrchestrator: orchestrator.runHexstrikeOrchestrator,
  };
}

async function resolveRequestedModules(client, args = {}) {
  const modules = cleanArray(args.modules);
  let playbook = null;
  if (args.playbook) {
    const body = await client.getJson(`/api/playbooks/${encodeURIComponent(String(args.playbook))}`, {
      timeoutMs: 10_000,
      auth: true,
    });
    playbook = body.playbook || null;
    for (const m of playbook?.modules || []) modules.push(String(m));
  }
  return {
    playbook,
    modules: [...new Set(modules.map((m) => String(m).trim()).filter(Boolean))],
  };
}

function evaluateMcpOpsec({
  modules = [],
  opsecProfile = 'standard',
  confirmActive = false,
  includeManualImplicit = false,
  kaliMode = false,
} = {}) {
  return gateModules({
    modules: expandIntrusiveRunModules({
      modules,
      includeManualImplicit,
      includeManualIntrusive: Boolean(confirmActive),
      kaliMode: Boolean(kaliMode),
    }),
    profile: opsecProfile,
    confirm: Boolean(confirmActive),
  });
}

async function buildReconPlan(client, args = {}) {
  const target = String(args.target || '').trim();
  if (!target) throw new Error('target vazio');
  const requestedProfile = String(args.profile || 'standard').trim().toLowerCase();
  const profile = ['quick', 'standard', 'deep'].includes(requestedProfile)
    ? requestedProfile
    : 'standard';
  const requestedOpsecProfile = String(args.opsecProfile || 'standard').trim().toLowerCase();
  const opsecProfile = ['passive', 'stealth', 'standard', 'aggressive'].includes(requestedOpsecProfile)
    ? requestedOpsecProfile
    : 'standard';
  const { playbook, modules } = await resolveRequestedModules(client, args);
  const cap = await client.capabilities();
  const manifestById = new Map((Array.isArray(cap.modules) ? cap.modules : []).map((m) => [m.id, m]));
  const modulePlan = modules.map((id) => {
    const manifest = manifestById.get(id) || null;
    return {
      id,
      known: Boolean(manifest),
      category: manifest?.category || null,
      intrusive: Boolean(manifest?.intrusive),
      requiresKali: Boolean(manifest?.requiresKali),
      source: id === 'hexstrike_orchestrator' ? 'hexstrike' : 'ghostrecon',
    };
  });
  const opsec = evaluateMcpOpsec({
    modules,
    opsecProfile,
    confirmActive: args.confirmActive === true,
    includeManualImplicit: true,
    kaliMode: false,
  });
  return {
    ok: opsec.ok,
    target,
    profile,
    opsecProfile,
    playbook: playbook ? {
      name: playbook.name,
      description: playbook.description || '',
      modules: playbook.modules || [],
    } : null,
    modules,
    modulePlan,
    opsec,
    execution: {
      endpoint: '/api/recon/stream',
      willRun: opsec.ok && args.dryRun !== true,
      requiresConfirmation: !opsec.ok,
      confirmActive: args.confirmActive === true,
    },
  };
}

function safeManualApprovalIdentity(identity) {
  if (!identity || typeof identity !== 'object') return null;
  const sha256 = String(identity.sha256 || '').trim().toLowerCase();
  return {
    algorithm: String(identity.algorithm || 'sha256').trim().toLowerCase(),
    sha256: /^[a-f0-9]{64}$/.test(sha256) ? sha256 : null,
    size: Number.isFinite(Number(identity.size)) ? Number(identity.size) : null,
  };
}

function safeManualApprovalEngine(engine = {}, {
  kind,
} = {}) {
  const source = engine && typeof engine === 'object' ? engine : {};
  if (kind === 'frameseven') {
    return {
      enabled: source.enabled === true,
      authenticated: source.authenticated === true,
      profile: source.profile ? String(source.profile) : null,
      tools: cleanArray(source.tools),
      timeoutMs: Number.isFinite(Number(source.timeoutMs)) ? Number(source.timeoutMs) : null,
      toolTimeoutMs: Number.isFinite(Number(source.toolTimeoutMs)) ? Number(source.toolTimeoutMs) : null,
      concurrency: Number.isFinite(Number(source.concurrency)) ? Number(source.concurrency) : null,
      rate: Number.isFinite(Number(source.rate)) ? Number(source.rate) : null,
      identity: safeManualApprovalIdentity(source.identity),
    };
  }
  return {
    enabled: source.enabled === true,
    agent: source.agent ? String(source.agent) : null,
    strategy: source.strategy ? String(source.strategy) : null,
    useCodex: source.useCodex === true,
    modules: cleanArray(source.modules),
    moduleTags: cleanArray(source.moduleTags),
    auditMode: source.auditMode ? String(source.auditMode) : null,
    only: source.only ? String(source.only) : null,
    reportOnly: source.reportOnly ? String(source.reportOnly) : null,
    htmlReport: source.htmlReport === true,
    identity: safeManualApprovalIdentity(source.identity),
  };
}

export function safeManualApprovalPlan(plan = {}) {
  const source = plan && typeof plan === 'object' ? plan : {};
  const execution = source.execution && typeof source.execution === 'object'
    ? source.execution
    : {};
  const authentication = source.authentication && typeof source.authentication === 'object'
    ? source.authentication
    : {};
  return {
    schemaVersion: Number(source.schemaVersion || 1),
    kind: String(source.kind || 'ghostrecon.manual-recon.plan'),
    target: String(source.target || ''),
    engagement: {
      id: source.engagement?.id ? String(source.engagement.id) : null,
      authorizationBinding: source.engagement?.authorizationBinding
        ? String(source.engagement.authorizationBinding)
        : null,
    },
    selectedModules: cleanArray(source.selectedModules),
    expandedModules: cleanArray(source.expandedModules),
    intrusiveModules: cleanArray(source.intrusiveModules),
    execution: {
      exactMatch: execution.exactMatch === true,
      kaliMode: execution.kaliMode === true,
      profile: String(execution.profile || 'standard'),
      opsecProfile: String(execution.opsecProfile || 'standard'),
      engine: String(execution.engine || 'node'),
      playbook: execution.playbook ? String(execution.playbook) : null,
      fullPreset: execution.fullPreset === true,
      navigatorMode: execution.navigatorMode === true,
      navigatorExec: execution.navigatorExec === true,
      navigatorUserMode: execution.navigatorUserMode === true,
      torRequired: execution.torRequired === true,
      torStrict: execution.torStrict === true,
      identityEnabled: execution.identityEnabled === true,
      outOfScope: cleanArray(execution.outOfScope),
    },
    authentication: {
      pipeline: {
        enabled: authentication.pipeline?.enabled === true,
        hasCookie: authentication.pipeline?.hasCookie === true,
        hasAuthorization: authentication.pipeline?.hasAuthorization === true,
        headerCount: Number(authentication.pipeline?.headerCount || 0),
      },
      vigolium: {
        enabled: authentication.vigolium?.enabled === true,
        sharesPipelineContext: authentication.vigolium?.sharesPipelineContext === true,
        inlineEntryCount: Number(authentication.vigolium?.inlineEntryCount || 0),
        authFileCount: Number(authentication.vigolium?.authFileCount || 0),
      },
    },
    engines: {
      frameseven: safeManualApprovalEngine(source.engines?.frameseven, {
        kind: 'frameseven',
      }),
      vigolium: safeManualApprovalEngine(source.engines?.vigolium, {
        kind: 'vigolium',
      }),
    },
    hash: String(source.hash || ''),
    requiresHumanApproval: source.requiresHumanApproval === true,
  };
}

function summarizeStreamEvents(events, result) {
  const findings = events.filter((e) => e?.type === 'finding' && e.finding).map((e) => e.finding);
  const errors = events.filter((e) => e?.type === 'error');
  const warnings = events.filter((e) => e?.type === 'log' && e.level === 'warn');
  const done = [...events].reverse().find((e) => e?.type === 'done') || null;
  const autoPlan = [...events].reverse().find((e) => e?.type === 'auto_plan')?.plan || null;
  const autoEvaluation = [...events].reverse().find((e) => e?.type === 'auto_evaluation')?.evaluation || null;
  const approvalRequired = [...events].reverse().find((e) => e?.type === 'auto_approval_required') || null;
  const approvalDenied = [...events].reverse().find((e) => (
    e?.type === 'auto_approval_denied' || e?.type === 'auto_approval_auto_denied'
  )) || null;
  return {
    ok: errors.length === 0,
    lines: result?.lines || 0,
    elapsedMs: result?.elapsedMs || 0,
    findingsTotal: findings.length,
    findings,
    warnings: warnings.map((e) => e.msg || e.message).filter(Boolean).slice(0, 30),
    errors: errors.map((e) => e.message || e.msg || 'erro').slice(0, 30),
    runId: done?.runId ?? null,
    storage: done?.storage ?? null,
    target: done?.target ?? null,
    autoPlan,
    autoEvaluation,
    approvalRequired: approvalRequired?.approval || null,
    approvalDenied: Boolean(approvalDenied),
  };
}

const resources = [
  {
    uri: 'ghostrecon://capabilities',
    name: 'GHOSTRECON capabilities',
    description: 'Snapshot resumido das capacidades locais do GHOSTRECON.',
    mimeType: 'application/json',
  },
  {
    uri: 'ghostrecon://playbooks',
    name: 'GHOSTRECON playbooks',
    description: 'Lista de playbooks disponiveis.',
    mimeType: 'application/json',
  },
  {
    uri: 'ghostrecon://runs/latest',
    name: 'Latest GHOSTRECON runs',
    description: 'Runs recentes do GHOSTRECON.',
    mimeType: 'application/json',
  },
  {
    uri: 'ghostrecon://auto-rag/index',
    name: 'Auto Mode RAG index',
    description: 'Indice das memorias Markdown geradas pelo Modo Auto.',
    mimeType: 'application/json',
  },
];

const prompts = [
  {
    name: 'ghostrecon-plan-recon',
    description: 'Planeja um recon autorizado antes de executar qualquer tool.',
    arguments: [
      { name: 'target', description: 'Dominio, URL ou IP autorizado.', required: true },
      { name: 'objective', description: 'Objetivo do recon.', required: false },
    ],
  },
  {
    name: 'ghostrecon-triage-findings',
    description: 'Prioriza findings por impacto, evidencia, OWASP e proximo passo.',
    arguments: [
      { name: 'runId', description: 'ID da run a analisar.', required: false },
      { name: 'target', description: 'Target quando nao houver runId.', required: false },
    ],
  },
  {
    name: 'ghostrecon-report-draft',
    description: 'Gera rascunho de reporte tecnico a partir de findings validados.',
    arguments: [
      { name: 'runId', description: 'ID da run.', required: true },
      { name: 'style', description: 'hackerone, bugcrowd, internal.', required: false },
    ],
  },
  {
    name: 'ghostrecon-auto-gap-analysis',
    description: 'Analisa lacunas do Modo Auto usando a RAG Markdown.',
    arguments: [
      { name: 'target', description: 'Target analisado.', required: false },
    ],
  },
];

const tools = [
  {
    name: 'ghostrecon_health',
    description: 'Verifica se a API local do GHOSTRECON esta online.',
    inputSchema: { type: 'object', properties: {}, additionalProperties: false },
  },
  {
    name: 'ghostrecon_capabilities',
    description: 'Lista capacidades locais: ferramentas, IA, HexStrike, Vigolium, modulos e integracoes.',
    inputSchema: {
      type: 'object',
      properties: {
        raw: { type: 'boolean', description: 'Se true, retorna o payload completo.' },
      },
      additionalProperties: false,
    },
  },
  {
    name: 'ghostrecon_list_modules',
    description: 'Lista modulos registrados pelo GHOSTRECON com categoria e flags de OPSEC.',
    inputSchema: { type: 'object', properties: {}, additionalProperties: false },
  },
  {
    name: 'ghostrecon_list_playbooks',
    description: 'Lista playbooks disponiveis no GHOSTRECON.',
    inputSchema: { type: 'object', properties: {}, additionalProperties: false },
  },
  {
    name: 'ghostrecon_plan_recon',
    description: 'Monta um plano dry-run para recon: resolve playbook/modulos e retorna gates OPSEC antes de executar.',
    inputSchema: {
      type: 'object',
      properties: {
        target: { type: 'string' },
        playbook: { type: 'string' },
        profile: { type: 'string', enum: ['quick', 'standard', 'deep'], default: 'standard' },
        opsecProfile: {
          type: 'string',
          enum: ['passive', 'stealth', 'standard', 'aggressive'],
          default: 'standard',
        },
        modules: { type: 'array', items: { type: 'string' } },
        confirmActive: { type: 'boolean', default: false },
      },
      required: ['target'],
      additionalProperties: false,
    },
  },
  {
    name: 'ghostrecon_run_recon',
    description:
      'Executa recon normal via /api/recon/stream. Planos intrusivos retornam '
      + 'approval_required e só continuam após aprovação separada pela UI/API.',
    inputSchema: {
      type: 'object',
      properties: {
        target: { type: 'string', description: 'Dominio, URL ou IP autorizado.' },
        playbook: { type: 'string', description: 'Nome do playbook, ex.: api-first ou quick-triage.' },
        profile: { type: 'string', enum: ['quick', 'standard', 'deep'], default: 'standard' },
        opsecProfile: {
          type: 'string',
          enum: ['passive', 'stealth', 'standard', 'aggressive'],
          default: 'standard',
          description: 'Perfil OPSEC independente do perfil de execução.',
        },
        modules: { type: 'array', items: { type: 'string' }, description: 'Modulos explicitos. Se omitido, use playbook.' },
        exactMatch: { type: 'boolean', default: false },
        timeoutMs: { type: 'integer', default: 1800000 },
        findingsLimit: { type: 'integer', default: 80 },
        confirmActive: { type: 'boolean', default: false },
        engagementId: { type: 'string' },
        manualApprovalId: {
          type: 'string',
          description: 'ID emitido pelo preflight e aprovado separadamente pela UI/API.',
        },
        manualApprovalHash: {
          type: 'string',
          description: 'Hash exato do plano aprovado separadamente pela UI/API.',
        },
      },
      required: ['target'],
      additionalProperties: false,
    },
  },
  {
    name: 'ghostrecon_run_auto',
    description: 'Executa Modo Auto não interativo. Se o plano exigir confirmação humana, nenhuma ação é executada e a tool devolve os detalhes para aprovação pela UI ou ghostrecon_auto_approve/deny.',
    inputSchema: {
      type: 'object',
      properties: {
        target: { type: 'string' },
        commanders: {
          type: 'array',
          items: { type: 'string', enum: ['codex', 'claude_code', 'cursor', 'openrouter', 'skynet', 'local_model'] },
        },
        mode: { type: 'string', enum: ['quick', 'balanced', 'deep'], default: 'balanced' },
        openrouterModel: { type: 'string' },
        modules: { type: 'array', items: { type: 'string' }, description: 'Modulos AUTO explicitamente solicitados.' },
        autonomyLevel: {
          type: 'string',
          enum: ['observation', 'assisted', 'authorized', 'authorized_opsec'],
          default: 'observation',
          description: 'Politica de selecao AUTO; nao substitui autorizacao, RBAC, engagement ou aprovacao humana.',
        },
        includeHexstrike: { type: 'boolean', default: false },
        includeDeepPassive: { type: 'boolean', default: true },
        includeVigolium: { type: 'boolean', default: false },
        vigoliumUseCodex: { type: 'boolean', default: false },
        includeFrameSeven: { type: 'boolean', default: false },
        frameSevenAuth: { type: 'boolean', default: false },
        confirmActive: {
          type: 'boolean',
          default: false,
          description: 'Compatibilidade: não aprova antecipadamente um plano Auto ainda desconhecido.',
        },
        engagementId: { type: 'string' },
        timeoutMs: { type: 'integer', default: 1800000 },
        findingsLimit: { type: 'integer', default: 80 },
      },
      required: ['target'],
      additionalProperties: false,
    },
  },
  {
    name: 'ghostrecon_auto_approve',
    description: 'Aprova um plano Auto pendente (sessionId + approvalId). Default do run_auto continua deny/não-interativo.',
    inputSchema: {
      type: 'object',
      properties: {
        sessionId: { type: 'string' },
        approvalId: { type: 'string' },
        reason: { type: 'string', default: 'mcp_approved' },
      },
      required: ['sessionId', 'approvalId'],
      additionalProperties: false,
    },
  },
  {
    name: 'ghostrecon_auto_deny',
    description: 'Nega um plano Auto pendente (sessionId + approvalId).',
    inputSchema: {
      type: 'object',
      properties: {
        sessionId: { type: 'string' },
        approvalId: { type: 'string' },
        reason: { type: 'string', default: 'mcp_denied' },
      },
      required: ['sessionId', 'approvalId'],
      additionalProperties: false,
    },
  },
  {
    name: 'ghostrecon_plan_auto',
    description: 'Monta uma prévia determinística e seu plano efetivo expandido, sem executar conselho, pipeline ou aprovação humana.',
    inputSchema: {
      type: 'object',
      properties: {
        target: { type: 'string' },
        commanders: {
          type: 'array',
          items: { type: 'string', enum: ['codex', 'claude_code', 'cursor', 'openrouter', 'skynet', 'local_model'] },
        },
        mode: { type: 'string', enum: ['quick', 'balanced', 'deep'], default: 'balanced' },
        openrouterModel: { type: 'string' },
        autonomyLevel: {
          type: 'string',
          enum: ['observation', 'assisted', 'authorized', 'authorized_opsec'],
          default: 'observation',
          description: 'Politica de selecao usada para filtrar o catalogo e calcular OPSEC.',
        },
        includeHexstrike: { type: 'boolean', default: false },
        includeDeepPassive: { type: 'boolean', default: true },
        includeVigolium: { type: 'boolean', default: false },
        vigoliumUseCodex: { type: 'boolean', default: false },
        includeFrameSeven: { type: 'boolean', default: false },
        frameSevenAuth: { type: 'boolean', default: false },
        modules: { type: 'array', items: { type: 'string' } },
        engagementId: { type: 'string' },
      },
      required: ['target'],
      additionalProperties: false,
    },
  },
  {
    name: 'ghostrecon_list_runs',
    description: 'Lista runs recentes do GHOSTRECON.',
    inputSchema: {
      type: 'object',
      properties: {
        limit: { type: 'integer', default: 20, minimum: 1, maximum: 100 },
      },
      additionalProperties: false,
    },
  },
  {
    name: 'ghostrecon_get_run',
    description: 'Busca uma run completa pelo ID.',
    inputSchema: {
      type: 'object',
      properties: {
        id: { type: ['string', 'integer'] },
      },
      required: ['id'],
      additionalProperties: false,
    },
  },
  {
    name: 'ghostrecon_diff_runs',
    description: 'Compara duas runs: newerId contra baselineId.',
    inputSchema: {
      type: 'object',
      properties: {
        newerId: { type: ['string', 'integer'] },
        baselineId: { type: ['string', 'integer'] },
      },
      required: ['newerId', 'baselineId'],
      additionalProperties: false,
    },
  },
  {
    name: 'ghostrecon_get_intel',
    description: 'Busca corpus de inteligencia deduplicado por target.',
    inputSchema: {
      type: 'object',
      properties: {
        target: { type: 'string' },
      },
      required: ['target'],
      additionalProperties: false,
    },
  },
  {
    name: 'ghostrecon_hexstrike_status',
    description: 'Retorna status da instalacao/HTTP/MCP do HexStrike detectado pelo GHOSTRECON.',
    inputSchema: { type: 'object', properties: {}, additionalProperties: false },
  },
  {
    name: 'ghostrecon_hexstrike_intel',
    description: 'Chama apenas endpoints de inteligencia permitidos do HexStrike e normaliza findings informacionais.',
    inputSchema: {
      type: 'object',
      properties: {
        target: { type: 'string' },
        objective: { type: 'string', default: 'comprehensive' },
      },
      required: ['target'],
      additionalProperties: false,
    },
  },
  {
    name: 'ghostrecon_auto_rag_list',
    description: 'Lista memorias Markdown recentes do Modo Auto para RAG/Obsidian.',
    inputSchema: {
      type: 'object',
      properties: {
        limit: { type: 'integer', default: 20 },
      },
      additionalProperties: false,
    },
  },
  {
    name: 'ghostrecon_auto_rag_read',
    description: 'Le uma memoria Markdown especifica do Modo Auto.',
    inputSchema: {
      type: 'object',
      properties: {
        name: { type: 'string' },
      },
      required: ['name'],
      additionalProperties: false,
    },
  },
  {
    name: 'ghostrecon_auto_rag_search',
    description: 'Busca memorias Markdown do Modo Auto por termos, retornando previews curtos para reduzir contexto.',
    inputSchema: {
      type: 'object',
      properties: {
        query: { type: 'string' },
        limit: { type: 'integer', default: 8 },
      },
      required: ['query'],
      additionalProperties: false,
    },
  },
  {
    name: 'ghostrecon_auto_rag_write_note',
    description: 'Cria uma nota Markdown local no vault Auto RAG para contexto humano ou de IA.',
    inputSchema: {
      type: 'object',
      properties: {
        title: { type: 'string' },
        body: { type: 'string' },
        target: { type: 'string' },
        tags: { type: 'array', items: { type: 'string' } },
        metadata: { type: 'object' },
      },
      required: ['title', 'body'],
      additionalProperties: false,
    },
  },
  {
    name: 'ghostrecon_auto_rag_write_lesson',
    description: 'Registra uma licao aprendida estruturada para o Modo Auto reutilizar em runs futuras.',
    inputSchema: {
      type: 'object',
      properties: {
        target: { type: 'string' },
        problem: { type: 'string' },
        decision: { type: 'string' },
        outcome: { type: 'string' },
        modules: { type: 'array', items: { type: 'string' } },
        commanders: { type: 'object' },
        confidence: { type: 'string' },
        tags: { type: 'array', items: { type: 'string' } },
        metadata: { type: 'object' },
      },
      required: ['problem', 'decision'],
      additionalProperties: false,
    },
  },
];

async function readResource(uri) {
  const client = makeClient();
  const rawUri = String(uri || '').trim();
  if (!rawUri) throw new Error('resource uri vazio');

  if (rawUri === 'ghostrecon://auto-rag/index') {
    const context = await loadAutoRagContext({ root: ROOT, limit: 40 });
    const { dir: _localPath, ...publicContext } = context || {};
    return {
      contents: [{
        uri: rawUri,
        mimeType: 'application/json',
        text: jsonText({ vault: 'auto-rag', ...publicContext }),
      }],
    };
  }
  if (rawUri.startsWith('ghostrecon://auto-rag/')) {
    const name = decodeURIComponent(rawUri.slice('ghostrecon://auto-rag/'.length));
    const item = await readAutoRagMarkdown(name, { root: ROOT });
    return {
      contents: [{ uri: rawUri, mimeType: 'text/markdown', text: item.text }],
    };
  }

  await ensureReady(client);
  if (rawUri === 'ghostrecon://capabilities') {
    return {
      contents: [{ uri: rawUri, mimeType: 'application/json', text: jsonText(await client.capabilities()) }],
    };
  }
  if (rawUri === 'ghostrecon://playbooks') {
    return {
      contents: [{ uri: rawUri, mimeType: 'application/json', text: jsonText(await client.listPlaybooks()) }],
    };
  }
  if (rawUri === 'ghostrecon://runs/latest') {
    return {
      contents: [{ uri: rawUri, mimeType: 'application/json', text: jsonText(await client.listRuns({ limit: 20 })) }],
    };
  }
  if (rawUri.startsWith('ghostrecon://runs/')) {
    const id = rawUri.slice('ghostrecon://runs/'.length).replace(/\/summary$/, '');
    return {
      contents: [{ uri: rawUri, mimeType: 'application/json', text: jsonText(await client.getRun(id)) }],
    };
  }
  if (rawUri.startsWith('ghostrecon://intel/')) {
    const target = decodeURIComponent(rawUri.slice('ghostrecon://intel/'.length));
    return {
      contents: [{ uri: rawUri, mimeType: 'application/json', text: jsonText(await client.getIntel(target)) }],
    };
  }
  throw new Error(`resource desconhecido: ${rawUri}`);
}

function promptText(name, args = {}) {
  if (name === 'ghostrecon-plan-recon') {
    return [
      'Voce e um operador GHOSTRECON em ambiente autorizado.',
      `Target: ${args.target || '(definir)'}`,
      `Objetivo: ${args.objective || 'recon seguro e priorizacao de achados'}`,
      '',
      'Antes de executar qualquer scan, use ghostrecon_plan_recon.',
      'Se o plano indicar OPSEC bloqueado ou modulo intrusivo, nao chame ghostrecon_run_recon sem confirmacao explicita.',
      'Prefira playbooks e modulos passivos quando a autorizacao nao estiver clara.',
    ].join('\n');
  }
  if (name === 'ghostrecon-triage-findings') {
    return [
      'Analise findings do GHOSTRECON e priorize por impacto real.',
      `Run ID: ${args.runId || '(usar latest/intel se ausente)'}`,
      `Target: ${args.target || '(opcional)'}`,
      '',
      'Para cada achado importante, retorne: severidade, evidencia, impacto, probabilidade de falso positivo, OWASP/MITRE quando houver, e proximo passo seguro.',
    ].join('\n');
  }
  if (name === 'ghostrecon-report-draft') {
    return [
      'Gere um rascunho de reporte tecnico a partir de uma run GHOSTRECON.',
      `Run ID: ${args.runId || '(obrigatorio)'}`,
      `Estilo: ${args.style || 'hackerone'}`,
      '',
      'Estrutura: titulo, resumo, impacto, passos de reproducao, evidencia, mitigacao, escopo e observacoes de seguranca.',
      'Nao invente prova. Se faltar evidencia, marque como pendente.',
    ].join('\n');
  }
  if (name === 'ghostrecon-auto-gap-analysis') {
    return [
      'Analise a RAG Markdown do Modo Auto para encontrar padroes, falhas recorrentes e lacunas de modulos.',
      `Target: ${args.target || '(opcional)'}`,
      '',
      'Use ghostrecon_auto_rag_list ou resource ghostrecon://auto-rag/index.',
      'Saida esperada: lacunas, modulo sugerido, risco OPSEC, dados necessarios e criterio de teste.',
    ].join('\n');
  }
  throw new Error(`prompt desconhecido: ${name}`);
}

function getPrompt(name, args = {}) {
  return {
    description: prompts.find((p) => p.name === name)?.description || name,
    messages: [
      {
        role: 'user',
        content: {
          type: 'text',
          text: promptText(name, args),
        },
      },
    ],
  };
}

export async function callTool(name, args = {}, {
  client = makeClient(),
  planningModulesLoader = loadAutoPlanningModules,
  ragContextLoader = loadAutoRagContext,
} = {}) {

  if (name === 'ghostrecon_auto_rag_list') {
    return toolResult({
      ok: true,
      vault: 'auto-rag',
      memories: (await listAutoRagMarkdown({ root: ROOT, limit: args.limit || 20 }))
        .map(publicRagMemory),
    });
  }

  if (name === 'ghostrecon_auto_rag_read') {
    return toolResult(publicRagMemory(await readAutoRagMarkdown(args.name, { root: ROOT })));
  }

  if (name === 'ghostrecon_auto_rag_search') {
    return toolResult({
      ok: true,
      vault: 'auto-rag',
      query: String(args.query || ''),
      memories: (await searchAutoRagMarkdown({
        root: ROOT,
        query: args.query,
        limit: args.limit || 8,
      })).map(publicRagMemory),
    });
  }

  if (name === 'ghostrecon_auto_rag_write_note') {
    return toolResult({
      ok: true,
      note: publicRagMemory(await writeAutoRagNote({
        root: ROOT,
        kind: 'note',
        title: args.title,
        body: args.body,
        target: args.target || '',
        tags: cleanArray(args.tags),
        metadata: args.metadata || null,
      })),
    });
  }

  if (name === 'ghostrecon_auto_rag_write_lesson') {
    return toolResult({
      ok: true,
      lesson: publicRagMemory(await writeAutoLesson({
        root: ROOT,
        target: args.target || '',
        problem: args.problem,
        decision: args.decision,
        outcome: args.outcome || '',
        modules: cleanArray(args.modules),
        commanders: args.commanders || null,
        confidence: args.confidence || '',
        tags: cleanArray(args.tags),
        metadata: args.metadata || null,
      })),
    });
  }

  await ensureReady(client);

  if (name === 'ghostrecon_health') {
    return toolResult(await client.health());
  }

  if (name === 'ghostrecon_capabilities') {
    const cap = await client.capabilities();
    if (args.raw) return toolResult(cap);
    return toolResult({
      ok: true,
      kali: Boolean(cap.kali),
      ai: cap.ai || null,
      github: cap.github || null,
      modules: Array.isArray(cap.modules) ? cap.modules.length : 0,
      externalTools: Array.isArray(cap.externalTools) ? cap.externalTools.length : 0,
      hexstrike: cap.hexstrike || null,
      vigolium: cap.vigolium || null,
      shannon: cap.shannon || null,
      pentestgpt: cap.pentestgpt || null,
    });
  }

  if (name === 'ghostrecon_list_modules') {
    const cap = await client.capabilities();
    return toolResult({ ok: true, modules: Array.isArray(cap.modules) ? cap.modules : [] });
  }

  if (name === 'ghostrecon_list_playbooks') {
    return toolResult({ ok: true, playbooks: await client.listPlaybooks() });
  }

  if (name === 'ghostrecon_plan_recon') {
    return toolResult(await buildReconPlan(client, { ...args, dryRun: true }));
  }

  if (name === 'ghostrecon_run_recon') {
    const target = String(args.target || '').trim();
    if (!target) return errorResult('target vazio');
    const manualApprovalId = String(args.manualApprovalId || '').trim();
    const manualApprovalHash = String(args.manualApprovalHash || '').trim();
    if (Boolean(manualApprovalId) !== Boolean(manualApprovalHash)) {
      return errorResult(
        'manualApprovalId e manualApprovalHash devem ser informados juntos após aprovação separada pela UI/API.',
      );
    }
    const plan = await buildReconPlan(client, args);
    if (!plan.opsec?.ok) {
      return errorResult('OPSEC bloqueou execucao via MCP. Revise o plano e envie confirmActive=true apenas se houver autorizacao.', { plan });
    }
    const body = {
      domain: target,
      profile: plan.profile,
      opsecProfile: plan.opsecProfile,
      exactMatch: Boolean(args.exactMatch),
      modules: plan.modules,
    };
    if (args.playbook) body.playbook = String(args.playbook);
    if (args.confirmActive === true) body.confirmActive = true;
    if (args.engagementId) body.engagementId = String(args.engagementId);
    if (manualApprovalId && manualApprovalHash) {
      body.manualApproval = {
        approvalId: manualApprovalId,
        planHash: manualApprovalHash,
      };
    } else if (args.confirmActive === true) {
      try {
        const preflight = await client.postJson('/api/recon/preflight', body);
        if (preflight?.requiresApproval) {
          const approvalId = String(preflight.approval?.approvalId || '').trim();
          const planHash = String(preflight.plan?.hash || '').trim();
          if (!approvalId || !planHash) {
            return errorResult('Servidor não emitiu identificadores válidos para aprovação vinculada.');
          }
          return toolResult({
            ok: false,
            status: 'approval_required',
            approvalRequired: true,
            plan: safeManualApprovalPlan(preflight.plan),
            approval: {
              approvalId,
              planHash,
              expiresAt: preflight.approval?.expiresAt || null,
            },
            nextAction:
              'Aprove este approvalId/hash separadamente pela UI/API com o mesmo principal e chame '
              + 'ghostrecon_run_recon novamente com manualApprovalId/manualApprovalHash.',
          });
        }
      } catch (error) {
        return errorResult('Falha no preflight vinculado do RUN manual.', {
          error: error?.message || String(error),
        });
      }
    }
    const events = [];
    const result = await client.streamRecon(body, (event) => events.push(event), {
      timeoutMs: Math.max(60_000, Number(args.timeoutMs || 1_800_000)),
    });
    const summary = summarizeStreamEvents(events, result);
    const limit = Math.max(1, Math.min(500, Number(args.findingsLimit || 80)));
    summary.findings = summary.findings.slice(0, limit);
    summary.findingsReturned = summary.findings.length;
    return toolResult(summary);
  }

  if (name === 'ghostrecon_run_auto') {
    const body = normalizeAutoMcpOptions(args);
    if (!body.domain) return errorResult('target vazio');
    const events = [];
    const result = await client.streamAutoRecon(body, (event) => events.push(event), {
      timeoutMs: Math.max(60_000, Number(args.timeoutMs || 1_800_000)),
    });
    const summary = summarizeStreamEvents(events, result);
    const limit = Math.max(1, Math.min(500, Number(args.findingsLimit || 80)));
    summary.findings = summary.findings.slice(0, limit);
    summary.findingsReturned = summary.findings.length;
    if (summary.approvalRequired) {
      return errorResult(
        'O plano Auto exige aprovação humana. Nada foi executado; use ghostrecon_auto_approve/deny ou a UI com sessionId+approvalId.',
        {
          approvalRequired: summary.approvalRequired,
          preconfirmationAccepted: false,
          summary,
        },
      );
    }
    return toolResult(summary);
  }

  if (name === 'ghostrecon_auto_approve' || name === 'ghostrecon_auto_deny') {
    const sessionId = String(args.sessionId || '').trim();
    const approvalId = String(args.approvalId || '').trim();
    if (!sessionId || !approvalId) return errorResult('sessionId e approvalId são obrigatórios');
    try {
      const response = await client.resolveAutoApproval(sessionId, {
        approvalId,
        approved: name === 'ghostrecon_auto_approve',
        reason: String(args.reason || (name === 'ghostrecon_auto_approve' ? 'mcp_approved' : 'mcp_denied')),
      });
      return toolResult({
        ok: true,
        approved: name === 'ghostrecon_auto_approve',
        sessionId,
        approvalId,
        response,
      });
    } catch (error) {
      return errorResult(error?.message || String(error), { sessionId, approvalId });
    }
  }

  if (name === 'ghostrecon_plan_auto') {
    const autoRequest = normalizeAutoMcpOptions(args);
    if (!autoRequest.domain) return errorResult('target vazio');
    const { detectAutoProviders, buildAutoToolCatalog, createAutoPlan } = await planningModulesLoader();
    const providers = await detectAutoProviders({ selected: autoRequest.commanders });
    const ragContext = await ragContextLoader({ root: ROOT, limit: 6 });
    const catalog = await buildAutoToolCatalog({
      includeHexstrike: autoRequest.includeHexstrike,
      includeDeepPassive: autoRequest.includeDeepPassive,
      includeIntrusive: ['authorized', 'authorized_opsec'].includes(autoRequest.autonomyLevel),
      includeFrameSeven: autoRequest.includeFrameSeven,
      frameSevenAuth: autoRequest.frameSevenAuth,
      includeVigolium: autoRequest.includeVigolium,
      ghostRoot: ROOT,
    });
    const requestedModules = [
      ...autoRequest.modules,
      ...(autoRequest.includeFrameSeven
        ? [autoRequest.frameSevenAuth ? 'frameseven_authenticated' : 'frameseven_recon']
        : []),
      ...(autoRequest.includeVigolium ? ['vigolium_dast'] : []),
    ];
    const plan = createAutoPlan({
      target: autoRequest.domain,
      mode: autoRequest.mode,
      requestedModules: [...new Set(requestedModules)],
      providers: providers.providers,
      catalog,
      openrouterModel: autoRequest.openrouterModel || null,
      includeHexstrike: autoRequest.includeHexstrike,
      includeDeepPassive: autoRequest.includeDeepPassive,
      ragContext,
      autonomyLevel: autoRequest.autonomyLevel,
    });
    plan.autonomyLevel = autoRequest.autonomyLevel;
    plan.policy = {
      ...(plan.policy || {}),
      opsecProfile: autoAutonomyToOpsecProfile(autoRequest.autonomyLevel),
    };
    const effectivePlan = buildEffectiveAutoPlan({
      plan,
      catalog,
      body: {
        domain: autoRequest.domain,
        mode: autoRequest.mode,
        engagementId: autoRequest.engagementId,
        includeHexstrike: autoRequest.includeHexstrike,
        includeFrameSeven: autoRequest.includeFrameSeven,
        frameSevenAuth: autoRequest.frameSevenAuth,
        includeVigolium: autoRequest.includeVigolium,
        vigoliumUseCodex: autoRequest.vigoliumUseCodex,
        opsecProfile: autoAutonomyToOpsecProfile(autoRequest.autonomyLevel),
      },
      autonomyLevel: autoRequest.autonomyLevel,
      frameSevenAvailable: Boolean(catalog.engines?.frameseven?.available),
      forceFrameSevenRecon: false,
    });
    const opsec = evaluateMcpOpsec({
      modules: effectivePlan.expandedModules,
      opsecProfile: effectivePlan.opsecProfile,
    });
    return toolResult({
      ok: true,
      previewOnly: true,
      exactRuntimePlan: false,
      runtimeMayDifferAfterCouncil: true,
      executableWithoutInteractiveApproval: opsec.ok && !effectivePlan.requiresHumanApproval,
      target: autoRequest.domain,
      providers,
      catalog: {
        modules: catalog.modules.map((m) => ({
          id: m.id,
          source: m.source,
          class: m.class,
          available: m.available !== false,
        })),
        hexstrike: catalog.hexstrike ? {
          installed: Boolean(catalog.hexstrike.installed),
          reachable: Boolean(catalog.hexstrike.reachable),
          baseUrl: catalog.hexstrike.baseUrl || null,
        } : null,
      },
      opsec,
      plan,
      effectivePlan,
      approval: effectivePlan.requiresHumanApproval
        ? effectivePlanApprovalDetails(effectivePlan)
        : null,
      limitations: [
        'A prévia usa a baseline determinística; o conselho de IA só decide dentro de uma sessão real.',
        'Engagement, escopo, RBAC e aprovação final continuam sendo validados pelo backend antes da execução.',
      ],
    });
  }

  if (name === 'ghostrecon_list_runs') {
    const limit = Math.max(1, Math.min(100, Number(args.limit || 20)));
    return toolResult({ ok: true, runs: await client.listRuns({ limit }) });
  }

  if (name === 'ghostrecon_get_run') {
    return toolResult(await client.getRun(args.id));
  }

  if (name === 'ghostrecon_diff_runs') {
    return toolResult(await client.diffRuns(args.baselineId, args.newerId));
  }

  if (name === 'ghostrecon_get_intel') {
    return toolResult(await client.getIntel(args.target));
  }

  if (name === 'ghostrecon_hexstrike_status') {
    const { getHexstrikeCapabilities } = await loadHexstrikeModules();
    return toolResult(await getHexstrikeCapabilities({ ghostRoot: ROOT }));
  }

  if (name === 'ghostrecon_hexstrike_intel') {
    const target = String(args.target || '').trim();
    if (!target) return errorResult('target vazio');
    const { runHexstrikeOrchestrator } = await loadHexstrikeModules();
    return toolResult(await runHexstrikeOrchestrator({
      target,
      objective: args.objective || 'comprehensive',
    }));
  }

  return errorResult(`tool desconhecida: ${name}`);
}

function writeMessage(message) {
  // MCP stdio exige JSON-RPC delimitado por newline no stdout (nao Content-Length).
  process.stdout.write(`${JSON.stringify(message)}\n`);
}

export async function handleRequest(message, { write = writeMessage } = {}) {
  const { id, method, params = {} } = message || {};
  if (id == null) return;
  try {
    if (method === 'initialize') {
      write({
        jsonrpc: '2.0',
        id,
        result: {
          protocolVersion: params.protocolVersion || DEFAULT_PROTOCOL_VERSION,
          capabilities: {
            tools: {},
            resources: {},
            prompts: {},
          },
          serverInfo: {
            name: SERVER_NAME,
            version: SERVER_VERSION,
          },
        },
      });
      return;
    }
    if (method === 'ping') {
      write({ jsonrpc: '2.0', id, result: {} });
      return;
    }
    if (method === 'tools/list') {
      write({ jsonrpc: '2.0', id, result: { tools } });
      return;
    }
    if (method === 'tools/call') {
      const result = await callTool(params.name, params.arguments || {});
      write({ jsonrpc: '2.0', id, result });
      return;
    }
    if (method === 'resources/list') {
      const rag = await listAutoRagMarkdown({ root: ROOT, limit: 20 }).catch(() => []);
      const ragResources = rag.map((item) => ({
        uri: `ghostrecon://auto-rag/${encodeURIComponent(item.name)}`,
        name: item.title || item.name,
        description: `Auto Mode memory: ${item.name}`,
        mimeType: 'text/markdown',
      }));
      write({ jsonrpc: '2.0', id, result: { resources: [...resources, ...ragResources] } });
      return;
    }
    if (method === 'resources/read') {
      write({ jsonrpc: '2.0', id, result: await readResource(params.uri) });
      return;
    }
    if (method === 'prompts/list') {
      write({ jsonrpc: '2.0', id, result: { prompts } });
      return;
    }
    if (method === 'prompts/get') {
      write({ jsonrpc: '2.0', id, result: getPrompt(params.name, params.arguments || {}) });
      return;
    }
    write({
      jsonrpc: '2.0',
      id,
      error: { code: -32601, message: `Metodo nao suportado: ${method}` },
    });
  } catch (e) {
    write({
      jsonrpc: '2.0',
      id,
      error: { code: -32000, message: e?.message || String(e) },
    });
  }
}

export function createFrameParser(onMessage) {
  let buffer = Buffer.alloc(0);
  return (chunk) => {
    buffer = Buffer.concat([buffer, chunk]);
    while (buffer.length) {
      const headerEnd = buffer.indexOf('\r\n\r\n');
      if (headerEnd >= 0) {
        const header = buffer.slice(0, headerEnd).toString('utf8');
        const match = /content-length:\s*(\d+)/i.exec(header);
        if (!match) {
          buffer = buffer.slice(headerEnd + 4);
          continue;
        }
        const length = Number(match[1]);
        const start = headerEnd + 4;
        const end = start + length;
        if (buffer.length < end) return;
        const raw = buffer.slice(start, end).toString('utf8');
        buffer = buffer.slice(end);
        try { onMessage(JSON.parse(raw)); } catch (e) { console.error(`[ghostrecon-mcp] JSON parse: ${e.message}`); }
        continue;
      }

      const newline = buffer.indexOf('\n');
      if (newline < 0) return;
      const raw = buffer.slice(0, newline).toString('utf8').trim();
      buffer = buffer.slice(newline + 1);
      if (!raw) continue;
      try { onMessage(JSON.parse(raw)); } catch (e) { console.error(`[ghostrecon-mcp] JSON line parse: ${e.message}`); }
    }
  };
}

const isMain = process.argv[1]
  && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url);

if (isMain) {
  const feed = createFrameParser((message) => {
    void handleRequest(message);
  });
  process.stdin.on('data', feed);
  process.stdin.on('error', (e) => {
    console.error(`[ghostrecon-mcp] stdin error: ${e?.message || e}`);
  });
}
