#!/usr/bin/env node
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { GhostClient } from '../server/modules/cli/client.mjs';
import { detectAutoProviders } from '../server/auto-agent/provider-detector.mjs';
import { buildAutoToolCatalog } from '../server/auto-agent/tool-catalog.mjs';
import { createAutoPlan } from '../server/auto-agent/planner.mjs';
import {
  listAutoRagMarkdown,
  readAutoRagMarkdown,
  loadAutoRagContext,
  resolveAutoRagDir,
} from '../server/auto-agent/rag-memory.mjs';
import { getHexstrikeCapabilities } from '../server/modules/hexstrike-capabilities.mjs';
import { runHexstrikeOrchestrator } from '../server/modules/hexstrike-orchestrator.mjs';
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

function evaluateMcpOpsec({ modules = [], profile = 'standard', confirmActive = false } = {}) {
  return gateModules({
    modules: expandIntrusiveRunModules({ modules }),
    profile,
    confirm: Boolean(confirmActive),
  });
}

async function buildReconPlan(client, args = {}) {
  const target = String(args.target || '').trim();
  if (!target) throw new Error('target vazio');
  const profile = String(args.profile || 'standard').trim().toLowerCase();
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
    profile,
    confirmActive: args.confirmActive === true,
  });
  return {
    ok: opsec.ok,
    target,
    profile,
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

function summarizeStreamEvents(events, result) {
  const findings = events.filter((e) => e?.type === 'finding' && e.finding).map((e) => e.finding);
  const errors = events.filter((e) => e?.type === 'error');
  const warnings = events.filter((e) => e?.type === 'log' && e.level === 'warn');
  const done = [...events].reverse().find((e) => e?.type === 'done') || null;
  const autoPlan = [...events].reverse().find((e) => e?.type === 'auto_plan')?.plan || null;
  const autoEvaluation = [...events].reverse().find((e) => e?.type === 'auto_evaluation')?.evaluation || null;
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
        modules: { type: 'array', items: { type: 'string' } },
        confirmActive: { type: 'boolean', default: false },
      },
      required: ['target'],
      additionalProperties: false,
    },
  },
  {
    name: 'ghostrecon_run_recon',
    description: 'Executa recon normal via /api/recon/stream e retorna resumo + findings.',
    inputSchema: {
      type: 'object',
      properties: {
        target: { type: 'string', description: 'Dominio, URL ou IP autorizado.' },
        playbook: { type: 'string', description: 'Nome do playbook, ex.: api-first ou quick-triage.' },
        profile: { type: 'string', enum: ['quick', 'standard', 'deep'], default: 'standard' },
        modules: { type: 'array', items: { type: 'string' }, description: 'Modulos explicitos. Se omitido, use playbook.' },
        exactMatch: { type: 'boolean', default: false },
        timeoutMs: { type: 'integer', default: 1800000 },
        findingsLimit: { type: 'integer', default: 80 },
        confirmActive: { type: 'boolean', default: false },
        engagementId: { type: 'string' },
      },
      required: ['target'],
      additionalProperties: false,
    },
  },
  {
    name: 'ghostrecon_run_auto',
    description: 'Executa Modo Auto via /api/recon/auto/stream com comandantes selecionados.',
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
        includeHexstrike: { type: 'boolean', default: true },
        includeDeepPassive: { type: 'boolean', default: true },
        confirmActive: { type: 'boolean', default: false },
        timeoutMs: { type: 'integer', default: 1800000 },
        findingsLimit: { type: 'integer', default: 80 },
      },
      required: ['target'],
      additionalProperties: false,
    },
  },
  {
    name: 'ghostrecon_plan_auto',
    description: 'Monta um plano dry-run do Modo Auto com comandantes, catalogo, HexStrike e contexto RAG, sem executar o pipeline.',
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
        includeHexstrike: { type: 'boolean', default: true },
        includeDeepPassive: { type: 'boolean', default: true },
        modules: { type: 'array', items: { type: 'string' } },
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
];

async function readResource(uri) {
  const client = makeClient();
  const rawUri = String(uri || '').trim();
  if (!rawUri) throw new Error('resource uri vazio');

  if (rawUri === 'ghostrecon://auto-rag/index') {
    const context = await loadAutoRagContext({ root: ROOT, limit: 40 });
    return {
      contents: [{ uri: rawUri, mimeType: 'application/json', text: jsonText(context) }],
    };
  }
  if (rawUri.startsWith('ghostrecon://auto-rag/decisions/')) {
    const name = decodeURIComponent(rawUri.slice('ghostrecon://auto-rag/decisions/'.length));
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

async function callTool(name, args = {}) {
  const client = makeClient();
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
    const plan = await buildReconPlan(client, args);
    if (!plan.opsec?.ok) {
      return errorResult('OPSEC bloqueou execucao via MCP. Revise o plano e envie confirmActive=true apenas se houver autorizacao.', { plan });
    }
    const body = {
      domain: target,
      profile: args.profile || 'standard',
      exactMatch: Boolean(args.exactMatch),
      modules: plan.modules,
    };
    if (args.playbook) body.playbook = String(args.playbook);
    if (args.confirmActive === true) body.confirmActive = true;
    if (args.engagementId) body.engagementId = String(args.engagementId);
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
    const target = String(args.target || '').trim();
    if (!target) return errorResult('target vazio');
    const commanders = cleanArray(args.commanders);
    const body = {
      domain: target,
      mode: args.mode || 'balanced',
      commanders,
      includeHexstrike: args.includeHexstrike !== false,
      includeDeepPassive: args.includeDeepPassive !== false,
    };
    if (args.confirmActive === true) body.confirmActive = true;
    if (args.openrouterModel) body.openrouterModel = String(args.openrouterModel).trim();
    const events = [];
    const result = await client.streamAutoRecon(body, (event) => events.push(event), {
      timeoutMs: Math.max(60_000, Number(args.timeoutMs || 1_800_000)),
    });
    const summary = summarizeStreamEvents(events, result);
    const limit = Math.max(1, Math.min(500, Number(args.findingsLimit || 80)));
    summary.findings = summary.findings.slice(0, limit);
    summary.findingsReturned = summary.findings.length;
    return toolResult(summary);
  }

  if (name === 'ghostrecon_plan_auto') {
    const target = String(args.target || '').trim();
    if (!target) return errorResult('target vazio');
    const commanders = cleanArray(args.commanders);
    const providers = await detectAutoProviders({ selected: commanders });
    const ragContext = await loadAutoRagContext({ root: ROOT, limit: 6 });
    const catalog = await buildAutoToolCatalog({
      includeHexstrike: args.includeHexstrike !== false,
      includeDeepPassive: args.includeDeepPassive !== false,
      ghostRoot: ROOT,
    });
    const plan = createAutoPlan({
      target,
      mode: args.mode || 'balanced',
      requestedModules: cleanArray(args.modules),
      providers: providers.providers,
      catalog,
      openrouterModel: args.openrouterModel || null,
      includeHexstrike: args.includeHexstrike !== false,
      includeDeepPassive: args.includeDeepPassive !== false,
      ragContext,
    });
    const opsec = evaluateMcpOpsec({ modules: plan.modules, profile: plan.mode === 'quick' ? 'quick' : 'standard' });
    return toolResult({
      ok: opsec.ok,
      target,
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
    return toolResult(await getHexstrikeCapabilities({ ghostRoot: ROOT }));
  }

  if (name === 'ghostrecon_hexstrike_intel') {
    const target = String(args.target || '').trim();
    if (!target) return errorResult('target vazio');
    return toolResult(await runHexstrikeOrchestrator({
      target,
      objective: args.objective || 'comprehensive',
    }));
  }

  if (name === 'ghostrecon_auto_rag_list') {
    return toolResult({
      ok: true,
      dir: resolveAutoRagDir({ root: ROOT }),
      memories: await listAutoRagMarkdown({ root: ROOT, limit: args.limit || 20 }),
    });
  }

  if (name === 'ghostrecon_auto_rag_read') {
    return toolResult(await readAutoRagMarkdown(args.name, { root: ROOT }));
  }

  return errorResult(`tool desconhecida: ${name}`);
}

function writeMessage(message) {
  const json = JSON.stringify(message);
  const payload = Buffer.from(json, 'utf8');
  process.stdout.write(`Content-Length: ${payload.length}\r\n\r\n`);
  process.stdout.write(payload);
}

async function handleRequest(message) {
  const { id, method, params = {} } = message || {};
  if (id == null) return;
  try {
    if (method === 'initialize') {
      writeMessage({
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
      writeMessage({ jsonrpc: '2.0', id, result: {} });
      return;
    }
    if (method === 'tools/list') {
      writeMessage({ jsonrpc: '2.0', id, result: { tools } });
      return;
    }
    if (method === 'tools/call') {
      const result = await callTool(params.name, params.arguments || {});
      writeMessage({ jsonrpc: '2.0', id, result });
      return;
    }
    if (method === 'resources/list') {
      const rag = await listAutoRagMarkdown({ root: ROOT, limit: 20 }).catch(() => []);
      const ragResources = rag.map((item) => ({
        uri: `ghostrecon://auto-rag/decisions/${encodeURIComponent(item.name)}`,
        name: item.title || item.name,
        description: `Auto Mode memory: ${item.name}`,
        mimeType: 'text/markdown',
      }));
      writeMessage({ jsonrpc: '2.0', id, result: { resources: [...resources, ...ragResources] } });
      return;
    }
    if (method === 'resources/read') {
      writeMessage({ jsonrpc: '2.0', id, result: await readResource(params.uri) });
      return;
    }
    if (method === 'prompts/list') {
      writeMessage({ jsonrpc: '2.0', id, result: { prompts } });
      return;
    }
    if (method === 'prompts/get') {
      writeMessage({ jsonrpc: '2.0', id, result: getPrompt(params.name, params.arguments || {}) });
      return;
    }
    writeMessage({
      jsonrpc: '2.0',
      id,
      error: { code: -32601, message: `Metodo nao suportado: ${method}` },
    });
  } catch (e) {
    writeMessage({
      jsonrpc: '2.0',
      id,
      error: { code: -32000, message: e?.message || String(e) },
    });
  }
}

function createFrameParser(onMessage) {
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

const feed = createFrameParser((message) => {
  void handleRequest(message);
});

process.stdin.on('data', feed);
process.stdin.on('error', (e) => {
  console.error(`[ghostrecon-mcp] stdin error: ${e?.message || e}`);
});
