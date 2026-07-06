import { randomBytes } from 'node:crypto';
import { detectAutoProviders } from './provider-detector.mjs';
import { buildAutoToolCatalog } from './tool-catalog.mjs';
import { createAutoPlan, evaluateAutoRun } from './planner.mjs';
import { expandIntrusiveRunModules, gateModules } from '../modules/opsec.mjs';

function sendSafe(emit, obj) {
  try { emit(obj); } catch { /* ignore */ }
}

export function normalizeAutoRequest(body = {}) {
  const commanders = Array.isArray(body.commanders)
    ? body.commanders
    : Array.isArray(body.providers)
      ? body.providers
      : typeof body.commander === 'string'
        ? [body.commander]
        : [];
  return {
    target: body.domain || body.target || '',
    mode: body.autoMode || body.mode || 'balanced',
    commanders,
    modules: Array.isArray(body.modules) ? body.modules.map(String) : [],
    openrouterModel:
      body.openrouterModel != null
        ? String(body.openrouterModel).trim()
        : body.model != null
          ? String(body.model).trim()
          : null,
    includeHexstrike: body.includeHexstrike !== false,
    includeDeepPassive: body.includeDeepPassive,
  };
}

export async function runAutoRecon({
  body = {},
  runPipeline,
  emit = () => {},
  ROOT,
  env = process.env,
  fetchImpl = globalThis.fetch,
  execFileImpl,
  pipelineOverrides = {},
} = {}) {
  if (typeof runPipeline !== 'function') {
    throw new Error('runPipeline ausente para Modo Auto');
  }
  const req = normalizeAutoRequest(body);
  const events = [];
  const requestRunId = `auto-${Date.now().toString(36)}-${randomBytes(4).toString('hex')}`;
  const captureEmit = (event) => {
    events.push(event);
    sendSafe(emit, event);
  };

  captureEmit({ type: 'auto_meta', requestRunId, mode: req.mode, commanders: req.commanders });
  const providers = await detectAutoProviders({ selected: req.commanders, env, fetchImpl, execFileImpl });
  captureEmit({ type: 'auto_providers', ...providers });

  const catalog = await buildAutoToolCatalog({
    includeHexstrike: req.includeHexstrike,
    includeDeepPassive: req.includeDeepPassive !== false,
    ghostRoot: ROOT,
  });
  captureEmit({
    type: 'auto_catalog',
    modules: catalog.modules.map((m) => ({ id: m.id, source: m.source, class: m.class, available: m.available !== false })),
    hexstrike: catalog.hexstrike ? {
      installed: Boolean(catalog.hexstrike.installed),
      reachable: Boolean(catalog.hexstrike.reachable),
      baseUrl: catalog.hexstrike.baseUrl || null,
    } : null,
  });

  const plan = createAutoPlan({
    target: req.target,
    mode: req.mode,
    requestedModules: req.modules,
    providers: providers.providers,
    catalog,
    openrouterModel: req.openrouterModel,
    includeHexstrike: req.includeHexstrike,
    includeDeepPassive: req.includeDeepPassive,
  });
  captureEmit({ type: 'auto_plan', plan });

  const pipelineBody = {
    ...body,
    domain: req.target,
    modules: plan.modules,
    profile: body.profile || (plan.mode === 'quick' ? 'quick' : 'standard'),
    opsecProfile: body.opsecProfile || 'standard',
    autoAiReports: body.autoAiReports === true,
    ...pipelineOverrides,
  };
  const gate = gateModules({
    modules: expandIntrusiveRunModules({
      modules: pipelineBody.modules,
      engine: pipelineBody.engine,
      vigoliumAgent: pipelineBody.vigoliumAgent,
    }),
    profile: pipelineBody.opsecProfile,
    confirm: pipelineBody.confirmActive === true || String(env.GHOSTRECON_CONFIRM_ACTIVE || '').trim() === '1',
  });
  if (!gate.ok) {
    captureEmit({ type: 'auto_step', step: 'opsec', status: 'blocked', opsec: gate });
    throw new Error(`Modo Auto bloqueado por OPSEC: ${gate.reason || gate.blocked?.join(', ')}`);
  }

  captureEmit({ type: 'auto_step', step: 'act', status: 'running', modules: plan.modules });
  await runPipeline({
    ...pipelineBody,
    emit: captureEmit,
  });
  captureEmit({ type: 'auto_step', step: 'act', status: 'done' });

  const evaluation = evaluateAutoRun({ events, plan });
  captureEmit({ type: 'auto_evaluation', evaluation });
  return { requestRunId, plan, evaluation, events };
}
