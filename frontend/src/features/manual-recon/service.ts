import {
  apiUrl,
  buildApiHeaders,
  requestCsrfToken,
  type OptionalAuthConfig,
} from '../../services/api-client';

export type ManualReconBody = Record<string, unknown> & {
  domain?: unknown;
  engagementId?: unknown;
  exactMatch?: unknown;
  outOfScope?: unknown;
  operator?: unknown;
};

export type ManualReconPlan = Record<string, any>;

export type ManualReconCallbacks = {
  onAuthorizationConsumed?: () => void;
  onPlanAuthorized?: (detail: {
    debugText: string;
    plan: ManualReconPlan;
    preflightBody: ManualReconBody;
  }) => void;
  onTemporaryAuthorization?: (engagementId: string) => void;
};

export type ManualReconOptions = ManualReconCallbacks & {
  authorizationBasis?: string;
  authorizationRequested?: boolean;
  signal?: AbortSignal;
};

export type ManualReconServiceDependencies = {
  apiBase: () => string;
  auth: () => OptionalAuthConfig | null;
  fetchImpl: typeof fetch;
};

function errorMessage(body: unknown, fallback: string): string {
  if (body && typeof body === 'object' && 'error' in body) {
    const value = (body as { error?: unknown }).error;
    if (value) return String(value);
  }
  return fallback;
}

function normalizeBasis(value: unknown): string {
  const normalized = String(value || 'explicit').trim().toLowerCase();
  return normalized || 'explicit';
}

function manualPlanDebugText(plan: ManualReconPlan, preflightBody: ManualReconBody): string {
  const frameSeven = plan.engines?.frameseven || {};
  const vigolium = plan.engines?.vigolium || {};
  const tools = Array.isArray(frameSeven.tools) && frameSeven.tools.length
    ? frameSeven.tools.join(', ')
    : '(não incluído)';
  const limits = frameSeven.enabled
    ? `FrameSeven: timeout=${frameSeven.timeoutMs}ms · tool-timeout=${frameSeven.toolTimeoutMs}ms · concorrência=${frameSeven.concurrency} · rate=${frameSeven.rate}`
    : 'FrameSeven: não incluído';
  const engines = [
    frameSeven.enabled ? `FrameSeven ${frameSeven.authenticated ? 'autenticado' : 'ofensivo'}` : null,
    vigolium.enabled ? `Vigolium ${vigolium.agent || 'sem agente'}` : null,
  ].filter(Boolean).join(', ') || 'pipeline GHOSTRECON';
  const binaryIdentities = [
    frameSeven.enabled && frameSeven.identity?.sha256
      ? `FrameSeven sha256=${String(frameSeven.identity.sha256).slice(0, 16)}…`
      : null,
    vigolium.enabled && vigolium.identity?.sha256
      ? `Vigolium sha256=${String(vigolium.identity.sha256).slice(0, 16)}…`
      : null,
  ].filter(Boolean).join(' · ') || '(nenhum binário externo)';
  const authSummary = plan.authentication || {};
  const pipelineAuth = authSummary.pipeline?.enabled
    ? `sim (cookie=${authSummary.pipeline.hasCookie ? 'sim' : 'não'}, authorization=${authSummary.pipeline.hasAuthorization ? 'sim' : 'não'}, headers=${authSummary.pipeline.headerCount || 0})`
    : 'não';
  const vigoliumAuth = authSummary.vigolium?.enabled
    ? `sim (compartilhado=${authSummary.vigolium.sharesPipelineContext ? 'sim' : 'não'}, inline=${authSummary.vigolium.inlineEntryCount || 0}, arquivos=${authSummary.vigolium.authFileCount || 0})`
    : 'não';
  const execution = plan.execution || {};
  const executionContext = [
    `navegador=${execution.navigatorMode ? (execution.navigatorExec ? 'execução autorizada' : 'somente contexto') : 'não'}`,
    `Tor=${execution.torRequired ? (execution.torStrict ? 'estrito' : 'obrigatório') : 'não'}`,
    `proxies=${execution.proxyCount || 0}${execution.proxyPoolBinding ? ' (selados)' : ''}`,
  ].join(' · ');

  return `\nAlvo: ${plan.target || preflightBody.domain}`
    + `\nEngagement: ${plan.engagement?.id || 'n/d'}`
    + `\nMódulos efetivos: ${(plan.expandedModules || []).join(', ') || '(nenhum)'}`
    + `\nMódulos intrusivos: ${(plan.intrusiveModules || []).join(', ') || '(nenhum)'}`
    + `\nMotores: ${engines}`
    + `\nFerramentas FrameSeven: ${tools}`
    + `\nLimites: ${limits}`
    + `\nIdentidades seladas: ${binaryIdentities}`
    + `\nAutenticação pipeline: ${pipelineAuth}`
    + `\nAutenticação Vigolium: ${vigoliumAuth}`
    + `\nContexto operacional: ${executionContext}`
    + `\nOPSEC: ${plan.execution?.opsecProfile || 'standard'}`
    + `\nHash do plano: ${plan.hash || 'n/d'}`
    + '\nPlano autorizado pela seleção explícita dos módulos no RUN manual (sem diálogo de confirmação — modo manual não bloqueia).';
}

export function createManualReconService(dependencies: ManualReconServiceDependencies) {
  const { apiBase, auth, fetchImpl } = dependencies;

  async function prepareApproval(
    inputBody: ManualReconBody,
    options: ManualReconOptions = {},
  ): Promise<{ approvedBody: ManualReconBody; preflight: Record<string, any> }> {
    const currentAuth = auth();
    const token = await requestCsrfToken({
      fetchImpl,
      base: apiBase(),
      auth: currentAuth,
      signal: options.signal,
    });
    const headers = buildApiHeaders({ auth: currentAuth, csrfToken: token, json: true });
    let preflightBody = { ...inputBody };

    if (!preflightBody.engagementId && options.authorizationRequested === true) {
      const response = await fetchImpl(apiUrl('/api/engagements/manual-authorization', apiBase()), {
        method: 'POST',
        headers,
        body: JSON.stringify({
          target: preflightBody.domain,
          authorizationConfirmed: true,
          basis: normalizeBasis(options.authorizationBasis),
          includeSubdomains: preflightBody.exactMatch !== true,
          exclusions: preflightBody.outOfScope || [],
          operator: preflightBody.operator || null,
        }),
        signal: options.signal,
      });
      const data = await response.json().catch(() => ({})) as Record<string, any>;
      if (!response.ok || !data?.ok || !data?.engagement?.id) {
        const permissionHint = response.status === 403
          ? ' Esta declaração exige sessão com papel red ou admin.'
          : '';
        throw new Error(`${errorMessage(data, `autorização manual HTTP ${response.status}`)}${permissionHint}`);
      }
      const engagementId = String(data.engagement.id);
      preflightBody = { ...preflightBody, engagementId };
      options.onTemporaryAuthorization?.(engagementId);
    }

    const preflightResponse = await fetchImpl(apiUrl('/api/recon/preflight', apiBase()), {
      method: 'POST',
      headers,
      body: JSON.stringify(preflightBody),
      signal: options.signal,
    });
    const preflight = await preflightResponse.json().catch(() => ({})) as Record<string, any>;
    if (!preflightResponse.ok || !preflight?.ok) {
      const checklistErrors = Array.isArray(preflight?.checklist?.errors)
        ? preflight.checklist.errors.filter(Boolean)
        : [];
      const detail = checklistErrors.length ? `: ${checklistErrors.join(' | ')}` : '';
      throw new Error(`${errorMessage(preflight, `preflight HTTP ${preflightResponse.status}`)}${detail}`);
    }
    if (options.authorizationRequested) options.onAuthorizationConsumed?.();
    if (!preflight.requiresApproval) return { approvedBody: preflightBody, preflight };

    const plan = (preflight.plan || {}) as ManualReconPlan;
    options.onPlanAuthorized?.({
      debugText: manualPlanDebugText(plan, preflightBody),
      plan,
      preflightBody,
    });
    const decisionResponse = await fetchImpl(apiUrl('/api/recon/approval', apiBase()), {
      method: 'POST',
      headers,
      body: JSON.stringify({
        approvalId: preflight.approval?.approvalId,
        planHash: plan.hash,
        approved: true,
      }),
      signal: options.signal,
    });
    const decision = await decisionResponse.json().catch(() => ({})) as Record<string, any>;
    if (!decisionResponse.ok || !decision?.ok) {
      throw new Error(errorMessage(decision, `aprovação HTTP ${decisionResponse.status}`));
    }
    return {
      preflight,
      approvedBody: {
        ...preflightBody,
        confirmActive: true,
        manualApproval: {
          approvalId: preflight.approval?.approvalId,
          planHash: plan.hash,
        },
      },
    };
  }

  async function openStream(
    body: ManualReconBody,
    options: ManualReconOptions = {},
  ): Promise<{
    approvedBody: ManualReconBody;
    preflight: Record<string, any>;
    response: Response;
  }> {
    const prepared = await prepareApproval(body, options);
    const currentAuth = auth();
    const token = await requestCsrfToken({
      fetchImpl,
      base: apiBase(),
      auth: currentAuth,
      signal: options.signal,
    });
    const response = await fetchImpl(apiUrl('/api/recon/stream', apiBase()), {
      method: 'POST',
      headers: buildApiHeaders({ auth: currentAuth, csrfToken: token, json: true }),
      body: JSON.stringify(prepared.approvedBody),
      signal: options.signal,
    });
    return { ...prepared, response };
  }

  return Object.freeze({ openStream, prepareApproval });
}

