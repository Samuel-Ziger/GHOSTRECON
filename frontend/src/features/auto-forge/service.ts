import {
  apiUrl,
  buildApiHeaders,
  requestCsrfToken,
  type OptionalAuthConfig,
} from '../../services/api-client';
import { safeRead, safeWrite, STORAGE_KEYS, type StorageLike } from '../../services/storage';

export const AUTO_TERMINAL_PHASES = new Set([
  'completed',
  'partial',
  'failed',
  'cancelled',
  'interrupted',
  'timed_out',
  'stalled',
  'budget_exceeded',
]);

export type AutoTerminalPhase =
  | 'completed'
  | 'partial'
  | 'failed'
  | 'cancelled'
  | 'interrupted'
  | 'timed_out'
  | 'stalled'
  | 'budget_exceeded';

export type AutoReconBody = Record<string, unknown> & {
  domain: string;
  mode?: string;
  resumeSessionId?: string | null;
};

export type AutoEvent = Record<string, any> & {
  type?: string;
  phase?: string;
  sessionId?: string;
};

export type AutoEventSummary = {
  message: string;
  level: 'section' | 'success' | 'info' | 'warn' | 'error';
  sessionId?: string;
  terminalPhase?: string;
  refreshRag?: boolean;
  plan?: unknown;
  evaluation?: unknown;
} | null;

export type ForgeLifecycleAction = 'canary' | 'promote' | 'rollback' | 'disable' | 'enable';
export type ForgeDecision = 'approve' | 'reject';

export type AutoForgeServiceDependencies = {
  apiBase: () => string;
  auth: () => OptionalAuthConfig | null;
  fetchImpl: typeof fetch;
  storage?: StorageLike | null;
  now?: () => number;
  sleep?: (milliseconds: number, signal?: AbortSignal) => Promise<void>;
};

type JsonRecord = Record<string, any>;

function apiError(body: unknown, status: number): Error {
  const record = body && typeof body === 'object' ? body as JsonRecord : {};
  return new Error(String(record.error || `HTTP ${status}`));
}

async function readJson(response: Response): Promise<JsonRecord> {
  return response.json().catch(() => ({})) as Promise<JsonRecord>;
}

function defaultSleep(milliseconds: number, signal?: AbortSignal): Promise<void> {
  if (signal?.aborted) {
    return Promise.reject(signal.reason || new DOMException('Abortado', 'AbortError'));
  }
  return new Promise((resolve, reject) => {
    let timer: ReturnType<typeof setTimeout>;
    const done = () => {
      signal?.removeEventListener('abort', abort);
      resolve();
    };
    const abort = () => {
      clearTimeout(timer);
      reject(signal?.reason || new DOMException('Abortado', 'AbortError'));
    };
    timer = setTimeout(done, milliseconds);
    signal?.addEventListener('abort', abort, { once: true });
  });
}

export function autoUiTerminalStatusText(outcome: unknown): string {
  if (outcome === 'completed') return 'AUTO COMPLETO';
  if (outcome === 'partial') return 'AUTO PARCIAL';
  if (['cancelled', 'interrupted', 'cancel_requested_unconfirmed'].includes(String(outcome || ''))) {
    return 'AUTO CANCELADO';
  }
  return 'ERRO';
}

/**
 * Transporte e estado persistente do Auto/Forge. A projeção visual continua no
 * controller compatível, mas nenhum request deste domínio precisa conhecer DOM.
 */
export function createAutoForgeService(dependencies: AutoForgeServiceDependencies) {
  const {
    apiBase,
    auth,
    fetchImpl,
    storage = null,
    now = Date.now,
    sleep = defaultSleep,
  } = dependencies;

  const headers = (json = false, csrfToken?: string | null) => buildApiHeaders({
    auth: auth(),
    csrfToken,
    json,
  });

  async function csrf(signal?: AbortSignal): Promise<string> {
    return requestCsrfToken({
      fetchImpl,
      base: apiBase(),
      auth: auth(),
      signal,
    });
  }

  async function getJson(pathname: string, signal?: AbortSignal): Promise<JsonRecord> {
    const response = await fetchImpl(apiUrl(pathname, apiBase()), {
      headers: headers(false),
      signal,
    });
    const body = await readJson(response);
    if (!response.ok || body.ok === false) throw apiError(body, response.status);
    return body;
  }

  async function postJson(
    pathname: string,
    body: unknown,
    signal?: AbortSignal,
  ): Promise<JsonRecord> {
    const token = await csrf(signal);
    const response = await fetchImpl(apiUrl(pathname, apiBase()), {
      method: 'POST',
      headers: headers(true, token),
      body: JSON.stringify(body || {}),
      signal,
    });
    const data = await readJson(response);
    if (!response.ok || data.ok === false) throw apiError(data, response.status);
    return data;
  }

  function lastSessionId(): string | null {
    const value = String(safeRead(storage, STORAGE_KEYS.autoSession) || '').trim();
    return value || null;
  }

  function rememberSession(sessionId: unknown): string | null {
    const value = String(sessionId || '').trim();
    if (!value) return null;
    safeWrite(storage, STORAGE_KEYS.autoSession, value);
    return value;
  }

  async function openStream(body: AutoReconBody, signal?: AbortSignal): Promise<Response> {
    const token = await csrf(signal);
    return fetchImpl(apiUrl('/api/recon/auto/stream', apiBase()), {
      method: 'POST',
      headers: headers(true, token),
      body: JSON.stringify(body),
      signal,
    });
  }

  async function listResumableSessions(signal?: AbortSignal): Promise<JsonRecord[]> {
    const data = await getJson('/api/recon/auto/sessions?resumable=1', signal);
    return Array.isArray(data.sessions) ? data.sessions.slice(0, 50) : [];
  }

  async function getSession(sessionId: string, signal?: AbortSignal): Promise<JsonRecord> {
    const id = String(sessionId || '').trim();
    if (!id) throw new Error('sessionId ausente');
    return getJson(`/api/recon/auto/sessions/${encodeURIComponent(id)}`, signal);
  }

  async function waitForTerminal(
    sessionId: string,
    options: { timeoutMs?: number; intervalMs?: number; signal?: AbortSignal } = {},
  ): Promise<{ status: AutoTerminalPhase; session: JsonRecord; source: unknown } | null> {
    const id = String(sessionId || '').trim();
    if (!id) return null;
    const timeoutMs = Math.max(2_000, Number(options.timeoutMs) || 30_000);
    const intervalMs = Math.max(250, Number(options.intervalMs) || 1_000);
    const deadline = now() + timeoutMs;
    while (now() < deadline) {
      if (options.signal?.aborted) {
        throw options.signal.reason || new DOMException('Abortado', 'AbortError');
      }
      try {
        const data = await getSession(id, options.signal);
        const status = String(data.session?.status || '');
        if (AUTO_TERMINAL_PHASES.has(status)) {
          return {
            status: status as AutoTerminalPhase,
            session: data.session,
            source: data.source || null,
          };
        }
      } catch (error) {
        if (options.signal?.aborted) throw error;
        // Snapshot pode estar entre escritas; tentamos até o deadline.
      }
      await sleep(intervalMs, options.signal);
    }
    return null;
  }

  async function requestCancel(sessionId: string, signal?: AbortSignal): Promise<JsonRecord> {
    const id = String(sessionId || '').trim();
    if (!id) throw new Error('sessionId ausente');
    return postJson(
      `/api/recon/auto/${encodeURIComponent(id)}/cancel`,
      { reason: 'operator_ui' },
      signal,
    );
  }

  async function respondApproval(
    sessionId: string,
    approvalId: string,
    approved: boolean,
    signal?: AbortSignal,
  ): Promise<JsonRecord> {
    const session = String(sessionId || '').trim();
    const approval = String(approvalId || '').trim();
    if (!session || !approval) throw new Error('identificador de aprovação ausente');
    return postJson(`/api/recon/auto/${encodeURIComponent(session)}/approval`, {
      approvalId: approval,
      approved,
      reason: approved ? 'operador confirmou' : 'operador recusou',
    }, signal);
  }

  async function listForge(signal?: AbortSignal): Promise<JsonRecord[]> {
    const data = await getJson('/api/auto-forge', signal);
    return Array.isArray(data.items) ? data.items : [];
  }

  async function inspectForge(forgeId: string, signal?: AbortSignal): Promise<JsonRecord> {
    const id = String(forgeId || '').trim();
    if (!id) throw new Error('forgeId ausente');
    const data = await getJson(`/api/auto-forge/${encodeURIComponent(id)}`, signal);
    return data.item || {};
  }

  async function lifecycleForge(
    forgeId: string,
    action: ForgeLifecycleAction,
    reason: string,
    percentage?: number,
    signal?: AbortSignal,
  ): Promise<JsonRecord> {
    const id = String(forgeId || '').trim();
    const normalizedReason = String(reason || '').trim();
    if (!id) throw new Error('forgeId ausente');
    if (!normalizedReason) throw new Error('justificativa ausente');
    if (action === 'canary' && (!Number.isFinite(percentage) || Number(percentage) < 1 || Number(percentage) > 100)) {
      throw new Error('percentual de canary inválido');
    }
    return postJson(`/api/auto-forge/${encodeURIComponent(id)}/lifecycle`, {
      action,
      reason: normalizedReason,
      ...(action === 'canary' ? { percentage: Number(percentage) } : {}),
    }, signal);
  }

  async function decideForge(
    forgeId: string,
    decision: ForgeDecision,
    reason: string,
    engagementId?: string,
    signal?: AbortSignal,
  ): Promise<JsonRecord> {
    const id = String(forgeId || '').trim();
    const normalizedReason = String(reason || '').trim();
    const engagement = String(engagementId || '').trim();
    if (!id) throw new Error('forgeId ausente');
    if (!normalizedReason) throw new Error('justificativa ausente');
    if (decision === 'approve' && !engagement) {
      throw new Error('aprovação exige engagement autorizado e no escopo');
    }
    return postJson(`/api/auto-forge/${encodeURIComponent(id)}/verdict`, {
      decision,
      reason: normalizedReason,
      ...(engagement ? { engagementId: engagement } : {}),
    }, signal);
  }

  function summarizeEvent(event: AutoEvent): AutoEventSummary {
    if (!event || typeof event !== 'object') return null;
    if (event.type === 'auto_session' && event.phase === 'started') {
      const sessionId = rememberSession(event.sessionId) || undefined;
      return {
        message: `AUTO: sessão ${event.sessionId || event.requestRunId || '?'} | modo ${event.mode || 'balanced'} | planejamento determinístico`,
        level: 'section',
        sessionId,
      };
    }
    if (event.type === 'auto_session' && AUTO_TERMINAL_PHASES.has(String(event.phase || ''))) {
      return {
        message: event.phase === 'completed'
          ? ''
          : `AUTO sessão ${event.phase}: ${event.error || event.session?.error || ''}`.trim(),
        level: event.phase === 'failed' ? 'error' : 'warn',
        terminalPhase: String(event.phase),
      };
    }
    if (event.type === 'auto_persist_failed') return { message: `AUTO persistência falhou (${event.stage || 'snapshot'}): ${event.error || 'erro'}`, level: 'error' };
    if (event.type === 'auto_stall_detected') return { message: `AUTO watchdog: sem progresso há ${Math.round((event.idleMs || 0) / 1000)}s | fase=${event.currentStage || '-'} | módulo=${event.currentModule || '-'}`, level: 'warn' };
    if (event.type === 'auto_catalog') {
      const count = Array.isArray(event.modules) ? event.modules.length : 0;
      const hx = event.hexstrike ? ` | HexStrike instalado=${event.hexstrike.installed ? 'sim' : 'nao'} online=${event.hexstrike.reachable ? 'sim' : 'nao'}` : '';
      return { message: `AUTO catalogo: ${count} modulo(s) disponiveis${hx}`, level: 'info' };
    }
    if (event.type === 'auto_plan' && event.plan) {
      const modules = Array.isArray(event.plan.modules) ? event.plan.modules : [];
      const rejected = Array.isArray(event.plan.moduleSelection?.operator?.rejected)
        ? event.plan.moduleSelection.operator.rejected
        : [];
      const rejectionSummary = rejected.length
        ? ` | rejeitados=${rejected.map((item: AutoEvent) => `${item.id || '?'}(${item.reason || 'rejeitado'})`).join(', ')}`
        : '';
      return {
        message: `AUTO plano determinístico: modulos=${modules.join(', ') || '(nenhum)'}${rejectionSummary}`,
        level: rejected.length ? 'warn' : 'success',
        plan: event.plan,
      };
    }
    if (event.type === 'auto_rag') {
      const memory = event.memory?.name || event.memory?.filename || event.memory?.filePath || '';
      return {
        message: `AUTO RAG ${event.phase || 'event'}${memory ? `: ${memory}` : ''}`,
        level: event.error || event.memory?.error ? 'warn' : 'info',
        refreshRag: ['plan_saved', 'evaluation_saved'].includes(String(event.phase || '')),
      };
    }
    if (event.type === 'auto_heartbeat') return { message: `AUTO heartbeat: iteração=${event.iteration || 0} tempo=${Math.round((event.elapsedMs || 0) / 1000)}s | atual=${event.currentModule || event.currentStage || '-'}`, level: 'info' };
    if (event.type === 'auto_report_ready') return { message: `AUTO relatório consolidado: ${event.reportUrl || event.runId || '?'}`, level: 'success' };
    if (event.type === 'auto_observation') return { message: `AUTO observação pós-pipeline: findings=${event.findings || 0} | warnings=${event.warnings || 0} | errors=${event.errors || 0}`, level: event.errors ? 'warn' : 'info' };
    if (event.type === 'auto_forge_status') {
      const gates = event.validationOk != null || event.testsOk != null ? ` | validação=${event.validationOk ? 'ok' : 'falha'} testes=${event.testsOk ? 'ok' : 'falha'}` : '';
      return { message: `AUTO Module Forge: ${event.status || '?'} | id=${event.forgeId || '-'} | autor=${event.author || '-'}${gates} | pipeline=${event.pipelineEnabled ? 'ativo' : 'bloqueado'}`, level: event.status === 'error' ? 'warn' : 'info' };
    }
    if (event.type === 'auto_step') return { message: `AUTO etapa ${event.step || '?'}: ${event.status || '?'}`, level: event.status === 'blocked' ? 'warn' : event.status === 'done' ? 'success' : 'info' };
    if (event.type === 'auto_effective_plan' && event.effectivePlan) {
      const selected = Array.isArray(event.effectivePlan.selectedModules) ? event.effectivePlan.selectedModules.join(', ') : '(nenhum)';
      return { message: `AUTO plano efetivo ${String(event.effectivePlan.hash || '').slice(0, 12)}: ${selected} | OPSEC=${event.effectivePlan.opsecProfile || '-'} | aprovação=${event.effectivePlan.requiresHumanApproval ? 'sim' : 'não'}`, level: 'section' };
    }
    if (event.type === 'phase_outcome') {
      const level = event.status === 'done' ? 'success' : event.status === 'skipped' ? 'info' : event.recoverable ? 'warn' : 'error';
      return { message: `AUTO fase ${event.phase || '?'}: ${event.status || '?'}${event.error ? ` — ${event.error}` : ''}${event.recoverable && !['done', 'skipped'].includes(event.status) ? ' (pipeline continuou)' : ''}`, level };
    }
    if (event.type === 'auto_module_outcome') return { message: `AUTO módulo ${event.moduleId || '?'} [${event.engine || '?'}]: ${event.status || '?'}${event.error ? ` — ${event.error}` : ''}`, level: event.status === 'done' ? 'success' : event.status === 'skipped' ? 'info' : 'warn' };
    if (event.type === 'engine_started') return { message: `Motor ${event.engine || '?'}: iniciado.`, level: 'info' };
    if (event.type === 'engine_done') return { message: `Motor ${event.engine || '?'}: concluído.`, level: 'success' };
    if (event.type === 'engine_partial') return { message: `Motor ${event.engine || '?'}: concluído parcialmente${event.phase ? ` (${event.phase})` : ''}${event.error ? ` — ${event.error}` : ''}.`, level: 'warn' };
    if (event.type === 'engine_timeout') return { message: `Motor ${event.engine || '?'}: timeout${event.error ? ` — ${event.error}` : ''}; os demais motores podem continuar quando o processo tiver sido encerrado.`, level: 'warn' };
    if (event.type === 'engine_skipped' || event.type === 'engine_unavailable') return { message: `Motor ${event.engine || '?'}: omitido (${event.reason || 'indisponível'}).`, level: 'warn' };
    if (event.type === 'engine_cancelled') return { message: `Motor ${event.engine || '?'}: cancelado.`, level: 'warn' };
    if (event.type === 'engine_failed') return { message: `Motor ${event.engine || '?'}: falhou${event.timeout ? ' por timeout' : ''}${event.error ? ` — ${event.error}` : ''}.`, level: 'error' };
    if (event.type === 'auto_evaluation' && event.evaluation) return { message: `AUTO avaliacao: ok=${event.evaluation.ok ? 'sim' : 'nao'} | findings=${event.evaluation.findings || 0} | high=${event.evaluation.highSignals || 0} | next=${event.evaluation.next || '-'}`, level: event.evaluation.ok ? 'success' : 'warn', evaluation: event.evaluation };
    return null;
  }

  return Object.freeze({
    autoUiTerminalStatusText,
    decideForge,
    getSession,
    inspectForge,
    lastSessionId,
    lifecycleForge,
    listForge,
    listResumableSessions,
    openStream,
    postJson,
    rememberSession,
    requestCancel,
    respondApproval,
    summarizeEvent,
    waitForTerminal,
  });
}
