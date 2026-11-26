import {
  extractFindings,
  normalizeTarget,
  snapshotFromFinding,
  targetUsableForApi,
  type ManualValidation,
  type ReportFinding,
} from './model';

type JsonRecord = Record<string, any>;
type BrainCategory = JsonRecord & { id: number; title?: unknown };

export type ReportService = ReturnType<typeof createReportService>;

function safeLocalStorage(): Storage | null {
  try { return window.localStorage; } catch { return null; }
}

export function reportApiBase(
  locationLike: Pick<Location, 'protocol'> = window.location,
  storage: Pick<Storage, 'getItem'> | null = safeLocalStorage(),
): string {
  if (!['file:', 'blob:'].includes(locationLike.protocol)) return '';
  return String(storage?.getItem('ghostrecon_api_base') || 'http://127.0.0.1:3847').replace(/\/+$/, '');
}

export function reportApiUrl(pathname: string, base = ''): string {
  const path = pathname.startsWith('/') ? pathname : `/${pathname}`;
  return base ? `${base}${path}` : path;
}

export function reportAuthHeaders(
  storage: Pick<Storage, 'getItem'> | null,
  extra: Record<string, string> = {},
): Record<string, string> {
  const headers = { ...extra };
  try {
    const config = JSON.parse(storage?.getItem('ghostrecon_auth_json') || 'null') as { ghostreconApiKey?: unknown } | null;
    if (config?.ghostreconApiKey) headers['X-API-Key'] = String(config.ghostreconApiKey);
  } catch { /* invalid optional config */ }
  return headers;
}

async function json(response: Response): Promise<JsonRecord> {
  return response.json().catch(() => ({})) as Promise<JsonRecord>;
}

function failure(body: JsonRecord, response: Response, fallback = 'HTTP'): Error {
  return new Error(String(body.error || `${fallback} ${response.status}`));
}

export function createReportService({
  fetchImpl = fetch,
  locationLike = window.location,
  storage = safeLocalStorage(),
}: {
  fetchImpl?: typeof fetch;
  locationLike?: Pick<Location, 'protocol'>;
  storage?: Storage | null;
} = {}) {
  const base = reportApiBase(locationLike, storage);
  const url = (pathname: string) => reportApiUrl(pathname, base);
  const headers = (extra: Record<string, string> = {}) => reportAuthHeaders(storage, extra);

  async function csrf(signal?: AbortSignal): Promise<string> {
    const response = await fetchImpl(url('/api/csrf-token'), { headers: headers(), signal });
    const body = await json(response);
    const token = String(body.token || '');
    if (!response.ok || !token) throw failure(body, response, 'CSRF');
    return token;
  }

  async function post(pathname: string, body: unknown, signal?: AbortSignal): Promise<JsonRecord> {
    const token = await csrf(signal);
    const response = await fetchImpl(url(pathname), {
      method: 'POST',
      headers: headers({ 'Content-Type': 'application/json', 'X-CSRF-Token': token }),
      body: JSON.stringify(body),
      signal,
    });
    const data = await json(response);
    if (!response.ok || data.ok === false) throw failure(data, response);
    return data;
  }

  async function capabilities(signal?: AbortSignal): Promise<JsonRecord> {
    const response = await fetchImpl(url('/api/capabilities'), { headers: headers(), signal });
    const body = await json(response);
    if (!response.ok) throw failure(body, response);
    return body;
  }

  async function loadValidations(target: string, signal?: AbortSignal): Promise<ManualValidation[]> {
    const normalized = normalizeTarget(target);
    if (!targetUsableForApi(normalized)) return [];
    const response = await fetchImpl(url(`/api/manual-validations/${encodeURIComponent(normalized)}`), {
      headers: headers(),
      signal,
    });
    const body = await json(response);
    if (!response.ok) throw failure(body, response, 'GET validações');
    return Array.isArray(body.items) ? body.items : [];
  }

  async function loadLatestRun(preferredTarget = '', signal?: AbortSignal): Promise<{ runId: number; target: string; findings: unknown[] }> {
    const response = await fetchImpl(url('/api/runs?limit=50'), { headers: headers(), signal });
    const list = await json(response);
    if (!response.ok) throw failure(list, response, 'listar recons');
    const runs = Array.isArray(list.runs) ? list.runs : [];
    if (!runs.length) throw new Error('Ainda não há recons gravados na base.');
    const target = normalizeTarget(preferredTarget);
    const chosen = runs.find((run: JsonRecord) => target && normalizeTarget(run?.target) === target) || runs[0];
    const runId = Number(chosen?.id);
    if (!Number.isFinite(runId)) throw new Error('Recon inválido retornado pela API.');
    const detailResponse = await fetchImpl(url(`/api/runs/${runId}`), { headers: headers(), signal });
    const detail = await json(detailResponse);
    if (!detailResponse.ok) throw failure(detail, detailResponse, `run #${runId}`);
    const findings = extractFindings(detail);
    if (!findings.length) throw new Error(`Run #${runId} não contém achados utilizáveis.`);
    return { runId, target: normalizeTarget(detail.target || chosen.target || target), findings };
  }

  async function persistValidation({
    target,
    finding,
    fingerprint,
    notes,
    validated,
  }: {
    target: string;
    finding: ReportFinding;
    fingerprint: string;
    notes: string;
    validated: boolean;
  }, signal?: AbortSignal): Promise<JsonRecord> {
    return post('/api/manual-validations', {
      target: normalizeTarget(target),
      fingerprint,
      validated,
      ...(validated ? { snapshot: snapshotFromFinding(finding), notes: String(notes || '').slice(0, 2000) } : {}),
    }, signal);
  }

  async function listBrainCategories(signal?: AbortSignal): Promise<BrainCategory[]> {
    const response = await fetchImpl(url('/api/brain/categories'), { headers: headers(), signal });
    const body = await json(response);
    if (!response.ok) throw failure(body, response);
    return (Array.isArray(body.items) ? body.items : []).flatMap((item: JsonRecord) => {
      const id = Number(item?.id);
      return Number.isFinite(id) ? [{ ...item, id }] : [];
    });
  }

  async function createBrainCategory(title: string, signal?: AbortSignal): Promise<number> {
    const body = await post('/api/brain/categories', { title }, signal);
    const id = Number(body.id);
    if (!Number.isFinite(id)) throw new Error('Categoria criada sem id.');
    return id;
  }

  async function linkBrain(target: string, fingerprint: string, categoryId: number, signal?: AbortSignal): Promise<JsonRecord> {
    return post('/api/brain/link', { target: normalizeTarget(target), fingerprint, categoryId }, signal);
  }

  async function generateAi(target: string, findings: ReportFinding[], aiUseOpenrouter: boolean, signal?: AbortSignal): Promise<JsonRecord> {
    return post('/api/manual-validations/ai-report', {
      target: normalizeTarget(target),
      findings,
      aiPrimaryCloud: 'openrouter',
      aiUseOpenrouter,
      stats: { subs: 0, endpoints: 0, params: 0, secrets: 0, dorks: 0, high: 0 },
    }, signal);
  }

  async function annotationHandoff(payload: unknown, signal?: AbortSignal): Promise<string> {
    const body = await post('/api/anotacao-handoff', { payload }, signal);
    if (!body.id) throw new Error('Resposta do servidor sem id de handoff.');
    return String(body.id);
  }

  return Object.freeze({
    annotationHandoff,
    apiBase: base,
    capabilities,
    createBrainCategory,
    generateAi,
    linkBrain,
    listBrainCategories,
    loadLatestRun,
    loadValidations,
    persistValidation,
  });
}
