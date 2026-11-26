import { buildQuery, unwrapWorkbenchResponse, workbenchRows, type AgentMode, type WorkbenchRecord } from './model';

export type WorkbenchStorage = Pick<Storage, 'getItem'>;

export type WorkbenchLocation = Pick<Location, 'protocol'>;

export type WorkbenchServiceDependencies = {
  fetchImpl?: typeof fetch;
  locationLike?: WorkbenchLocation;
  storage?: WorkbenchStorage | null;
};

type QueryValues = Record<string, unknown>;

function apiError(body: unknown, status: number): Error {
  const record = body && typeof body === 'object' ? body as WorkbenchRecord : {};
  return new Error(String(record.error || `HTTP ${status}`));
}

export function workbenchApiUrl(pathname: string, protocol = 'http:'): string {
  const path = pathname.startsWith('/') ? pathname : `/${pathname}`;
  return protocol === 'file:' ? `http://127.0.0.1:3847${path}` : path;
}

export function workbenchAuthHeaders(
  storage: WorkbenchStorage | null | undefined,
  extra: Record<string, string> = {},
): Record<string, string> {
  const headers = { ...extra };
  try {
    const raw = storage?.getItem('ghostrecon_auth_json');
    const config = raw ? JSON.parse(raw) as WorkbenchRecord : null;
    if (config?.ghostreconApiKey) headers['X-API-Key'] = String(config.ghostreconApiKey);
  } catch {
    // Storage can be unavailable in sandboxed file:// contexts.
  }
  return headers;
}

export function createVigoliumWorkbenchService({
  fetchImpl = fetch,
  locationLike = window.location,
  storage = window.localStorage,
}: WorkbenchServiceDependencies = {}) {
  let csrfToken = '';
  const url = (pathname: string) => workbenchApiUrl(pathname, locationLike.protocol);

  async function get(pathname: string, signal?: AbortSignal): Promise<any> {
    const response = await fetchImpl(url(pathname), {
      headers: workbenchAuthHeaders(storage),
      signal,
    });
    const body = await response.json().catch(() => ({}));
    if (!response.ok) throw apiError(body, response.status);
    return body;
  }

  async function csrf(signal?: AbortSignal): Promise<string> {
    if (csrfToken) return csrfToken;
    const response = await fetchImpl(url('/api/csrf-token'), {
      headers: workbenchAuthHeaders(storage),
      signal,
    });
    const body = await response.json().catch(() => ({})) as WorkbenchRecord;
    if (!response.ok) throw apiError(body, response.status);
    csrfToken = String(body.token || '');
    if (!csrfToken) throw new Error('token CSRF vazio');
    return csrfToken;
  }

  async function post(pathname: string, payload: unknown, signal?: AbortSignal): Promise<any> {
    const token = await csrf(signal);
    const response = await fetchImpl(url(pathname), {
      method: 'POST',
      headers: workbenchAuthHeaders(storage, {
        'Content-Type': 'application/json',
        'X-CSRF-Token': token,
      }),
      body: JSON.stringify(payload || {}),
      signal,
    });
    const body = await response.json().catch(() => ({}));
    if (!response.ok) throw apiError(body, response.status);
    return body;
  }

  async function list(pathname: string, signal?: AbortSignal) {
    return workbenchRows(await get(pathname, signal));
  }

  return Object.freeze({
    apiUrl: url,
    status: (signal?: AbortSignal) => get('/api/vigolium/server/status', signal),
    scans: (signal?: AbortSignal) => list('/api/vigolium/server/scans?limit=20', signal),
    requests: (filters: QueryValues, signal?: AbortSignal) => (
      list(`/api/vigolium/server/http-records?${buildQuery({ limit: 100, ...filters })}`, signal)
    ),
    request: async (id: string, signal?: AbortSignal) => (
      unwrapWorkbenchResponse(await get(`/api/vigolium/server/http-records/${encodeURIComponent(id)}`, signal)) as WorkbenchRecord
    ),
    findings: (filters: QueryValues, signal?: AbortSignal) => (
      list(`/api/vigolium/server/findings?${buildQuery({ limit: 100, ...filters })}`, signal)
    ),
    finding: async (id: string, signal?: AbortSignal) => (
      unwrapWorkbenchResponse(await get(`/api/vigolium/server/findings/${encodeURIComponent(id)}`, signal)) as WorkbenchRecord
    ),
    oast: (filters: QueryValues, signal?: AbortSignal) => (
      list(`/api/vigolium/server/oast-interactions?${buildQuery({ limit: 100, ...filters })}`, signal)
    ),
    oastDetail: async (id: string, signal?: AbortSignal) => (
      unwrapWorkbenchResponse(await get(`/api/vigolium/server/oast-interactions/${encodeURIComponent(id)}`, signal)) as WorkbenchRecord
    ),
    agentSessions: (signal?: AbortSignal) => list('/api/vigolium/server/agent-sessions?limit=50', signal),
    agentSession: async (id: string, signal?: AbortSignal) => (
      unwrapWorkbenchResponse(await get(`/api/vigolium/server/agent-sessions/${encodeURIComponent(id)}`, signal)) as WorkbenchRecord
    ),
    runAgent: (mode: AgentMode, payload: unknown, signal?: AbortSignal) => (
      post(`/api/vigolium/agent/${mode}`, payload, signal)
    ),
    modules: async (filters: QueryValues, signal?: AbortSignal) => (
      get(`/api/vigolium/modules?${buildQuery({ limit: 200, ...filters })}`, signal)
    ),
    reports: async (signal?: AbortSignal) => get('/api/vigolium/reports', signal),
    importReport: (payload: unknown, signal?: AbortSignal) => post('/api/vigolium/reports/import', payload, signal),
  });
}

export type VigoliumWorkbenchService = ReturnType<typeof createVigoliumWorkbenchService>;
