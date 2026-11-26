import {
  apiUrl,
  buildApiHeaders,
  readOptionalAuthConfig,
  requestCsrfToken,
  resolveApiBase,
  type OptionalAuthConfig,
} from '../../services/api-client';

export type NeuroSploitRecord = Record<string, any>;

type Dependencies = {
  apiBase: () => string;
  auth: () => OptionalAuthConfig | null;
  fetchImpl: typeof fetch;
};

async function parse(response: Response): Promise<NeuroSploitRecord> {
  const data = await response.json().catch(() => ({})) as NeuroSploitRecord;
  if (!response.ok || data.ok === false) throw new Error(String(data.error || `HTTP ${response.status}`));
  return data;
}

export function createNeuroSploitService({ apiBase, auth, fetchImpl }: Dependencies) {
  const headers = (json = false, csrfToken?: string) => buildApiHeaders({ auth: auth(), csrfToken, json });
  const get = async (pathname: string, signal?: AbortSignal) => parse(await fetchImpl(apiUrl(pathname, apiBase()), {
    headers: headers(), signal,
  }));
  const post = async (pathname: string, body?: unknown, signal?: AbortSignal) => {
    const csrf = await requestCsrfToken({ fetchImpl, base: apiBase(), auth: auth(), signal });
    return parse(await fetchImpl(apiUrl(pathname, apiBase()), {
      method: 'POST',
      headers: headers(body !== undefined, csrf),
      body: body === undefined ? undefined : JSON.stringify(body),
      signal,
    }));
  };
  return Object.freeze({
    status: (signal?: AbortSignal) => get('/api/neurosploit/status', signal),
    job: (id: string, signal?: AbortSignal) => get(`/api/neurosploit/jobs/${encodeURIComponent(id)}`, signal),
    start: (body: NeuroSploitRecord, signal?: AbortSignal) => post('/api/neurosploit/jobs', body, signal),
    control: (id: string, action: 'pause' | 'continue' | 'stop' | 'resume', signal?: AbortSignal) => post(`/api/neurosploit/jobs/${encodeURIComponent(id)}/${action}`, undefined, signal),
    artifacts: (id: string, signal?: AbortSignal) => get(`/api/neurosploit/jobs/${encodeURIComponent(id)}/artifacts`, signal),
    artifact: async (id: string, relative: string, signal?: AbortSignal) => {
      const response = await fetchImpl(apiUrl(`/api/neurosploit/jobs/${encodeURIComponent(id)}/artifacts/${relative.split('/').map(encodeURIComponent).join('/')}`, apiBase()), {
        headers: headers(), signal,
      });
      if (!response.ok) throw new Error(`Falha ao baixar artefato: HTTP ${response.status}`);
      return response.blob();
    },
    engagements: (signal?: AbortSignal) => get('/api/engagements', signal),
  });
}

export function createBrowserNeuroSploitService() {
  let storage: Storage | null = null;
  try { storage = window.localStorage; } catch { storage = null; }
  return createNeuroSploitService({
    apiBase: () => resolveApiBase({ protocol: window.location.protocol, storage }),
    auth: () => readOptionalAuthConfig(storage),
    fetchImpl: window.fetch.bind(window),
  });
}
