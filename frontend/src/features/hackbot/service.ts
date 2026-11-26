import {
  apiUrl,
  buildApiHeaders,
  readOptionalAuthConfig,
  requestCsrfToken,
  resolveApiBase,
  type OptionalAuthConfig,
} from '../../services/api-client';

export type HackbotRecord = Record<string, any>;

type Dependencies = {
  apiBase: () => string;
  auth: () => OptionalAuthConfig | null;
  fetchImpl: typeof fetch;
};

async function parse(response: Response): Promise<HackbotRecord> {
  const data = await response.json().catch(() => ({})) as HackbotRecord;
  if (!response.ok || data.ok === false) throw new Error(String(data.error || data.detail || `HTTP ${response.status}`));
  return data;
}

export function createHackbotService({ apiBase, auth, fetchImpl }: Dependencies) {
  const headers = (json = false, csrfToken?: string) => buildApiHeaders({ auth: auth(), csrfToken, json });
  const get = async (pathname: string, signal?: AbortSignal) => parse(await fetchImpl(apiUrl(pathname, apiBase()), {
    headers: headers(), signal,
  }));
  const mutate = async (method: 'POST' | 'DELETE', pathname: string, body?: unknown, signal?: AbortSignal) => {
    const csrfToken = await requestCsrfToken({ fetchImpl, base: apiBase(), auth: auth(), signal });
    return parse(await fetchImpl(apiUrl(pathname, apiBase()), {
      method,
      headers: headers(body !== undefined, csrfToken),
      body: body === undefined ? undefined : JSON.stringify(body),
      signal,
    }));
  };
  return Object.freeze({
    status: (signal?: AbortSignal) => get('/api/hackbot/status', signal),
    agents: (signal?: AbortSignal) => get('/api/hackbot/agents', signal),
    models: (signal?: AbortSignal) => get('/api/hackbot/models', signal),
    mindSkills: (signal?: AbortSignal) => get('/api/hackbot/mind/skills', signal),
    conversations: (signal?: AbortSignal) => get('/api/hackbot/conversations', signal),
    createConversation: (body: HackbotRecord, signal?: AbortSignal) => mutate('POST', '/api/hackbot/conversations', body, signal),
    conversation: (id: string, signal?: AbortSignal) => get(`/api/hackbot/conversations/${encodeURIComponent(id)}/messages`, signal),
    send: (id: string, body: HackbotRecord, signal?: AbortSignal) => mutate('POST', `/api/hackbot/conversations/${encodeURIComponent(id)}/messages`, body, signal),
    remove: (id: string, signal?: AbortSignal) => mutate('DELETE', `/api/hackbot/conversations/${encodeURIComponent(id)}`, undefined, signal),
    saveConfig: (body: HackbotRecord, signal?: AbortSignal) => mutate('POST', '/api/hackbot/config', body, signal),
  });
}

export function createBrowserHackbotService() {
  let storage: Storage | null = null;
  try { storage = window.localStorage; } catch { storage = null; }
  return createHackbotService({
    apiBase: () => resolveApiBase({ protocol: window.location.protocol, storage }),
    auth: () => readOptionalAuthConfig(storage),
    fetchImpl: window.fetch.bind(window),
  });
}
