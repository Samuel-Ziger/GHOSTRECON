import {
  apiUrl,
  buildApiHeaders,
  readOptionalAuthConfig,
  requestCsrfToken,
  resolveApiBase,
  type OptionalAuthConfig,
} from '../../services/api-client';

export type ArtexRecord = Record<string, any>;

export type ArtexServiceDependencies = {
  apiBase: () => string;
  auth: () => OptionalAuthConfig | null;
  fetchImpl: typeof fetch;
};

async function json(response: Response): Promise<ArtexRecord> {
  const data = await response.json().catch(() => ({})) as ArtexRecord;
  if (!response.ok || data.ok === false) throw new Error(String(data.error || `HTTP ${response.status}`));
  return data;
}

export function createArtexService({ apiBase, auth, fetchImpl }: ArtexServiceDependencies) {
  const headers = (isJson = false, csrfToken?: string) => buildApiHeaders({
    auth: auth(),
    csrfToken,
    json: isJson,
  });
  const get = async (pathname: string, signal?: AbortSignal) => json(await fetchImpl(apiUrl(pathname, apiBase()), {
    headers: headers(),
    signal,
  }));
  const post = async (pathname: string, body: unknown = {}, signal?: AbortSignal) => {
    const csrfToken = await requestCsrfToken({ fetchImpl, base: apiBase(), auth: auth(), signal });
    return json(await fetchImpl(apiUrl(pathname, apiBase()), {
      method: 'POST',
      headers: headers(true, csrfToken),
      body: JSON.stringify(body),
      signal,
    }));
  };
  const del = async (pathname: string, signal?: AbortSignal) => {
    const csrfToken = await requestCsrfToken({ fetchImpl, base: apiBase(), auth: auth(), signal });
    return json(await fetchImpl(apiUrl(pathname, apiBase()), {
      method: 'DELETE',
      headers: headers(false, csrfToken),
      signal,
    }));
  };

  return Object.freeze({
    status: (signal?: AbortSignal) => get('/api/artex/status', signal),
    ensureIntegration: (signal?: AbortSignal) => post('/api/artex/integration/ensure', {}, signal),
    connectChatGptPlan: (signal?: AbortSignal) => post('/api/artex/chatgpt-plan/connect', {}, signal),
    chatGptPlanModels: (signal?: AbortSignal) => get('/api/artex/chatgpt-plan/models', signal),
    saveProfile: (profile: ArtexRecord, signal?: AbortSignal) => post('/api/artex/llm/profiles', profile, signal),
    activateProfile: (id: string | number, signal?: AbortSignal) => post('/api/artex/llm/profiles/active', { id }, signal),
    deleteProfile: (id: string | number, signal?: AbortSignal) => del(`/api/artex/llm/profiles/${encodeURIComponent(String(id))}`, signal),
    listModels: (config: ArtexRecord, signal?: AbortSignal) => post('/api/artex/llm/models', config, signal),
    testProfile: (id: string | number, signal?: AbortSignal) => post(`/api/artex/llm/profiles/${encodeURIComponent(String(id))}/test`, {}, signal),
    createConversation: (body: ArtexRecord = {}, signal?: AbortSignal) => post('/api/artex/conversations', body, signal),
    deleteConversation: (id: string | number, signal?: AbortSignal) => del(`/api/artex/conversations/${encodeURIComponent(String(id))}`, signal),
    messages: (id: string | number, since = 0, signal?: AbortSignal) => get(`/api/artex/conversations/${encodeURIComponent(String(id))}/messages?since=${Number(since) || 0}`, signal),
    messageDetail: (id: string | number, seq: string | number, signal?: AbortSignal) => get(`/api/artex/conversations/${encodeURIComponent(String(id))}/messages/${encodeURIComponent(String(seq))}`, signal),
    sendMessage: (id: string | number, message: string, signal?: AbortSignal) => post(`/api/artex/conversations/${encodeURIComponent(String(id))}/messages`, { message }, signal),
    stopConversation: (id: string | number, signal?: AbortSignal) => post(`/api/artex/conversations/${encodeURIComponent(String(id))}/stop`, {}, signal),
  });
}

export function createBrowserArtexService() {
  let storage: Storage | null = null;
  try { storage = window.localStorage; } catch { storage = null; }
  const apiBase = () => resolveApiBase({ protocol: window.location.protocol, storage });
  const auth = () => readOptionalAuthConfig(storage);
  return createArtexService({ apiBase, auth, fetchImpl: window.fetch.bind(window) });
}
