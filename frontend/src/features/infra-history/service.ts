import {
  apiUrl,
  buildApiHeaders,
  readOptionalAuthConfig,
  requestCsrfToken as requestApiCsrfToken,
  resolveApiBase,
  type OptionalAuthConfig,
} from '../../services/api-client';
import {
  safeRead,
  safeWrite,
  STORAGE_KEYS,
  type StorageLike,
} from '../../services/storage';

type JsonRecord = Record<string, any>;
type StorageSource = StorageLike | null | undefined | (() => StorageLike | null | undefined);
type ProtocolSource = string | (() => string);

export type InfraHistoryServiceDependencies = {
  fetchImpl: typeof fetch;
  storage?: StorageSource;
  protocol?: ProtocolSource;
  apiBase?: () => string;
  auth?: () => OptionalAuthConfig | null;
};

export type AutoAuthTestResult = {
  authenticated: boolean;
  body: JsonRecord;
  runCount: number;
  status: number;
};

export type AutoAuthResult = {
  apiKey: string;
  authTest: AutoAuthTestResult | null;
  authenticated: boolean | null;
  persisted: boolean;
  skipped: boolean;
};

export type AutoRagStatus = JsonRecord & {
  ok: boolean;
  vault: string;
  partition: string;
  count: number;
  counts: Record<string, number>;
  recent: JsonRecord[];
};

export type IntelCorpus = JsonRecord & {
  target: string;
  totalUnique: number;
  items: JsonRecord[];
};

export type TunnelStatus = JsonRecord & {
  ok: boolean;
  active: boolean;
  tor: string;
  openvpn: string;
};

export type TunnelMutationResult = JsonRecord & {
  action: 'enable' | 'disable';
  ok: boolean;
  run: JsonRecord;
  status: TunnelStatus;
};

export type RunsList = JsonRecord & {
  runs: JsonRecord[];
};

export type RunDownloadArtifact = {
  content: string;
  filename: string;
  mimeType: 'application/json';
  run: JsonRecord;
};

export type ManualValidationFingerprints = JsonRecord & {
  target: string;
  items: JsonRecord[];
  fingerprints: string[];
};

export class InfraHistoryRequestError extends Error {
  readonly body: JsonRecord;
  readonly code: string;
  readonly endpoint: string;
  readonly status: number;

  constructor(endpoint: string, status: number, body: JsonRecord = {}) {
    const code = String(body.error || body.code || '').trim();
    const message = String(body.message || code || `HTTP ${status}`);
    super(message);
    this.name = 'InfraHistoryRequestError';
    this.body = body;
    this.code = code;
    this.endpoint = endpoint;
    this.status = status;
  }
}

function record(value: unknown): JsonRecord {
  return value && typeof value === 'object' && !Array.isArray(value)
    ? value as JsonRecord
    : {};
}

async function responseJson(response: Response): Promise<JsonRecord> {
  return response.json().then(record).catch(() => ({}));
}

function normalizedNumber(value: unknown, fallback = 0): number {
  const parsed = Number(value);
  return Number.isFinite(parsed) && parsed >= 0 ? parsed : fallback;
}

function normalizedRecords(value: unknown): JsonRecord[] {
  return Array.isArray(value)
    ? value.filter((item) => item && typeof item === 'object' && !Array.isArray(item)).map(record)
    : [];
}

function normalizedCounts(value: unknown): Record<string, number> {
  return Object.fromEntries(
    Object.entries(record(value)).map(([name, count]) => [name, normalizedNumber(count)]),
  );
}

function storageFrom(source: StorageSource): StorageLike | null {
  try {
    const value = typeof source === 'function' ? source() : source;
    return value || null;
  } catch {
    return null;
  }
}

function protocolFrom(source: ProtocolSource | undefined): string {
  try {
    if (typeof source === 'function') return String(source() || 'http:');
    if (source) return String(source);
    return typeof window === 'undefined' ? 'http:' : window.location.protocol;
  } catch {
    return 'http:';
  }
}

function normalizedTarget(value: unknown): string {
  return String(value || '').trim().toLowerCase();
}

export function isInfraHistoryTarget(value: unknown): boolean {
  return /^[a-z0-9][a-z0-9.-]*[a-z0-9]$/.test(normalizedTarget(value));
}

function runId(value: unknown): string {
  const parsed = Number(value);
  if (!Number.isSafeInteger(parsed) || parsed < 0) throw new Error('id de run inválido');
  return String(parsed);
}

function normalizeTunnelStatus(body: unknown): TunnelStatus {
  const data = record(body);
  return {
    ...data,
    ok: data.ok !== false,
    active: Boolean(data.active),
    tor: String(data.tor || 'unknown'),
    openvpn: String(data.openvpn || 'unknown'),
  };
}

export function createInfraHistoryService(dependencies: InfraHistoryServiceDependencies) {
  const { fetchImpl } = dependencies;
  const currentStorage = () => storageFrom(dependencies.storage);
  const apiBase = dependencies.apiBase || (() => resolveApiBase({
    protocol: protocolFrom(dependencies.protocol),
    storage: currentStorage(),
  }));
  const currentAuth = dependencies.auth || (() => readOptionalAuthConfig(currentStorage()));
  const url = (pathname: string) => apiUrl(pathname, apiBase());

  function assertSuccessful(pathname: string, response: Response, body: JsonRecord): void {
    if (!response.ok || body.ok === false) {
      throw new InfraHistoryRequestError(pathname, response.status, body);
    }
  }

  async function getJson(pathname: string, signal?: AbortSignal): Promise<JsonRecord> {
    const response = await fetchImpl(url(pathname), {
      headers: buildApiHeaders({ auth: currentAuth() }),
      signal,
    });
    const body = await responseJson(response);
    assertSuccessful(pathname, response, body);
    return body;
  }

  async function requestCsrfToken(signal?: AbortSignal): Promise<string> {
    return requestApiCsrfToken({
      fetchImpl,
      base: apiBase(),
      auth: currentAuth(),
      signal,
    });
  }

  async function postJson(
    pathname: string,
    payload: unknown,
    signal?: AbortSignal,
  ): Promise<JsonRecord> {
    const csrfToken = await requestCsrfToken(signal);
    const response = await fetchImpl(url(pathname), {
      method: 'POST',
      headers: buildApiHeaders({ auth: currentAuth(), csrfToken, json: true }),
      body: JSON.stringify(payload ?? {}),
      signal,
    });
    const body = await responseJson(response);
    assertSuccessful(pathname, response, body);
    return body;
  }

  async function setupAutoAuth(signal?: AbortSignal): Promise<{ apiKey: string }> {
    const pathname = '/api/setup/auto-auth';
    const response = await fetchImpl(url(pathname), { signal });
    const body = await responseJson(response);
    assertSuccessful(pathname, response, body);
    const apiKey = String(body.apiKey || '').trim();
    if (!apiKey) throw new InfraHistoryRequestError(pathname, response.status, {
      ...body,
      error: 'AUTO_AUTH_KEY_EMPTY',
      message: 'servidor não devolveu chave',
    });
    return { apiKey };
  }

  async function testRunsAuth(
    apiKey: string,
    signal?: AbortSignal,
  ): Promise<AutoAuthTestResult> {
    const key = String(apiKey || '').trim();
    if (!key) throw new Error('chave da API ausente');
    const response = await fetchImpl(url('/api/runs'), {
      headers: buildApiHeaders({
        auth: {
          ghostreconApiKey: key,
          headers: {},
          cookie: '',
        },
      }),
      signal,
    });
    const body = await responseJson(response);
    return {
      authenticated: response.ok && body.ok !== false,
      body,
      runCount: Array.isArray(body.runs) ? body.runs.length : 0,
      status: response.status,
    };
  }

  async function autoAuth(
    options: { force?: boolean; signal?: AbortSignal } = {},
  ): Promise<AutoAuthResult> {
    const existing = safeRead(currentStorage(), STORAGE_KEYS.auth);
    if (!options.force && existing) {
      return {
        apiKey: readOptionalAuthConfig(currentStorage())?.ghostreconApiKey || '',
        authTest: null,
        authenticated: null,
        persisted: true,
        skipped: true,
      };
    }

    const setup = await setupAutoAuth(options.signal);
    const persisted = safeWrite(currentStorage(), STORAGE_KEYS.auth, JSON.stringify({
      ghostreconApiKey: setup.apiKey,
      headers: {},
      cookie: '',
      programHeadersEnabled: false,
      programHeadersRaw: '',
    }));
    const authTest = await testRunsAuth(setup.apiKey, options.signal);
    return {
      apiKey: setup.apiKey,
      authTest,
      authenticated: authTest.authenticated,
      persisted,
      skipped: false,
    };
  }

  async function autoRagStatus(signal?: AbortSignal): Promise<AutoRagStatus> {
    const body = await getJson('/api/auto-rag/status', signal);
    return {
      ...body,
      ok: true,
      vault: String(body.vault || 'auto-rag'),
      partition: String(body.partition || ''),
      count: normalizedNumber(body.count),
      counts: normalizedCounts(body.counts),
      recent: normalizedRecords(body.recent),
    };
  }

  async function intelCorpus(target: string, signal?: AbortSignal): Promise<IntelCorpus> {
    const normalized = normalizedTarget(target);
    if (!isInfraHistoryTarget(normalized)) throw new Error('domínio inválido');
    const body = await getJson(`/api/intel/${encodeURIComponent(normalized)}`, signal);
    return {
      ...body,
      target: normalizedTarget(body.target) || normalized,
      totalUnique: normalizedNumber(body.totalUnique),
      items: normalizedRecords(body.items),
    };
  }

  async function refreshToolPath(signal?: AbortSignal): Promise<JsonRecord> {
    return postJson('/api/tool-path-refresh', {}, signal);
  }

  async function tunnelStatus(signal?: AbortSignal): Promise<TunnelStatus> {
    return normalizeTunnelStatus(await getJson('/api/tunnel/status', signal));
  }

  async function setTunnelState(
    action: 'enable' | 'disable',
    options: { dryRun?: boolean; systemMode?: boolean; signal?: AbortSignal } = {},
  ): Promise<TunnelMutationResult> {
    if (action !== 'enable' && action !== 'disable') throw new Error('ação de tunnel inválida');
    const payload: JsonRecord = { dryRun: options.dryRun === true };
    if (options.systemMode !== undefined) payload.systemMode = options.systemMode === true;
    const body = await postJson(`/api/tunnel/${action}`, payload, options.signal);
    return {
      ...body,
      action,
      ok: true,
      run: record(body.run),
      status: normalizeTunnelStatus(body.status),
    };
  }

  async function enableTunnel(
    options: { dryRun?: boolean; systemMode?: boolean; signal?: AbortSignal } = {},
  ): Promise<TunnelMutationResult> {
    return setTunnelState('enable', options);
  }

  async function disableTunnel(
    options: { dryRun?: boolean; systemMode?: boolean; signal?: AbortSignal } = {},
  ): Promise<TunnelMutationResult> {
    return setTunnelState('disable', options);
  }

  async function listRuns(limit = 10, signal?: AbortSignal): Promise<RunsList> {
    const normalizedLimit = Math.max(1, Math.min(500, Math.floor(Number(limit) || 10)));
    const body = await getJson(`/api/runs?limit=${normalizedLimit}`, signal);
    return { ...body, runs: normalizedRecords(body.runs) };
  }

  async function runDetail(id: string | number, signal?: AbortSignal): Promise<JsonRecord> {
    return getJson(`/api/runs/${runId(id)}`, signal);
  }

  async function downloadRun(
    id: string | number,
    signal?: AbortSignal,
  ): Promise<RunDownloadArtifact> {
    const normalizedId = runId(id);
    const run = await runDetail(normalizedId, signal);
    return {
      content: JSON.stringify(run, null, 2),
      filename: `ghostrecon_run_${normalizedId}.json`,
      mimeType: 'application/json',
      run,
    };
  }

  async function manualValidationFingerprints(
    target: string,
    signal?: AbortSignal,
  ): Promise<ManualValidationFingerprints> {
    const normalized = normalizedTarget(target);
    if (!isInfraHistoryTarget(normalized)) {
      return { target: normalized, items: [], fingerprints: [] };
    }
    const body = await getJson(
      `/api/manual-validations/${encodeURIComponent(normalized)}`,
      signal,
    );
    const items = normalizedRecords(body.items);
    const fingerprints = [...new Set(
      items.map((item) => String(item.fingerprint || '').trim().toLowerCase()).filter(Boolean),
    )];
    return {
      ...body,
      target: normalizedTarget(body.target) || normalized,
      items,
      fingerprints,
    };
  }

  async function lmStudioCheck(signal?: AbortSignal): Promise<JsonRecord> {
    const body = await getJson('/api/ai/lmstudio-check', signal);
    return { ...body, ok: true };
  }

  return Object.freeze({
    autoAuth,
    autoRagStatus,
    disableTunnel,
    downloadRun,
    enableTunnel,
    intelCorpus,
    listRuns,
    lmStudioCheck,
    manualValidationFingerprints,
    refreshToolPath,
    requestCsrfToken,
    runDetail,
    setTunnelState,
    setupAutoAuth,
    testRunsAuth,
    tunnelStatus,
  });
}

export type InfraHistoryService = ReturnType<typeof createInfraHistoryService>;
