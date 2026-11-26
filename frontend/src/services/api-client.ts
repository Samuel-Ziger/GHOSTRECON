import { safeRead, STORAGE_KEYS, type StorageLike } from './storage';

export type OptionalAuthConfig = {
  ghostreconApiKey: string;
  headers: Record<string, string>;
  cookie: string;
  programHeadersEnabled?: boolean;
  programHeadersRaw?: string;
};

export type PipelineAuthConfig = {
  headers: Record<string, string>;
  cookie: string;
};

export function resolveApiBase({
  protocol,
  storage,
  fallback = 'http://127.0.0.1:3847',
}: {
  protocol: string;
  storage?: StorageLike | null;
  fallback?: string;
}): string {
  if (protocol !== 'file:' && protocol !== 'blob:') return '';
  return String(safeRead(storage, STORAGE_KEYS.apiBase) || fallback).replace(/\/+$/, '');
}

export function apiUrl(pathname: string, base = ''): string {
  const path = pathname.startsWith('/') ? pathname : `/${pathname}`;
  return base ? `${base.replace(/\/+$/, '')}${path}` : path;
}

export function parseProgramHeaders(raw: unknown): Record<string, string> {
  const headers: Record<string, string> = {};
  for (const line of String(raw || '').split(/\r?\n/)) {
    const normalized = line.trim();
    if (!normalized) continue;
    const separator = normalized.indexOf(':');
    if (separator <= 0) continue;
    const name = normalized.slice(0, separator).trim();
    const value = normalized.slice(separator + 1).trim();
    if (name && value) headers[name] = value;
  }
  return headers;
}

export function readOptionalAuthConfig(
  storage: StorageLike | null | undefined,
): OptionalAuthConfig | null {
  const raw = safeRead(storage, STORAGE_KEYS.auth);
  if (!raw) return null;
  try {
    const parsed = JSON.parse(raw) as Record<string, unknown>;
    if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) return null;
    const headers = parsed.headers && typeof parsed.headers === 'object' && !Array.isArray(parsed.headers)
      ? Object.fromEntries(
        Object.entries(parsed.headers as Record<string, unknown>)
          .map(([name, value]) => [name, String(value ?? '')])
          .filter(([, value]) => Boolean(value)),
      )
      : {};
    return {
      ghostreconApiKey: parsed.ghostreconApiKey ? String(parsed.ghostreconApiKey) : '',
      headers,
      cookie: parsed.cookie ? String(parsed.cookie) : '',
      programHeadersEnabled: parsed.programHeadersEnabled === true,
      programHeadersRaw: parsed.programHeadersRaw ? String(parsed.programHeadersRaw) : '',
    };
  } catch {
    return null;
  }
}

export function toPipelineAuth(config: OptionalAuthConfig | null): PipelineAuthConfig | null {
  if (!config) return null;
  const headers = { ...config.headers };
  const cookie = String(config.cookie || '');
  return Object.keys(headers).length || cookie ? { headers, cookie } : null;
}

export function buildApiHeaders({
  auth,
  csrfToken,
  json = false,
}: {
  auth?: OptionalAuthConfig | null;
  csrfToken?: string | null;
  json?: boolean;
} = {}): Record<string, string> {
  const headers: Record<string, string> = {};
  if (json) headers['Content-Type'] = 'application/json';
  if (auth?.ghostreconApiKey) headers['X-API-Key'] = auth.ghostreconApiKey;
  if (csrfToken) headers['X-CSRF-Token'] = csrfToken;
  return headers;
}

export async function requestCsrfToken({
  fetchImpl = fetch,
  base = '',
  auth = null,
  signal,
}: {
  fetchImpl?: typeof fetch;
  base?: string;
  auth?: OptionalAuthConfig | null;
  signal?: AbortSignal;
} = {}): Promise<string> {
  const response = await fetchImpl(apiUrl('/api/csrf-token', base), {
    headers: buildApiHeaders({ auth }),
    signal,
  });
  if (!response.ok) throw new Error(`falha ao obter token CSRF (HTTP ${response.status})`);
  const body = await response.json() as { token?: unknown };
  const token = String(body?.token || '');
  if (!token) throw new Error('token CSRF vazio');
  return token;
}
