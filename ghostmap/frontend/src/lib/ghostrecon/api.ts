import type { HistoryEntry } from './types';

function apiBase(): string {
  const env = process.env.NEXT_PUBLIC_GHOSTRECON_API?.trim();
  if (env) return env.replace(/\/+$/, '');
  if (typeof window === 'undefined') return '';
  try {
    const proto = window.location.protocol;
    if (proto === 'file:' || proto === 'blob:') {
      return (
        localStorage.getItem('ghostrecon_api_base') || 'http://127.0.0.1:3847'
      ).replace(/\/+$/, '');
    }
  } catch {
    /* ignore */
  }
  return '';
}

export function apiUrl(path: string): string {
  const base = apiBase();
  const p = path.startsWith('/') ? path : `/${path}`;
  return base ? base + p : p;
}

export function authHeaders(): Record<string, string> {
  try {
    const j = JSON.parse(localStorage.getItem('ghostrecon_auth_json') || '{}');
    return j.ghostreconApiKey ? { 'X-API-Key': String(j.ghostreconApiKey) } : {};
  } catch {
    return {};
  }
}

export async function fetchCsrf(): Promise<string> {
  const r = await fetch(apiUrl('/api/csrf-token'), { headers: authHeaders() });
  const d = await r.json();
  const token = String(d.token || '');
  if (!token) throw new Error('CSRF vazio');
  return token;
}

export async function fetchHistory(opts: {
  limit?: number;
  after?: number;
  target?: string;
}): Promise<HistoryEntry[]> {
  const params = new URLSearchParams();
  params.set('limit', String(opts.limit ?? 1000));
  if (opts.after) params.set('after', String(opts.after));
  if (opts.target) params.set('target', opts.target);
  const r = await fetch(`${apiUrl('/api/history/recon')}?${params}`, {
    headers: authHeaders()
  });
  if (!r.ok) throw new Error(`HTTP ${r.status}`);
  const data = await r.json();
  return Array.isArray(data.items) ? data.items : [];
}

export interface ProxyStatus {
  ok?: boolean;
  running?: boolean;
  mitmEnabled?: boolean;
  port?: number;
  capturedCount?: number;
}

export async function fetchProxyStatus(): Promise<ProxyStatus> {
  const r = await fetch(apiUrl('/api/proxy/status'), { headers: authHeaders() });
  if (!r.ok) return {};
  return r.json();
}

export async function proxyAction(
  action: 'start' | 'stop' | 'mitm',
  body?: { enabled?: boolean }
): Promise<ProxyStatus> {
  const token = await fetchCsrf();
  const r = await fetch(apiUrl(`/api/proxy/${action}`), {
    method: 'POST',
    headers: {
      ...authHeaders(),
      'Content-Type': 'application/json',
      'X-CSRF-Token': token
    },
    body: JSON.stringify(body ?? {})
  });
  const d = await r.json();
  if (!d.ok) throw new Error(d.error || String(r.status));
  return d;
}
