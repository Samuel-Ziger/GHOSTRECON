/** Cliente HTTP para a API GHOSTRECON (mesma origem quando servido via proxy /anotacao). */

function getApiBase(): string {
  if (typeof window === 'undefined') return '';
  const env = process.env.NEXT_PUBLIC_GHOSTRECON_API?.trim();
  if (env) return env.replace(/\/+$/, '');
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
  const base = getApiBase();
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

let csrfCache = '';

export async function fetchCsrf(): Promise<string> {
  const r = await fetch(apiUrl('/api/csrf-token'));
  const d = await r.json();
  csrfCache = String(d.token || '');
  if (!csrfCache) throw new Error('CSRF vazio');
  return csrfCache;
}

export async function fetchHandoffById(id: string): Promise<unknown> {
  const clean = id.trim().toLowerCase().replace(/[^a-f0-9]/g, '');
  const r = await fetch(apiUrl(`/api/anotacao-handoff/${encodeURIComponent(clean)}`));
  const d = await r.json().catch(() => ({}));
  if (!r.ok) throw new Error((d as { error?: string }).error || `GET handoff: ${r.status}`);
  return d;
}

export async function postAnnotationsAi(markdown: string, target: string): Promise<string> {
  await fetchCsrf();
  const r = await fetch(apiUrl('/api/manual-validations/annotations-ai'), {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'X-CSRF-Token': csrfCache,
      ...authHeaders()
    },
    body: JSON.stringify({ markdown, target })
  });
  const d = await r.json().catch(() => ({}));
  if (!r.ok) throw new Error((d as { error?: string }).error || String(r.status));
  return String((d as { markdown?: string }).markdown || '').trim();
}

export async function fetchCapabilities(): Promise<{ ai?: { openrouter?: boolean } }> {
  try {
    const r = await fetch(apiUrl('/api/capabilities'));
    if (!r.ok) return {};
    return await r.json();
  } catch {
    return {};
  }
}

export async function listManualValidations(target: string): Promise<
  Array<{ fingerprint?: string; notes?: string }>
> {
  const r = await fetch(apiUrl(`/api/manual-validations/${encodeURIComponent(target)}`));
  if (!r.ok) throw new Error(`GET validações: ${r.status}`);
  const d = await r.json();
  return Array.isArray((d as { items?: unknown }).items)
    ? ((d as { items: Array<{ fingerprint?: string; notes?: string }> }).items ?? [])
    : [];
}
