import type { CortexCategory, CortexLink, CortexSnapshot } from './model';

type JsonRecord = Record<string, unknown>;

export type CortexService = ReturnType<typeof createCortexService>;

export function cortexApiBase(locationLike: Pick<Location, 'href' | 'protocol'>): string {
  if (locationLike.protocol === 'file:') return 'http://127.0.0.1:3847';
  return new URL('.', locationLike.href).origin;
}

export function cortexApiUrl(pathname: string, base: string): string {
  const path = pathname.startsWith('/') ? pathname : `/${pathname}`;
  return `${base.replace(/\/+$/, '')}${path}`;
}

async function readJson(response: Response): Promise<JsonRecord> {
  return response.json().catch(() => ({})) as Promise<JsonRecord>;
}

function responseError(body: JsonRecord, response: Response): Error {
  return new Error(String(body.error || response.status));
}

export function createCortexService({
  fetchImpl = fetch,
  locationLike = window.location,
}: {
  fetchImpl?: typeof fetch;
  locationLike?: Pick<Location, 'href' | 'protocol'>;
} = {}) {
  const base = cortexApiBase(locationLike);
  const url = (pathname: string) => cortexApiUrl(pathname, base);

  async function csrf(signal?: AbortSignal): Promise<string> {
    const response = await fetchImpl(url('/api/csrf-token'), { signal });
    const body = await readJson(response);
    const token = String(body.token || '');
    if (!response.ok || !token) throw responseError(body, response);
    return token;
  }

  async function listCategories(signal?: AbortSignal): Promise<CortexCategory[]> {
    const response = await fetchImpl(url('/api/brain/categories'), {
      cache: 'no-store',
      signal,
    });
    const body = await readJson(response);
    if (!response.ok) throw responseError(body, response);
    return Array.isArray(body.items) ? body.items as CortexCategory[] : [];
  }

  async function getCategory(categoryId: number, signal?: AbortSignal): Promise<{
    category: CortexCategory;
    links: CortexLink[];
  }> {
    const response = await fetchImpl(url(`/api/brain/category/${encodeURIComponent(String(categoryId))}`), {
      cache: 'no-store',
      signal,
    });
    const body = await readJson(response);
    if (!response.ok) throw responseError(body, response);
    return {
      category: (body.category || { id: categoryId, title: 'Categoria' }) as CortexCategory,
      links: Array.isArray(body.links) ? body.links as CortexLink[] : [],
    };
  }

  async function saveCategoryDescription(
    categoryId: number,
    description: string,
    signal?: AbortSignal,
  ): Promise<CortexCategory> {
    const token = await csrf(signal);
    const response = await fetchImpl(
      url(`/api/brain/categories/${encodeURIComponent(String(categoryId))}/description`),
      {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'X-CSRF-Token': token },
        body: JSON.stringify({ description: String(description || '').trim().slice(0, 2000) }),
        signal,
      },
    );
    const body = await readJson(response);
    if (!response.ok) throw responseError(body, response);
    return (body.category || { id: categoryId, description }) as CortexCategory;
  }

  async function saveValidation(
    link: CortexLink,
    { notes, marked }: { notes: string; marked: boolean },
    signal?: AbortSignal,
  ): Promise<{ notes: string; snapshot: CortexSnapshot }> {
    const token = await csrf(signal);
    const snapshot: CortexSnapshot = link.snapshot && typeof link.snapshot === 'object'
      ? { ...link.snapshot }
      : {};
    if (marked) snapshot.cortex_marked = true;
    else delete snapshot.cortex_marked;
    const normalizedNotes = String(notes || '').slice(0, 2000);
    const response = await fetchImpl(url('/api/manual-validations'), {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'X-CSRF-Token': token },
      body: JSON.stringify({
        target: link.target,
        fingerprint: link.fingerprint,
        validated: true,
        snapshot,
        notes: normalizedNotes,
      }),
      signal,
    });
    const body = await readJson(response);
    if (!response.ok) throw responseError(body, response);
    return { notes: normalizedNotes, snapshot };
  }

  return Object.freeze({
    apiBase: base,
    getCategory,
    listCategories,
    saveCategoryDescription,
    saveValidation,
  });
}
