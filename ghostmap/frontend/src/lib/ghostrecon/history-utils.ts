import type { HistoryEntry, HistoryFilters, HistorySortCol } from './types';

export function hostOf(url?: string): string {
  if (!url) return '';
  try {
    return new URL(url).host;
  } catch {
    return url.split('/')[0] || url;
  }
}

export function pathOf(url?: string): string {
  if (!url) return '';
  try {
    const u = new URL(url);
    return u.pathname + (u.search || '');
  } catch {
    return url;
  }
}

export function extOf(url?: string): string {
  try {
    const p = new URL(url || '').pathname;
    const m = p.match(/\.([a-zA-Z0-9]{1,6})$/);
    return m ? m[1].toLowerCase() : '';
  } catch {
    return '';
  }
}

export function hasParams(entry: HistoryEntry): boolean {
  try {
    if (new URL(entry.url || '').search.length > 1) return true;
  } catch {
    /* ignore */
  }
  return Boolean(entry.requestBody?.trim());
}

export function fmtSize(n?: number | null): string {
  if (n == null || Number.isNaN(Number(n))) return '-';
  const v = Number(n);
  if (v >= 1048576) return `${(v / 1048576).toFixed(1)}M`;
  if (v >= 1024) return `${(v / 1024).toFixed(1)}K`;
  return `${v}B`;
}

export function mimeCategory(entry: HistoryEntry): string {
  const m = entry.mimeType || '';
  if (/json/.test(m)) return 'json';
  if (/html/.test(m)) return 'html';
  if (/javascript|ecmascript/.test(m)) return 'js';
  if (/css/.test(m)) return 'css';
  if (/xml/.test(m)) return 'xml';
  if (/image\//.test(m)) return 'img';
  return 'other';
}

export function mimeLabel(mime?: string): string {
  if (!mime) return '-';
  if (/json/.test(mime)) return 'json';
  if (/html/.test(mime)) return 'html';
  if (/javascript|ecmascript/.test(mime)) return 'js';
  if (/css/.test(mime)) return 'css';
  if (/xml/.test(mime)) return 'xml';
  if (/image\//.test(mime)) return 'img';
  const parts = mime.split('/');
  return (parts[1] || parts[0]).split('+')[0].slice(0, 8);
}

export function statusClass(entry: HistoryEntry): string {
  if (entry.error) return 'text-red-400';
  const s = Number(entry.status);
  if (!s) return 'text-zinc-500';
  if (s < 200) return 'text-zinc-400';
  if (s < 300) return 'text-emerald-400';
  if (s < 400) return 'text-sky-400';
  if (s < 500) return 'text-orange-400';
  return 'text-red-400';
}

export function methodClass(m: string): string {
  const map: Record<string, string> = {
    GET: 'text-cyan-400',
    POST: 'text-amber-400',
    PUT: 'text-violet-400',
    PATCH: 'text-violet-300',
    DELETE: 'text-red-400',
    HEAD: 'text-zinc-400'
  };
  return map[m.toUpperCase()] || 'text-zinc-400';
}

export function filterAndSort(
  rows: HistoryEntry[],
  filters: HistoryFilters,
  sortCol: HistorySortCol,
  sortDir: number
): HistoryEntry[] {
  const filtered = rows.filter((r) => {
    const s = filters.search.toLowerCase();
    if (s) {
      const hay = `${r.url || ''} ${r.requestBody || ''} ${r.responseBody || ''}`;
      if (!hay.toLowerCase().includes(s)) return false;
    }
    if (filters.method && String(r.method || '').toUpperCase() !== filters.method) return false;
    if (filters.status) {
      if (filters.status === 'e') {
        if (!r.error) return false;
      } else if (String(r.status || '')[0] !== filters.status) return false;
    }
    if (filters.mime && mimeCategory(r) !== filters.mime) return false;
    if (filters.source && String(r.source || '') !== filters.source) return false;
    return true;
  });

  return filtered.sort((a, b) => {
    let va: string | number = 0;
    let vb: string | number = 0;
    switch (sortCol) {
      case 'id':
        va = Number(a.id);
        vb = Number(b.id);
        break;
      case 'ms':
        va = Number(a.durationMs ?? -1);
        vb = Number(b.durationMs ?? -1);
        break;
      case 'status':
        va = Number(a.status ?? 0);
        vb = Number(b.status ?? 0);
        break;
      case 'len':
        va = Number(a.responseSize ?? -1);
        vb = Number(b.responseSize ?? -1);
        break;
      case 'host':
        va = hostOf(a.url).toLowerCase();
        vb = hostOf(b.url).toLowerCase();
        break;
      case 'url':
        va = pathOf(a.url).toLowerCase();
        vb = pathOf(b.url).toLowerCase();
        break;
      case 'method':
        va = String(a.method || '');
        vb = String(b.method || '');
        break;
      default:
        va = 0;
        vb = 0;
    }
    if (va < vb) return -sortDir;
    if (va > vb) return sortDir;
    return 0;
  });
}
