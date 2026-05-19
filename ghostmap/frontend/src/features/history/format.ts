import type { HistoryEntry } from '@/lib/ghostrecon/types';
import { mimeCategory } from '@/lib/ghostrecon/history-utils';

export function esc(s: string): string {
  return s
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;');
}

export function formatRawRequest(entry: HistoryEntry): string {
  const lines: string[] = [];
  const method = String(entry.method || 'GET').toUpperCase();
  let path = '/';
  try {
    const u = new URL(entry.url || '');
    path = u.pathname + (u.search || '');
  } catch {
    path = entry.url || '/';
  }
  lines.push(`${method} ${path} HTTP/1.1`);
  const hdrs = entry.requestHeaders || {};
  for (const [k, v] of Object.entries(hdrs)) lines.push(`${k}: ${v}`);
  if (entry.requestBody?.trim()) {
    lines.push('');
    lines.push(entry.requestBody);
  }
  return lines.join('\n');
}

export function formatRawResponse(entry: HistoryEntry): string {
  const lines: string[] = [];
  const status = entry.error
    ? `ERROR ${entry.error}`
    : `HTTP/1.1 ${entry.status ?? '-'} ${entry.statusText || ''}`.trim();
  lines.push(status);
  const hdrs = entry.responseHeaders || {};
  for (const [k, v] of Object.entries(hdrs)) lines.push(`${k}: ${v}`);
  if (entry.responseBody?.trim()) {
    lines.push('');
    lines.push(entry.responseBody);
  }
  return lines.join('\n');
}

export function prettyResponseBody(entry: HistoryEntry): string {
  if (!entry.responseBody?.trim()) return '';
  if (mimeCategory(entry) === 'json') {
    try {
      return JSON.stringify(JSON.parse(entry.responseBody), null, 2);
    } catch {
      /* fall through */
    }
  }
  return entry.responseBody;
}

export function headersTable(
  hdrs?: Record<string, string>
): { name: string; value: string }[] {
  if (!hdrs) return [];
  return Object.entries(hdrs).map(([name, value]) => ({ name, value }));
}
