export type WorkbenchRecord = Record<string, any>;

export type AgentMode = 'autopilot' | 'swarm' | 'audit' | 'query';

export type ReviewTemplate = {
  instruction: string;
  mode: AgentMode;
  prompt: string;
};

export const REVIEW_TEMPLATES: Record<'auth' | 'pr' | 'api' | 'fp', ReviewTemplate> = {
  auth: {
    mode: 'audit',
    prompt: 'Review authentication and authorization flows. Focus on IDOR/BOLA, missing checks, privilege escalation, session handling, JWT/OIDC flaws, and unsafe middleware.',
    instruction: 'Return concrete vulnerable files/routes, exploit preconditions, impact, and minimal fixes. Prefer high-confidence issues.',
  },
  pr: {
    mode: 'autopilot',
    prompt: 'Review this PR/diff for security regressions and exploitable behavior.',
    instruction: 'Focus only on changed code paths. Include attack scenario, affected endpoint, and patch guidance.',
  },
  api: {
    mode: 'swarm',
    prompt: 'Map API routes and test auth bypass, mass assignment, rate-limit bypass, injection, SSRF, and unsafe object access.',
    instruction: 'Prioritize bugs that can be proven from request/response evidence.',
  },
  fp: {
    mode: 'query',
    prompt: 'Review the supplied finding/request/response and decide if it is a real vulnerability or likely false positive.',
    instruction: 'Answer with verdict, confidence, reasoning, missing evidence, and next verification step.',
  },
};

export function unwrapWorkbenchResponse(value: unknown): WorkbenchRecord | unknown[] {
  if (value && typeof value === 'object' && Object.hasOwn(value as object, 'data')) {
    return (value as WorkbenchRecord).data;
  }
  return (value || {}) as WorkbenchRecord;
}

export function workbenchRows(value: unknown): { rows: WorkbenchRecord[]; total: number } {
  const unwrapped = unwrapWorkbenchResponse(value);
  if (Array.isArray(unwrapped)) return { rows: unwrapped as WorkbenchRecord[], total: unwrapped.length };
  const record = unwrapped && typeof unwrapped === 'object' ? unwrapped as WorkbenchRecord : {};
  const rows = Array.isArray(record.data)
    ? record.data as WorkbenchRecord[]
    : Array.isArray(record.items)
      ? record.items as WorkbenchRecord[]
      : [];
  return { rows, total: Number(record.total ?? rows.length) };
}

export function buildQuery(values: Record<string, unknown>): string {
  const params = new URLSearchParams();
  for (const [name, value] of Object.entries(values || {})) {
    const normalized = String(value ?? '').trim();
    if (normalized) params.set(name, normalized);
  }
  return params.toString();
}

export function shortText(value: unknown, limit: number): string {
  const text = String(value ?? '');
  return text.length > limit ? `${text.slice(0, Math.max(0, limit - 1))}...` : text;
}

export function formatWorkbenchDate(value: unknown): string {
  if (!value) return '-';
  const date = new Date(String(value));
  return Number.isNaN(date.getTime()) ? String(value) : date.toLocaleString();
}

export function formatBytes(value: unknown): string {
  const size = Number(value || 0);
  if (size < 1024) return `${size} B`;
  if (size < 1024 * 1024) return `${(size / 1024).toFixed(1)} KB`;
  return `${(size / 1024 / 1024).toFixed(1)} MB`;
}

export function safeDecode(value: unknown): string {
  if (!value) return '';
  const raw = String(value);
  if (/^(GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS|HTTP\/)/.test(raw.trim())) return raw;
  try {
    return atob(raw);
  } catch {
    return raw;
  }
}

export function toBase64(value: unknown): string {
  const text = String(value || '');
  try {
    return btoa(unescape(encodeURIComponent(text)));
  } catch {
    return btoa(text);
  }
}

export function curlFor(record: WorkbenchRecord): string {
  const raw = safeDecode(record.raw_request || '');
  const fallback = raw.match(/^(\S+)/)?.[1] || 'GET';
  const method = String(record.method || fallback);
  let command = `curl -i -X ${method} '${String(record.url || '')}'`;
  const headers = raw.split(/\r?\n/).filter((line) => /^[^:]+:\s+/.test(line)).slice(0, 30);
  for (const header of headers) {
    if (/^host:/i.test(header)) continue;
    command += ` \\\n  -H '${header.replace(/'/g, "'\\''")}'`;
  }
  const body = raw.split(/\r?\n\r?\n/).slice(1).join('\n\n');
  if (body) command += ` \\\n  --data '${body.replace(/'/g, "'\\''")}'`;
  return command;
}

export function findingHost(finding: WorkbenchRecord): string {
  const matched = Array.isArray(finding.matched_at) ? finding.matched_at[0] : '';
  const value = String(finding.hostname || finding.url || matched || '');
  try {
    return new URL(value).hostname;
  } catch {
    return value || '(unknown)';
  }
}

export function groupBy<T>(items: T[], key: (item: T) => string): Array<[string, T[]]> {
  const groups = new Map<string, T[]>();
  for (const item of items) {
    const name = key(item);
    groups.set(name, [...(groups.get(name) || []), item]);
  }
  return [...groups.entries()].sort((left, right) => right[1].length - left[1].length);
}

export function statusClass(status: unknown): string {
  return `status ${String(status || '').toLowerCase().replace(/[^a-z0-9_-]+/g, '-')}`;
}

export function severityClass(severity: unknown): string {
  return `sev ${String(severity || '').toLowerCase().replace(/[^a-z0-9_-]+/g, '-')}`;
}

export function responseClass(statusCode: unknown): string {
  return `s${Math.floor(Number(statusCode || 0) / 100)}`;
}

export function normalizeMatchedAt(finding: WorkbenchRecord): string[] {
  if (Array.isArray(finding.matched_at)) return finding.matched_at.map(String);
  return [String(finding.url || '')].filter(Boolean);
}
