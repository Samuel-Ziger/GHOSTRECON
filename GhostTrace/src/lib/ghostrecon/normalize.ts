import type { Severity } from '@/lib/types';
import type { GhostreconFinding, GhostreconHandoffPayload } from './types';
import { REPORT_IMPORT_MAX } from './constants';

const FP_URL_NORMALIZE_TYPES = new Set([
  'endpoint',
  'param',
  'js',
  'security',
  'tls',
  'nuclei',
  'xss',
  'sqli',
  'dalfox',
  'wpscan',
  'intel'
]);

export function normalizeTarget(raw: string): string {
  let s = String(raw || '').trim().toLowerCase();
  if (!s) return '';
  s = s.replace(/^\*\./, '');
  if (/^[a-z][a-z0-9+.-]*:\/\//.test(s)) {
    try {
      s = new URL(s).hostname.toLowerCase();
    } catch {
      /* ignore */
    }
  } else if (/[/?#]/.test(s)) {
    s = s.split(/[/?#]/, 1)[0];
  }
  return s.replace(/:\d+$/, '').replace(/\.$/, '');
}

export function targetUsable(t: string): boolean {
  const s = normalizeTarget(t);
  return Boolean(s && /^[a-z0-9][a-z0-9.-]*[a-z0-9]$/.test(s));
}

function normUrlForFp(u: string): string {
  if (!u) return '';
  try {
    const x = new URL(String(u));
    x.hash = '';
    const keys = [...new Set([...x.searchParams.keys()])].sort();
    const sp = new URLSearchParams();
    for (const k of keys) for (const v of x.searchParams.getAll(k)) sp.append(k, v);
    x.search = sp.toString() ? '?' + sp.toString() : '';
    return x.href.toLowerCase();
  } catch {
    return String(u || '')
      .trim()
      .toLowerCase()
      .replace(/\s+/g, ' ');
  }
}

export async function sha256Hex(text: string): Promise<string> {
  const data = new TextEncoder().encode(String(text || ''));
  const dig = await crypto.subtle.digest('SHA-256', data);
  return Array.from(new Uint8Array(dig))
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('');
}

export async function ensureFingerprint(
  f: GhostreconFinding,
  target: string
): Promise<GhostreconFinding> {
  const fo = { ...f };
  if (/^[a-f0-9]{64}$/.test(String(fo.fingerprint || ''))) return fo;
  const typeNorm = String(fo.type || '')
    .trim()
    .toLowerCase();
  const urlPart = FP_URL_NORMALIZE_TYPES.has(typeNorm)
    ? normUrlForFp(fo.url || '')
    : String(fo.url || '')
        .trim()
        .toLowerCase()
        .replace(/\s+/g, ' ');
  const raw =
    String(target || '')
      .trim()
      .toLowerCase() +
    '|' +
    typeNorm +
    '|' +
    String(fo.value || '')
      .trim()
      .toLowerCase()
      .replace(/\s+/g, ' ') +
    '|' +
    urlPart;
  try {
    fo.fingerprint = await sha256Hex(raw);
  } catch {
    fo.fingerprint = '';
  }
  return fo;
}

export function prioToSeverity(prio?: string): Severity {
  const p = String(prio || '').toLowerCase();
  if (p === 'critical') return 'critical';
  if (p === 'high') return 'high';
  if (p === 'medium') return 'medium';
  if (p === 'low') return 'low';
  return 'info';
}

export function normalizeImportedFinding(f: unknown): GhostreconFinding | null {
  if (!f || typeof f !== 'object') return null;
  const row = f as Record<string, unknown>;
  const fp = String(row.fingerprint || '')
    .trim()
    .toLowerCase();
  const out: GhostreconFinding = {
    type: String(row.type ?? ''),
    prio: String(row.prio ?? row.priority ?? ''),
    value: String(row.value ?? ''),
    url: String(row.url ?? ''),
    meta: String(row.meta ?? '')
  };
  if (row.score != null) out.score = Number(row.score);
  if (row.owasp) out.owasp = String(row.owasp);
  if (row.mitre) out.mitre = String(row.mitre);
  if (row.cvss) out.cvss = String(row.cvss);
  if (/^[a-f0-9]{64}$/.test(fp)) out.fingerprint = fp;
  return out;
}

export function extractFindings(obj: unknown): unknown[] {
  if (Array.isArray(obj)) return obj;
  if (obj && typeof obj === 'object') {
    const o = obj as Record<string, unknown>;
    if (Array.isArray(o.findings)) return o.findings;
    if (Array.isArray(o.items)) return o.items;
  }
  return [];
}

export async function normalizeHandoffPayload(
  pack: GhostreconHandoffPayload
): Promise<{
  target: string;
  findings: GhostreconFinding[];
  validatedFingerprints: string[];
}> {
  const target = normalizeTarget(pack.target || '');
  const rawFindings = extractFindings(pack)
    .map(normalizeImportedFinding)
    .filter((x): x is GhostreconFinding => Boolean(x))
    .slice(0, REPORT_IMPORT_MAX);
  const findings = await Promise.all(rawFindings.map((f) => ensureFingerprint(f, target)));

  const validated = new Set<string>();
  for (const row of pack.manualValidations || []) {
    const fp = String(row.fingerprint || '')
      .trim()
      .toLowerCase();
    if (/^[a-f0-9]{64}$/.test(fp)) validated.add(fp);
  }

  return {
    target,
    findings,
    validatedFingerprints: [...validated]
  };
}
