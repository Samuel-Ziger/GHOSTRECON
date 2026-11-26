export const REPORT_PAYLOAD_KEY = 'ghostrecon_reporte_payload';
export const REPORT_SHARED_KEY = 'ghostrecon_reporte_payload_shared';
export const ANNOTATION_PAYLOAD_KEY = 'ghostrecon_anotacao_payload';
export const ANNOTATION_HANDOFF_KEY = 'ghostrecon_anotacao_handoff_v1';
export const MITRE_SESSION_KEY = 'ghostrecon_mitre_live_session_id';
export const REPORT_IMPORT_MAX = 6000;

export type TaxonomyTag = string | {
  id?: unknown;
  title?: unknown;
  label?: unknown;
  url?: unknown;
};

export type ReportFinding = {
  fingerprint?: string;
  meta?: string;
  mitre?: TaxonomyTag[];
  owasp?: TaxonomyTag[];
  prio?: string;
  priority?: string;
  score?: unknown;
  type?: string;
  url?: string;
  value?: string;
  [key: string]: unknown;
};

export type ManualValidation = {
  brainCategoryTitle?: unknown;
  fingerprint?: unknown;
  notes?: unknown;
  snapshot?: Record<string, unknown> | null;
  validated_at?: unknown;
};

export type ReportPayload = {
  exportedAt?: unknown;
  findings?: unknown[];
  subsetFilter?: unknown;
  target?: unknown;
  updatedAt?: unknown;
};

export type AnnotationMap = Record<'s1' | 's2' | 's3' | 's4' | 's5' | 's6' | 's7' | 's8' | 's9' | 's10', string>;

const FP_URL_TYPES = new Set([
  'endpoint', 'param', 'js', 'security', 'tls', 'nuclei', 'xss', 'sqli',
  'dalfox', 'wpscan', 'intel',
]);
const ANN_KEYS = ['s1', 's2', 's3', 's4', 's5', 's6', 's7', 's8', 's9', 's10'] as const;

export function normalizeTarget(raw: unknown): string {
  let value = String(raw || '').trim().toLowerCase().replace(/^\*\./, '');
  if (!value) return '';
  if (/^[a-z][a-z0-9+.-]*:\/\//.test(value)) {
    try { value = String(new URL(value).hostname || '').toLowerCase(); } catch { /* keep fallback */ }
  } else if (/[/?#]/.test(value)) {
    [value] = value.split(/[/?#]/, 1);
  }
  return value.replace(/:\d+$/, '').replace(/\.$/, '');
}

export function targetUsableForApi(raw: unknown): boolean {
  const value = normalizeTarget(raw);
  return Boolean(value && /^[a-z0-9][a-z0-9.-]*[a-z0-9]$/.test(value));
}

export function deriveTargetFromFinding(finding: ReportFinding | null | undefined): string {
  if (!finding) return '';
  for (const candidate of [finding.url, finding.value]) {
    const raw = String(candidate || '').trim();
    if (!raw) continue;
    if (/^[a-z][a-z0-9+.-]*:\/\//i.test(raw)) {
      try {
        const host = normalizeTarget(new URL(raw).hostname);
        if (targetUsableForApi(host)) return host;
      } catch { /* try direct target */ }
    }
    const direct = normalizeTarget(raw);
    if (targetUsableForApi(direct)) return direct;
  }
  return '';
}

export function deriveTargetFromFindings(findings: ReportFinding[]): string {
  for (const finding of findings) {
    const target = deriveTargetFromFinding(finding);
    if (target) return target;
  }
  return '';
}

export function normalizeSpace(value: unknown): string {
  return String(value == null ? '' : value).trim().toLowerCase().replace(/\s+/g, ' ');
}

export function normalizeUrlForFingerprint(value: unknown): string {
  if (!value) return '';
  try {
    const url = new URL(String(value));
    url.hash = '';
    const keys = [...new Set([...url.searchParams.keys()])].sort();
    const search = new URLSearchParams();
    for (const key of keys) for (const item of url.searchParams.getAll(key)) search.append(key, item);
    url.search = search.size ? `?${search.toString()}` : '';
    return url.href.toLowerCase();
  } catch {
    return normalizeSpace(value);
  }
}

export async function sha256Hex(value: unknown): Promise<string> {
  if (!globalThis.crypto?.subtle || typeof TextEncoder === 'undefined') {
    throw new Error('SHA-256 indisponível neste browser');
  }
  const data = new TextEncoder().encode(String(value || ''));
  const digest = await globalThis.crypto.subtle.digest('SHA-256', data);
  return [...new Uint8Array(digest)].map((byte) => byte.toString(16).padStart(2, '0')).join('');
}

export function normalizeImportedFinding(input: unknown): ReportFinding | null {
  if (!input || typeof input !== 'object' || Array.isArray(input)) return null;
  const finding = input as Record<string, unknown>;
  const fingerprint = String(finding.fingerprint || '').trim().toLowerCase();
  const priority = finding.prio ?? finding.priority ?? '';
  const output: ReportFinding = {
    type: String(finding.type ?? ''),
    prio: String(priority ?? ''),
    value: String(finding.value ?? ''),
    url: String(finding.url ?? ''),
    meta: String(finding.meta ?? ''),
  };
  if (finding.score != null) output.score = finding.score;
  if (Array.isArray(finding.owasp)) output.owasp = finding.owasp as TaxonomyTag[];
  if (Array.isArray(finding.mitre)) output.mitre = finding.mitre as TaxonomyTag[];
  if (/^[a-f0-9]{64}$/.test(fingerprint)) output.fingerprint = fingerprint;
  return output;
}

export async function ensureFindingFingerprint(targetRaw: unknown, finding: ReportFinding): Promise<ReportFinding> {
  const output = { ...finding };
  const existing = String(output.fingerprint || '').trim().toLowerCase();
  if (/^[a-f0-9]{64}$/.test(existing)) {
    output.fingerprint = existing;
    return output;
  }
  const type = normalizeSpace(output.type);
  const url = FP_URL_TYPES.has(type) ? normalizeUrlForFingerprint(output.url) : normalizeSpace(output.url);
  output.fingerprint = await sha256Hex(`${normalizeSpace(targetRaw)}|${type}|${normalizeSpace(output.value)}|${url}`);
  return output;
}

export async function hydrateFindings(rows: unknown[], target: unknown): Promise<ReportFinding[]> {
  const output: ReportFinding[] = [];
  for (const row of rows.slice(0, REPORT_IMPORT_MAX)) {
    const normalized = normalizeImportedFinding(row);
    if (!normalized) continue;
    try { output.push(await ensureFindingFingerprint(target, normalized)); }
    catch { output.push({ ...normalized, fingerprint: '' }); }
  }
  return output;
}

export function extractFindings(root: unknown): unknown[] {
  if (Array.isArray(root)) return root;
  if (!root || typeof root !== 'object') return [];
  const record = root as Record<string, unknown>;
  if (Array.isArray(record.findings)) return record.findings;
  if (Array.isArray(record.items)) return record.items;
  return [];
}

export function normalizeTaxonomy(list: unknown, pattern: RegExp): Array<{ id: string; title?: string; label?: string; url?: string }> {
  const output: Array<{ id: string; title?: string; label?: string; url?: string }> = [];
  for (const value of Array.isArray(list) ? list : []) {
    const tag = value && typeof value === 'object' ? value as Record<string, unknown> : null;
    const id = String(typeof value === 'string' ? value : tag?.id || '').trim().toUpperCase();
    if (!pattern.test(id) || output.some((item) => item.id === id)) continue;
    output.push({
      id,
      ...(tag?.title != null ? { title: String(tag.title) } : {}),
      ...(tag?.label != null ? { label: String(tag.label) } : {}),
      ...(tag?.url != null ? { url: String(tag.url) } : {}),
    });
  }
  return output.slice(0, 12);
}

export function taxonomyIds(list: unknown, pattern: RegExp): string[] {
  return normalizeTaxonomy(list, pattern).map((item) => item.id);
}

export function isDorkFinding(finding: ReportFinding): boolean {
  const type = String(finding.type || '').trim().toLowerCase();
  if (type === 'dork' || type === 'dorks') return true;
  return /\bdork\b|google\s*dork|ghdb|search\s*dork/i.test(String(finding.meta || ''));
}

export function applySubset(findings: ReportFinding[], subset: unknown, validated = new Set<string>()): ReportFinding[] {
  const mode = String(subset || '').toLowerCase();
  if (mode === 'high') {
    return findings.filter((finding) => ['high', 'critical'].includes(String(finding.prio || finding.priority || '').toLowerCase())).map((finding) => ({ ...finding }));
  }
  if (mode === 'validated') {
    return findings.filter((finding) => validated.has(String(finding.fingerprint || '').toLowerCase())).map((finding) => ({ ...finding }));
  }
  return findings.map((finding) => ({ ...finding }));
}

export function snapshotFromFinding(finding: ReportFinding): Record<string, unknown> {
  const owasp = normalizeTaxonomy(finding.owasp, /^A\d{2}$/i);
  const mitre = normalizeTaxonomy(finding.mitre, /^T\d{4}(?:\.\d{3})?$/i);
  return {
    type: finding.type,
    prio: finding.prio,
    value: finding.value,
    url: finding.url || '',
    meta: String(finding.meta || '').slice(0, 800),
    ...(owasp.length ? { owasp } : {}),
    ...(mitre.length ? { mitre } : {}),
  };
}

export function externalUrl(raw: unknown): string {
  const value = String(raw || '').trim();
  if (!value) return '';
  if (/^https?:\/\//i.test(value)) {
    try { return new URL(value).href; } catch { return encodeURI(value); }
  }
  if (/^[a-z][a-z0-9+.-]*:\/\//i.test(value)) return '';
  if (/^[a-z0-9][a-z0-9.-]*[a-z0-9](\/.*)?$/i.test(value)) {
    try { return new URL(`https://${value}`).href; } catch { return encodeURI(`https://${value}`); }
  }
  return '';
}

export function emptyAnnotationMap(): AnnotationMap {
  return Object.fromEntries(ANN_KEYS.map((key) => [key, ''])) as AnnotationMap;
}

function appendDedupe(text: string, line: string): string {
  const normalized = line.trim();
  if (!normalized) return text;
  if (text.split(/\r?\n/).some((item) => item.trim().toLowerCase() === normalized.toLowerCase())) return text;
  return text ? `${text}\n${normalized}` : normalized;
}

function fpSection(text: string, fingerprint: string, body: string): string {
  const fp = fingerprint.toLowerCase();
  const matcher = new RegExp(`\\n?# --- ${fp} ---\\n[\\s\\S]*?(?=\\n# --- [a-f0-9]{64} ---|$)`);
  const base = String(text || '').replace(matcher, '').trim();
  return `${base}${base ? '\n' : ''}# --- ${fp} ---\n${body.trim()}`.trim();
}

export function removeAnnotationFinding(text: string, fingerprint: string): string {
  const fp = fingerprint.toLowerCase();
  return String(text || '').replace(new RegExp(`\\n?# --- ${fp} ---\\n[\\s\\S]*?(?=\\n# --- [a-f0-9]{64} ---|$)`), '').trim();
}

export function mergeFindingIntoAnnotations(
  current: AnnotationMap,
  finding: ReportFinding,
  fingerprint: string,
  notes = '',
  target = '',
  full = true,
): AnnotationMap {
  if (!/^[a-f0-9]{64}$/.test(fingerprint)) return current;
  const next = { ...current };
  const type = String(finding.type || '').trim().toLowerCase();
  const value = String(finding.value || '').trim();
  const url = String(finding.url || '').trim();
  if (full && !next.s1.trim()) {
    next.s1 = `Alvo: ${targetUsableForApi(target) ? normalizeTarget(target) : '(indica alvo no pacote)'}\nData/Hora: ${new Date().toISOString()}\nFase: Recon — checklist Reporte (validação manual)`;
  }
  if (full) {
    if (type === 'nmap' || /\d+\/(tcp|udp)/i.test(value)) next.s2 = appendDedupe(next.s2, `- ${value || '(serviço sem descrição)'}`);
    if (['tech', 'wappalyzer', 'fingerprint', 'cms'].includes(type)) next.s3 = appendDedupe(next.s3, `- [tech] ${value || type}`);
    if (['endpoint', 'url', 'path'].includes(type)) next.s3 = appendDedupe(next.s3, `- [endpoint] ${url || value}`);
    if (['param', 'parameter'].includes(type)) next.s3 = appendDedupe(next.s3, `- [parâmetro] ${value}${url ? ` @ ${url}` : ''}`);
    next.s4 = appendDedupe(next.s4, `[ ] ${['high', 'critical'].includes(String(finding.prio || '').toLowerCase()) ? '(prioridade alta) ' : ''}${type}: ${value || '(sem valor)'}${url ? ` — ${url}` : ''}`);
    for (const id of taxonomyIds(finding.owasp, /^A\d{2}$/i)) next.s9 = appendDedupe(next.s9, `- OWASP: ${id}`);
    for (const id of taxonomyIds(finding.mitre, /^T\d{4}(?:\.\d{3})?$/i)) next.s9 = appendDedupe(next.s9, `- MITRE ATT&CK: ${id}`);
  }
  next.s5 = fpSection(next.s5, fingerprint, [
    `Tipo: ${type}`,
    `Valor / contexto: ${value || '—'}`,
    url ? `URL: ${url}` : '',
    notes.trim() ? `Notas (manual): ${notes.trim()}` : '',
    'Estado: validado no checklist Reporte.',
  ].filter(Boolean).join('\n'));
  return next;
}

export function buildReportMarkdown(target: string, findings: ReportFinding[], validated: Set<string>, notes: Record<string, string>): string {
  const rows = findings.filter((finding) => validated.has(String(finding.fingerprint || '').toLowerCase()));
  const lines = [`# Relatório GHOSTRECON`, '', `- Alvo: ${normalizeTarget(target) || 'n/d'}`, `- Gerado: ${new Date().toISOString()}`, `- Validados: ${rows.length}`, ''];
  rows.forEach((finding, index) => {
    const fp = String(finding.fingerprint || '').toLowerCase();
    lines.push(`## ${index + 1}. ${finding.type || 'finding'} · ${finding.prio || '—'}`, '', String(finding.value || '—'));
    if (finding.url) lines.push('', `URL: ${finding.url}`);
    if (notes[fp]) lines.push('', `Notas: ${notes[fp]}`);
    lines.push('', `Fingerprint: ${fp}`, '');
  });
  return lines.join('\n');
}

export function buildReportHtml(markdown: string): string {
  const escaped = markdown.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
  return `<!doctype html><html lang="pt"><meta charset="utf-8"><title>Relatório GHOSTRECON</title><style>body{font:14px system-ui;max-width:900px;margin:40px auto;padding:0 24px;white-space:pre-wrap;color:#18202b}h1{color:#075985}</style><body>${escaped}</body></html>`;
}
