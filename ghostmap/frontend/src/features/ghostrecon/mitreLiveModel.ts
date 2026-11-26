export const PIPE_ORDER = [
  'input', 'subdomains', 'dns_enrichment', 'rdap', 'alive', 'surface',
  'urls', 'params', 'js', 'dorks', 'secrets', 'verify', 'webshell_probe',
  'sqlmap', 'kali', 'nmap', 'nmap_udp', 'whois', 'ffuf', 'nuclei',
  'nuclei_xss', 'nuclei_sqli', 'wpscan', 'dalfox', 'xss_vibes', 'assets',
  'score',
] as const;

export type PipeState = 'pending' | 'active' | 'done' | 'skip';

export type Finding = {
  endpoint?: string;
  link?: string;
  meta?: string;
  prio?: string;
  priority?: string;
  type?: string;
  url?: string;
  value?: string;
  [key: string]: unknown;
};

export type OwaspHint = string | { id?: string; label?: string; title?: string };

export type FindingPayload = {
  finding: Finding;
  mitreHints: string[];
  owaspHints: OwaspHint[];
  ts: number;
};

export type FindingBranch = FindingPayload & {
  badgeLabel: string;
  kind: 'finding';
  seq: number;
};

export type CascadeBranch = {
  domain: string;
  kind: 'cascade';
  root: string;
  tag: string;
  ts: number;
};

export type Branch = FindingBranch | CascadeBranch;

export type Tactic = { id: string; name?: string };
export type Technique = { id: string; name?: string; phases?: string[]; url?: string };
export type MitreBundle = {
  generatedAt?: string;
  phases?: string[];
  scope?: string;
  tactics?: Tactic[];
  techniques?: Technique[];
};

export type ProjectSecretPeer = {
  kind_hint?: string;
  preview?: string;
  targets?: string[];
};

export type TimelineEvent = {
  finding?: Finding;
  kind: string;
  mitreHints?: string[];
  owaspHints?: OwaspHint[];
  t: number;
  [key: string]: unknown;
};

export type LiveState = {
  branches: Branch[];
  bundle: MitreBundle | null;
  bundleError: string;
  connected: boolean;
  events: TimelineEvent[];
  findingsReceivedCount: number;
  highMitreIds: string[];
  kaliMode: boolean | null;
  lastMessageAt: number;
  lastPipeLabel: string;
  liveTactics: string[];
  mitreHitSnippets: Record<string, string[]>;
  mitreHits: string[];
  nextFindingSeq: number;
  owaspHits: string[];
  peers: ProjectSecretPeer[];
  pipeline: Record<string, PipeState>;
  sessionId: string;
  sessionResolved: boolean;
  statusClass: string;
  statusText: string;
  target: string;
};

export type LiveAction =
  | { type: 'session'; sessionId: string }
  | { type: 'bundle'; bundle: MitreBundle }
  | { type: 'bundle_error'; message: string }
  | { type: 'connected' }
  | { type: 'message'; message: Record<string, unknown>; now: number }
  | { type: 'import'; findings: FindingPayload[]; target: string; now: number }
  | { type: 'status'; text: string; className?: string };

const PIPE_TACTICS: Record<string, string[]> = {
  assets: ['TA0042', 'TA0043'],
  dalfox: ['TA0001'],
  ffuf: ['TA0001'],
  kali: ['TA0001'],
  nmap: ['TA0043'],
  nuclei: ['TA0001'],
  nuclei_sqli: ['TA0001'],
  nuclei_xss: ['TA0001'],
  sqlmap: ['TA0001'],
  verify: ['TA0001', 'TA0043'],
  webshell_probe: ['TA0001'],
  whois: ['TA0043'],
  wpscan: ['TA0001', 'TA0043'],
  xss_vibes: ['TA0001'],
};

const MAX_EVENTS = 200;
const MAX_SEGMENTS = 80;

export function createPendingPipeline(): Record<string, PipeState> {
  return Object.fromEntries(PIPE_ORDER.map((name) => [name, 'pending'])) as Record<string, PipeState>;
}

export const INITIAL_LIVE_STATE: LiveState = {
  branches: [],
  bundle: null,
  bundleError: '',
  connected: false,
  events: [],
  findingsReceivedCount: 0,
  highMitreIds: [],
  kaliMode: null,
  lastMessageAt: 0,
  lastPipeLabel: '',
  liveTactics: [],
  mitreHitSnippets: {},
  mitreHits: [],
  nextFindingSeq: 0,
  owaspHits: [],
  peers: [],
  pipeline: createPendingPipeline(),
  sessionId: '',
  sessionResolved: false,
  statusClass: 'pill waiting',
  statusText: 'À espera',
  target: '',
};

function asRecord(value: unknown): Record<string, unknown> {
  return value && typeof value === 'object' ? value as Record<string, unknown> : {};
}

function asStringArray(value: unknown): string[] {
  return Array.isArray(value)
    ? value.filter((entry): entry is string => typeof entry === 'string')
    : [];
}

function normalizePipeState(value: unknown): PipeState {
  return value === 'active' || value === 'done' || value === 'skip' ? value : 'pending';
}

function normalizeOwaspHints(value: unknown): OwaspHint[] {
  if (!Array.isArray(value)) return [];
  return value.filter((entry): entry is OwaspHint => (
    typeof entry === 'string' || Boolean(entry && typeof entry === 'object')
  ));
}

function owaspId(hint: OwaspHint): string {
  const raw = typeof hint === 'string' ? hint : hint.id;
  const id = String(raw || '').toUpperCase();
  return /^A\d{2}$/.test(id) ? id : '';
}

export function normalizeFindingPayload(value: Record<string, unknown>, now = Date.now()): FindingPayload {
  return {
    finding: asRecord(value.finding) as Finding,
    mitreHints: asStringArray(value.mitreHints).filter((id) => id.startsWith('T')),
    owaspHints: normalizeOwaspHints(value.owaspHints),
    ts: Number(value.ts) || now,
  };
}

function pushEvent(events: TimelineEvent[], event: TimelineEvent): TimelineEvent[] {
  return [...events, event].slice(-MAX_EVENTS);
}

function appendFinding(state: LiveState, payload: FindingPayload): LiveState {
  const seq = state.nextFindingSeq + 1;
  const prio = String(payload.finding.prio || payload.finding.priority || '').toLowerCase();
  const highMitreIds = new Set(state.highMitreIds);
  const mitreHits = new Set(state.mitreHits);
  const owaspHits = new Set(state.owaspHits);
  const snippets = { ...state.mitreHitSnippets };

  for (const id of payload.mitreHints) {
    mitreHits.add(id);
    if (prio === 'high') highMitreIds.add(id);
    snippets[id] = [
      ...(snippets[id] || []),
      String(payload.finding.value || '').slice(0, 160),
      String(payload.finding.type || ''),
    ];
  }
  for (const hint of payload.owaspHints) {
    const id = owaspId(hint);
    if (id) owaspHits.add(id);
  }

  const branch: FindingBranch = {
    ...payload,
    badgeLabel: payload.mitreHints[0] || `#${seq}`,
    kind: 'finding',
    seq,
  };
  return {
    ...state,
    branches: [...state.branches, branch].slice(-MAX_SEGMENTS),
    findingsReceivedCount: state.findingsReceivedCount + 1,
    highMitreIds: [...highMitreIds],
    mitreHitSnippets: snippets,
    mitreHits: [...mitreHits],
    nextFindingSeq: seq,
    owaspHits: [...owaspHits],
  };
}

function resetTarget(state: LiveState, target: string, cascade: boolean, message: Record<string, unknown>, now: number): LiveState {
  const divider: CascadeBranch = {
    domain: target || 'alvo',
    kind: 'cascade',
    root: String(message.cascadeRoot || ''),
    tag: String(message.cascadeTag || 'SEGUINTE'),
    ts: now,
  };
  return {
    ...state,
    branches: cascade ? [...state.branches, divider].slice(-MAX_SEGMENTS) : [],
    events: [{ t: now, kind: 'target', domain: target, cascadeContinue: cascade }],
    findingsReceivedCount: 0,
    highMitreIds: [],
    kaliMode: typeof message.kaliMode === 'boolean' ? message.kaliMode : state.kaliMode,
    mitreHitSnippets: {},
    mitreHits: [],
    nextFindingSeq: cascade ? state.nextFindingSeq : 0,
    owaspHits: [],
    pipeline: { ...createPendingPipeline(), input: 'done' },
    target,
  };
}

export function liveReducer(state: LiveState, action: LiveAction): LiveState {
  if (action.type === 'session') {
    if (!action.sessionId) {
      return {
        ...state,
        sessionId: '',
        sessionResolved: true,
        statusClass: 'pill err',
        statusText: 'Sem sessão',
      };
    }
    return { ...state, sessionId: action.sessionId, sessionResolved: true };
  }
  if (action.type === 'bundle') return { ...state, bundle: action.bundle, bundleError: '' };
  if (action.type === 'bundle_error') return { ...state, bundleError: action.message };
  if (action.type === 'connected') {
    return {
      ...state,
      connected: true,
      statusClass: 'pill waiting',
      statusText: state.bundleError ? 'Ligado · sem matriz' : 'Ligado',
    };
  }
  if (action.type === 'status') {
    return { ...state, statusText: action.text, statusClass: action.className || 'pill' };
  }
  if (action.type === 'import') {
    let next = { ...state, target: action.target || state.target };
    for (const payload of action.findings) {
      next = appendFinding(next, payload);
      next = {
        ...next,
        events: pushEvent(next.events, {
          t: payload.ts,
          finding: payload.finding,
          kind: 'finding',
          mitreHints: payload.mitreHints,
          owaspHints: payload.owaspHints,
        }),
      };
    }
    next.events = pushEvent(next.events, { t: action.now, kind: 'import_json', count: action.findings.length });
    next.statusClass = 'pill';
    next.statusText = `Importados ${action.findings.length} achado(s)`;
    return next;
  }

  const message = action.message;
  if (message.type === 'reporte_payload') return state;
  let next: LiveState = { ...state, lastMessageAt: action.now };

  if (message.type === 'target') {
    return resetTarget(
      next,
      String(message.domain || '').trim(),
      Boolean(message.cascadeContinue),
      message,
      action.now,
    );
  }
  if (message.type === 'pipe') {
    const name = String(message.name || '');
    const pipeState = normalizePipeState(message.state);
    const event: TimelineEvent = { t: action.now, kind: 'pipe', name, state: pipeState, target: message.target };
    return {
      ...next,
      events: pushEvent(next.events, event),
      kaliMode: typeof message.kaliMode === 'boolean' ? message.kaliMode : next.kaliMode,
      lastPipeLabel: `${name} · ${String(message.state || '')}`,
      liveTactics: pipeState === 'active' ? (PIPE_TACTICS[name] || ['TA0043']) : [],
      pipeline: { ...next.pipeline, [name]: pipeState },
      statusClass: pipeState === 'active' ? 'pill live' : next.statusClass,
      statusText: pipeState === 'active' ? 'Recon em curso' : next.statusText,
    };
  }
  if (message.type === 'finding_card') {
    const payload = normalizeFindingPayload(message, action.now);
    next = appendFinding(next, payload);
    return {
      ...next,
      events: pushEvent(next.events, {
        t: payload.ts,
        finding: payload.finding,
        kind: 'finding',
        mitreHints: payload.mitreHints,
        owaspHints: payload.owaspHints,
      }),
    };
  }
  if (message.type === 'mitre_hints') {
    return { ...next, mitreHits: [...new Set([...next.mitreHits, ...asStringArray(message.ids).filter((id) => id.startsWith('T'))])] };
  }
  if (message.type === 'findings_rescore') {
    const mitreIds = asStringArray(message.mitreIds).filter((id) => id.startsWith('T'));
    const hints = [...normalizeOwaspHints(message.owaspIds), ...normalizeOwaspHints(message.owaspDetails)];
    const owaspIds = hints.map(owaspId).filter(Boolean);
    return {
      ...next,
      events: pushEvent(next.events, { t: action.now, kind: 'findings_rescore', mitreIds, owaspIds }),
      mitreHits: [...new Set([...next.mitreHits, ...mitreIds])],
      owaspHits: [...new Set([...next.owaspHits, ...owaspIds])],
    };
  }
  if (message.type === 'project_secret_peers') {
    const peers = Array.isArray(message.duplicates)
      ? message.duplicates.filter((entry): entry is ProjectSecretPeer => Boolean(entry && typeof entry === 'object'))
      : [];
    return {
      ...next,
      events: pushEvent(next.events, { t: action.now, kind: 'project_secret_peers', duplicates: peers }),
      peers,
    };
  }
  if (message.type === 'run_end') {
    return {
      ...next,
      events: pushEvent(next.events, { t: action.now, kind: 'run_end', lastPipe: next.lastPipeLabel }),
      liveTactics: [],
      statusClass: 'pill',
      statusText: 'Stream terminado',
    };
  }
  return next;
}

export const PIPE_DISPLAY_NAMES: Record<string, string> = {
  alive: 'alive check', assets: 'assets', dalfox: 'dalfox', dns_enrichment: 'DNS enrich',
  dorks: 'dorks', ffuf: 'ffuf', input: 'input', js: 'JS', kali: 'Kali (fase)',
  nmap: 'nmap', nmap_udp: 'nmap UDP', nuclei: 'nuclei', nuclei_sqli: 'nuclei · SQLi',
  nuclei_xss: 'nuclei · XSS', params: 'params', rdap: 'RDAP', score: 'prioritize',
  secrets: 'secrets', sqlmap: 'sqlmap', subdomains: 'subdomains', surface: 'surface',
  urls: 'URLs', verify: 'verify', webshell_probe: 'webshell', whois: 'whois',
  wpscan: 'wpscan', xss_vibes: 'xss_vibes',
};

export function pipeDisplayName(id: string): string {
  return PIPE_DISPLAY_NAMES[id] || id.replace(/_/g, ' ');
}

export function extractUrls(value: unknown): string[] {
  const matches = String(value || '').match(/\bhttps?:\/\/[^\s<>"'`]+/gi) || [];
  return [...new Set(matches.map((url) => url.replace(/[),.;]+$/g, '')).filter(Boolean))];
}

export function findFindingLinks(finding: Finding): string[] {
  return [...new Set(['url', 'link', 'endpoint', 'value', 'meta'].flatMap((key) => extractUrls(finding[key])))].slice(0, 4);
}

export function extractImportFindings(raw: unknown): Record<string, unknown>[] {
  if (Array.isArray(raw)) return raw.filter((row): row is Record<string, unknown> => Boolean(row && typeof row === 'object'));
  const obj = asRecord(raw);
  if (Array.isArray(obj.findings)) return extractImportFindings(obj.findings);
  if (typeof obj.findings_json === 'string') {
    try { return extractImportFindings(JSON.parse(obj.findings_json)); } catch { return []; }
  }
  return [];
}

export function rowToFindingImportPayload(row: Record<string, unknown>, index: number, now = Date.now()): FindingPayload {
  const finding: Finding = {
    meta: String(row.meta ?? '').slice(0, 160),
    prio: String(row.priority ?? row.prio ?? '').toLowerCase(),
    type: row.type == null ? 'achado' : String(row.type),
    value: String(row.value ?? '').slice(0, 220),
  };
  const url = String(row.url ?? '').trim();
  if (url) finding.url = url.slice(0, 220);
  const mitreHints = Array.isArray(row.mitre)
    ? row.mitre.map((item) => typeof item === 'string' ? item : String(asRecord(item).id || '')).filter((id) => id.startsWith('T'))
    : [];
  const owaspHints: OwaspHint[] = Array.isArray(row.owasp)
    ? row.owasp.map((item) => {
      if (typeof item === 'string') return item.toUpperCase();
      const obj = asRecord(item);
      return { id: String(obj.id || '').toUpperCase(), title: String(obj.title || ''), label: String(obj.label || '') };
    }).filter((item) => Boolean(owaspId(item)))
    : [];
  return { finding, mitreHints, owaspHints, ts: now + index };
}

export function mitreTechniqueUrl(id: string): string {
  if (!id.startsWith('T')) return 'https://attack.mitre.org/';
  const [root] = id.split('.');
  return id.includes('.')
    ? `https://attack.mitre.org/techniques/${root}/${id}/`
    : `https://attack.mitre.org/techniques/${id}/`;
}

export const OWASP_TOP10_2025: Record<string, { title: string; url: string }> = {
  A01: { title: 'Broken Access Control', url: 'https://owasp.org/Top10/A01_2021-Broken_Access_Control/' },
  A02: { title: 'Security Misconfiguration', url: 'https://owasp.org/Top10/A05_2021-Security_Misconfiguration/' },
  A03: { title: 'Software Supply Chain Failures', url: 'https://owasp.org/Top10/A06_2021-Vulnerable_and_Outdated_Components/' },
  A04: { title: 'Cryptographic Failures', url: 'https://owasp.org/Top10/A02_2021-Cryptographic_Failures/' },
  A05: { title: 'Injection', url: 'https://owasp.org/Top10/A03_2021-Injection/' },
  A06: { title: 'Insecure Design', url: 'https://owasp.org/Top10/A04_2021-Insecure_Design/' },
  A07: { title: 'Authentication Failures', url: 'https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/' },
  A08: { title: 'Software or Data Integrity Failures', url: 'https://owasp.org/Top10/A08_2021-Software_and_Data_Integrity_Failures/' },
  A09: { title: 'Security Logging and Alerting Failures', url: 'https://owasp.org/Top10/A09_2021-Security_Logging_and_Monitoring_Failures/' },
  A10: { title: 'Mishandling of Exceptional Conditions', url: 'https://owasp.org/www-project-top-ten/' },
};

export function owaspEntry(id: string): { title: string; url: string } {
  return OWASP_TOP10_2025[id.toUpperCase()] || { title: 'OWASP Top 10', url: 'https://owasp.org/www-project-top-ten/' };
}
