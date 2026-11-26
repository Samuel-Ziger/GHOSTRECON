import type { ExecutionState, ExecutionStore } from '../execution/store';
import type { Finding } from '../findings/model';

export const MITRE_LIVE_SESSION_STORAGE_KEY = 'ghostrecon_mitre_live_session_id';
export const REPORT_PAYLOAD_SESSION_KEY = 'ghostrecon_reporte_payload';
export const REPORT_PAYLOAD_SHARED_KEY = 'ghostrecon_reporte_payload_shared';
export const GHOSTDESK_URL_STORAGE_KEY = 'ghostrecon_ghostdesk_url';
export const GHOST_UI_URL_STORAGE_KEY = 'ghostrecon_ghost_ui_url';

const MAX_HANDOFF_BYTES = 4_500_000;
const REPORT_LIVE_MIN_MS = 520;
const POPUP_FEATURES = 'noopener,noreferrer';
const MITRE_READY_TITLE =
  'Abre o Ghostmap — mapa MITRE ao vivo (BroadcastChannel; podes abrir antes do recon para exportar JSON vazio ou ver o mapa).';

type JsonRecord = Record<string, unknown>;
type ExportSubset = 'all' | 'high' | 'validated' | null | undefined;
type LogLevel = 'info' | 'warn' | 'error' | 'success' | 'find' | string;
type PopupEvent = Pick<MouseEvent, 'shiftKey'> | { shiftKey?: boolean } | null | undefined;
type ExportFinding = Finding & JsonRecord;
type StorageReader = Pick<Storage, 'getItem' | 'setItem'>;

export type DownloadArtifact = {
  content: string;
  filename: string;
  mimeType: string;
};

export type JsonDownloadArtifact = DownloadArtifact & {
  payload: JsonRecord;
};

export type ExportsIntegrationsService = ReturnType<typeof createExportsIntegrationsService>;

type CockpitExportsWindow = Window & {
  BroadcastChannel?: typeof BroadcastChannel;
  URL: typeof URL;
  __ghostreconManualFp?: Set<string>;
  __kaliScanAvailable?: boolean;
  __mitreLiveBc?: BroadcastChannel | null;
  __mitreLiveSessionId?: string | null;
  addLog?: (message: string, level: LogLevel) => void;
};

function record(value: unknown): JsonRecord {
  return value && typeof value === 'object' ? value as JsonRecord : {};
}

function text(value: unknown): string {
  return String(value ?? '');
}

function cloneFinding(finding: Finding): ExportFinding {
  return { ...finding };
}

function normalizedFingerprint(value: unknown): string {
  return text(value).trim().toLowerCase();
}

function findingRisk(finding: Finding): JsonRecord {
  return record(finding.risk);
}

function findingProvenance(finding: Finding): JsonRecord {
  return record(finding.provenance);
}

function storage(windowRef: Window, kind: 'localStorage' | 'sessionStorage'): Storage | null {
  try {
    return windowRef[kind];
  } catch {
    return null;
  }
}

function pageOrigin(location: Pick<Location, 'origin' | 'protocol'>): string {
  if (location.origin && location.origin !== 'null') return location.origin;
  if (location.protocol === 'https:') return 'https://127.0.0.1:3847';
  return 'http://127.0.0.1:3847';
}

function severity(finding: Finding): string {
  return text(finding.prio || finding.priority).toLowerCase();
}

export function mapFindingForJsonExport(finding: Finding): JsonRecord {
  const verificationRecord = record(finding.verification);
  const evidence = record(verificationRecord.evidence);
  const responseSnippet = evidence.responseSnippet;
  const requestSnippet = evidence.requestSnippet;
  const provenance = findingProvenance(finding);
  const verification = Object.keys(verificationRecord).length
    ? {
        classification: verificationRecord.classification,
        confidenceScore: verificationRecord.confidenceScore,
        verifiedAt: verificationRecord.verifiedAt,
        evidenceHash: evidence.evidenceHash,
        responseSnippetPreview:
          typeof responseSnippet === 'string' ? responseSnippet.slice(0, 1800) : undefined,
        requestSnippetPreview:
          typeof requestSnippet === 'string' ? requestSnippet.slice(0, 800) : undefined,
      }
    : undefined;
  return {
    type: finding.type,
    priority: finding.prio,
    score: finding.score || 0,
    value: finding.value,
    meta: finding.meta || '',
    url: finding.url || '',
    fingerprint: finding.fingerprint || '',
    compositeScore: finding.compositeScore,
    attackTier: finding.attackTier,
    bountyProbability: finding.bountyProbability,
    priorityWhy: finding.priorityWhy,
    provenance: provenance.how || provenance.relation
      ? { how: provenance.how || '', relation: provenance.relation || '' }
      : undefined,
    risk: finding.risk || undefined,
    verification,
    owasp: Array.isArray(finding.owasp) && finding.owasp.length ? finding.owasp : undefined,
    mitre: Array.isArray(finding.mitre) && finding.mitre.length ? finding.mitre : undefined,
  };
}

export function filterFindingsForSubset(
  findings: Finding[],
  subset: ExportSubset,
  validatedFingerprints: Iterable<string> = [],
): ExportFinding[] {
  const cloned = Array.isArray(findings) ? findings.map(cloneFinding) : [];
  if (!subset || subset === 'all') return cloned;
  if (subset === 'high') {
    return cloned.filter((finding) => ['high', 'critical'].includes(severity(finding)));
  }
  if (subset === 'validated') {
    const valid = new Set([...validatedFingerprints].map(normalizedFingerprint).filter(Boolean));
    if (!valid.size) return [];
    return cloned.filter((finding) => valid.has(normalizedFingerprint(finding.fingerprint)));
  }
  return cloned;
}

function projectName(documentRef: Document): string | undefined {
  const input = documentRef.getElementById('projectNameInput') as HTMLInputElement | null;
  return input?.value.trim() || undefined;
}

function exportBasePayload(
  state: ExecutionState,
  timestamp: string,
  name?: string,
): JsonRecord {
  const multi = state.batchTargets.length > 1;
  return {
    projectName: name,
    target: state.target,
    targets: multi ? [...state.batchTargets] : undefined,
    timestamp,
    stats: { ...state.pipeline.stats },
    reconCoverage: state.coverage || undefined,
  };
}

export function buildJsonExport(
  state: ExecutionState,
  options: {
    now?: number;
    projectName?: string;
    subset?: ExportSubset;
    findings?: Finding[];
  } = {},
): JsonDownloadArtifact {
  const now = options.now ?? Date.now();
  const subset = options.subset;
  const findings = options.findings || state.findings;
  const multi = state.batchTargets.length > 1;
  const payload = {
    ...exportBasePayload(state, new Date(now).toISOString(), options.projectName),
    ...(subset && subset !== 'all' ? { subsetFilter: subset } : {}),
    findings: findings.map(mapFindingForJsonExport),
  };
  let filename: string;
  if (subset && subset !== 'all') {
    const tag = subset === 'high' ? 'high' : 'validados';
    filename = multi
      ? `ghostrecon_${tag}_fila_${state.batchTargets.length}_${now}.json`
      : `ghostrecon_${tag}_${state.target}_${now}.json`;
  } else {
    filename = multi
      ? `ghostrecon_fila_${state.batchTargets.length}_${now}.json`
      : `ghostrecon_${state.target}_${now}.json`;
  }
  return {
    content: JSON.stringify(payload, null, 2),
    filename,
    mimeType: 'application/json',
    payload,
  };
}

export function buildPlatformExport(
  state: ExecutionState,
  options: { now?: number; projectName?: string } = {},
): JsonDownloadArtifact {
  const now = options.now ?? Date.now();
  const bundle = record(state.lastPipelineBundle);
  const histogram = { high: 0, med: 0, low: 0 };
  for (const finding of state.findings) {
    const key = severity(finding) === 'high' ? 'high' : severity(finding) === 'med' ? 'med' : 'low';
    histogram[key] += 1;
  }
  const payload: JsonRecord = {
    schemaVersion: 2,
    source: 'ghostrecon-platform-export',
    exportedAt: new Date(now).toISOString(),
    projectName: options.projectName,
    target: state.target,
    targets: state.batchTargets.length > 1 ? [...state.batchTargets] : undefined,
    stats: { ...state.pipeline.stats },
    severityHistogram: histogram,
    runId: bundle.runId ?? null,
    storage: bundle.storage ?? null,
    intelMerge: bundle.intelMerge ?? null,
    reconCoverage: bundle.reconCoverage || state.coverage || null,
    correlation: bundle.correlation ?? null,
    reportTemplates: bundle.reportTemplates ?? [],
    findings: state.findings.map(mapFindingForJsonExport),
  };
  return {
    content: JSON.stringify(payload, null, 2),
    filename: `ghostrecon_platform_${state.target}_${now}.json`,
    mimeType: 'application/json',
    payload,
  };
}

function reportTargetLine(state: ExecutionState, markdown: boolean): string {
  if (state.batchTargets.length > 1) {
    const line = `Fila (${state.batchTargets.length} alvos): ${state.batchTargets.join(', ')}`;
    return markdown ? `**${line.split(': ')[0]}:** ${state.batchTargets.join(', ')}` : line;
  }
  return markdown ? `**Alvo:** ${state.target}` : `Alvo: ${state.target}`;
}

export function buildMarkdownExport(
  state: ExecutionState,
  mode: 'technical' | 'bounty' = 'technical',
  now = Date.now(),
): DownloadArtifact {
  const findings = state.findings;
  const multi = state.batchTargets.length > 1;
  const timestamp = new Date(now).toISOString();
  const targetLine = reportTargetLine(state, true);
  const high = findings.filter((finding) => severity(finding) === 'high');
  const reproductionUrls = [...new Set(
    findings.map((finding) => text(finding.url)).filter(Boolean),
  )].slice(0, 40);

  if (mode === 'bounty') {
    const prioritized = findings
      .filter((finding) => ['high', 'med'].includes(severity(finding)))
      .sort((left, right) => (Number(right.score) || 0) - (Number(left.score) || 0))
      .slice(0, 12);
    let content = `# Bug bounty report - ${state.target}\n\n${targetLine}\n\n**Generated:** ${timestamp}\n\n`;
    content += `## Summary\n\nFound ${prioritized.length} prioritized issue(s). Reproduction guidance below is intentionally safe/manual.\n\n`;
    for (const finding of prioritized) {
      const risk = findingRisk(finding);
      content += `## [${severity(finding).toUpperCase()}] ${text(finding.value).replace(/\n/g, ' ')}\n\n`;
      content += `- Type: ${text(finding.type)}\n`;
      if (finding.url) content += `- URL: ${text(finding.url)}\n`;
      if (finding.meta) content += `- Evidence: ${text(finding.meta).replace(/\n/g, ' ')}\n`;
      if (risk.why) content += `- Impact: ${text(risk.why).replace(/\n/g, ' ')}\n`;
      if (risk.next) content += `- Safe validation: ${text(risk.next).replace(/\n/g, ' ')}\n`;
      if (risk.falsePositive) {
        content += `- False-positive note: ${text(risk.falsePositive).replace(/\n/g, ' ')}\n`;
      }
      content += '\n';
    }
    return {
      content,
      filename: multi
        ? `ghostrecon_bounty_fila_${state.batchTargets.length}_${now}.md`
        : `ghostrecon_bounty_${state.target}_${now}.md`,
      mimeType: 'text/markdown',
    };
  }

  const groups = new Map<string, Finding[]>();
  for (const finding of findings) {
    const type = text(finding.type);
    groups.set(type, [...(groups.get(type) || []), finding]);
  }
  const stats = state.pipeline.stats;
  let content = `# GHOSTRECON — relatório técnico\n\n${targetLine}\n\n**Data (ISO):** ${timestamp}\n\n`;
  content += '## Resumo\n| Métrica | Valor |\n|---|---|\n';
  content += `| Subdomínios | ${stats.subs} |\n| Endpoints | ${stats.endpoints} |\n| Parâmetros | ${stats.params} |\n| Secrets | ${stats.secrets} |\n| Dorks | ${stats.dorks} |\n| Prioridade alta (UI) | ${stats.high} |\n\n`;
  if (high.length) {
    content += '## Alto risco (prioridade HIGH)\n';
    for (const finding of high) {
      const risk = findingRisk(finding);
      const provenance = findingProvenance(finding);
      content += `- **${text(finding.type)}** — \`${text(finding.value).replace(/`/g, "'")}\`\n`;
      if (finding.meta) content += `  - _${text(finding.meta).replace(/_/g, '\\_')}_\n`;
      if (risk.why) content += `  - Risco: ${text(risk.why).replace(/\n/g, ' ')}\n`;
      if (risk.next) content += `  - Proximo passo seguro: ${text(risk.next).replace(/\n/g, ' ')}\n`;
      if (finding.url) content += `  - URL: ${text(finding.url)}\n`;
      if (provenance.how) content += `  - Como: ${text(provenance.how).replace(/\n/g, ' ')}\n`;
      if (provenance.relation) {
        content += `  - Relação ao alvo: ${text(provenance.relation).replace(/\n/g, ' ')}\n`;
      }
    }
    content += '\n';
  }
  if (reproductionUrls.length) {
    content += '## URLs para reprodução / verificação manual\n';
    for (const url of reproductionUrls) content += `- ${url}\n`;
    content += '\n';
  }
  for (const [type, items] of groups) {
    content += `## ${type.toUpperCase()}\n`;
    for (const finding of items) {
      const risk = findingRisk(finding);
      const provenance = findingProvenance(finding);
      content += `- **[${severity(finding).toUpperCase()}]** \`${text(finding.value).replace(/`/g, "'")}\`${finding.meta ? ` — ${text(finding.meta).replace(/`/g, "'")}` : ''}\n`;
      if (risk.why) content += `  - Risco: ${text(risk.why).replace(/\n/g, ' ')}\n`;
      if (risk.next) content += `  - Proximo passo seguro: ${text(risk.next).replace(/\n/g, ' ')}\n`;
      if (provenance.how) {
        content += `  - Como: ${text(provenance.how).replace(/\*\*/g, '').replace(/\n/g, ' ')}\n`;
      }
      if (provenance.relation) {
        content += `  - Relação: ${text(provenance.relation).replace(/\*\*/g, '').replace(/\n/g, ' ')}\n`;
      }
    }
    content += '\n';
  }
  return {
    content,
    filename: multi
      ? `ghostrecon_fila_${state.batchTargets.length}_${now}.md`
      : `ghostrecon_${state.target}_${now}.md`,
    mimeType: 'text/markdown',
  };
}

export function buildTextExport(state: ExecutionState, now = Date.now()): DownloadArtifact {
  const findings = state.findings;
  const stats = state.pipeline.stats;
  const multi = state.batchTargets.length > 1;
  const high = findings.filter((finding) => severity(finding) === 'high');
  const reproductionUrls = [...new Set(
    findings.map((finding) => text(finding.url)).filter(Boolean),
  )].slice(0, 40);
  let content = `GHOSTRECON — relatório bug bounty\n${reportTargetLine(state, false)}\nData: ${new Date(now).toISOString()}\n${'='.repeat(60)}\n\n`;
  content += `RESUMO: subs ${stats.subs} | endpoints ${stats.endpoints} | params ${stats.params} | secrets ${stats.secrets} | HIGH ${stats.high}\n\n`;
  if (high.length) {
    content += '--- ALTO RISCO ---\n';
    for (const finding of high) {
      const risk = findingRisk(finding);
      const provenance = findingProvenance(finding);
      content += `[${text(finding.type)}] ${text(finding.value)}\n  ${text(finding.meta)}\n  ${text(finding.url)}\n`;
      if (risk.why) content += `  Risco: ${text(risk.why)}\n`;
      if (risk.next) content += `  Proximo passo seguro: ${text(risk.next)}\n`;
      if (provenance.how) content += `  Como: ${text(provenance.how).replace(/\*\*/g, '')}\n`;
      if (provenance.relation) {
        content += `  Relação ao alvo: ${text(provenance.relation).replace(/\*\*/g, '')}\n`;
      }
      content += '\n';
    }
  }
  if (reproductionUrls.length) {
    content += '--- URLs (reprodução) ---\n';
    for (const url of reproductionUrls) content += `${url}\n`;
    content += '\n';
  }
  content += '--- TODOS OS ACHADOS ---\n';
  for (const finding of findings) {
    const risk = findingRisk(finding);
    const provenance = findingProvenance(finding);
    content += `[${severity(finding).toUpperCase()}] [${text(finding.type)}] ${text(finding.value)}\n  → ${text(finding.meta)}\n`;
    if (risk.why) content += `  Risco: ${text(risk.why)}\n`;
    if (risk.next) content += `  Proximo passo seguro: ${text(risk.next)}\n`;
    if (provenance.how) content += `  Como: ${text(provenance.how).replace(/\*\*/g, '')}\n`;
    if (provenance.relation) {
      content += `  Relação ao alvo: ${text(provenance.relation).replace(/\*\*/g, '')}\n`;
    }
  }
  return {
    content,
    filename: multi
      ? `ghostrecon_fila_${state.batchTargets.length}_${now}.txt`
      : `ghostrecon_${state.target}_${now}.txt`,
    mimeType: 'text/plain',
  };
}

export function resolveGhostDeskUrl(
  location: Pick<Location, 'href' | 'hostname' | 'port' | 'protocol'>,
  localStorage: Pick<StorageReader, 'getItem'> | null,
): string {
  try {
    const configured = text(localStorage?.getItem(GHOSTDESK_URL_STORAGE_KEY)).trim();
    if (configured) return new URL(configured, location.href).href;
  } catch {
    // Storage/configuration is optional.
  }
  const protocol = location.protocol === 'https:' ? 'https:' : 'http:';
  const host = location.hostname || '127.0.0.1';
  if (location.port === '5173' || location.port === '') return new URL('/', location.href).href;
  return `${protocol}//${host}:5173/`;
}

export function resolveGhostAssistantUrl(
  location: Pick<Location, 'href' | 'hostname' | 'protocol'>,
  localStorage: Pick<StorageReader, 'getItem'> | null,
): string {
  try {
    const configured = text(localStorage?.getItem(GHOST_UI_URL_STORAGE_KEY)).trim();
    if (configured) return new URL(configured, location.href).href;
  } catch {
    // Storage/configuration is optional.
  }
  const protocol = location.protocol === 'https:' ? 'https:' : 'http:';
  return `${protocol}//${location.hostname || '127.0.0.1'}:8000/gui/`;
}

export function createExportsIntegrationsService({
  windowRef = window,
  documentRef = document,
  executionStore,
  now = () => Date.now(),
}: {
  windowRef?: CockpitExportsWindow;
  documentRef?: Document;
  executionStore?: ExecutionStore;
  now?: () => number;
} = {}) {
  let reportLiveTimer: number | null = null;
  let reportLiveLastSentAt = 0;

  const state = (): ExecutionState => {
    const store = executionStore || windowRef.__ghostreconExecutionStore;
    if (!store) throw new Error('ExecutionStore indisponível para exports/integrações.');
    return store.getState();
  };
  const log = (message: string, level: LogLevel = 'info') => windowRef.addLog?.(message, level);
  const local = () => storage(windowRef, 'localStorage');
  const session = () => storage(windowRef, 'sessionStorage');
  const running = () => Boolean((documentRef.getElementById('runBtn') as HTMLButtonElement | null)?.disabled);
  const reportTargetKey = () => {
    const input = (documentRef.getElementById('domainInput') as HTMLInputElement | null)?.value
      .trim()
      .toLowerCase() || '';
    const current = state().target.trim().toLowerCase();
    return running() ? current || input : input || current;
  };
  const apiUrl = (pathname: string) => {
    const nativeUrl = windowRef.__ghostreconNativeServices?.api.url;
    if (nativeUrl) return nativeUrl(pathname);
    return new URL(pathname, pageOrigin(windowRef.location)).href;
  };
  const popup = (url: string, name: string, features = POPUP_FEATURES) => (
    windowRef.open(url, name, features)
  );
  const updateMitreButton = (ready: boolean) => {
    const button = documentRef.getElementById('mitreMapBtn') as HTMLButtonElement | null;
    if (!button) return;
    button.classList.toggle('mitre-map-btn--ready', ready);
    if (ready) {
      button.disabled = false;
      button.title = MITRE_READY_TITLE;
    }
  };
  const randomSessionId = () => {
    try {
      return windowRef.crypto.randomUUID();
    } catch {
      return `${now().toString(36)}-${Math.random().toString(36).slice(2)}`;
    }
  };

  function download(filename: string, content: string, mimeType: string): void {
    const anchor = documentRef.createElement('a');
    anchor.href = windowRef.URL.createObjectURL(new Blob([content], { type: mimeType }));
    anchor.download = filename;
    anchor.click();
  }

  function downloadArtifact(artifact: DownloadArtifact): void {
    download(artifact.filename, artifact.content, artifact.mimeType);
  }

  function mitreLiveCurrentKaliMode(): boolean {
    const enabled = (documentRef.getElementById('kaliModeToggle') as HTMLInputElement | null)?.checked;
    return Boolean(enabled && windowRef.__kaliScanAvailable);
  }

  function mitreLivePost(message: unknown): void {
    try {
      windowRef.__mitreLiveBc?.postMessage(message);
    } catch {
      // Closing/navigating a tab can race BroadcastChannel.postMessage.
    }
  }

  function mitreLivePostPipelineInputPhase(): void {
    const target = state().target || '';
    const kaliMode = mitreLiveCurrentKaliMode();
    mitreLivePost({ type: 'pipe', name: 'input', state: 'active', target, kaliMode });
    mitreLivePost({ type: 'pipe', name: 'input', state: 'done', target, kaliMode });
  }

  function closeMitreLiveQuiet(): void {
    try {
      windowRef.__mitreLiveBc?.close();
    } catch {
      // Channel may already be closed.
    }
    windowRef.__mitreLiveBc = null;
    windowRef.__mitreLiveSessionId = null;
    updateMitreButton(false);
  }

  function ensureGhostmapLiveChannel(): boolean {
    if (!windowRef.BroadcastChannel) return false;
    if (windowRef.__mitreLiveBc) return true;
    let id = windowRef.__mitreLiveSessionId || '';
    if (!id) {
      try {
        id = local()?.getItem(MITRE_LIVE_SESSION_STORAGE_KEY) || '';
      } catch {
        // Fall through to a fresh ID.
      }
    }
    if (!id) {
      id = randomSessionId();
      try {
        local()?.setItem(MITRE_LIVE_SESSION_STORAGE_KEY, id);
      } catch {
        // A live in-memory channel is still useful when storage is unavailable.
      }
    }
    windowRef.__mitreLiveSessionId = id;
    try {
      windowRef.__mitreLiveBc = new windowRef.BroadcastChannel(`ghostrecon-mitre-${id}`);
    } catch {
      windowRef.__mitreLiveBc = null;
      return false;
    }
    updateMitreButton(true);
    mitreLivePost({
      type: 'target',
      domain: state().target,
      kaliMode: mitreLiveCurrentKaliMode(),
    });
    return true;
  }

  function initMitreLiveSession(): void {
    if (reportLiveTimer) windowRef.clearTimeout(reportLiveTimer);
    reportLiveTimer = null;
    reportLiveLastSentAt = 0;
    closeMitreLiveQuiet();
    if (!windowRef.BroadcastChannel) return;
    const id = randomSessionId();
    windowRef.__mitreLiveSessionId = id;
    try {
      windowRef.__mitreLiveBc = new windowRef.BroadcastChannel(`ghostrecon-mitre-${id}`);
    } catch {
      windowRef.__mitreLiveBc = null;
      return;
    }
    try {
      local()?.setItem(MITRE_LIVE_SESSION_STORAGE_KEY, id);
    } catch {
      // Live channel remains usable in-memory.
    }
    updateMitreButton(true);
    mitreLivePost({
      type: 'target',
      domain: state().target,
      kaliMode: mitreLiveCurrentKaliMode(),
    });
    mitreLivePostPipelineInputPhase();
  }

  function closeMitreLive(): void {
    mitreLivePost({ type: 'run_end' });
    closeMitreLiveQuiet();
    initMitreLiveSession();
  }

  async function refreshManualValidationFps(): Promise<void> {
    const target = state().target.trim().toLowerCase();
    const store = executionStore || windowRef.__ghostreconExecutionStore;
    if (!target || !/^[a-z0-9][a-z0-9.-]*[a-z0-9]$/.test(target)) {
      windowRef.__ghostreconManualFp = new Set();
      store?.setManualFingerprints([]);
      return;
    }
    try {
      const nativeLookup = windowRef.__ghostreconNativeServices?.infraHistory
        ?.manualValidationFingerprints;
      let fingerprints: string[];
      if (nativeLookup) {
        fingerprints = (await nativeLookup(target)).fingerprints;
      } else {
        const response = await windowRef.fetch(
          apiUrl(`/api/manual-validations/${encodeURIComponent(target)}`),
        );
        if (!response.ok) return;
        const body = record(await response.json());
        fingerprints = (Array.isArray(body.items) ? body.items : [])
          .map((item) => normalizedFingerprint(record(item).fingerprint))
          .filter(Boolean);
      }
      windowRef.__ghostreconManualFp = new Set(fingerprints);
      store?.setManualFingerprints(fingerprints);
    } catch {
      // Report/export remains available offline.
    }
  }

  function filterFindingsForReporteSubset(
    findings: Finding[],
    subset: ExportSubset,
  ): ExportFinding[] {
    return filterFindingsForSubset(findings, subset, state().manualFingerprints);
  }

  function postReporteLivePayload(immediate = false): void {
    if (!running() || !windowRef.BroadcastChannel || !windowRef.__mitreLiveBc) return;
    const flush = () => {
      reportLiveTimer = null;
      reportLiveLastSentAt = now();
      try {
        const payload = {
          type: 'reporte_payload',
          live: true,
          target: reportTargetKey(),
          updatedAt: new Date(now()).toISOString(),
          findings: state().findings.map(cloneFinding),
        };
        if (JSON.stringify(payload).length <= MAX_HANDOFF_BYTES) {
          windowRef.__mitreLiveBc?.postMessage(payload);
        }
      } catch {
        // Best-effort live handoff.
      }
    };
    if (immediate) {
      if (reportLiveTimer) windowRef.clearTimeout(reportLiveTimer);
      reportLiveTimer = null;
      flush();
      return;
    }
    const elapsed = now() - reportLiveLastSentAt;
    if (elapsed >= REPORT_LIVE_MIN_MS) {
      flush();
      return;
    }
    if (!reportLiveTimer) {
      reportLiveTimer = windowRef.setTimeout(
        flush,
        Math.max(40, REPORT_LIVE_MIN_MS - elapsed),
      );
    }
  }

  async function openReportePageWithSubset(
    subset: ExportSubset,
    targetWindowName?: string,
  ): Promise<void> {
    const target = reportTargetKey();
    const full = state().findings.map(cloneFinding);
    if (subset === 'validated') await refreshManualValidationFps();
    const selected = filterFindingsForSubset(full, subset || 'all', state().manualFingerprints);
    if (!target) {
      log('Reporte: sem alvo — importa JSON no Reporte ou indica Target ($) para gravar validações na SQLite.', 'info');
    } else if (!selected.length && full.length) {
      if (subset === 'high') {
        log('Reporte: filtro HIGH não devolveu achados — abre checklist vazia para este filtro.', 'warn');
      }
      if (subset === 'validated') {
        log('Reporte: nenhum achado validado na base para este alvo — checklist vazia. Valida no Reporte ou abre sem filtro.', 'warn');
      }
    } else if (!selected.length) {
      log('Reporte: lista vazia — corre o recon ou importa JSON.', 'info');
    }
    const payload = {
      target,
      updatedAt: new Date(now()).toISOString(),
      findings: selected,
      subsetFilter: subset || undefined,
    };
    try {
      const raw = JSON.stringify(payload);
      if (raw.length > MAX_HANDOFF_BYTES) {
        log('Reporte: pacote ainda grande — usa «⬇ JSON · high» ou «· validados» na barra inferior e importa no Reporte.', 'warn');
        return;
      }
      session()?.setItem(REPORT_PAYLOAD_SESSION_KEY, raw);
      try {
        local()?.setItem(REPORT_PAYLOAD_SHARED_KEY, raw);
      } catch {
        // Session handoff is enough when local storage is blocked.
      }
    } catch {
      log('Reporte: não foi possível gravar o pacote (sessionStorage).', 'error');
      return;
    }
    const url = new URL('reporte.html', windowRef.location.href).href;
    const name = targetWindowName?.trim() || '_blank';
    if (!popup(url, name)) {
      log(`Reporte: popup bloqueado — permite popups ou abre: ${url}`, 'warn');
    }
  }

  function openReportePage(): void {
    void openReportePageWithSubset(null);
  }

  function openCortexPage(event?: PopupEvent): void {
    const url = new URL('cortex.html', windowRef.location.href);
    if (event?.shiftKey) url.searchParams.set('demo', '1');
    const opened = popup(url.href, '_blank');
    if (!opened) log(`Cortex: popup bloqueado — permite popups ou abre: ${url.href}`, 'warn');
    else if (event?.shiftKey) log('Cortex: modo demonstração (dados fictícios).', 'info');
  }

  function openHistoryPage(): void {
    const url = new URL('/ghostmap/history', pageOrigin(windowRef.location));
    const target = reportTargetKey();
    if (target) url.searchParams.set('target', target);
    if (!popup(url.href, 'ghostrecon_history')) {
      log(`History: popup bloqueado — permite popups ou abre: ${url.href}`, 'warn');
    }
  }

  function openComoUsarPage(): void {
    const url = new URL('como-usar.html', windowRef.location.href).href;
    if (!popup(url, 'ghostrecon_como_usar')) {
      log(`Como usar: popup bloqueado — abre manualmente: ${url}`, 'warn');
    }
  }

  function openVigoliumWorkbenchPage(): void {
    const url = new URL('vigolium-workbench.html', windowRef.location.href);
    const target = reportTargetKey();
    if (target) url.searchParams.set('target', target);
    if (!popup(url.href, 'ghostrecon_vigolium_workbench')) {
      log(`Vigolium Workbench: popup bloqueado - permite popups ou abre: ${url.href}`, 'warn');
    }
  }

  function openPostExPage(): void {
    const url = new URL('post-exploitation.html', windowRef.location.href);
    const target = reportTargetKey();
    if (target) url.searchParams.set('target', target);
    if (!popup(url.href, 'ghostrecon_postex')) {
      log(`Pós-Exploração: popup bloqueado — permite popups ou abre: ${url.href}`, 'warn');
    }
  }

  function openWifiPentestPage(): void {
    const url = new URL('wifi-pentest.html', windowRef.location.href).href;
    if (!popup(url, 'ghostrecon_wifi_pentest')) {
      log(`Pentest WiFi: popup bloqueado — permite popups ou abre: ${url}`, 'warn');
    }
  }

  function openGhostDeskPage(): void {
    const url = resolveGhostDeskUrl(windowRef.location, local());
    if (!popup(url, 'ghostrecon_ghostdesk')) {
      log(`GhostDesk: popup bloqueado — abre manualmente: ${url}`, 'warn');
    } else {
      log('GhostDesk: painel de gestão aberto.', 'info');
    }
  }

  function openGhostAssistantUi(event?: PopupEvent): void {
    const url = resolveGhostAssistantUrl(windowRef.location, local());
    let opened: Window | null = null;
    if (!event?.shiftKey) {
      opened = popup(
        url,
        'ghostrecon_ghost_ui',
        'popup=yes,noopener,noreferrer,width=1320,height=900',
      );
    }
    if (!opened) opened = popup(url, '_blank');
    if (!opened) {
      log(`Ghost IA: popup bloqueado — abre manualmente: ${url}`, 'warn');
      return;
    }
    log(
      event?.shiftKey
        ? 'Ghost IA aberto em nova aba.'
        : 'Ghost IA aberto em janela dedicada (reutilizável).',
      'info',
    );
  }

  function openMitreMapPage(targetWindowName?: string): void {
    if (!windowRef.BroadcastChannel) {
      log('Ghostmap: BroadcastChannel não disponível neste browser.', 'warn');
      return;
    }
    if (!ensureGhostmapLiveChannel()) {
      log('Ghostmap: não foi possível criar a ligação ao vivo.', 'warn');
      return;
    }
    const id = windowRef.__mitreLiveSessionId;
    if (!id) {
      log('Ghostmap: sessão inválida — recarrega a página e tenta de novo.', 'warn');
      return;
    }
    const url = new URL('/ghostmap/ghostrecon', pageOrigin(windowRef.location));
    url.hash = id;
    const name = targetWindowName?.trim() || '_blank';
    if (!popup(url.href, name)) {
      log(`Ghostmap: popup bloqueado — permite popups para este site ou abre manualmente: ${url.href}`, 'warn');
    }
  }

  function openGhostmapAndReporteOnReconStartSync(): void {
    if (!windowRef.BroadcastChannel) {
      log('Ghostmap: BroadcastChannel indisponível — abre /ghostmap/ghostrecon manualmente.', 'warn');
    } else if (!ensureGhostmapLiveChannel()) {
      log('Ghostmap: não foi possível criar a ligação ao vivo.', 'warn');
    } else {
      const id = windowRef.__mitreLiveSessionId;
      if (id) {
        const url = new URL('/ghostmap/ghostrecon', pageOrigin(windowRef.location));
        url.hash = id;
        if (!popup(url.href, 'ghostrecon_ghostmap')) {
          log('Ghostmap: popup bloqueado — permite janelas em pop-up para ver o mapa ao vivo.', 'warn');
        }
      }
    }
    // This starts synchronously until its first optional await; the null subset
    // therefore preserves the browser user-activation needed by the popup.
    void openReportePageWithSubset(null, 'ghostrecon_reporte');
    log('Ghostmap e Reporte abertos automaticamente (ou reutilizados nas mesmas janelas).', 'info');
  }

  function exportJSON(): void {
    downloadArtifact(buildJsonExport(state(), {
      now: now(),
      projectName: projectName(documentRef),
    }));
  }

  async function exportJSONSubset(subset: Exclude<ExportSubset, null | undefined | 'all'>): Promise<void> {
    if (subset === 'validated') await refreshManualValidationFps();
    const current = state();
    const findings = filterFindingsForSubset(
      current.findings,
      subset,
      current.manualFingerprints,
    );
    downloadArtifact(buildJsonExport(current, {
      findings,
      now: now(),
      projectName: projectName(documentRef),
      subset,
    }));
    log(`Export JSON (${subset === 'high' ? 'high' : 'validados'}): ${findings.length} achado(s).`, 'info');
  }

  function exportPlatformBundle(): void {
    downloadArtifact(buildPlatformExport(state(), {
      now: now(),
      projectName: projectName(documentRef),
    }));
  }

  function exportMarkdown(mode: 'technical' | 'bounty' = 'technical'): void {
    downloadArtifact(buildMarkdownExport(state(), mode, now()));
  }

  function exportTXT(): void {
    downloadArtifact(buildTextExport(state(), now()));
  }

  function cleanup(): void {
    if (reportLiveTimer) windowRef.clearTimeout(reportLiveTimer);
    reportLiveTimer = null;
    closeMitreLiveQuiet();
  }

  return Object.freeze({
    cleanup,
    closeMitreLive,
    closeMitreLiveQuiet,
    download,
    ensureGhostmapLiveChannel,
    exportJSON,
    exportJSONSubset,
    exportMarkdown,
    exportPlatformBundle,
    exportTXT,
    filterFindingsForReporteSubset,
    ghostreconReportTargetKey: reportTargetKey,
    initMitreLiveSession,
    mapFindingForJsonExport,
    mitreLiveCurrentKaliMode,
    mitreLivePost,
    mitreLivePostPipelineInputPhase,
    openComoUsarPage,
    openCortexPage,
    openGhostAssistantUi,
    openGhostDeskPage,
    openGhostmapAndReporteOnReconStartSync,
    openHistoryPage,
    openMitreMapPage,
    openPostExPage,
    openReportePage,
    openReportePageWithSubset,
    openVigoliumWorkbenchPage,
    openWifiPentestPage,
    postReporteLivePayload,
    refreshManualValidationFps,
    resolveGhostAssistantUrl: () => resolveGhostAssistantUrl(windowRef.location, local()),
    resolveGhostDeskUrl: () => resolveGhostDeskUrl(windowRef.location, local()),
  });
}

const COMPATIBILITY_GLOBALS = [
  'closeMitreLive',
  'closeMitreLiveQuiet',
  'download',
  'ensureGhostmapLiveChannel',
  'exportJSON',
  'exportJSONSubset',
  'exportMarkdown',
  'exportPlatformBundle',
  'exportTXT',
  'filterFindingsForReporteSubset',
  'ghostreconReportTargetKey',
  'initMitreLiveSession',
  'mapFindingForJsonExport',
  'mitreLiveCurrentKaliMode',
  'mitreLivePost',
  'mitreLivePostPipelineInputPhase',
  'openComoUsarPage',
  'openCortexPage',
  'openGhostAssistantUi',
  'openGhostDeskPage',
  'openGhostmapAndReporteOnReconStartSync',
  'openHistoryPage',
  'openMitreMapPage',
  'openPostExPage',
  'openReportePage',
  'openReportePageWithSubset',
  'openVigoliumWorkbenchPage',
  'openWifiPentestPage',
  'postReporteLivePayload',
  'refreshManualValidationFps',
  'resolveGhostAssistantUrl',
  'resolveGhostDeskUrl',
] as const;

export function installExportsIntegrations(windowRef: Window): () => void {
  const cockpitWindow = windowRef as CockpitExportsWindow;
  const service = createExportsIntegrationsService({ windowRef: cockpitWindow });
  const globals = windowRef as unknown as Record<string, unknown>;
  const previous = new Map<string, unknown>();
  for (const name of COMPATIBILITY_GLOBALS) {
    previous.set(name, globals[name]);
    globals[name] = service[name];
  }
  document.body.dataset.ghostreconExportsIntegrations = '1';
  return () => {
    service.cleanup();
    for (const name of COMPATIBILITY_GLOBALS) {
      if (globals[name] !== service[name]) continue;
      const value = previous.get(name);
      if (value === undefined) delete globals[name];
      else globals[name] = value;
    }
    delete document.body.dataset.ghostreconExportsIntegrations;
  };
}

declare global {
  interface Window {
    __ghostreconManualFp?: Set<string>;
    __kaliScanAvailable?: boolean;
    __mitreLiveBc?: BroadcastChannel | null;
    __mitreLiveSessionId?: string | null;
    addLog?: (message: string, level: LogLevel) => void;
  }
}
