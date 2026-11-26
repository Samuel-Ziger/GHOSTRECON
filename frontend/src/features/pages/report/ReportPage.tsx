import {
  useCallback,
  useEffect,
  useMemo,
  useRef,
  useState,
  type ChangeEvent,
} from 'react';
import { appendHeadMarkup, snapshotLegacyDocument } from '../../../LegacyDocument';
import type { ReactUiPage } from '../../../page-registry';
import {
  ANNOTATION_HANDOFF_KEY,
  ANNOTATION_PAYLOAD_KEY,
  MITRE_SESSION_KEY,
  REPORT_IMPORT_MAX,
  REPORT_PAYLOAD_KEY,
  REPORT_SHARED_KEY,
  applySubset,
  buildReportHtml,
  buildReportMarkdown,
  deriveTargetFromFinding,
  deriveTargetFromFindings,
  emptyAnnotationMap,
  externalUrl,
  extractFindings,
  hydrateFindings,
  isDorkFinding,
  mergeFindingIntoAnnotations,
  normalizeTarget,
  removeAnnotationFinding,
  snapshotFromFinding,
  targetUsableForApi,
  taxonomyIds,
  type AnnotationMap,
  type ManualValidation,
  type ReportFinding,
  type ReportPayload,
} from './model';
import { createReportService } from './service';

type Message = { kind: '' | 'ok' | 'err'; text: string };
type BrainState = {
  categories: Array<{ id: number; title?: unknown }>;
  finding: ReportFinding | null;
  fingerprint: string;
  newTitle: string;
  open: boolean;
  selectedId: number | null;
  stage: 'ask' | 'pick';
};

const CLOSED_BRAIN: BrainState = {
  categories: [], finding: null, fingerprint: '', newTitle: '', open: false, selectedId: null, stage: 'ask',
};

function safeStorage(kind: 'local' | 'session'): Storage | null {
  try { return kind === 'local' ? window.localStorage : window.sessionStorage; } catch { return null; }
}

function consumeInitialPayload(): string {
  const session = safeStorage('session');
  const local = safeStorage('local');
  const sessionRaw = session?.getItem(REPORT_PAYLOAD_KEY) || '';
  if (sessionRaw) {
    session?.removeItem(REPORT_PAYLOAD_KEY);
    return sessionRaw;
  }
  const shared = local?.getItem(REPORT_SHARED_KEY) || '';
  if (shared) local?.removeItem(REPORT_SHARED_KEY);
  return shared;
}

function persistPayload(target: string, findings: ReportFinding[]) {
  const raw = JSON.stringify({ target, updatedAt: new Date().toISOString(), findings });
  if (raw.length > 4_500_000) throw new Error('Pacote demasiado grande para storage (máx. ~4,5 MB).');
  safeStorage('session')?.setItem(REPORT_PAYLOAD_KEY, raw);
  safeStorage('local')?.setItem(REPORT_SHARED_KEY, raw);
}

function annotationKey(target: string): string {
  const normalized = normalizeTarget(target);
  return `ghostrecon_reporte_ann_v1:${targetUsableForApi(normalized) ? normalized : '_sem_alvo'}`;
}

function readAnnotations(target: string): AnnotationMap {
  try {
    const parsed = JSON.parse(safeStorage('local')?.getItem(annotationKey(target)) || 'null') as Record<string, unknown> | null;
    const output = emptyAnnotationMap();
    if (parsed) for (const key of Object.keys(output) as Array<keyof AnnotationMap>) if (typeof parsed[key] === 'string') output[key] = parsed[key] as string;
    return output;
  } catch { return emptyAnnotationMap(); }
}

function writeAnnotations(target: string, value: AnnotationMap) {
  try { safeStorage('local')?.setItem(annotationKey(target), JSON.stringify({ ...value, savedAt: new Date().toISOString() })); } catch { /* quota/private mode */ }
}

function download(name: string, content: string, type: string) {
  const href = URL.createObjectURL(new Blob([content], { type }));
  const anchor = document.createElement('a');
  anchor.href = href;
  anchor.download = name;
  anchor.rel = 'noopener';
  anchor.click();
  URL.revokeObjectURL(href);
}

function GhostMark() {
  return (
    <svg viewBox="0 0 48 52" xmlns="http://www.w3.org/2000/svg" width="100" height="108" focusable="false">
      <defs>
        <linearGradient id="reporteBgGhostGrad" x1="0%" y1="0%" x2="100%" y2="100%"><stop offset="0%" stopColor="#e8fbff" /><stop offset="45%" stopColor="#5ee0ff" /><stop offset="100%" stopColor="#00a8d4" /></linearGradient>
        <linearGradient id="reporteBgGhostSheen" x1="15%" y1="0%" x2="75%" y2="85%"><stop offset="0%" stopColor="rgba(255,255,255,0.35)" /><stop offset="45%" stopColor="rgba(255,255,255,0)" /><stop offset="100%" stopColor="rgba(0,45,70,0.22)" /></linearGradient>
      </defs>
      <g className="ghost-anim-reporte"><path fill="url(#reporteBgGhostGrad)" stroke="rgba(0,212,255,0.45)" strokeWidth="0.55" d="M 24 5 C 13 5 5 13.5 5 24.5 V 40 Q 8.5 36.5 12 40 Q 15.5 36.5 19 40 Q 22.5 36.5 26 40 Q 29.5 36.5 33 40 Q 36.5 36.5 40 40 Q 43.5 36.5 43 40 V 24.5 C 43 13.5 35 5 24 5 Z" /><path fill="url(#reporteBgGhostSheen)" d="M 24 8 C 15 8 9 15 9 23.5 V 33 Q 16 28 24 32 Q 32 28 39 33 V 23.5 C 39 15 33 8 24 8 Z" opacity="0.88" /><ellipse className="ghost-eye-reporte" cx="17" cy="22" rx="3.2" ry="4.2" fill="#050709" /><ellipse className="ghost-eye-reporte ghost-eye-reporte-r" cx="31" cy="22" rx="3.2" ry="4.2" fill="#050709" /></g>
    </svg>
  );
}

export function ReportPage({ page }: { page: ReactUiPage }) {
  const snapshot = useMemo(() => snapshotLegacyDocument(page.source), [page.source]);
  const service = useMemo(() => createReportService(), []);
  const fileRef = useRef<HTMLInputElement>(null);
  const liveSequence = useRef(0);
  const [target, setTarget] = useState('');
  const [findings, setFindings] = useState<ReportFinding[]>([]);
  const [serverItems, setServerItems] = useState<ManualValidation[]>([]);
  const [validated, setValidated] = useState<Set<string>>(() => new Set());
  const [notes, setNotes] = useState<Record<string, string>>({});
  const [message, setMessage] = useState<Message>({ kind: '', text: '' });
  const [showDorks, setShowDorks] = useState(false);
  const [dockOpen, setDockOpen] = useState(false);
  const [importVisible, setImportVisible] = useState(true);
  const [importText, setImportText] = useState('');
  const [live, setLive] = useState(false);
  const [aiUseOpenrouter, setAiUseOpenrouter] = useState(false);
  const [busy, setBusy] = useState(false);
  const [brain, setBrain] = useState<BrainState>(CLOSED_BRAIN);
  const [subsetFilter, setSubsetFilter] = useState<string | null>(null);
  const [headline, setHeadline] = useState('A carregar…');

  const setError = (error: unknown) => setMessage({ kind: 'err', text: error instanceof Error ? error.message : String(error) });

  useEffect(() => {
    document.title = snapshot.title;
    document.documentElement.lang = snapshot.htmlLang;
    document.body.dataset.ghostreconReactPage = page.id;
    document.body.dataset.ghostreconReactTree = '1';
    document.body.dataset.ghostreconNativeReport = '1';
    document.body.dataset.ghostreconLegacyReady = '1';
    for (const [name, value] of snapshot.bodyAttributes) document.body.setAttribute(name, value);
    const head = snapshot.headMarkup.map((markup) => appendHeadMarkup(markup, page.id)).filter((value): value is HTMLElement => Boolean(value));
    return () => { head.forEach((value) => value.remove()); delete document.body.dataset.ghostreconNativeReport; };
  }, [page.id, snapshot]);

  const loadValidationState = useCallback(async (nextTarget: string, signal?: AbortSignal) => {
    if (!targetUsableForApi(nextTarget)) {
      setServerItems([]);
      setValidated(new Set());
      setNotes({});
      return [];
    }
    const rows = await service.loadValidations(nextTarget, signal);
    setServerItems(rows);
    const fingerprints = new Set<string>();
    const nextNotes: Record<string, string> = {};
    rows.forEach((row) => {
      const fp = String(row.fingerprint || '').toLowerCase();
      if (!/^[a-f0-9]{64}$/.test(fp)) return;
      fingerprints.add(fp);
      nextNotes[fp] = String(row.notes || '');
    });
    setValidated(fingerprints);
    setNotes(nextNotes);
    return rows;
  }, [service]);

  const applyPayload = useCallback(async (payload: ReportPayload, options: { live?: boolean; signal?: AbortSignal } = {}) => {
    const seq = ++liveSequence.current;
    const normalizedTarget = normalizeTarget(payload.target || '');
    const rows = await hydrateFindings(extractFindings(payload), normalizedTarget);
    let nextTarget = normalizedTarget || deriveTargetFromFindings(rows);
    const filter = payload.subsetFilter && payload.subsetFilter !== 'all' ? String(payload.subsetFilter).toLowerCase() : subsetFilter;
    let validationRows: ManualValidation[] = [];
    try { validationRows = await loadValidationState(nextTarget, options.signal); } catch { /* local package stays usable offline */ }
    if (seq !== liveSequence.current) return;
    const currentValidated = new Set(validationRows.map((row) => String(row.fingerprint || '').toLowerCase()).filter((fp) => /^[a-f0-9]{64}$/.test(fp)));
    const filtered = applySubset(rows, filter, currentValidated).slice(0, REPORT_IMPORT_MAX);
    if (!nextTarget) nextTarget = deriveTargetFromFindings(filtered);
    setSubsetFilter(filter || null);
    setTarget(nextTarget);
    setFindings(filtered);
    setLive(Boolean(options.live));
    const stamp = String(payload.updatedAt || payload.exportedAt || '?').slice(0, 19).replace('T', ' ');
    setHeadline(targetUsableForApi(nextTarget) ? `Alvo: ${nextTarget} · ${options.live ? 'ao vivo' : 'pacote'} · ${stamp}` : `Sem alvo válido · ${options.live ? 'ao vivo' : 'pacote'} · ${stamp}`);
    try { persistPayload(nextTarget, filtered); } catch { /* keep memory state */ }
    setMessage({ kind: filtered.length ? 'ok' : 'err', text: options.live ? `Actualização ao vivo — ${filtered.length} achado(s).` : filtered.length ? 'Marca apenas o que testaste manualmente.' : 'Pacote sem achados utilizáveis.' });
  }, [loadValidationState, subsetFilter]);

  useEffect(() => {
    const abort = new AbortController();
    void (async () => {
      try {
        const raw = consumeInitialPayload();
        if (!raw) {
          setTarget(''); setFindings([]); setHeadline('Sem pacote — abre a partir do GHOSTRECON.');
          setMessage({ kind: 'err', text: 'Sem pacote na sessão. Usa Recarregar da base ou Importar JSON.' });
        } else {
          await applyPayload(JSON.parse(raw) as ReportPayload, { signal: abort.signal });
        }
      } catch (error) { if (!abort.signal.aborted) setError(error); }
      try {
        const capabilities = await service.capabilities(abort.signal);
        if (!abort.signal.aborted) setAiUseOpenrouter(Boolean(capabilities?.ai?.openrouter));
      } catch { /* optional AI capability */ }
    })();
    return () => abort.abort();
  }, [applyPayload, service]);

  useEffect(() => {
    if (typeof BroadcastChannel === 'undefined') return undefined;
    let channel: BroadcastChannel | null = null;
    const connect = () => {
      channel?.close(); channel = null;
      const id = safeStorage('local')?.getItem(MITRE_SESSION_KEY) || '';
      if (!id) return;
      channel = new BroadcastChannel(`ghostrecon-mitre-${id}`);
      channel.addEventListener('message', (event) => {
        const payload = event.data as Record<string, unknown>;
        if (payload?.type !== 'reporte_payload' || payload.live !== true) return;
        void applyPayload(payload as ReportPayload, { live: true }).catch(setError);
      });
    };
    const storage = (event: StorageEvent) => { if (event.key === MITRE_SESSION_KEY) connect(); };
    connect(); window.addEventListener('storage', storage);
    return () => { channel?.close(); window.removeEventListener('storage', storage); };
  }, [applyPayload]);

  useEffect(() => {
    const keydown = (event: KeyboardEvent) => {
      if (event.key !== 'Escape') return;
      if (dockOpen) { setDockOpen(false); event.preventDefault(); }
      else if (brain.open) { setBrain(CLOSED_BRAIN); event.preventDefault(); }
    };
    document.addEventListener('keydown', keydown);
    return () => document.removeEventListener('keydown', keydown);
  }, [brain.open, dockOpen]);

  const inferred = deriveTargetFromFindings(findings);
  const mismatch = targetUsableForApi(target) && targetUsableForApi(inferred) && normalizeTarget(target) !== inferred;
  const visibleFindings = findings.filter((finding) => /^[a-f0-9]{64}$/.test(String(finding.fingerprint || '')) && (showDorks || !isDorkFinding(finding)));
  const validatedRows = findings.filter((finding) => validated.has(String(finding.fingerprint || '').toLowerCase()));

  const refresh = async () => {
    setBusy(true); setMessage({ kind: '', text: 'A sincronizar…' });
    try {
      if (!findings.length) {
        const run = await service.loadLatestRun(target);
        const rows = await hydrateFindings(run.findings, run.target);
        setTarget(run.target); setFindings(rows); persistPayload(run.target, rows);
        await loadValidationState(run.target);
        setHeadline(`Alvo: ${run.target} · run #${run.runId}`);
      } else await loadValidationState(target);
      setMessage({ kind: 'ok', text: 'Sincronizado com a base.' });
    } catch (error) { setError(error); } finally { setBusy(false); }
  };

  const importJson = async () => {
    try {
      const parsed = JSON.parse(importText.trim()) as ReportPayload | unknown[];
      const payload = Array.isArray(parsed) ? { target: '', findings: parsed } : parsed;
      await applyPayload(payload as ReportPayload);
      setMessage({ kind: 'ok', text: `Checklist actualizado com até ${REPORT_IMPORT_MAX} achados.` });
    } catch (error) { setError(error instanceof SyntaxError ? new Error('JSON inválido (parse).') : error); }
  };

  const fileChange = (event: ChangeEvent<HTMLInputElement>) => {
    const file = event.currentTarget.files?.[0]; if (!file) return;
    const reader = new FileReader(); reader.onload = () => setImportText(String(reader.result || '')); reader.readAsText(file);
  };

  const saveAnnotationState = (finding: ReportFinding, fingerprint: string, note: string, on: boolean, full = true, targetOverride = target) => {
    let map = readAnnotations(targetOverride);
    map = on ? mergeFindingIntoAnnotations(map, finding, fingerprint, note, targetOverride, full) : { ...map, s5: removeAnnotationFinding(map.s5, fingerprint) };
    writeAnnotations(targetOverride, map);
  };

  const toggleValidation = async (finding: ReportFinding) => {
    const fp = String(finding.fingerprint || '').toLowerCase();
    const next = !validated.has(fp);
    const resolvedTarget = targetUsableForApi(target) ? normalizeTarget(target) : deriveTargetFromFinding(finding) || deriveTargetFromFindings(findings);
    if (!targetUsableForApi(resolvedTarget)) { setError(new Error('Não foi possível inferir um domínio válido.')); return; }
    setBusy(true);
    try {
      await service.persistValidation({ target: resolvedTarget, finding, fingerprint: fp, notes: notes[fp] || '', validated: next });
      setTarget(resolvedTarget);
      setValidated((current) => { const copy = new Set(current); if (next) copy.add(fp); else copy.delete(fp); return copy; });
      saveAnnotationState(finding, fp, notes[fp] || '', next, true, resolvedTarget);
      safeStorage('local')?.setItem('ghostrecon_manual_val_bump', String(Date.now()));
      setMessage({ kind: 'ok', text: next ? 'Gravado como validado.' : 'Validação removida.' });
      if (next) setBrain({ ...CLOSED_BRAIN, open: true, stage: 'ask', fingerprint: fp, finding });
    } catch (error) { setError(error); } finally { setBusy(false); }
  };

  const saveNote = async (finding: ReportFinding) => {
    const fp = String(finding.fingerprint || '').toLowerCase();
    if (!validated.has(fp)) return;
    try {
      await service.persistValidation({ target, finding, fingerprint: fp, notes: notes[fp] || '', validated: true });
      saveAnnotationState(finding, fp, notes[fp] || '', true, false);
      setMessage({ kind: 'ok', text: 'Notas actualizadas.' });
    } catch (error) { setError(error); }
  };

  const openBrainPicker = async () => {
    try {
      const categories = await service.listBrainCategories();
      setBrain((current) => ({ ...current, categories, selectedId: categories[0]?.id ?? null, stage: 'pick' }));
    } catch (error) { setError(error); }
  };

  const createCategory = async () => {
    const title = brain.newTitle.trim(); if (!title) return;
    try {
      const id = await service.createBrainCategory(title);
      const categories = await service.listBrainCategories();
      setBrain((current) => ({ ...current, categories, selectedId: id, newTitle: '' }));
    } catch (error) { setError(error); }
  };

  const saveBrain = async () => {
    if (!brain.selectedId || !brain.fingerprint) { setError(new Error('Selecciona ou cria uma categoria.')); return; }
    try {
      await service.linkBrain(target, brain.fingerprint, brain.selectedId);
      const label = String(brain.categories.find((category) => category.id === brain.selectedId)?.title || 'OK');
      setServerItems((items) => {
        const match = items.find((item) => String(item.fingerprint || '').toLowerCase() === brain.fingerprint);
        return match ? items.map((item) => item === match ? { ...item, brainCategoryTitle: label } : item) : [...items, { fingerprint: brain.fingerprint, brainCategoryTitle: label }];
      });
      setBrain(CLOSED_BRAIN); setMessage({ kind: 'ok', text: `Ligado ao cérebro: ${label}` });
    } catch (error) { setError(error); }
  };

  const generateAi = async () => {
    if (!validatedRows.length) return;
    setBusy(true); setMessage({ kind: '', text: 'A pedir relatório por IA…' });
    try {
      const data = await service.generateAi(target, validatedRows, aiUseOpenrouter);
      const engines = ['openrouter', 'gemini', 'lmstudio', 'claude'].map((name) => `${name}: ${data[name]?.ok ? 'OK' : data[name]?.error || '—'}`).join(' · ');
      setMessage({ kind: Object.values(data).some((value: any) => value?.ok) ? 'ok' : 'err', text: `${engines}${data.outputDir ? `\nSaída: ${data.outputDir}` : ''}` });
    } catch (error) { setError(error); } finally { setBusy(false); }
  };

  const annotationPayload = () => {
    const validations = new Map(serverItems.flatMap((item) => {
      const fingerprint = String(item.fingerprint || '').trim().toLowerCase();
      return /^[a-f0-9]{64}$/.test(fingerprint) ? [[fingerprint, {
        fingerprint,
        notes: String(item.notes || ''),
        snapshot: item.snapshot && typeof item.snapshot === 'object' ? item.snapshot : null,
        validated_at: String(item.validated_at || ''),
      }] as const] : [];
    }));
    validatedRows.forEach((finding) => {
      const fp = String(finding.fingerprint || '').toLowerCase();
      const stored = validations.get(fp);
      validations.set(fp, { fingerprint: fp, notes: notes[fp] || stored?.notes || '', snapshot: stored?.snapshot || snapshotFromFinding(finding), validated_at: stored?.validated_at || '' });
    });
    return {
      target: normalizeTarget(target), updatedAt: new Date().toISOString(), findings: findings.map((finding) => ({ ...finding })),
      manualValidations: [...validations.values()],
    };
  };

  const openAnnotations = async () => {
    const popup = window.open('about:blank', '_blank');
    if (popup) popup.opener = null;
    const payload = annotationPayload();
    const raw = JSON.stringify(payload);
    if (raw.length > 4_500_000) { popup?.close(); setError(new Error('Pacote demasiado grande (máx. ~4,5 MB).')); return; }
    const destination = new URL('/anotacao/ghostrecon/import', window.location.origin === 'null' ? 'http://127.0.0.1:3847' : window.location.origin);
    try { destination.searchParams.set('handoff', await service.annotationHandoff(payload)); }
    catch (error) { setMessage({ kind: 'err', text: `Aviso handoff: ${error instanceof Error ? error.message : String(error)} (fallback storage).` }); }
    safeStorage('session')?.setItem(ANNOTATION_PAYLOAD_KEY, raw);
    safeStorage('session')?.setItem(REPORT_PAYLOAD_KEY, raw);
    safeStorage('local')?.setItem(REPORT_SHARED_KEY, raw);
    safeStorage('local')?.setItem(ANNOTATION_HANDOFF_KEY, raw);
    if (popup) popup.location.href = destination.href;
    else setError(new Error('Popup bloqueado — permite popups para abrir Anotações.'));
  };

  const markdown = () => buildReportMarkdown(target, findings, validated, notes);
  const safeName = (normalizeTarget(target) || 'reporte').replace(/[^a-z0-9.-]+/gi, '_');
  const exportJson = () => download(`${safeName}.json`, JSON.stringify(annotationPayload(), null, 2), 'application/json');
  const exportMarkdown = () => download(`${safeName}.md`, markdown(), 'text/markdown');
  const exportHtml = () => download(`${safeName}.html`, buildReportHtml(markdown()), 'text/html');
  const copyReport = async () => { try { await navigator.clipboard.writeText(markdown()); setMessage({ kind: 'ok', text: 'Relatório copiado.' }); } catch (error) { setError(error); } };

  return (
    <>
      <header className="reporte-hd"><div className="reporte-ghost-bg" aria-hidden="true"><GhostMark /></div><div className="reporte-hd-inner"><h1>Reporte — checklist manual</h1><div className="sub" id="headLine">{headline}</div><div id="targetMismatchBanner" className="reporte-banner-warn" role="status" aria-live="polite" style={{ display: mismatch ? 'block' : 'none' }}>{mismatch ? `Alvo do pacote: «${normalizeTarget(target)}» — primeiro host inferido: «${inferred}». Confirma o domínio.` : ''}</div></div></header>
      <main>
        <div className="toolbar">
          <button type="button" id="btnReload" disabled={busy} onClick={() => void refresh()}>Recarregar da base</button>
          <button type="button" className="btn-primary" id="btnAi" disabled={busy || !validatedRows.length} onClick={() => void generateAi()}>Gerar relatório IA ({validatedRows.length} validados)</button>
          <button type="button" id="btnToggleDorks" onClick={() => setShowDorks((value) => !value)}>{showDorks ? 'Ocultar dorks' : 'Mostrar dorks'}</button>
          <button type="button" className="btn-primary" id="btnAnotacao" onClick={() => void openAnnotations()}>ANOTAÇÃO</button>
          <button type="button" id="btnExportJson" onClick={exportJson}>JSON</button><button type="button" id="btnExportMarkdown" onClick={exportMarkdown}>Markdown</button><button type="button" id="btnExportHtml" onClick={exportHtml}>HTML</button><button type="button" id="btnPrintPdf" onClick={() => window.print()}>PDF / imprimir</button><button type="button" id="btnCopyReport" onClick={() => void copyReport()}>Copiar</button>
          <span className="sub" id="countLine">{visibleFindings.length} na checklist (de {findings.length}) · {validated.size} com validação</span><span className="reporte-live-pill" id="reporteLivePill" hidden={!live}>Ao vivo</span>
        </div>
        <div id="list">
          {!visibleFindings.length ? <div className="empty">{findings.length ? 'Nenhum achado com fingerprint válido nesta vista.' : 'Sem achados. Usa RUN RECON, Recarregar ou Importar.'}</div> : null}
          {visibleFindings.map((finding) => {
            const fp = String(finding.fingerprint || '').toLowerCase(); const on = validated.has(fp);
            const previous = serverItems.find((item) => String(item.fingerprint || '').toLowerCase() === fp);
            const brainTitle = String(previous?.brainCategoryTitle || '');
            const link = externalUrl(finding.url) || externalUrl(finding.value);
            return <div className={`row${on ? ' validated' : ''}`} key={fp}><div><div className="meta">{finding.type || ''} · {finding.prio || ''} · <code>{fp.slice(0, 12)}…</code></div><div className="val">{String(finding.value || '')}</div>{link ? <button type="button" className="url report-open-url-hit" aria-label="Abrir URL em nova aba" onClick={() => window.open(link, '_blank', 'noopener,noreferrer')}>↗ URL</button> : null}<div className="taxo-tags">{taxonomyIds(finding.owasp, /^A\d{2}$/i).map((id) => <span key={id} className="taxo-tag owasp">{id}</span>)}{taxonomyIds(finding.mitre, /^T\d{4}(?:\.\d{3})?$/i).map((id) => <span key={id} className="taxo-tag mitre">{id}</span>)}</div><textarea className="notes-in" data-fp={fp} rows={2} placeholder="Notas do teste manual (opcional)" value={notes[fp] || ''} onChange={(event) => setNotes((current) => ({ ...current, [fp]: event.currentTarget.value }))} onBlur={() => void saveNote(finding)} />{on && brainTitle ? <div className="brain-badge">🧠 {brainTitle}</div> : null}{on && !brainTitle ? <button type="button" className="brain-add-btn" onClick={() => { setBrain({ ...CLOSED_BRAIN, open: true, stage: 'pick', fingerprint: fp, finding }); void service.listBrainCategories().then((categories) => setBrain((current) => ({ ...current, categories, selectedId: categories[0]?.id ?? null }))).catch(setError); }}>+ Cérebro</button> : null}</div><button type="button" className={`val-toggle${on ? ' is-on' : ''}`} data-state={on ? 'ON' : 'OFF'} aria-pressed={on} aria-label={on ? 'Validado manualmente' : 'Marcar como validado'} disabled={busy} onClick={() => void toggleValidation(finding)} /></div>;
          })}
        </div>
        <div className={`log${message.kind ? ` ${message.kind}` : ''}`} id="msg">{message.text}</div>
      </main>
      <div id="reportJsonDockWrap" className={`report-json-dock-wrap${dockOpen ? ' is-open' : ''}`}><button type="button" id="reportJsonDockTab" className="report-json-dock-tab" aria-expanded={dockOpen} aria-controls="reportJsonDockPanel" onClick={() => setDockOpen((value) => !value)}>Importar</button><aside id="reportJsonDockPanel" className="report-json-dock-panel" aria-label="Importar JSON no checklist" aria-hidden={!dockOpen}><div className="report-json-dock-head"><h2 className="report-json-dock-title">Importar JSON</h2><button type="button" className="report-json-dock-close" id="reportJsonDockClose" aria-label="Fechar painel" onClick={() => setDockOpen(false)}>×</button></div><div className="report-json-toggle-row"><label htmlFor="reportJsonPanelToggle"><input type="checkbox" id="reportJsonPanelToggle" checked={importVisible} onChange={(event) => setImportVisible(event.currentTarget.checked)} /> Mostrar campo importar</label></div><div id="reportJsonPanelWrap" style={{ display: importVisible ? 'block' : 'none' }}><div className="report-json-import-bar"><label htmlFor="reportImportJson">JSON com <code>target</code> e <code>findings</code>.</label><textarea id="reportImportJson" spellCheck={false} autoComplete="off" value={importText} onChange={(event) => setImportText(event.currentTarget.value)} /><div className="report-json-import-actions"><input ref={fileRef} type="file" id="reportImportFile" accept=".json,application/json" onChange={fileChange} /><button type="button" id="reportImportApply" onClick={() => void importJson()}>Aplicar checklist</button><button type="button" id="reportImportClearField" onClick={() => { setImportText(''); if (fileRef.current) fileRef.current.value = ''; }}>Limpar campo</button></div><p className="report-json-hint">Máx. 6000 achados; fingerprints ausentes são calculados no browser.</p></div></div></aside></div>
      <div id="brainModal" className={`modal-overlay${brain.open ? ' is-open' : ''}`} aria-hidden={!brain.open} onClick={(event) => { if (event.target === event.currentTarget) setBrain(CLOSED_BRAIN); }}><div className="modal-box" role="dialog" aria-modal="true" aria-labelledby="brainModalHead"><div className="modal-head" id="brainModalHead">Modo cérebro</div><div id="brainModalBody">{brain.stage === 'ask' ? <p className="modal-p">Queres adicionar este achado confirmado ao <strong>modo cérebro</strong>?</p> : <><p className="modal-p">Escolhe ou cria uma categoria:</p><div className="brain-chips" id="brainChipsHost">{brain.categories.map((category) => <button type="button" key={category.id} className={`brain-chip${brain.selectedId === category.id ? ' is-sel' : ''}`} onClick={() => setBrain((current) => ({ ...current, selectedId: category.id }))}>{String(category.title || category.id)}</button>)}</div><div id="brainNewWrap"><input type="text" id="brainNewTitle" className="notes-in" value={brain.newTitle} onChange={(event) => setBrain((current) => ({ ...current, newTitle: event.currentTarget.value }))} /><button type="button" id="brainNewCreate" onClick={() => void createCategory()}>Criar categoria</button></div></>}</div><div className="modal-actions" id="brainModalActions">{brain.stage === 'ask' ? <><button type="button" id="brainYes" onClick={() => void openBrainPicker()}>Sim, escolher tipo</button><button type="button" id="brainNo" onClick={() => setBrain(CLOSED_BRAIN)}>Não</button></> : <><button type="button" id="brainSave" onClick={() => void saveBrain()}>Guardar no cérebro</button><button type="button" id="brainCancel" onClick={() => setBrain(CLOSED_BRAIN)}>Cancelar</button></>}</div></div></div>
      <footer><span className="sub" id="footHint">Marca apenas o que testaste manualmente. O badge Ao vivo indica BroadcastChannel activo; Anotação usa apenas achados validados.</span></footer>
    </>
  );
}
