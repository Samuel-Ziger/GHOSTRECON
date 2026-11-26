import {
  Fragment,
  useEffect,
  useLayoutEffect,
  useRef,
  useState,
  type KeyboardEvent as ReactKeyboardEvent,
  type PointerEvent as ReactPointerEvent,
  type ReactNode,
} from 'react';
import {
  isVigoliumFinding,
  selectFindings,
  type Finding,
} from '../findings/model';
import { useExecutionState, useExecutionStore } from './store';

const FILTERS = [
  ['all', 'ALL'],
  ['dorks', 'DORKS'],
  ['high', '🔴 HIGH'],
  ['med', '🟡 MED'],
  ['low', '🟢 LOW'],
  ['subdomain', 'SUBS'],
  ['subfinder', 'HOSTS', 'Hosts com DNS OK reportados pelo subfinder (Kali)'],
  ['endpoint', 'ENDPOINTS'],
  ['param', 'PARAMS'],
  ['secret', 'SECRETS'],
  ['nmap', 'NMAP'],
  ['exploit', 'EXPLOIT.DB'],
  ['nuclei', 'NUCLEI'],
  ['vigolium', 'VIGOLIUM'],
  ['wpscan', 'WPSCAN'],
  ['dalfox', 'DALFOX'],
  ['xss', 'XSS'],
  ['sqli', 'SQLI'],
  ['lfi', 'LFI'],
  ['open_redirect', 'REDIRECT'],
  ['idor', 'IDOR'],
  ['takeover', 'TAKEOVER'],
  ['secret_validation', 'SECRET-CHECK'],
  ['whois', 'WHOIS'],
  ['security', 'SEC'],
  ['tls', 'TLS'],
  ['rdap', 'RDAP'],
] as const;

const SEARCH_CHIPS = ['login', 'admin', 'api', 'graphql', 'sqli', 'xss', 'idor', 'secret', 'token', 'cors'];
const FINDINGS_WIDTH_STORAGE_KEY = 'ghostrecon.ui.findingsPanelWidth';
const FINDINGS_MIN_WIDTH = 320;
const TERMINAL_MIN_WIDTH = 280;
const FINDINGS_STACK_BREAKPOINT = 1020;

function storedFindingsWidth(): number | null {
  try {
    const value = Number(window.localStorage.getItem(FINDINGS_WIDTH_STORAGE_KEY));
    return Number.isFinite(value) && value >= FINDINGS_MIN_WIDTH ? value : null;
  } catch {
    return null;
  }
}

type TaxonomyTag = { id?: unknown; label?: unknown; title?: unknown };

function taxonomy(value: unknown): TaxonomyTag[] {
  return Array.isArray(value)
    ? value.filter((entry): entry is TaxonomyTag => Boolean(entry && typeof entry === 'object'))
    : [];
}

function inlineStrong(value: unknown): ReactNode[] {
  return String(value || '').split(/(\*\*[^*]+\*\*)/g).filter(Boolean).map((part, index) => (
    part.startsWith('**') && part.endsWith('**')
      ? <strong key={index}>{part.slice(2, -2)}</strong>
      : <Fragment key={index}>{part}</Fragment>
  ));
}

function openFinding(value: unknown) {
  const url = String(value || '').trim();
  if (url) window.open(url, '_blank', 'noopener,noreferrer');
}

async function copyFinding(value: unknown) {
  const text = String(value ?? '');
  const legacy = (window as Window & { copyText?: (value: string) => void }).copyText;
  if (typeof legacy === 'function') {
    legacy(text);
    return;
  }
  try {
    await navigator.clipboard.writeText(text);
  } catch {
    // Clipboard can be denied in file://. The value remains selectable in the card.
  }
}

function FindingCard({ finding, manuallyValidated }: {
  finding: Finding;
  manuallyValidated: boolean;
}) {
  const store = useExecutionStore();
  const priority = String(finding.prio || 'low');
  const highProbability = finding.attackTier === 'HIGH_PROBABILITY';
  const scoreClass = priority === 'high' ? 'score-high' : priority === 'med' ? 'score-med' : 'score-low';
  const reasons = Array.isArray(finding.priorityWhy) ? finding.priorityWhy.map(String) : [];
  const composite = Number(finding.compositeScore);
  const risk = finding.risk && typeof finding.risk === 'object'
    ? finding.risk as Record<string, unknown>
    : null;
  const provenance = finding.provenance && typeof finding.provenance === 'object'
    ? finding.provenance as Record<string, unknown>
    : null;
  const fingerprint = String(finding.fingerprint || '');

  const dismiss = () => {
    const legacy = (window as Window & {
      dismissFindingFingerprint?: (value: string) => void;
    }).dismissFindingFingerprint;
    if (typeof legacy === 'function') legacy(fingerprint);
    else store.dismissFingerprint(fingerprint);
  };

  return (
    <div
      className={`finding-card prio-${priority}${highProbability ? ' finding-hpt' : ''}`}
      data-prio={priority}
      data-type={String(finding.type || '')}
    >
      <div className="finding-top">
        <span className={`finding-type type-${String(finding.type || '')}`}>
          {String(finding.type || '?').toUpperCase()}
        </span>
        {highProbability ? (
          <span className="finding-hpt-badge" title={reasons.join(' · ') || 'Priorização v2 — alvo de teste prioritário'}>
            Alta prob.
          </span>
        ) : null}
        {isVigoliumFinding(finding) ? (
          <span className="finding-vigolium-badge" title={finding.moduleId ? `Modulo Vigolium: ${String(finding.moduleId)}` : 'Finding produzido pelo motor Vigolium'}>
            Vigolium
          </span>
        ) : null}
        {manuallyValidated ? (
          <span
            className="finding-manual-val-badge"
            title="Fingerprint já marcado como validado manualmente (Reporte + SQLite). Em recons futuros no mesmo alvo, o mesmo achado volta a mostrar este estado."
          >
            ✓ Manual
          </span>
        ) : null}
        <span style={{ marginLeft: 'auto', display: 'flex', alignItems: 'center', gap: 8 }}>
          {finding.score ? <span className={`finding-score ${scoreClass}`}>{String(finding.score)}</span> : null}
          {Number.isFinite(composite) ? (
            <span className="finding-comp-score" title={reasons.join('\n')}>
              COMP {Math.round(composite)}
            </span>
          ) : null}
        </span>
      </div>
      <div className="finding-value">{String(finding.value ?? '')}</div>
      {finding.meta ? <div className="finding-meta">{String(finding.meta)}</div> : null}
      {risk && (risk.why || risk.next || risk.falsePositive) ? (
        <div className="finding-risk">
          {risk.confidence ? <><strong>Conf.</strong> {String(risk.confidence)}<br /></> : null}
          {risk.why ? <><strong>Risco</strong> {String(risk.why)}<br /></> : null}
          {risk.next ? <><strong>Prox.</strong> {String(risk.next)}<br /></> : null}
          {risk.falsePositive ? <><strong>FP comum</strong> {String(risk.falsePositive)}</> : null}
        </div>
      ) : null}
      {taxonomy(finding.owasp).length ? (
        <div className="finding-owasp">
          {taxonomy(finding.owasp).map((tag, index) => (
            <span className="owasp-tag" key={`${String(tag.id)}-${index}`} title={String(tag.label || `${String(tag.id || '?')}:2025 — ${String(tag.title || '')}`)}>
              {String(tag.id || '?')}
            </span>
          ))}
        </div>
      ) : null}
      {taxonomy(finding.mitre).length ? (
        <div className="finding-mitre">
          {taxonomy(finding.mitre).map((tag, index) => (
            <span className="mitre-tag" key={`${String(tag.id)}-${index}`} title={String(tag.label || `${String(tag.id || '?')} — ${String(tag.title || '')}`)}>
              {String(tag.id || '?')}
            </span>
          ))}
        </div>
      ) : null}
      {provenance?.how || provenance?.relation ? (
        <div className="finding-provenance">
          {provenance.how ? (
            <>
              <div className="finding-provenance-label">Como foi encontrado</div>
              <div className="finding-provenance-text">{inlineStrong(provenance.how)}</div>
            </>
          ) : null}
          {provenance.relation ? (
            <>
              <div className="finding-provenance-label">Relação ao alvo</div>
              <div className="finding-provenance-text">{inlineStrong(provenance.relation)}</div>
            </>
          ) : null}
        </div>
      ) : null}
      <div className="finding-actions">
        {finding.url ? <button className="find-btn" type="button" onClick={() => openFinding(finding.url)}>↗ OPEN</button> : null}
        {fingerprint ? (
          <button className="find-btn dismiss-fp" type="button" title="Marcar como falso positivo (ocultar neste browser)" onClick={dismiss}>
            ✕ FP
          </button>
        ) : null}
        <button className="find-btn" type="button" onClick={() => void copyFinding(finding.value)}>⎘ COPY</button>
      </div>
    </div>
  );
}

export function FindingsPanel() {
  const store = useExecutionStore();
  const state = useExecutionState();
  const panelRef = useRef<HTMLDivElement>(null);
  const dragRef = useRef<{ pointerId: number; startWidth: number; startX: number } | null>(null);
  const [panelWidth, setPanelWidth] = useState<number | null>(storedFindingsWidth);
  const nativeSelect = window.__ghostreconNativeServices?.findings?.select;
  const selected = typeof nativeSelect === 'function'
    ? nativeSelect(state.findings, { filter: state.filter, query: state.search })
    : selectFindings(state.findings, { filter: state.filter, query: state.search });
  const manual = new Set(state.manualFingerprints);
  const setSearch = (query: string) => {
    const legacy = (window as Window & {
      setFindingsSearchQuery?: (value: string) => void;
    }).setFindingsSearchQuery;
    if (typeof legacy === 'function') legacy(query);
    else store.setSearch(query);
  };
  const setFilter = (filter: string) => {
    const legacy = (window as Window & {
      filterFindings?: (value: string) => void;
    }).filterFindings;
    if (typeof legacy === 'function') legacy(filter);
    else store.setFilter(filter);
  };
  const chooseChip = (query: string) => {
    setSearch(state.search.trim().toLowerCase() === query.toLowerCase() ? '' : query);
  };
  const clampWidth = (width: number) => {
    const contentWidth = panelRef.current?.parentElement?.clientWidth || 0;
    const maximum = contentWidth
      ? Math.max(FINDINGS_MIN_WIDTH, contentWidth - TERMINAL_MIN_WIDTH)
      : 900;
    return Math.round(Math.min(maximum, Math.max(FINDINGS_MIN_WIDTH, width)));
  };
  const updatePanelWidth = (width: number) => setPanelWidth(clampWidth(width));
  const resizePanel = (delta: number) => {
    const currentWidth = panelRef.current?.getBoundingClientRect().width || panelWidth || 520;
    updatePanelWidth(currentWidth + delta);
  };
  const resetPanelWidth = () => setPanelWidth(null);
  const startResize = (event: ReactPointerEvent<HTMLDivElement>) => {
    if (window.matchMedia(`(max-width: ${FINDINGS_STACK_BREAKPOINT}px)`).matches) return;
    dragRef.current = {
      pointerId: event.pointerId,
      startWidth: panelRef.current?.getBoundingClientRect().width || 520,
      startX: event.clientX,
    };
    event.currentTarget.setPointerCapture(event.pointerId);
    document.body.classList.add('is-resizing-findings');
    event.preventDefault();
  };
  const moveResize = (event: ReactPointerEvent<HTMLDivElement>) => {
    const drag = dragRef.current;
    if (!drag || drag.pointerId !== event.pointerId) return;
    updatePanelWidth(drag.startWidth + drag.startX - event.clientX);
  };
  const stopResize = (event: ReactPointerEvent<HTMLDivElement>) => {
    if (dragRef.current?.pointerId !== event.pointerId) return;
    dragRef.current = null;
    document.body.classList.remove('is-resizing-findings');
    if (event.currentTarget.hasPointerCapture(event.pointerId)) {
      event.currentTarget.releasePointerCapture(event.pointerId);
    }
  };
  const resizeWithKeyboard = (event: ReactKeyboardEvent<HTMLDivElement>) => {
    if (event.key === 'ArrowLeft') {
      resizePanel(40);
      event.preventDefault();
    } else if (event.key === 'ArrowRight') {
      resizePanel(-40);
      event.preventDefault();
    } else if (event.key === 'Home') {
      resetPanelWidth();
      event.preventDefault();
    }
  };

  useLayoutEffect(() => {
    const contentArea = panelRef.current?.parentElement;
    if (!contentArea) return;
    if (panelWidth === null) contentArea.style.removeProperty('--findings-panel-width');
    else contentArea.style.setProperty('--findings-panel-width', `${panelWidth}px`);
    try {
      if (panelWidth === null) window.localStorage.removeItem(FINDINGS_WIDTH_STORAGE_KEY);
      else window.localStorage.setItem(FINDINGS_WIDTH_STORAGE_KEY, String(panelWidth));
    } catch {
      // Preferência visual continua válida na sessão mesmo com storage bloqueado.
    }
  }, [panelWidth]);

  useLayoutEffect(() => {
    const contentArea = panelRef.current?.parentElement;
    if (!contentArea || typeof ResizeObserver === 'undefined') return undefined;
    const keepInsideRightEdge = () => {
      const available = contentArea.clientWidth;
      if (!available) return;
      const maximum = Math.max(FINDINGS_MIN_WIDTH, available - TERMINAL_MIN_WIDTH);
      setPanelWidth((current) => {
        if (current === null || current <= maximum) return current;
        return Math.round(maximum);
      });
    };
    keepInsideRightEdge();
    const observer = new ResizeObserver(keepInsideRightEdge);
    observer.observe(contentArea);
    return () => observer.disconnect();
  }, []);

  useEffect(() => {
    const contentArea = panelRef.current?.parentElement;
    return () => {
      contentArea?.style.removeProperty('--findings-panel-width');
      document.body.classList.remove('is-resizing-findings');
    };
  }, []);

  return (
    <div className="findings-panel" data-react-findings="1" ref={panelRef}>
      <div
        aria-label="Redimensionar painel de findings"
        aria-orientation="vertical"
        className="findings-resize-handle"
        onKeyDown={resizeWithKeyboard}
        onPointerCancel={stopResize}
        onPointerDown={startResize}
        onPointerMove={moveResize}
        onPointerUp={stopResize}
        role="separator"
        tabIndex={0}
        title="Arraste para aumentar ou diminuir o painel"
      />
      <div className="panel-header">
        <div className="panel-title-row">
          <div className="panel-title">FINDINGS</div>
          <button
            type="button"
            className="findings-help-trigger"
            title="O que significa cada filtro?"
            aria-label="Ajuda: filtros de achados"
            onClick={() => (window as Window & { openFindingsHelpModal?: () => void }).openFindingsHelpModal?.()}
          >?</button>
        </div>
        <div className="findings-panel-header-actions">
          <div className="findings-size-controls" aria-label="Tamanho do painel">
            <button
              aria-label="Diminuir painel de findings"
              onClick={() => resizePanel(-80)}
              title="Diminuir painel"
              type="button"
            >−</button>
            <button
              aria-label="Restaurar tamanho do painel de findings"
              className="findings-size-reset"
              onClick={resetPanelWidth}
              title="Restaurar tamanho padrão"
              type="button"
            >↔</button>
            <button
              aria-label="Aumentar painel de findings"
              onClick={() => resizePanel(80)}
              title="Aumentar painel"
              type="button"
            >+</button>
          </div>
          <div className="counter" id="findCount">{selected.length} de {state.findings.length} achados</div>
        </div>
      </div>
      <div className="filter-tabs" id="filterTabs">
        {FILTERS.map(([value, label, title]) => (
          <div
            className={`filter-tab${state.filter === value ? ' active' : ''}`}
            key={value}
            title={title}
            onClick={() => setFilter(value)}
          >
            {label}
          </div>
        ))}
      </div>
      <div className="findings-search-row">
        <input
          id="findingsSearchInput"
          className="findings-search-input"
          type="text"
          placeholder="Pesquisar achados (tipo, valor, URL, meta)..."
          autoComplete="off"
          spellCheck={false}
          value={state.search}
          onChange={(event) => setSearch(event.currentTarget.value)}
        />
        <button
          type="button"
          id="findingsSearchClear"
          className="findings-search-clear"
          title="Limpa a pesquisa de achados"
          onClick={() => setSearch('')}
        >
          Limpar busca
        </button>
      </div>
      <div className="findings-search-chips" id="findingsSearchChips">
        {SEARCH_CHIPS.map((query) => (
          <button
            type="button"
            className={`findings-search-chip${state.search.trim().toLowerCase() === query ? ' is-active' : ''}`}
            data-q={query}
            key={query}
            onClick={() => chooseChip(query)}
          >
            {query}
          </button>
        ))}
      </div>
      <div className="findings-list" id="findingsList">
        {selected.length ? selected.map((finding, index) => (
          <FindingCard
            finding={finding}
            key={String(finding.fingerprint || `${finding.type || 'finding'}-${finding.__idx ?? index}`)}
            manuallyValidated={manual.has(String(finding.fingerprint || ''))}
          />
        )) : (
          <div style={{ textAlign: 'center', padding: 30, color: 'var(--text-dim)', fontFamily: 'var(--mono)', fontSize: 11 }}>
            {state.findings.length
              ? `Sem resultados para o filtro "${state.filter === 'subfinder' ? 'HOSTS (subfinder)' : state.filter}"`
              : 'Nenhum achado ainda. Execute o recon para iniciar.'}
          </div>
        )}
      </div>
    </div>
  );
}
