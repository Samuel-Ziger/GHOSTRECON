'use client';

import { useCallback, useEffect, useMemo, useReducer } from 'react';
import {
  INITIAL_LIVE_STATE,
  PIPE_ORDER,
  extractImportFindings,
  liveReducer,
  mitreTechniqueUrl,
  owaspEntry,
  rowToFindingImportPayload,
  type Finding,
  type LiveState,
  type MitreBundle,
  type OwaspHint,
} from './mitreLiveModel';

declare global {
  interface Window {
    __ghostmapMitreLiveChannel?: BroadcastChannel;
  }
}

const SESSION_KEY = 'ghostrecon_mitre_live_session_id';

function resolveSessionId(): string {
  const fromHash = window.location.hash.replace(/^#/, '').trim();
  let fromStorage = '';
  try {
    fromStorage = window.localStorage.getItem(SESSION_KEY) || '';
  } catch {
    // Sandboxed/file contexts can reject localStorage; the hash still works.
  }
  const sessionId = fromStorage || fromHash;
  if (sessionId && sessionId !== fromHash) {
    try {
      const next = new URL(window.location.href);
      next.hash = sessionId;
      window.history.replaceState(null, '', next.toString());
    } catch {
      // Keeping the active channel is more important than cosmetic URL sync.
    }
  }
  return sessionId;
}

function asBundle(value: unknown): MitreBundle {
  return value && typeof value === 'object' ? value as MitreBundle : {};
}

function eventFindingRows(state: LiveState) {
  return state.events.flatMap((event) => {
    if (event.kind !== 'finding' || !event.finding || typeof event.finding !== 'object') return [];
    const finding = event.finding as Finding;
    const row: Record<string, unknown> = {
      type: finding.type,
      priority: finding.prio || finding.priority || '',
      value: finding.value,
      meta: finding.meta || '',
    };
    if (finding.url) row.url = finding.url;
    const mitreHints = Array.isArray(event.mitreHints) ? event.mitreHints : [];
    const mitre = mitreHints
      .filter((id): id is string => typeof id === 'string' && id.startsWith('T'))
      .map((id) => ({ id }));
    if (mitre.length) row.mitre = mitre;
    const owaspHints = Array.isArray(event.owaspHints) ? event.owaspHints as OwaspHint[] : [];
    const owasp = owaspHints.flatMap((hint) => {
      const id = typeof hint === 'string' ? hint : hint.id;
      if (!id || !/^A\d{2}$/i.test(id)) return [];
      return [{
        id: id.toUpperCase(),
        ...(typeof hint === 'object' && hint.title ? { title: hint.title } : {}),
        ...(typeof hint === 'object' && hint.label ? { label: hint.label } : {}),
      }];
    });
    if (owasp.length) row.owasp = owasp;
    return [row];
  });
}

export function buildLiveJson(state: LiveState) {
  const latestTimestamp = state.lastMessageAt || state.events.at(-1)?.t || 0;
  const techniques = state.bundle?.techniques || [];
  const mitreTechniquesHit = [...state.mitreHits].sort((a, b) => a.localeCompare(b, undefined, { numeric: true })).map((id) => {
    const meta = techniques.find((technique) => technique.id === id);
    return { id, name: meta?.name || null, url: meta?.url || mitreTechniqueUrl(id) };
  });
  const bundle = state.bundle
    ? {
      generatedAt: state.bundle.generatedAt || null,
      loaded: true,
      phases: state.bundle.phases,
      scope: state.bundle.scope,
      tacticCount: state.bundle.tactics?.length || 0,
      techniqueCount: state.bundle.techniques?.length || 0,
    }
    : { loaded: false };
  return {
    schemaVersion: 2,
    kind: 'ghostrecon_mitre_live_state',
    note: 'Estado ao vivo do mapa MITRE/OWASP para integração ou debug.',
    target: state.target || null,
    kaliMode: state.kaliMode,
    updatedAt: latestTimestamp ? new Date(latestTimestamp).toISOString() : null,
    bundle,
    pipelineMilestones: { ...state.pipeline },
    mitreTechniquesHit,
    owaspHit: [...state.owaspHits].sort().map((id) => ({ id, ...owaspEntry(id) })),
    timelineEvents: state.events.slice(-120),
  };
}

export function useMitreLiveRuntime() {
  const [state, dispatch] = useReducer(liveReducer, INITIAL_LIVE_STATE);

  useEffect(() => {
    const previousTitle = document.title;
    document.title = 'GHOSTRECON · MITRE + OWASP';
    const basePath = process.env.NEXT_PUBLIC_BASE_PATH || '';
    const stylesheet = document.createElement('link');
    stylesheet.rel = 'stylesheet';
    stylesheet.href = `${basePath}/mitre-live-react.css`;
    stylesheet.dataset.ghostmapMitreLive = 'style';
    document.head.appendChild(stylesheet);
    const fonts = document.createElement('link');
    fonts.rel = 'stylesheet';
    fonts.href = 'https://fonts.googleapis.com/css2?family=Share+Tech+Mono&family=Rajdhani:wght@400;500;600;700&display=swap';
    fonts.dataset.ghostmapMitreLive = 'fonts';
    document.head.appendChild(fonts);
    return () => {
      stylesheet.remove();
      fonts.remove();
      document.title = previousTitle;
    };
  }, []);

  useEffect(() => {
    dispatch({ type: 'session', sessionId: resolveSessionId() });
  }, []);

  useEffect(() => {
    if (!state.sessionResolved || !state.sessionId) return undefined;
    const abort = new AbortController();
    let disposed = false;
    let channel: BroadcastChannel | null = null;

    void (async () => {
      try {
        const response = await fetch('/mitre-attack/recon-bundle.json', {
          cache: 'no-store',
          signal: abort.signal,
        });
        if (!response.ok) throw new Error(`recon-bundle.json HTTP ${response.status}`);
        const bundle = asBundle(await response.json());
        if (!disposed) dispatch({ type: 'bundle', bundle });
      } catch (error) {
        if (!disposed && !abort.signal.aborted) {
          dispatch({ type: 'bundle_error', message: error instanceof Error ? error.message : String(error) });
        }
      }

      if (disposed) return;
      if (typeof BroadcastChannel === 'undefined') {
        dispatch({ type: 'status', text: 'Sem BroadcastChannel', className: 'pill err' });
        return;
      }
      window.__ghostmapMitreLiveChannel?.close();
      channel = new BroadcastChannel(`ghostrecon-mitre-${state.sessionId}`);
      window.__ghostmapMitreLiveChannel = channel;
      channel.addEventListener('message', (event) => {
        const message = event.data && typeof event.data === 'object'
          ? event.data as Record<string, unknown>
          : {};
        dispatch({ type: 'message', message, now: Date.now() });
      });
      dispatch({ type: 'connected' });
    })();

    return () => {
      disposed = true;
      abort.abort();
      channel?.close();
      if (window.__ghostmapMitreLiveChannel === channel) delete window.__ghostmapMitreLiveChannel;
    };
  }, [state.sessionId, state.sessionResolved]);

  const importJson = useCallback((text: string): boolean => {
    let parsed: unknown;
    try {
      parsed = JSON.parse(text);
    } catch {
      dispatch({ type: 'status', text: 'JSON inválido', className: 'pill err' });
      return false;
    }
    const rows = extractImportFindings(parsed).slice(0, 600);
    if (!rows.length) {
      dispatch({ type: 'status', text: 'Sem findings no JSON', className: 'pill err' });
      return false;
    }
    const now = Date.now();
    const target = parsed && typeof parsed === 'object' && !Array.isArray(parsed)
      ? String((parsed as Record<string, unknown>).target || '').trim()
      : '';
    dispatch({
      type: 'import',
      findings: rows.map((row, index) => rowToFindingImportPayload(row, index, now)),
      target,
      now,
    });
    return true;
  }, []);

  const exportJson = useCallback(() => {
    const findings = eventFindingRows(state);
    const output = {
      schemaVersion: 1,
      source: 'ghostrecon-ghostmap-export',
      exportedAt: new Date().toISOString(),
      target: state.target || null,
      findings,
    };
    const safe = (state.target || 'export').replace(/[^\w.-]+/g, '_').slice(0, 80);
    const anchor = document.createElement('a');
    anchor.href = URL.createObjectURL(new Blob([JSON.stringify(output, null, 2)], { type: 'application/json' }));
    anchor.download = `ghostmap_${safe}_${Date.now()}.json`;
    anchor.rel = 'noopener';
    anchor.click();
    URL.revokeObjectURL(anchor.href);
    dispatch({
      type: 'status',
      text: findings.length ? `Export JSON: ${findings.length} achado(s)` : 'Export JSON: ficheiro vazio (0 achados)',
    });
  }, [state]);

  const liveJson = useMemo(() => buildLiveJson(state), [state]);
  return { exportJson, importJson, liveJson, state };
}
