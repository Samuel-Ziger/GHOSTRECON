import type { GhostreconHandoffPayload } from './types';
import {
  ANOTACAO_HANDOFF_LS_KEY,
  ANOTACAO_PAYLOAD_KEY,
  REPORTE_PAYLOAD_KEY,
  REPORTE_PAYLOAD_SHARED_KEY
} from './constants';
import { fetchHandoffById } from './api';

function readPayloadRawFromStorage(): string {
  if (typeof window === 'undefined') return '';
  try {
    const a = sessionStorage.getItem(ANOTACAO_PAYLOAD_KEY);
    if (a) {
      sessionStorage.removeItem(ANOTACAO_PAYLOAD_KEY);
      return a;
    }
  } catch {
    /* ignore */
  }
  try {
    const h = localStorage.getItem(ANOTACAO_HANDOFF_LS_KEY) || '';
    if (h) {
      localStorage.removeItem(ANOTACAO_HANDOFF_LS_KEY);
      return h;
    }
  } catch {
    /* ignore */
  }
  try {
    const r = sessionStorage.getItem(REPORTE_PAYLOAD_KEY);
    if (r) {
      sessionStorage.removeItem(REPORTE_PAYLOAD_KEY);
      return r;
    }
  } catch {
    /* ignore */
  }
  try {
    return localStorage.getItem(REPORTE_PAYLOAD_SHARED_KEY) || '';
  } catch {
    return '';
  }
}

/** Carrega pacote Reporte→Anotações (handoff URL, API ou storage). */
export async function loadGhostreconHandoff(): Promise<GhostreconHandoffPayload | null> {
  if (typeof window === 'undefined') return null;

  const params = new URLSearchParams(window.location.search || '');
  const handoffId = String(params.get('handoff') || '')
    .trim()
    .toLowerCase()
    .replace(/[^a-f0-9]/g, '');

  if (handoffId && /^[a-f0-9]{32}$/.test(handoffId)) {
    const data = (await fetchHandoffById(handoffId)) as GhostreconHandoffPayload;
    try {
      const u = new URL(window.location.href);
      u.searchParams.delete('handoff');
      window.history.replaceState({}, '', u.pathname + u.search + u.hash);
    } catch {
      /* ignore */
    }
    return data;
  }

  const raw = readPayloadRawFromStorage();
  if (!raw) return null;
  try {
    return JSON.parse(raw) as GhostreconHandoffPayload;
  } catch {
    return null;
  }
}
