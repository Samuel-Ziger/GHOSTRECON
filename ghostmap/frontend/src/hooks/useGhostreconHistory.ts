'use client';

import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import {
  fetchHistory,
  fetchProxyStatus,
  proxyAction,
  type ProxyStatus
} from '@/lib/ghostrecon/api';
import type { HistoryEntry, HistoryFilters, HistorySortCol } from '@/lib/ghostrecon/types';
import { filterAndSort } from '@/lib/ghostrecon/history-utils';

const BC_CHANNEL = 'ghostrecon-history';

export function useGhostreconHistory(initialTarget = '') {
  const rowsRef = useRef<HistoryEntry[]>([]);
  const [version, setVersion] = useState(0);
  const [selectedId, setSelectedId] = useState<number | null>(null);
  const lastSeenId = useRef(0);
  const [status, setStatus] = useState('conectando…');
  const [alive, setAlive] = useState(true);
  const [filters, setFilters] = useState<HistoryFilters>({
    search: initialTarget,
    method: '',
    status: '',
    mime: '',
    source: ''
  });
  const [sortCol, setSortCol] = useState<HistorySortCol>('id');
  const [sortDir, setSortDir] = useState(-1);
  const [proxy, setProxy] = useState<ProxyStatus>({});

  const bump = useCallback(() => setVersion((v) => v + 1), []);

  const upsert = useCallback(
    (entry: HistoryEntry) => {
      if (!entry?.id) return;
      const i = rowsRef.current.findIndex((x) => x.id === entry.id);
      if (i >= 0) rowsRef.current[i] = { ...rowsRef.current[i], ...entry };
      else rowsRef.current.push(entry);
      lastSeenId.current = Math.max(lastSeenId.current, Number(entry.id) || 0);
      bump();
    },
    [bump]
  );

  const rows = rowsRef.current;

  const filtered = useMemo(
    () => filterAndSort(rows, filters, sortCol, sortDir),
    // eslint-disable-next-line react-hooks/exhaustive-deps
    [version, filters, sortCol, sortDir]
  );

  const selected = useMemo(
    () => rows.find((x) => x.id === selectedId) ?? null,
    [rows, selectedId, version]
  );

  const loadHistory = useCallback(async (incremental = false) => {
    const items = await fetchHistory({
      limit: incremental ? 400 : 1000,
      after: incremental ? lastSeenId.current : 0
    });
    for (const item of items) upsert(item);
    setAlive(true);
    const n = rowsRef.current.length;
    setStatus(`${n} entradas no histórico`);
  }, [upsert]);

  const refreshProxy = useCallback(async () => {
    try {
      setProxy(await fetchProxyStatus());
    } catch {
      /* ignore */
    }
  }, []);

  const runProxy = useCallback(
    async (action: 'start' | 'stop' | 'mitm') => {
      const body = action === 'mitm' ? { enabled: !proxy.mitmEnabled } : undefined;
      const d = await proxyAction(action, body);
      setProxy(d);
    },
    [proxy.mitmEnabled]
  );

  const clearLocal = useCallback(() => {
    rowsRef.current = [];
    lastSeenId.current = 0;
    setSelectedId(null);
    bump();
    setStatus('histórico local limpo');
  }, [bump]);

  const toggleSort = useCallback((col: HistorySortCol) => {
    setSortCol((c) => {
      if (c === col) {
        setSortDir((d) => -d);
        return c;
      }
      setSortDir(col === 'id' ? -1 : 1);
      return col;
    });
  }, []);

  useEffect(() => {
    loadHistory().catch((e) => {
      setAlive(false);
      setStatus(`erro: ${e.message}`);
    });
    const poll = setInterval(() => loadHistory(true).catch(() => {}), 2000);
    return () => clearInterval(poll);
  }, [loadHistory]);

  useEffect(() => {
    refreshProxy();
    const t = setInterval(refreshProxy, 4000);
    return () => clearInterval(t);
  }, [refreshProxy]);

  useEffect(() => {
    try {
      const bc = new BroadcastChannel(BC_CHANNEL);
      bc.onmessage = (ev) => {
        const msg = ev.data || {};
        if (msg.type !== 'http_history') return;
        upsert(msg.entry);
        setStatus(`${rowsRef.current.length} total · ao vivo`);
        setAlive(true);
      };
      return () => bc.close();
    } catch {
      return undefined;
    }
  }, [upsert]);

  return {
    allRows: rows,
    filtered,
    selected,
    selectedId,
    setSelectedId,
    filters,
    setFilters,
    sortCol,
    sortDir,
    toggleSort,
    status,
    alive,
    proxy,
    loadHistory,
    clearLocal,
    runProxy,
    refreshProxy
  };
}
