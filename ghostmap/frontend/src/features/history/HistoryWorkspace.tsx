'use client';

import { useCallback, useEffect, useRef, useState } from 'react';
import { useSearchParams } from 'next/navigation';
import Link from 'next/link';
import clsx from 'clsx';
import { useGhostreconHistory } from '@/hooks/useGhostreconHistory';
import { ProxyBar } from './ProxyBar';
import { HistoryTable } from './HistoryTable';
import { DetailPanes } from './DetailPanes';
import { GhostGraphRecon } from '@/components/graph/GhostGraphRecon';
import type { HistoryFilters } from '@/lib/ghostrecon/types';

type ViewTab = 'inspector' | 'graph';

export function HistoryWorkspace() {
  const search = useSearchParams();
  const initialTarget = search.get('target') || '';
  const [view, setView] = useState<ViewTab>('inspector');
  const tableWrapRef = useRef<HTMLDivElement>(null);

  const h = useGhostreconHistory(initialTarget);

  useEffect(() => {
    if (initialTarget) {
      h.setFilters((f: HistoryFilters) => ({ ...f, search: initialTarget }));
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [initialTarget]);

  const onDragV = useCallback((e: React.MouseEvent) => {
    const tw = tableWrapRef.current;
    if (!tw) return;
    const startY = e.clientY;
    const startH = tw.offsetHeight;
    const move = (ev: MouseEvent) => {
      const nh = Math.max(
        80,
        Math.min(window.innerHeight - 200, startH + (ev.clientY - startY))
      );
      tw.style.height = `${nh}px`;
      tw.style.flex = 'none';
    };
    const up = () => {
      document.removeEventListener('mousemove', move);
      document.removeEventListener('mouseup', up);
      document.body.style.userSelect = '';
      document.body.style.cursor = '';
    };
    document.body.style.userSelect = 'none';
    document.body.style.cursor = 'row-resize';
    document.addEventListener('mousemove', move);
    document.addEventListener('mouseup', up);
  }, []);

  return (
    <div className="flex flex-col h-full min-h-0 bg-[#080c10] text-[#c4d4da]">
      <header className="shrink-0 h-[54px] flex items-center justify-between gap-3 px-4 border-b border-white/10 bg-[#060a0e]/95">
        <div className="font-bold tracking-widest text-[#eef8ff]">
          GHOST<span className="text-amber-400">RECON</span>
          <span className="ml-2 text-xs font-mono opacity-45 font-normal tracking-normal">
            / http history
          </span>
        </div>
        <div className="flex items-center gap-3 text-xs font-mono">
          <span
            className={clsx(
              'h-2 w-2 rounded-full',
              h.alive ? 'bg-emerald-400 shadow-[0_0_10px_rgba(52,211,153,.6)]' : 'bg-red-500'
            )}
          />
          <span className="text-zinc-500">{h.status}</span>
          <button
            type="button"
            onClick={() => h.loadHistory()}
            className="px-2 py-1 border border-amber-500/30 text-amber-400 rounded hover:border-amber-400"
          >
            Atualizar
          </button>
          <button
            type="button"
            onClick={h.clearLocal}
            className="px-2 py-1 border border-red-500/30 text-red-400 rounded hover:border-red-400"
          >
            Limpar
          </button>
          <Link
            href="/ghostrecon"
            className="px-2 py-1 border border-violet-500/30 text-violet-300 rounded hover:border-violet-400 hidden sm:inline"
          >
            MITRE Map
          </Link>
        </div>
      </header>

      <ProxyBar
        proxy={h.proxy}
        onStart={() => h.runProxy('start').catch(() => {})}
        onStop={() => h.runProxy('stop').catch(() => {})}
        onMitm={() => h.runProxy('mitm').catch(() => {})}
      />

      <div className="shrink-0 flex items-center gap-1 px-3 py-2 border-b border-white/10 bg-[#0c1218]">
        <button
          type="button"
          onClick={() => setView('inspector')}
          className={clsx(
            'px-3 py-1 rounded text-xs font-mono',
            view === 'inspector'
              ? 'bg-cyan-500/15 text-cyan-300 border border-cyan-500/30'
              : 'text-zinc-500 hover:text-zinc-300'
          )}
        >
          Inspector
        </button>
        <button
          type="button"
          onClick={() => setView('graph')}
          className={clsx(
            'px-3 py-1 rounded text-xs font-mono',
            view === 'graph'
              ? 'bg-violet-500/15 text-violet-300 border border-violet-500/30'
              : 'text-zinc-500 hover:text-zinc-300'
          )}
        >
          Grafo
        </button>
      </div>

      {view === 'graph' ? (
        <div className="flex-1 min-h-0">
          <GhostGraphRecon entries={h.allRows} />
        </div>
      ) : (
        <>
          <div className="shrink-0 flex flex-wrap items-center gap-2 px-3 py-2 border-b border-white/10 bg-[#0c1218] text-xs">
            <span className="text-zinc-500 font-mono">Search</span>
            <input
              value={h.filters.search}
              onChange={(e) =>
                h.setFilters((f) => ({ ...f, search: e.target.value }))
              }
              placeholder="url, host, body…"
              className="flex-1 min-w-[140px] max-w-xs h-8 px-2 bg-[#080c10] border border-white/10 rounded font-mono text-sm text-zinc-100 outline-none focus:border-cyan-500/50"
            />
            <select
              value={h.filters.method}
              onChange={(e) =>
                h.setFilters((f) => ({ ...f, method: e.target.value }))
              }
              className="h-8 px-2 bg-[#080c10] border border-white/10 rounded font-mono"
            >
              <option value="">Method: All</option>
              {['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'HEAD'].map((m) => (
                <option key={m} value={m}>
                  {m}
                </option>
              ))}
            </select>
            <select
              value={h.filters.status}
              onChange={(e) =>
                h.setFilters((f) => ({ ...f, status: e.target.value }))
              }
              className="h-8 px-2 bg-[#080c10] border border-white/10 rounded font-mono"
            >
              <option value="">Status: All</option>
              <option value="2">2xx</option>
              <option value="3">3xx</option>
              <option value="4">4xx</option>
              <option value="5">5xx</option>
              <option value="e">Erro</option>
            </select>
            <select
              value={h.filters.mime}
              onChange={(e) =>
                h.setFilters((f) => ({ ...f, mime: e.target.value }))
              }
              className="h-8 px-2 bg-[#080c10] border border-white/10 rounded font-mono"
            >
              <option value="">MIME: All</option>
              {['json', 'html', 'js', 'css', 'xml', 'img', 'other'].map((m) => (
                <option key={m} value={m}>
                  {m}
                </option>
              ))}
            </select>
            <select
              value={h.filters.source}
              onChange={(e) =>
                h.setFilters((f) => ({ ...f, source: e.target.value }))
              }
              className="h-8 px-2 bg-[#080c10] border border-white/10 rounded font-mono"
            >
              <option value="">Source: All</option>
              <option value="fetch">Fetch</option>
              <option value="browser">Browser</option>
            </select>
          </div>

          <div className="flex-1 flex flex-col min-h-0 overflow-hidden">
            <div
              ref={tableWrapRef}
              className="overflow-auto shrink-0"
              style={{ height: '42vh' }}
            >
              <HistoryTable
                rows={h.filtered}
                selectedId={h.selectedId}
                sortCol={h.sortCol}
                sortDir={h.sortDir}
                onSelect={h.setSelectedId}
                onSort={h.toggleSort}
              />
            </div>
            <button
              type="button"
              aria-label="Redimensionar"
              onMouseDown={onDragV}
              className="h-1.5 shrink-0 bg-[#141e28] border-y border-white/10 cursor-row-resize flex items-center justify-center"
            >
              <span className="w-8 h-0.5 bg-zinc-600 rounded" />
            </button>
            <DetailPanes entry={h.selected} />
          </div>
        </>
      )}
    </div>
  );
}

