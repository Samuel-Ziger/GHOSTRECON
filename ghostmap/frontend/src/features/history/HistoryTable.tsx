'use client';

import clsx from 'clsx';
import type { HistoryEntry, HistorySortCol } from '@/lib/ghostrecon/types';
import {
  extOf,
  fmtSize,
  hasParams,
  hostOf,
  methodClass,
  mimeLabel,
  pathOf,
  statusClass
} from '@/lib/ghostrecon/history-utils';

export function HistoryTable({
  rows,
  selectedId,
  sortCol,
  sortDir,
  onSelect,
  onSort
}: {
  rows: HistoryEntry[];
  selectedId: number | null;
  sortCol: HistorySortCol;
  sortDir: number;
  onSelect: (id: number) => void;
  onSort: (col: HistorySortCol) => void;
}) {
  const th = (col: HistorySortCol, label: string, className?: string) => (
    <th
      className={clsx(
        'px-2 py-1.5 text-left text-[11px] text-zinc-500 cursor-pointer hover:text-cyan-400',
        className,
        sortCol === col && (sortDir > 0 ? 'text-amber-400' : 'text-amber-400')
      )}
      onClick={() => onSort(col)}
    >
      {label}
      {sortCol === col ? (sortDir > 0 ? ' ↑' : ' ↓') : ''}
    </th>
  );

  if (!rows.length) {
    return (
      <div className="p-8 text-center text-zinc-500 font-mono text-sm">
        <strong className="block text-zinc-300 mb-1">Sem requests no histórico</strong>
        Inicia um RUN RECON ou o proxy — as requests aparecem aqui ao vivo.
      </div>
    );
  }

  return (
    <table className="w-full border-collapse table-fixed text-xs font-mono">
      <thead className="sticky top-0 z-10 bg-[#101820]">
        <tr className="border-b border-border">
          {th('id', '#', 'w-10')}
          {th('host', 'Host', 'w-36 hidden md:table-cell')}
          {th('method', 'Method', 'w-16')}
          {th('url', 'URL')}
          <th className="w-8 hidden md:table-cell text-zinc-500" title="Params">
            ?
          </th>
          {th('status', 'Status', 'w-14')}
          {th('len', 'Length', 'w-16 hidden lg:table-cell')}
          <th className="w-14 hidden lg:table-cell text-zinc-500">MIME</th>
          <th className="w-10 hidden lg:table-cell text-zinc-500">Ext</th>
          {th('ms', 'ms', 'w-14')}
        </tr>
      </thead>
      <tbody>
        {rows.map((r) => {
          const meth = String(r.method || 'GET').toUpperCase();
          const sc = r.error ? 'ERR' : r.status == null ? '-' : String(r.status);
          return (
            <tr
              key={r.id}
              onClick={() => onSelect(r.id)}
              className={clsx(
                'border-b border-white/5 cursor-pointer hover:bg-cyan-500/5',
                selectedId === r.id && 'bg-cyan-500/10 shadow-[inset_3px_0_0_#fbbf24]'
              )}
            >
              <td className="px-2 py-1 text-zinc-500">{r.id}</td>
              <td className="px-2 py-1 text-cyan-400 truncate hidden md:table-cell" title={hostOf(r.url)}>
                {hostOf(r.url)}
              </td>
              <td className="px-2 py-1">
                <span className={clsx('text-[10px] border rounded px-1', methodClass(meth))}>
                  {meth}
                </span>
              </td>
              <td className="px-2 py-1 text-zinc-100 truncate" title={r.url}>
                {pathOf(r.url)}
              </td>
              <td className="px-2 py-1 text-center text-emerald-500 hidden md:table-cell">
                {hasParams(r) ? '●' : ''}
              </td>
              <td className={clsx('px-2 py-1 font-semibold', statusClass(r))}>{sc}</td>
              <td className="px-2 py-1 text-zinc-500 hidden lg:table-cell">
                {fmtSize(r.responseSize)}
              </td>
              <td className="px-2 py-1 text-violet-400 hidden lg:table-cell">
                {mimeLabel(r.mimeType)}
              </td>
              <td className="px-2 py-1 text-zinc-500 hidden lg:table-cell">{extOf(r.url)}</td>
              <td className="px-2 py-1 text-zinc-500">
                {r.durationMs == null ? '-' : r.durationMs}
              </td>
            </tr>
          );
        })}
      </tbody>
    </table>
  );
}


