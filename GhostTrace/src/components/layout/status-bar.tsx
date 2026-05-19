'use client';

import { Activity, Wifi, ShieldCheck, Database } from 'lucide-react';
import { SEVERITY_COLOR, SEVERITY_LABEL, SEVERITY_ORDER } from '@/lib/utils/severity';
import type { Severity } from '@/lib/types';
import { useStore } from '@/lib/mock/store';
import { isApiEnabled } from '@/lib/api/config';

interface Props {
  project?: { codename?: string; client: string; status: string };
  counts?: Record<Severity, number>;
  pivots?: number;
  hostActive?: string;
}

export function StatusBar({ project, counts, pivots, hostActive }: Props) {
  const apiStatus = useStore((s) => s.apiStatus);
  const apiOn = isApiEnabled();
  const apiLabel =
    !apiOn ? 'LOCAL' : apiStatus === 'syncing' ? 'SYNC…' : apiStatus === 'online' ? 'API OK' : apiStatus === 'offline' ? 'API OFF' : 'API';
  const apiDot =
    !apiOn || apiStatus === 'online'
      ? 'bg-accent'
      : apiStatus === 'syncing'
        ? 'bg-[var(--sev-medium)] animate-pulse'
        : 'bg-[var(--sev-critical)]';

  return (
    <footer className="h-7 border-t border-border bg-bg/95 backdrop-blur flex items-center px-4 text-[11px] font-mono text-fg-muted gap-5">
      <div className="flex items-center gap-1.5">
        <span className={`w-1.5 h-1.5 rounded-full ${apiDot}`} />
        <span className="text-fg">{apiLabel}</span>
        {apiOn && <Database size={10} className="text-fg-dim" />}
      </div>

      {project && (
        <>
          <div className="flex items-center gap-1.5">
            <ShieldCheck size={11} className="text-accent" />
            <span className="text-fg-dim">PROJ</span>
            <span className="text-fg">{project.codename || project.client}</span>
            <span className="text-fg-dim uppercase">· {project.status}</span>
          </div>
        </>
      )}

      {counts && (
        <div className="flex items-center gap-3">
          {SEVERITY_ORDER.map((s) =>
            counts[s] > 0 ? (
              <div key={s} className="flex items-center gap-1">
                <span
                  className="w-1.5 h-1.5 rounded-full"
                  style={{ background: SEVERITY_COLOR[s] }}
                />
                <span style={{ color: SEVERITY_COLOR[s] }}>{counts[s]}</span>
                <span className="text-fg-dim">{SEVERITY_LABEL[s]}</span>
              </div>
            ) : null
          )}
        </div>
      )}

      {typeof pivots === 'number' && pivots > 0 && (
        <div className="flex items-center gap-1.5">
          <Wifi size={11} />
          <span className="text-fg-dim">PIVOTS</span>
          <span className="text-fg">{pivots}</span>
        </div>
      )}

      {hostActive && (
        <div className="flex items-center gap-1.5">
          <Activity size={11} className="text-accent" />
          <span className="text-fg-dim">HOST</span>
          <span className="text-fg">{hostActive}</span>
        </div>
      )}

      <div className="flex-1" />
      <span className="text-fg-dim">ghosttrace · v0.1.0 · build dev</span>
    </footer>
  );
}
