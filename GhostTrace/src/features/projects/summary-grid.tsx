'use client';

import { SEVERITY_COLOR, SEVERITY_LABEL, SEVERITY_ORDER } from '@/lib/utils/severity';
import type { Severity } from '@/lib/types';

interface Props {
  bySeverity: Record<Severity, number>;
  totalUnique: number;
  zeroDay: number;
  easilyExploitable: number;
}

export function SummaryGrid({ bySeverity, totalUnique, zeroDay, easilyExploitable }: Props) {
  return (
    <div className="grid grid-cols-1 lg:grid-cols-7 gap-3">
      <div className="lg:col-span-2 rounded-lg border border-border bg-surface p-5 relative overflow-hidden">
        <div className="text-2xs uppercase tracking-wider text-fg-dim">
          Total de vulnerabilidades únicas
        </div>
        <div className="mt-3 text-5xl font-mono font-medium text-fg">
          {String(totalUnique).padStart(2, '0')}
        </div>
        <div className="absolute right-3 bottom-3 text-2xs font-mono text-fg-dim">
          únicas · não duplicadas
        </div>
      </div>

      {SEVERITY_ORDER.map((s) => (
        <div key={s} className="rounded-lg border border-border bg-surface p-4 severity-bar" style={{ ['--bar-color' as any]: SEVERITY_COLOR[s] }}>
          <div
            className="text-2xs uppercase tracking-wider font-mono"
            style={{ color: SEVERITY_COLOR[s] }}
          >
            {SEVERITY_LABEL[s]}
          </div>
          <div className="mt-2 text-3xl font-mono font-medium" style={{ color: SEVERITY_COLOR[s] }}>
            {bySeverity[s]}
          </div>
        </div>
      ))}

      <div className="lg:col-span-7 grid grid-cols-2 gap-3 mt-1">
        <KpiSmall label="Zero-Day" value={zeroDay} />
        <KpiSmall label="Easily-Exploitable" value={easilyExploitable} accent />
      </div>
    </div>
  );
}

function KpiSmall({ label, value, accent }: { label: string; value: number; accent?: boolean }) {
  return (
    <div className="rounded-lg border border-border bg-surface px-4 py-3 flex items-center justify-between">
      <span className="text-2xs uppercase tracking-wider text-fg-muted">{label}</span>
      <span
        className={`font-mono text-2xl ${
          accent ? 'text-accent' : value > 0 ? 'text-fg' : 'text-fg-dim'
        }`}
      >
        {value}
      </span>
    </div>
  );
}
