'use client';

import Link from 'next/link';
import { EVENT_COLOR, EVENT_LABEL } from '@/lib/utils/severity';
import { fmtDateTime, fmtTime } from '@/lib/utils/format';
import type { TimelineEvent } from '@/lib/types';

interface Props {
  events: TimelineEvent[];
  projectId: string;
}

export function TimelineFeed({ events, projectId }: Props) {
  let lastDay = '';
  return (
    <ol className="relative">
      <div className="absolute left-[68px] top-0 bottom-0 w-px bg-border" />
      {events.map((evt, i) => {
        const day = evt.ts.slice(0, 10);
        const newDay = day !== lastDay;
        lastDay = day;
        return (
          <li key={evt.id} className="relative">
            {newDay && (
              <div className="pl-[88px] py-3 text-2xs font-mono uppercase tracking-wider text-fg-dim">
                ── {fmtDateTime(evt.ts).split(' · ')[0]}
              </div>
            )}
            <div className="flex items-start gap-4 py-3 group">
              <span className="w-14 shrink-0 text-right text-2xs font-mono text-fg-dim mt-1.5">
                {fmtTime(evt.ts)}
              </span>
              <div className="relative shrink-0 flex flex-col items-center">
                <div
                  className="w-3 h-3 rounded-full border-2 border-bg z-10"
                  style={{ background: EVENT_COLOR[evt.type] }}
                />
              </div>
              <div className="flex-1 -mt-0.5 pb-2">
                <div className="flex items-center gap-2 flex-wrap">
                  <span
                    className="text-2xs font-mono font-medium uppercase tracking-wider"
                    style={{ color: EVENT_COLOR[evt.type] }}
                  >
                    {EVENT_LABEL[evt.type]}
                  </span>
                  {evt.host && (
                    <span className="text-2xs font-mono text-fg-dim">@ {evt.host}</span>
                  )}
                  {evt.target && !evt.host && (
                    <span className="text-2xs font-mono text-fg-dim">→ {evt.target}</span>
                  )}
                  {evt.vulnerabilityId && (
                    <Link
                      href={`/projects/${projectId}/vulnerabilities/${evt.vulnerabilityId}`}
                      className="text-2xs text-accent hover:underline font-mono"
                    >
                      → vuln
                    </Link>
                  )}
                </div>
                <p className="text-sm text-fg mt-0.5">{evt.title}</p>
                {evt.details && (
                  <p className="text-xs text-fg-muted mt-1 leading-relaxed">{evt.details}</p>
                )}
              </div>
            </div>
          </li>
        );
      })}
    </ol>
  );
}
