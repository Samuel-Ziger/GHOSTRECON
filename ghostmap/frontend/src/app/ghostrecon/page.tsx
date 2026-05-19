'use client';

import { useMemo, useState } from 'react';
import { useMitreSessionId } from '@/lib/ghostrecon/use-mitre-session';
import { GhostGraphRecon } from '@/components/graph/GhostGraphRecon';

type Tab = 'mitre' | 'graph';

export default function GhostreconHubPage() {
  const sessionId = useMitreSessionId();
  const [tab, setTab] = useState<Tab>('mitre');

  const mitreSrc = useMemo(() => {
    const base = '/ghostmap/mitre-live.html';
    return sessionId ? `${base}#${sessionId}` : base;
  }, [sessionId]);

  return (
    <div className="flex flex-col h-full">
      <header className="shrink-0 flex items-center gap-2 px-4 py-2 border-b border-border bg-panel/80">
        <span className="text-mute text-xs uppercase tracking-wider">GHOSTRECON</span>
        <span className="text-ink font-semibold">GhostMap</span>
        <span className="text-mute text-xs">· MITRE + OWASP + grafo de achados</span>
        <div className="flex-1" />
        <nav className="flex gap-1">
          <TabBtn active={tab === 'mitre'} onClick={() => setTab('mitre')}>
            Mapa MITRE / OWASP
          </TabBtn>
          <TabBtn active={tab === 'graph'} onClick={() => setTab('graph')}>
            Grafo (achados)
          </TabBtn>
        </nav>
      </header>

      <div className="flex-1 min-h-0 relative">
        {tab === 'mitre' && (
          <iframe
            title="GHOSTRECON MITRE live"
            src={mitreSrc}
            className="absolute inset-0 w-full h-full border-0 bg-bg"
          />
        )}
        {tab === 'graph' && (
          <div className="absolute inset-0">
            <GhostGraphRecon sessionId={sessionId} />
          </div>
        )}
      </div>
    </div>
  );
}

function TabBtn({
  active,
  onClick,
  children
}: {
  active: boolean;
  onClick: () => void;
  children: React.ReactNode;
}) {
  return (
    <button
      type="button"
      onClick={onClick}
      className={`px-3 py-1.5 rounded text-xs font-medium border transition-colors ${
        active
          ? 'bg-accent/20 text-ink border-accent/40'
          : 'text-mute border-transparent hover:border-border hover:text-ink'
      }`}
    >
      {children}
    </button>
  );
}
