'use client';

import { apiUrl } from '@/lib/ghostrecon/api';
import type { ProxyStatus } from '@/lib/ghostrecon/api';

export function ProxyBar({
  proxy,
  onStart,
  onStop,
  onMitm
}: {
  proxy: ProxyStatus;
  onStart: () => void;
  onStop: () => void;
  onMitm: () => void;
}) {
  const running = Boolean(proxy.running);
  const port = proxy.port ?? 8081;
  const mitm = Boolean(proxy.mitmEnabled);

  return (
    <div className="shrink-0 flex flex-wrap items-center justify-between gap-3 px-3 py-2 border-b border-border bg-[#0c1218] text-xs font-mono">
      <div className="flex items-center gap-2 flex-wrap">
        <span
          className={`h-2 w-2 rounded-full ${running ? 'bg-emerald-400 shadow-[0_0_8px_rgba(52,211,153,.6)]' : 'bg-zinc-600'}`}
        />
        <span className="text-amber-400/90 tracking-wider">PROXY</span>
        <span className="text-cyan-400">:{port}</span>
        <span className="text-zinc-600">|</span>
        <span className={mitm ? 'text-violet-400' : 'text-zinc-500'}>
          MITM {mitm ? 'ON' : 'OFF'}
        </span>
        <span className="text-zinc-600">|</span>
        <span className="text-zinc-400">{proxy.capturedCount ?? 0} capturados</span>
      </div>
      <div className="flex items-center gap-2 flex-wrap">
        <button
          type="button"
          onClick={onStart}
          disabled={running}
          className="px-2 py-1 rounded border border-amber-500/30 text-amber-400 hover:border-amber-400 disabled:opacity-40"
        >
          ▶ Start
        </button>
        <button
          type="button"
          onClick={onStop}
          disabled={!running}
          className="px-2 py-1 rounded border border-red-500/30 text-red-400 hover:border-red-400 disabled:opacity-40"
        >
          ■ Stop
        </button>
        <button
          type="button"
          onClick={onMitm}
          className="px-2 py-1 rounded border border-violet-500/30 text-violet-300 hover:border-violet-400"
        >
          MITM
        </button>
        <a
          href={apiUrl('/api/proxy/ca.crt')}
          download="ghostrecon-ca.crt"
          className="px-2 py-1 rounded border border-border text-zinc-300 hover:text-white"
        >
          CA cert
        </a>
        <span className="text-zinc-500 hidden sm:inline">
          Browser: HTTP proxy 127.0.0.1:{port}
        </span>
      </div>
    </div>
  );
}

