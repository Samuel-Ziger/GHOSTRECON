'use client';

import { useState } from 'react';
import type { HistoryEntry } from '@/lib/ghostrecon/types';
import { mimeCategory } from '@/lib/ghostrecon/history-utils';
import {
  formatRawRequest,
  formatRawResponse,
  headersTable,
  prettyResponseBody
} from './format';

type Tab = 'raw' | 'headers' | 'params' | 'pretty' | 'render';

function TabBar({
  tabs,
  active,
  onChange
}: {
  tabs: { id: Tab; label: string }[];
  active: Tab;
  onChange: (t: Tab) => void;
}) {
  return (
    <div className="flex border-b border-border bg-[#0c1218]">
      {tabs.map((t) => (
        <button
          key={t.id}
          type="button"
          onClick={() => onChange(t.id)}
          className={`px-3 py-1.5 text-[10px] uppercase tracking-wider ${
            active === t.id
              ? 'text-amber-400 border-b-2 border-amber-400'
              : 'text-zinc-500 hover:text-zinc-300'
          }`}
        >
          {t.label}
        </button>
      ))}
    </div>
  );
}

function CodeBlock({ text }: { text: string }) {
  return (
    <pre className="p-3 text-[11px] leading-relaxed text-zinc-300 overflow-auto h-full whitespace-pre-wrap break-all font-mono">
      {text || '—'}
    </pre>
  );
}

function HeadersView({ hdrs }: { hdrs?: Record<string, string> }) {
  const rows = headersTable(hdrs);
  if (!rows.length) return <CodeBlock text="(sem headers)" />;
  return (
    <table className="w-full text-xs font-mono">
      <thead>
        <tr className="text-zinc-500 border-b border-border">
          <th className="text-left p-2">Name</th>
          <th className="text-left p-2">Value</th>
        </tr>
      </thead>
      <tbody>
        {rows.map((r) => (
          <tr key={r.name} className="border-b border-white/5">
            <td className="p-2 text-cyan-400/90 align-top">{r.name}</td>
            <td className="p-2 text-zinc-300 break-all">{r.value}</td>
          </tr>
        ))}
      </tbody>
    </table>
  );
}

function ParamsView({ entry }: { entry: HistoryEntry }) {
  const parts: string[] = [];
  try {
    const u = new URL(entry.url || '');
    u.searchParams.forEach((v, k) => parts.push(`${k}=${v}`));
  } catch {
    /* ignore */
  }
  const body = entry.requestBody?.trim();
  if (!parts.length && !body) {
    return <p className="p-4 text-zinc-500 text-sm">Sem parâmetros.</p>;
  }
  return (
    <div className="p-3 space-y-3 text-xs font-mono overflow-auto h-full">
      {parts.length > 0 && (
        <table className="w-full">
          <thead>
            <tr className="text-zinc-500">
              <th className="text-left p-1">Query</th>
              <th className="text-left p-1">Value</th>
            </tr>
          </thead>
          <tbody>
            {Array.from(new URL(entry.url || 'http://x').searchParams.entries()).map(
              ([k, v]) => (
                <tr key={k} className="border-t border-white/5">
                  <td className="p-1 text-cyan-400">{k}</td>
                  <td className="p-1 text-zinc-300 break-all">{v}</td>
                </tr>
              )
            )}
          </tbody>
        </table>
      )}
      {body && (
        <>
          <p className="text-zinc-500 text-[10px] uppercase">Body</p>
          <CodeBlock text={body} />
        </>
      )}
    </div>
  );
}

export function DetailPanes({ entry }: { entry: HistoryEntry | null }) {
  const [reqTab, setReqTab] = useState<Tab>('raw');
  const [resTab, setResTab] = useState<Tab>('raw');

  const reqContent = !entry ? (
    <p className="p-4 text-zinc-500 text-sm">Seleciona uma request na tabela.</p>
  ) : reqTab === 'raw' ? (
    <CodeBlock text={formatRawRequest(entry)} />
  ) : reqTab === 'headers' ? (
    <HeadersView hdrs={entry.requestHeaders} />
  ) : (
    <ParamsView entry={entry} />
  );

  const resContent = !entry ? (
    <p className="p-4 text-zinc-500 text-sm">Seleciona uma request na tabela.</p>
  ) : resTab === 'raw' ? (
    <CodeBlock text={formatRawResponse(entry)} />
  ) : resTab === 'headers' ? (
    <HeadersView hdrs={entry.responseHeaders} />
  ) : resTab === 'pretty' ? (
    <CodeBlock text={prettyResponseBody(entry) || '(vazio)'} />
  ) : mimeCategory(entry) === 'html' && entry.responseBody ? (
    <iframe
      title="render"
      sandbox="allow-same-origin"
      srcDoc={entry.responseBody}
      className="w-full h-full border-0 bg-white"
    />
  ) : (
    <p className="p-4 text-zinc-500 text-sm">Render só para HTML.</p>
  );

  return (
    <div className="flex flex-1 min-h-0 min-w-0">
      <section className="flex flex-col flex-1 min-w-0 border-r border-border">
        <header className="flex items-stretch h-8 border-b border-border bg-[#0c1218]">
          <span className="px-3 flex items-center text-[10px] uppercase tracking-widest text-zinc-500">
            Request
          </span>
          <TabBar
            tabs={[
              { id: 'raw', label: 'Raw' },
              { id: 'headers', label: 'Headers' },
              { id: 'params', label: 'Params' }
            ]}
            active={reqTab}
            onChange={setReqTab}
          />
        </header>
        <div className="flex-1 min-h-0 overflow-hidden">{reqContent}</div>
      </section>
      <section className="flex flex-col flex-1 min-w-0">
        <header className="flex items-stretch h-8 border-b border-border bg-[#0c1218]">
          <span className="px-3 flex items-center text-[10px] uppercase tracking-widest text-zinc-500">
            Response
          </span>
          <TabBar
            tabs={[
              { id: 'raw', label: 'Raw' },
              { id: 'headers', label: 'Headers' },
              { id: 'pretty', label: 'Pretty' },
              { id: 'render', label: 'Render' }
            ]}
            active={resTab}
            onChange={setResTab}
          />
        </header>
        <div className="flex-1 min-h-0 overflow-hidden">{resContent}</div>
      </section>
    </div>
  );
}

