"use client";
import { useEffect } from "react";
import { useProxyStore } from "@/store/proxy.store";
import { useSessionStore } from "@/store/session.store";
import { api } from "@/lib/api";
import clsx from "clsx";

const STATUS_COLOR = (s: number | null) => {
  if (s === null) return "text-mute";
  if (s >= 500) return "text-danger";
  if (s >= 400) return "text-warn";
  if (s >= 300) return "text-accent2";
  if (s >= 200) return "text-ok";
  return "text-mute";
};

export default function ProxyPage() {
  const { liveRequests, push, clear, select, selectedRequestId, filter, setFilter } = useProxyStore();
  const active = useSessionStore((s) => s.activeProject);

  // load inicial via REST (em paralelo ao live via WS)
  useEffect(() => {
    if (!active?.id) return;
    api.listRequests(active.id, { limit: 200 }).then((r) => {
      r.items.forEach(push);
    });
  }, [active?.id, push]);

  if (!active?.id) {
    const hint = process.env.NEXT_PUBLIC_DEFAULT_PROJECT_ID?.slice(0, 8) ?? "f7bc9473";
    return (
      <div className="p-10 max-w-xl text-sm text-mute space-y-3">
        <p className="text-ink font-medium">Nenhum projeto selecionado</p>
        <p>Escolha um projeto no menu <b>Projeto</b> no topo. Você tem dois chamados &quot;teste&quot; — escolha o que começa com <code className="text-accent2">{hint}…</code> (o do <code className="text-accent2">.env</code>).</p>
      </div>
    );
  }

  const filtered = liveRequests.filter((r) => {
    if (filter.method && r.method !== filter.method) return false;
    if (filter.only_xhr && !r.is_xhr) return false;
    if (filter.only_graphql && !r.is_graphql) return false;
    if (filter.q && !r.url.toLowerCase().includes(filter.q.toLowerCase())) return false;
    return true;
  });

  return (
    <div className="flex h-[calc(100vh-3rem)]">
      <div className="w-2/3 border-r border-border flex flex-col">
        <div className="p-3 border-b border-border flex items-center gap-2 text-xs">
          <input
            placeholder="search url..." value={filter.q ?? ""}
            onChange={(e) => setFilter({ q: e.target.value })}
            className="bg-bg border border-border rounded px-2 py-1 flex-1"
          />
          <select value={filter.method ?? ""} onChange={(e) => setFilter({ method: e.target.value || undefined })}
            className="bg-bg border border-border rounded px-2 py-1">
            <option value="">all methods</option>
            {["GET","POST","PUT","PATCH","DELETE"].map((m) => <option key={m}>{m}</option>)}
          </select>
          <label className="flex items-center gap-1">
            <input type="checkbox" checked={filter.only_xhr} onChange={(e) => setFilter({ only_xhr: e.target.checked })}/>
            XHR
          </label>
          <label className="flex items-center gap-1">
            <input type="checkbox" checked={filter.only_graphql} onChange={(e) => setFilter({ only_graphql: e.target.checked })}/>
            GraphQL
          </label>
          <button onClick={clear} className="ml-auto text-mute hover:text-danger">limpar</button>
          {active?.id && (
            <a href={api.exportHar(active.id)} className="text-accent2 hover:underline" target="_blank" rel="noreferrer">
              export HAR
            </a>
          )}
        </div>
        <div className="overflow-auto flex-1">
          <table className="w-full text-xs font-mono">
            <thead className="sticky top-0 bg-panel text-mute">
              <tr className="text-left">
                <th className="px-3 py-2 w-16">M</th>
                <th className="px-3 py-2 w-14">code</th>
                <th className="px-3 py-2 w-16">ms</th>
                <th className="px-3 py-2">URL</th>
              </tr>
            </thead>
            <tbody>
              {filtered.map((r) => (
                <tr key={r.id}
                    onClick={() => select(r.id)}
                    className={clsx("border-t border-border cursor-pointer hover:bg-white/5",
                      selectedRequestId === r.id && "bg-accent/10")}>
                  <td className="px-3 py-1.5 text-accent">{r.method}</td>
                  <td className={clsx("px-3 py-1.5 tabular-nums", STATUS_COLOR(r.status))}>{r.status ?? "—"}</td>
                  <td className="px-3 py-1.5 tabular-nums text-mute">{r.duration_ms ?? "—"}</td>
                  <td className="px-3 py-1.5 truncate max-w-[600px]" title={r.url}>{r.url}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
      <RequestPanel />
    </div>
  );
}

function RequestPanel() {
  const { selectedRequestId, liveRequests } = useProxyStore();
  const r = liveRequests.find((x) => x.id === selectedRequestId);
  if (!r) return (
    <div className="flex-1 p-6 text-mute text-sm">Selecione um request para inspecionar.</div>
  );
  return (
    <div className="flex-1 overflow-auto p-5 text-xs font-mono space-y-4">
      <div>
        <div className="text-mute uppercase tracking-wide mb-1">request</div>
        <div className="text-accent">{r.method}</div>
        <div className="break-all">{r.url}</div>
      </div>
      <div>
        <div className="text-mute uppercase tracking-wide mb-1">response</div>
        <div>status: <span className="text-ink">{r.status}</span></div>
        <div>duration: <span className="text-ink">{r.duration_ms}ms</span></div>
      </div>
      <div className="text-mute italic">
        Body completo e replay disponíveis em <a className="text-accent2 underline" href={`/replay?req=${r.id}`}>/replay</a>
      </div>
    </div>
  );
}
