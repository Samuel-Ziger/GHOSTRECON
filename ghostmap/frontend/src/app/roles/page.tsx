"use client";
import { useEffect, useState } from "react";
import { api } from "@/lib/api";
import { useSessionStore } from "@/store/session.store";
import type { RoleDiffResponse } from "@/lib/types";
import clsx from "clsx";

const SUSPICION_COLOR: Record<string, string> = {
  privilege_escalation: "text-danger",
  potential_idor: "text-warn",
  hidden_endpoint: "text-accent2",
  mass_assignment_candidate: "text-accent",
};

export default function RolesPage() {
  const active = useSessionStore((s) => s.activeProject);
  const { roles, setRoles } = useSessionStore();
  const [baseline, setBaseline] = useState<string>("");
  const [candidates, setCandidates] = useState<string[]>([]);
  const [diff, setDiff] = useState<RoleDiffResponse | null>(null);
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    if (!active?.id) return;
    api.listRoles(active.id).then(setRoles);
  }, [active?.id, setRoles]);

  async function createRole(name: string) {
    if (!active?.id) return;
    const r = await api.createRole(active.id, name);
    setRoles([...roles, r]);
  }

  async function runDiff() {
    if (!active?.id || !baseline || candidates.length === 0) return;
    setBusy(true);
    try { setDiff(await api.roleDiff(active.id, baseline, candidates)); }
    finally { setBusy(false); }
  }

  return (
    <div className="p-6 grid grid-cols-12 gap-4">
      <div className="col-span-4 space-y-3">
        <h2 className="text-xl font-semibold">Roles</h2>
        <div className="flex gap-2">
          <input placeholder="nova role (guest, user, admin...)"
            onKeyDown={(e) => {
              if (e.key === "Enter") {
                const v = (e.target as HTMLInputElement).value.trim();
                if (v) { createRole(v); (e.target as HTMLInputElement).value = ""; }
              }
            }}
            className="flex-1 bg-bg border border-border rounded px-2 py-1 text-sm"/>
        </div>
        <ul className="border border-border rounded divide-y divide-border">
          {roles.map((r) => (
            <li key={r.id} className="flex items-center gap-2 px-3 py-2 text-sm">
              <span className="h-2 w-2 rounded-full" style={{ background: r.color }} />
              <span className="flex-1">{r.name}</span>
              <input type="radio" name="baseline" checked={baseline === r.id}
                onChange={() => setBaseline(r.id)} title="baseline" />
              <input type="checkbox" checked={candidates.includes(r.id)}
                onChange={(e) => setCandidates(
                  e.target.checked ? [...candidates, r.id] : candidates.filter((x) => x !== r.id)
                )} title="candidate" />
            </li>
          ))}
        </ul>
        <button onClick={runDiff} disabled={busy || !baseline || candidates.length === 0}
          className="w-full px-3 py-2 rounded bg-accent/20 border border-accent/40 disabled:opacity-40">
          {busy ? "diffing..." : "rodar diff"}
        </button>
      </div>

      <div className="col-span-8">
        <h2 className="text-xl font-semibold mb-3">Differential</h2>
        {!diff && <div className="text-mute text-sm">Selecione uma baseline e marque candidatas, depois rode o diff.</div>}
        {diff && (
          <div className="space-y-2">
            <div className="text-xs text-mute">
              baseline: <span className="text-ink">{diff.baseline}</span>
              {" · "}
              candidates: <span className="text-ink">{diff.candidates.join(", ")}</span>
              {" · "}
              endpoints: <span className="text-ink">{diff.differences.length}</span>
            </div>
            <div className="border border-border rounded overflow-hidden">
              <table className="w-full text-xs">
                <thead className="bg-panel text-mute">
                  <tr className="text-left">
                    <th className="px-3 py-2">suspicion</th>
                    <th className="px-3 py-2">conf</th>
                    <th className="px-3 py-2">method</th>
                    <th className="px-3 py-2">host</th>
                    <th className="px-3 py-2">path</th>
                    <th className="px-3 py-2">only_in</th>
                  </tr>
                </thead>
                <tbody>
                  {diff.differences.map((d) => (
                    <tr key={d.endpoint_id} className="border-t border-border">
                      <td className={clsx("px-3 py-1.5", d.suspicion && SUSPICION_COLOR[d.suspicion])}>
                        {d.suspicion ?? "—"}
                      </td>
                      <td className="px-3 py-1.5 tabular-nums">{(d.confidence * 100).toFixed(0)}%</td>
                      <td className="px-3 py-1.5 text-accent">{d.method}</td>
                      <td className="px-3 py-1.5">{d.host}</td>
                      <td className="px-3 py-1.5 font-mono">{d.path}</td>
                      <td className="px-3 py-1.5 text-mute">{d.only_in.join(", ")}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
