"use client";
import { useState } from "react";
import { useSearchParams } from "next/navigation";
import { api } from "@/lib/api";

export default function ReplayPage() {
  const params = useSearchParams();
  const requestId = params.get("req") ?? "";
  const [reqId, setReqId] = useState(requestId);
  const [add, setAdd] = useState('{"Authorization": "Bearer <swap_token>"}');
  const [result, setResult] = useState<unknown>(null);
  const [busy, setBusy] = useState(false);

  async function fire() {
    if (!reqId) return;
    setBusy(true); setResult(null);
    try {
      const r = await api.replay(reqId, {
        add_headers: JSON.parse(add || "{}"),
      });
      setResult(r);
    } catch (e: any) {
      setResult({ error: e?.message ?? String(e) });
    } finally { setBusy(false); }
  }

  return (
    <div className="p-8 max-w-3xl space-y-4">
      <h2 className="text-2xl font-semibold">Replay</h2>
      <p className="text-mute text-sm">
        Reexecuta um request armazenado com mutações opcionais. Útil para
        validar manualmente IDOR, troca de roles, edição de body, etc.
      </p>
      <label className="block text-xs text-mute">request id (UUID)</label>
      <input value={reqId} onChange={(e) => setReqId(e.target.value)}
        className="w-full bg-bg border border-border rounded px-3 py-2 font-mono text-xs" />

      <label className="block text-xs text-mute">add_headers (JSON)</label>
      <textarea value={add} onChange={(e) => setAdd(e.target.value)} rows={4}
        className="w-full bg-bg border border-border rounded px-3 py-2 font-mono text-xs" />

      <button onClick={fire} disabled={busy}
        className="px-4 py-2 rounded bg-accent/20 border border-accent/40 disabled:opacity-40">
        {busy ? "executando..." : "disparar replay"}
      </button>

      {result !== null && (
        <pre className="mt-4 bg-panel border border-border rounded p-4 text-xs whitespace-pre-wrap overflow-auto">
          {JSON.stringify(result, null, 2)}
        </pre>
      )}
    </div>
  );
}
