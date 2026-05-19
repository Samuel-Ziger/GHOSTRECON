"use client";
import { useState } from "react";
import { api } from "@/lib/api";
import { useSessionStore } from "@/store/session.store";
import { useAIStore, type AgentName } from "@/store/ai.store";

const AGENTS: { name: AgentName; title: string; desc: string }[] = [
  { name: "flow_analyzer",           title: "Flow Analyzer",
    desc: "Descreve o fluxo da aplicação a partir de uma sessão." },
  { name: "trust_boundary_detector", title: "Trust Boundary Detector",
    desc: "Identifica onde a aplicação cruza fronteiras de confiança." },
  { name: "hypothesis_generator",    title: "Hypothesis Generator",
    desc: "Gera hipóteses ofensivas (NÃO executa nada). Foco: IDOR, BAC, SSRF, etc." },
  { name: "heatmap_classifier",      title: "Heatmap Classifier",
    desc: "Classifica risco de endpoints (roda local via Ollama por padrão)." },
];

export default function AIPage() {
  const active = useSessionStore((s) => s.activeProject);
  const { lastOutputs, running, setOutput, setRunning } = useAIStore();
  const [ctxText, setCtxText] = useState('{"endpoint": {"host": "api.target.com", "path": "/v1/users/:id", "method": "GET"}}');

  async function run(agent: AgentName) {
    if (!active?.id) return;
    setRunning(agent);
    try {
      const ctx = JSON.parse(ctxText || "{}");
      const out = await api.runAgent(active.id, agent, ctx);
      setOutput(agent, out);
    } catch (e: any) {
      setOutput(agent, { error: e?.message ?? String(e) });
    } finally {
      setRunning(null);
    }
  }

  return (
    <div className="p-6 grid grid-cols-12 gap-4">
      <div className="col-span-5 space-y-3">
        <h2 className="text-xl font-semibold">AI Agents</h2>
        <p className="text-mute text-sm">
          Política: <b>nunca</b> ataca automaticamente. Apenas correlaciona contexto,
          explica fluxos, sugere hipóteses e classifica risco.
        </p>
        <label className="block text-xs text-mute">contexto (JSON livre)</label>
        <textarea value={ctxText} onChange={(e) => setCtxText(e.target.value)} rows={8}
          className="w-full bg-bg border border-border rounded px-3 py-2 font-mono text-xs"/>
        <div className="space-y-2">
          {AGENTS.map((a) => (
            <button key={a.name} onClick={() => run(a.name)}
              disabled={running === a.name}
              className="w-full text-left p-3 rounded border border-border bg-panel hover:border-accent/40 disabled:opacity-50">
              <div className="font-medium">{a.title} {running === a.name && <span className="text-accent2 text-xs ml-2 animate-pulseSoft">rodando…</span>}</div>
              <div className="text-xs text-mute">{a.desc}</div>
            </button>
          ))}
        </div>
      </div>
      <div className="col-span-7 space-y-3">
        <h2 className="text-xl font-semibold">Última saída</h2>
        {AGENTS.map((a) => (
          <details key={a.name} className="border border-border rounded">
            <summary className="px-3 py-2 cursor-pointer text-sm">{a.title}</summary>
            <pre className="px-3 py-2 text-xs whitespace-pre-wrap overflow-auto max-h-[400px]">
              {JSON.stringify(lastOutputs[a.name], null, 2) || "—"}
            </pre>
          </details>
        ))}
      </div>
    </div>
  );
}
