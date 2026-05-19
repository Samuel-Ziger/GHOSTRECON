"use client";
import { useEffect } from "react";
import { useSessionStore } from "@/store/session.store";
import { api } from "@/lib/api";

const DEFAULT_PROJECT_ID = process.env.NEXT_PUBLIC_DEFAULT_PROJECT_ID ?? "";

export function TopBar() {
  const { projects, activeProject, setActiveProject, setProjects } = useSessionStore();

  useEffect(() => {
    api.listProjects().then((ps) => {
      setProjects(ps);
      const current = useSessionStore.getState().activeProject;
      if (current) return;
      const preferred = DEFAULT_PROJECT_ID
        ? ps.find((p) => p.id === DEFAULT_PROJECT_ID)
        : ps[0];
      if (preferred) setActiveProject(preferred);
    }).catch(() => {});
  }, [setProjects, setActiveProject]);

  return (
    <header className="h-12 border-b border-border bg-panel/80 backdrop-blur flex items-center px-4 gap-3">
      <span className="text-xs text-mute">Projeto:</span>
      <select
        value={activeProject?.id ?? ""}
        onChange={(e) => {
          const p = projects.find((x) => x.id === e.target.value) ?? null;
          setActiveProject(p);
        }}
        className="bg-bg border border-border rounded px-2 py-1 text-sm"
      >
        <option value="">— selecionar —</option>
        {projects.map((p) => (
          <option key={p.id} value={p.id}>
            {p.name} ({p.id.slice(0, 8)}…)
          </option>
        ))}
      </select>

      <div className="ml-auto flex items-center gap-3 text-xs text-mute">
        <span className="px-2 py-0.5 rounded bg-ok/15 text-ok border border-ok/30">live</span>
        <span>API: {process.env.NEXT_PUBLIC_API_URL || "http://localhost:8000"}</span>
      </div>
    </header>
  );
}
