"use client";
import { useEffect, useState } from "react";
import { api } from "@/lib/api";
import { useSessionStore } from "@/store/session.store";

export default function ProjectsPage() {
  const { projects, setProjects, setActiveProject, activeProject } = useSessionStore();
  const [name, setName] = useState("");

  useEffect(() => { api.listProjects().then(setProjects); }, [setProjects]);

  async function create() {
    if (!name.trim()) return;
    const p = await api.createProject(name.trim());
    setProjects([p, ...projects]);
    setActiveProject(p);
    setName("");
  }

  return (
    <div className="p-8 max-w-3xl">
      <h2 className="text-2xl font-semibold mb-4">Projetos</h2>
      <div className="flex gap-2 mb-6">
        <input value={name} onChange={(e) => setName(e.target.value)}
          placeholder="Nome do projeto (ex.: target.com)"
          className="flex-1 bg-bg border border-border rounded px-3 py-2"/>
        <button onClick={create} className="px-4 py-2 rounded bg-accent/20 border border-accent/40 hover:bg-accent/30">
          Criar
        </button>
      </div>
      <ul className="divide-y divide-border border border-border rounded-lg overflow-hidden">
        {projects.map((p) => (
          <li key={p.id}
              onClick={() => setActiveProject(p)}
              className={`px-4 py-3 cursor-pointer hover:bg-white/5 flex items-center justify-between
                          ${activeProject?.id === p.id ? "bg-accent/10" : ""}`}>
            <div>
              <div className="font-medium">{p.name}</div>
              <div className="text-xs text-mute">{p.id}</div>
            </div>
            <div className="text-xs text-mute">{new Date(p.created_at).toLocaleString()}</div>
          </li>
        ))}
        {projects.length === 0 && (
          <li className="px-4 py-6 text-center text-mute text-sm">
            Nenhum projeto. Crie um acima para começar.
          </li>
        )}
      </ul>
    </div>
  );
}
