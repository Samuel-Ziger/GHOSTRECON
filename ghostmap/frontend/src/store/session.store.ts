import { create } from "zustand";
import { persist } from "zustand/middleware";
import type { Project, Role } from "@/lib/types";

interface SessionState {
  activeProject: Project | null;
  projects: Project[];
  roles: Role[];
  setActiveProject: (p: Project | null) => void;
  setProjects: (ps: Project[]) => void;
  setRoles: (rs: Role[]) => void;
}

export const useSessionStore = create<SessionState>()(
  persist(
    (set) => ({
      activeProject: null,
      projects: [],
      roles: [],
      setActiveProject: (p) => set({ activeProject: p }),
      setProjects: (projects) => set({ projects }),
      setRoles: (roles) => set({ roles }),
    }),
    { name: "ghostmap.session" }
  )
);
