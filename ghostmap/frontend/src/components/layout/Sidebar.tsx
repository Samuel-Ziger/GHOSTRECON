"use client";
import Link from "next/link";
import { usePathname } from "next/navigation";
import clsx from "clsx";
import {
  Activity, Network, Repeat, Users, Brain, FolderKanban, History,
} from "lucide-react";

const items = [
  { href: "/history", label: "HTTP History", icon: History, accent: true },
  { href: "/ghostrecon", label: "MITRE Hub", icon: Network, accent: true },
  { href: "/projects", label: "Projetos", icon: FolderKanban },
  { href: "/graph",    label: "Grafo",    icon: Network },
  { href: "/proxy",    label: "Proxy",    icon: Activity },
  { href: "/replay",   label: "Replay",   icon: Repeat },
  { href: "/roles",    label: "Roles",    icon: Users },
  { href: "/ai",       label: "IA",       icon: Brain },
];

export function Sidebar() {
  const path = usePathname();
  return (
    <aside className="w-56 border-r border-border bg-panel flex flex-col">
      <Link href="/" className="px-5 pt-5 pb-4 flex items-center gap-2">
        <div className="h-7 w-7 rounded bg-accent shadow-glow" />
        <span className="font-semibold tracking-tight text-lg">
          ghost<span className="text-accent">recon</span>
          <span className="text-mute font-normal text-sm"> · map</span>
        </span>
      </Link>
      <nav className="px-2 flex-1">
        {items.map((it) => {
          const Icon = it.icon;
          const active = path?.startsWith(it.href);
          return (
            <Link
              key={it.href}
              href={it.href}
              className={clsx(
                "flex items-center gap-3 px-3 py-2 rounded text-sm transition-colors",
                active
                  ? "bg-accent/15 text-ink border border-accent/30"
                  : "text-mute hover:text-ink hover:bg-white/5 border border-transparent",
              )}
            >
              <Icon size={16} />
              <span>{it.label}</span>
            </Link>
          );
        })}
      </nav>
      <div className="px-4 py-3 text-[11px] text-mute border-t border-border">
        v0.1 · research preview
      </div>
    </aside>
  );
}
