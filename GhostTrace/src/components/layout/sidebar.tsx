'use client';

import Link from 'next/link';
import { usePathname } from 'next/navigation';
import {
  LayoutDashboard,
  Bug,
  Activity,
  GitBranch,
  Image as ImageIcon,
  KeyRound,
  FileText,
  Settings,
  FolderKanban,
  Radar
} from 'lucide-react';
import { GhostTraceMark } from '@/components/icons/ghosttrace-mark';
import { cn } from '@/lib/utils/cn';

interface Props {
  projectId?: string;
}

export function Sidebar({ projectId }: Props) {
  const pathname = usePathname();

  const items = projectId
    ? [
        { href: `/projects/${projectId}`, label: 'Dashboard', icon: LayoutDashboard, exact: true },
        { href: `/projects/${projectId}/vulnerabilities`, label: 'Vulnerabilidades', icon: Bug },
        { href: `/projects/${projectId}/timeline`, label: 'Timeline', icon: Activity },
        { href: `/projects/${projectId}/attack-chain`, label: 'Attack Chain', icon: GitBranch },
        { href: `/projects/${projectId}/evidence`, label: 'Evidências', icon: ImageIcon },
        { href: `/projects/${projectId}/credentials`, label: 'Credenciais', icon: KeyRound },
        { href: `/projects/${projectId}/report`, label: 'Relatório', icon: FileText }
      ]
    : [{ href: '/projects', label: 'Projetos', icon: FolderKanban, exact: true }];

  return (
    <aside className="w-[208px] shrink-0 h-screen border-r border-border bg-bg/95 backdrop-blur flex flex-col sticky top-0">
      <div className="px-4 py-4 border-b border-border flex items-center gap-2.5">
        <GhostTraceMark size={26} className="text-accent" />
        <div className="flex flex-col leading-none">
          <span className="font-mono text-sm tracking-tight text-fg">
            ghost<span className="text-accent">recon</span>
          </span>
          <span className="font-mono text-[10px] uppercase text-fg-dim mt-0.5">
            trace · anotações
          </span>
        </div>
      </div>

      {projectId && (
        <Link
          href="/projects"
          className="px-4 py-2.5 border-b border-border text-2xs uppercase tracking-wider text-fg-dim hover:text-fg hover:bg-surface-2 transition-colors flex items-center gap-2"
        >
          <FolderKanban size={12} />
          ← todos os projetos
        </Link>
      )}

      <nav className="flex-1 py-3 overflow-y-auto">
        {items.map((item) => {
          const Icon = item.icon;
          const active =
            'exact' in item && item.exact
              ? pathname === item.href
              : pathname.startsWith(item.href);
          return (
            <Link
              key={item.href}
              href={item.href}
              className={cn(
                'group relative flex items-center gap-2.5 px-4 py-2 text-sm transition-all',
                active
                  ? 'text-fg bg-accent-soft'
                  : 'text-fg-muted hover:text-fg hover:bg-surface-2'
              )}
            >
              {active && (
                <span className="absolute left-0 top-1 bottom-1 w-0.5 bg-accent rounded-r" />
              )}
              <Icon size={15} className={cn(active && 'text-accent')} />
              {item.label}
            </Link>
          );
        })}
      </nav>

      <div className="border-t border-border py-2">
        <Link
          href="/settings"
          className={cn(
            'flex items-center gap-2.5 px-4 py-2 text-sm transition-colors',
            pathname === '/settings'
              ? 'text-fg bg-accent-soft'
              : 'text-fg-muted hover:text-fg hover:bg-surface-2'
          )}
        >
          <Settings size={15} />
          Configurações
        </Link>
        <div className="px-4 py-2 mt-1 text-[10px] font-mono text-fg-dim border-t border-border">
          operator@ghosttrace
        </div>
      </div>
    </aside>
  );
}
