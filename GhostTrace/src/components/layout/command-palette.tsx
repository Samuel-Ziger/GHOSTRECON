'use client';

import { useEffect, useState } from 'react';
import { useRouter } from 'next/navigation';
import { Command } from 'cmdk';
import {
  Bug,
  Activity,
  GitBranch,
  KeyRound,
  FileText,
  Plus,
  FolderKanban,
  Settings,
  LayoutDashboard,
  type LucideIcon
} from 'lucide-react';
import { motion, AnimatePresence } from 'framer-motion';

interface Props {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  projectId?: string;
}

export function CommandPalette({ open, onOpenChange, projectId }: Props) {
  const router = useRouter();
  const [query, setQuery] = useState('');

  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if ((e.metaKey || e.ctrlKey) && e.key === 'k') {
        e.preventDefault();
        onOpenChange(!open);
      }
      if (e.key === 'Escape') onOpenChange(false);
    };
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, [open, onOpenChange]);

  function go(href: string) {
    onOpenChange(false);
    setQuery('');
    router.push(href);
  }

  return (
    <AnimatePresence>
      {open && (
        <>
          <motion.div
            className="fixed inset-0 z-50 bg-bg/70 backdrop-blur-sm"
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            exit={{ opacity: 0 }}
            onClick={() => onOpenChange(false)}
          />
          <div className="fixed inset-0 z-50 flex items-start justify-center p-4 pt-24 pointer-events-none">
            <motion.div
              initial={{ opacity: 0, y: -8, scale: 0.98 }}
              animate={{ opacity: 1, y: 0, scale: 1 }}
              exit={{ opacity: 0, y: -4, scale: 0.98 }}
              transition={{ duration: 0.15, ease: [0.2, 0.8, 0.2, 1] }}
              className="w-full max-w-xl bg-surface border border-border-strong rounded-lg shadow-2xl overflow-hidden pointer-events-auto"
            >
              <Command className="text-fg" label="Command Palette">
                <div className="border-b border-border px-4 py-3 flex items-center gap-3">
                  <span className="text-accent font-mono text-sm">{'>'}</span>
                  <Command.Input
                    value={query}
                    onValueChange={setQuery}
                    placeholder="Buscar ações, navegar, criar..."
                    className="flex-1 bg-transparent outline-none text-sm placeholder:text-fg-dim"
                  />
                  <kbd className="text-[10px] font-mono text-fg-dim border border-border rounded px-1.5 py-0.5">
                    ESC
                  </kbd>
                </div>
                <Command.List className="max-h-80 overflow-y-auto p-2">
                  <Command.Empty className="py-8 text-center text-sm text-fg-muted">
                    Nenhum resultado.
                  </Command.Empty>

                  {projectId && (
                    <Command.Group heading="Navegar" className="[&_[cmdk-group-heading]]:px-2 [&_[cmdk-group-heading]]:py-1.5 [&_[cmdk-group-heading]]:text-2xs [&_[cmdk-group-heading]]:uppercase [&_[cmdk-group-heading]]:tracking-wider [&_[cmdk-group-heading]]:text-fg-dim">
                      <PItem icon={LayoutDashboard} onSelect={() => go(`/projects/${projectId}`)}>
                        Dashboard
                      </PItem>
                      <PItem icon={Bug} onSelect={() => go(`/projects/${projectId}/vulnerabilities`)}>
                        Vulnerabilidades
                      </PItem>
                      <PItem icon={Activity} onSelect={() => go(`/projects/${projectId}/timeline`)}>
                        Timeline
                      </PItem>
                      <PItem
                        icon={GitBranch}
                        onSelect={() => go(`/projects/${projectId}/attack-chain`)}
                      >
                        Attack chain
                      </PItem>
                      <PItem
                        icon={KeyRound}
                        onSelect={() => go(`/projects/${projectId}/credentials`)}
                      >
                        Credenciais
                      </PItem>
                      <PItem icon={FileText} onSelect={() => go(`/projects/${projectId}/report`)}>
                        Relatório
                      </PItem>
                    </Command.Group>
                  )}

                  <Command.Group heading="Ações" className="[&_[cmdk-group-heading]]:px-2 [&_[cmdk-group-heading]]:py-1.5 [&_[cmdk-group-heading]]:text-2xs [&_[cmdk-group-heading]]:uppercase [&_[cmdk-group-heading]]:tracking-wider [&_[cmdk-group-heading]]:text-fg-dim">
                    {projectId && (
                      <PItem
                        icon={Plus}
                        kbd="N"
                        onSelect={() => go(`/projects/${projectId}/vulnerabilities/new`)}
                      >
                        Nova vulnerabilidade
                      </PItem>
                    )}
                    <PItem icon={FolderKanban} onSelect={() => go('/projects')}>
                      Todos os projetos
                    </PItem>
                    <PItem icon={Plus} onSelect={() => go('/projects/new')}>
                      Novo projeto
                    </PItem>
                    <PItem icon={Settings} onSelect={() => go('/settings')}>
                      Configurações · API keys
                    </PItem>
                  </Command.Group>
                </Command.List>
              </Command>
            </motion.div>
          </div>
        </>
      )}
    </AnimatePresence>
  );
}

function PItem({
  icon: Icon,
  children,
  onSelect,
  kbd
}: {
  icon: LucideIcon;
  children: React.ReactNode;
  onSelect: () => void;
  kbd?: string;
}) {
  return (
    <Command.Item
      onSelect={onSelect}
      className="flex items-center gap-3 px-2 py-2 rounded-md text-sm text-fg-muted cursor-pointer aria-selected:bg-surface-2 aria-selected:text-fg transition-colors"
    >
      <Icon size={14} />
      <span className="flex-1">{children}</span>
      {kbd && (
        <kbd className="text-[10px] font-mono text-fg-dim border border-border rounded px-1.5 py-0.5">
          {kbd}
        </kbd>
      )}
    </Command.Item>
  );
}
