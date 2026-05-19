'use client';

import { Search, Command } from 'lucide-react';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';

interface Props {
  title: string;
  subtitle?: string;
  breadcrumbs?: { label: string; href?: string }[];
  actions?: React.ReactNode;
  onOpenCommand?: () => void;
}

export function TopBar({ title, subtitle, breadcrumbs, actions, onOpenCommand }: Props) {
  return (
    <header className="h-14 px-6 border-b border-border bg-bg/85 backdrop-blur sticky top-0 z-30 flex items-center justify-between">
      <div className="flex items-center gap-4 min-w-0">
        <div className="min-w-0">
          {breadcrumbs && breadcrumbs.length > 0 && (
            <div className="flex items-center gap-1.5 text-2xs text-fg-dim uppercase tracking-wider mb-0.5">
              {breadcrumbs.map((bc, i) => (
                <span key={i} className="flex items-center gap-1.5">
                  {bc.label}
                  {i < breadcrumbs.length - 1 && <span className="text-fg-dim">/</span>}
                </span>
              ))}
            </div>
          )}
          <div className="flex items-center gap-3">
            <h1 className="text-base font-medium text-fg truncate">{title}</h1>
            {subtitle && <Badge mono>{subtitle}</Badge>}
          </div>
        </div>
      </div>

      <div className="flex items-center gap-2">
        <Button
          variant="secondary"
          size="md"
          onClick={onOpenCommand}
          className="font-normal pr-1.5 text-fg-muted hover:text-fg"
        >
          <Search size={14} />
          <span className="hidden sm:inline">Buscar ou comandar</span>
          <kbd className="ml-3 hidden sm:inline-flex items-center gap-1 px-1.5 py-0.5 text-[10px] font-mono text-fg-dim bg-bg border border-border rounded">
            <Command size={10} /> K
          </kbd>
        </Button>
        {actions}
      </div>
    </header>
  );
}
