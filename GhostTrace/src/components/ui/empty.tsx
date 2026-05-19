import type { LucideIcon } from 'lucide-react';
import { cn } from '@/lib/utils/cn';

interface Props {
  icon?: LucideIcon;
  title: string;
  description?: string;
  action?: React.ReactNode;
  className?: string;
}

export function Empty({ icon: Icon, title, description, action, className }: Props) {
  return (
    <div
      className={cn(
        'flex flex-col items-center justify-center text-center py-16 px-6 border border-dashed border-border rounded-lg bg-surface/40',
        className
      )}
    >
      {Icon && (
        <div className="w-12 h-12 rounded-md border border-border bg-surface-2 flex items-center justify-center mb-3 text-fg-dim">
          <Icon size={20} />
        </div>
      )}
      <p className="text-sm text-fg font-medium">{title}</p>
      {description && (
        <p className="text-xs text-fg-muted mt-1 max-w-xs">{description}</p>
      )}
      {action && <div className="mt-4">{action}</div>}
    </div>
  );
}
