import type { HTMLAttributes } from 'react';
import { cn } from '@/lib/utils/cn';

interface Props extends HTMLAttributes<HTMLSpanElement> {
  tone?: 'neutral' | 'accent' | 'muted';
  mono?: boolean;
}

export function Badge({ className, tone = 'neutral', mono, ...rest }: Props) {
  const toneClass =
    tone === 'accent'
      ? 'bg-accent-soft text-accent border-accent/30'
      : tone === 'muted'
      ? 'bg-surface-2 text-fg-dim border-border'
      : 'bg-surface-2 text-fg-muted border-border';

  return (
    <span
      className={cn(
        'inline-flex items-center px-2 py-0.5 text-2xs uppercase tracking-wide rounded border',
        mono && 'font-mono',
        toneClass,
        className
      )}
      {...rest}
    />
  );
}
