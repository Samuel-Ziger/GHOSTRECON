'use client';

import { forwardRef, type ButtonHTMLAttributes } from 'react';
import { cn } from '@/lib/utils/cn';

type Variant = 'primary' | 'secondary' | 'ghost' | 'danger' | 'outline';
type Size = 'sm' | 'md' | 'lg' | 'icon';

interface Props extends ButtonHTMLAttributes<HTMLButtonElement> {
  variant?: Variant;
  size?: Size;
}

const variants: Record<Variant, string> = {
  primary:
    'bg-accent text-bg hover:bg-accent/90 shadow-glow-soft hover:shadow-glow font-medium',
  secondary:
    'bg-surface-2 text-fg hover:bg-surface-3 border border-border hover:border-border-strong',
  ghost: 'text-fg-muted hover:text-fg hover:bg-surface-2',
  danger:
    'bg-[var(--sev-critical)]/10 text-[var(--sev-critical)] border border-[var(--sev-critical)]/30 hover:bg-[var(--sev-critical)]/20',
  outline:
    'border border-border-strong text-fg hover:border-accent hover:text-accent'
};

const sizes: Record<Size, string> = {
  sm: 'h-7 px-2.5 text-xs gap-1.5',
  md: 'h-9 px-3.5 text-sm gap-2',
  lg: 'h-11 px-5 text-sm gap-2',
  icon: 'h-9 w-9'
};

export const Button = forwardRef<HTMLButtonElement, Props>(
  ({ className, variant = 'secondary', size = 'md', ...rest }, ref) => (
    <button
      ref={ref}
      className={cn(
        'inline-flex items-center justify-center rounded-md transition-all duration-150 ease-snap disabled:opacity-40 disabled:cursor-not-allowed focus-visible:outline-none focus-visible:shadow-glow',
        variants[variant],
        sizes[size],
        className
      )}
      {...rest}
    />
  )
);
Button.displayName = 'Button';
