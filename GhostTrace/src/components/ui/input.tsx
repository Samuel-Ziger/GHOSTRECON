'use client';

import { forwardRef, type InputHTMLAttributes, type TextareaHTMLAttributes } from 'react';
import { cn } from '@/lib/utils/cn';

export const Input = forwardRef<HTMLInputElement, InputHTMLAttributes<HTMLInputElement>>(
  ({ className, ...rest }, ref) => (
    <input
      ref={ref}
      className={cn(
        'w-full h-9 px-3 text-sm bg-surface-2 border border-border rounded-md',
        'text-fg placeholder:text-fg-dim',
        'focus-visible:outline-none focus-visible:border-accent/60 focus-visible:shadow-glow-soft',
        'transition-all duration-150 ease-snap',
        className
      )}
      {...rest}
    />
  )
);
Input.displayName = 'Input';

export const Textarea = forwardRef<HTMLTextAreaElement, TextareaHTMLAttributes<HTMLTextAreaElement>>(
  ({ className, ...rest }, ref) => (
    <textarea
      ref={ref}
      className={cn(
        'w-full px-3 py-2 text-sm bg-surface-2 border border-border rounded-md',
        'text-fg placeholder:text-fg-dim resize-vertical',
        'focus-visible:outline-none focus-visible:border-accent/60 focus-visible:shadow-glow-soft',
        'transition-all duration-150 ease-snap',
        className
      )}
      {...rest}
    />
  )
);
Textarea.displayName = 'Textarea';

interface LabelProps {
  children: React.ReactNode;
  hint?: string;
  required?: boolean;
}

export function Label({ children, hint, required }: LabelProps) {
  return (
    <div className="flex items-center justify-between mb-1.5">
      <label className="text-xs font-medium uppercase tracking-wider text-fg-muted">
        {children}
        {required && <span className="text-[var(--sev-critical)] ml-1">*</span>}
      </label>
      {hint && <span className="text-2xs text-fg-dim">{hint}</span>}
    </div>
  );
}

export function Field({
  label,
  hint,
  required,
  children
}: {
  label?: string;
  hint?: string;
  required?: boolean;
  children: React.ReactNode;
}) {
  return (
    <div>
      {label && (
        <Label hint={hint} required={required}>
          {label}
        </Label>
      )}
      {children}
    </div>
  );
}
