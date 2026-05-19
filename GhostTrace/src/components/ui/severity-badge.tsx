import { cn } from '@/lib/utils/cn';
import { SEVERITY_COLOR, SEVERITY_LABEL } from '@/lib/utils/severity';
import type { Severity } from '@/lib/types';

interface Props {
  severity: Severity;
  size?: 'sm' | 'md';
  className?: string;
}

export function SeverityBadge({ severity, size = 'md', className }: Props) {
  const sz = size === 'sm' ? 'h-5 px-1.5 text-2xs' : 'h-6 px-2 text-xs';
  return (
    <span
      className={cn(
        'inline-flex items-center gap-1.5 rounded font-mono uppercase tracking-wider font-medium border',
        sz,
        className
      )}
      style={{
        color: SEVERITY_COLOR[severity],
        borderColor: `${SEVERITY_COLOR[severity]}55`,
        background: `${SEVERITY_COLOR[severity]}10`
      }}
    >
      <span
        className="w-1.5 h-1.5 rounded-full"
        style={{ background: SEVERITY_COLOR[severity], boxShadow: `0 0 8px ${SEVERITY_COLOR[severity]}` }}
      />
      {SEVERITY_LABEL[severity]}
    </span>
  );
}
