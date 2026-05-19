import type { Severity, VulnStatus, TimelineEventType, ChainPrivilege } from '@/lib/types';

export const SEVERITY_ORDER: Severity[] = ['critical', 'high', 'medium', 'low', 'info'];

export const SEVERITY_LABEL: Record<Severity, string> = {
  critical: 'CRÍTICA',
  high: 'ALTA',
  medium: 'MÉDIA',
  low: 'BAIXA',
  info: 'INFO'
};

export const SEVERITY_COLOR: Record<Severity, string> = {
  critical: 'var(--sev-critical)',
  high: 'var(--sev-high)',
  medium: 'var(--sev-medium)',
  low: 'var(--sev-low)',
  info: 'var(--sev-info)'
};

export const SEVERITY_WEIGHT: Record<Severity, number> = {
  critical: 5,
  high: 4,
  medium: 3,
  low: 2,
  info: 1
};

export const STATUS_LABEL: Record<VulnStatus, string> = {
  unfixed: 'NÃO CORRIGIDO',
  fixed: 'CORRIGIDO',
  retest: 'EM RETESTE',
  wont_fix: 'NÃO CORRIGIRÁ'
};

export const STATUS_COLOR: Record<VulnStatus, string> = {
  unfixed: 'var(--sev-critical)',
  fixed: 'var(--sev-low)',
  retest: 'var(--sev-info)',
  wont_fix: 'var(--sev-medium)'
};

export const EVENT_LABEL: Record<TimelineEventType, string> = {
  recon: 'RECON',
  enumeration: 'ENUM',
  creds: 'CREDS',
  rce: 'RCE',
  shell: 'SHELL',
  privesc: 'PRIVESC',
  pivot: 'PIVOT',
  exfil: 'EXFIL',
  lateral: 'LATERAL',
  persistence: 'PERSIST',
  note: 'NOTE'
};

export const EVENT_COLOR: Record<TimelineEventType, string> = {
  recon: 'var(--sev-info)',
  enumeration: 'var(--sev-info)',
  creds: 'var(--sev-medium)',
  rce: 'var(--sev-critical)',
  shell: 'var(--sev-high)',
  privesc: 'var(--sev-critical)',
  pivot: 'var(--sev-high)',
  exfil: 'var(--sev-critical)',
  lateral: 'var(--sev-high)',
  persistence: 'var(--sev-medium)',
  note: 'hsl(var(--fg-muted))'
};

export const PRIVILEGE_LABEL: Record<ChainPrivilege, string> = {
  unauth: 'UNAUTH',
  user: 'USER',
  root: 'ROOT'
};

export const PRIVILEGE_COLOR: Record<ChainPrivilege, string> = {
  unauth: 'hsl(var(--fg-muted))',
  user: 'var(--sev-info)',
  root: 'var(--sev-critical)'
};

export function compareBySeverity(a: Severity, b: Severity): number {
  return SEVERITY_WEIGHT[b] - SEVERITY_WEIGHT[a];
}
