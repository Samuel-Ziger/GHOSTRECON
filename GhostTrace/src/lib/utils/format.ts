import { format, formatDistanceToNow, parseISO } from 'date-fns';

export function fmtDate(iso: string, pattern = 'dd MMM yyyy'): string {
  try {
    return format(parseISO(iso), pattern);
  } catch {
    return iso;
  }
}

export function fmtTime(iso: string): string {
  try {
    return format(parseISO(iso), 'HH:mm:ss');
  } catch {
    return iso;
  }
}

export function fmtDateTime(iso: string): string {
  try {
    return format(parseISO(iso), 'dd MMM · HH:mm');
  } catch {
    return iso;
  }
}

export function fmtRelative(iso: string): string {
  try {
    return formatDistanceToNow(parseISO(iso), { addSuffix: true });
  } catch {
    return iso;
  }
}

export function fmtRange(startIso: string, endIso?: string): string {
  if (!endIso) return fmtDate(startIso);
  return `${fmtDate(startIso)} → ${fmtDate(endIso)}`;
}
