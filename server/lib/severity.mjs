export function sevToPrio(sev) {
  const s = String(sev || '').toLowerCase();
  if (s === 'critical' || s === 'high') return 'high';
  if (s === 'medium') return 'med';
  return 'low';
}

export function sevToScore(sev) {
  const s = String(sev || '').toLowerCase();
  if (s === 'critical') return 95;
  if (s === 'high') return 86;
  if (s === 'medium') return 68;
  return 42;
}
