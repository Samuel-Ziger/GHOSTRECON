/**
 * Resumo de findings Vigolium no terminal da UI (sem stdout do binário).
 * @param {(msg: string, level?: string) => void} log
 * @param {object[]} findings
 * @param {{ label?: string, maxLines?: number }} [opts]
 */
export function logVigoliumFindingsSummary(log, findings, opts = {}) {
  const label = String(opts.label || 'Vigolium').trim();
  const maxLines = Math.max(1, Number(opts.maxLines) || 40);
  const list = Array.isArray(findings) ? findings : [];

  if (!list.length) {
    log(`${label}: sem vulnerabilidades`, 'success');
    return;
  }

  log(`${label}: ${list.length} achado(s)`, 'warn');

  const shown = list.slice(0, maxLines);
  for (const f of shown) {
    const prio = String(f.prio || 'low').toLowerCase();
    const moduleId = extractVigoliumModuleId(f.meta) || 'vigolium';
    const where = String(f.url || f.value || '').trim();
    const hint = shortMetaHint(f.meta);
    const body = [where, hint].filter(Boolean).join(' — ');
    log(`[${prio}] ${moduleId}: ${body}`.slice(0, 320), 'find');
  }

  if (list.length > maxLines) {
    log(`… e mais ${list.length - maxLines} no painel FINDINGS`, 'info');
  }
}

function extractVigoliumModuleId(meta) {
  const m = String(meta || '').match(/source=vigolium:([^\s•]+)/);
  return m ? m[1] : '';
}

function shortMetaHint(meta) {
  const raw = String(meta || '');
  const desc = raw.split(' • ').find((p) => !p.startsWith('source=') && !p.startsWith('tags=') && !p.startsWith('confidence='));
  if (!desc) return '';
  return desc.slice(0, 120);
}
