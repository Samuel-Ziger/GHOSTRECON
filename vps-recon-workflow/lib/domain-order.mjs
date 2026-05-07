import { parse } from 'tldts';

export function apexFor(host) {
  const h = String(host).trim().toLowerCase();
  const p = parse(h);
  return p.domain || null;
}

/**
 * 0 = próprio apex (eTLD+1); ≥1 = há labels à esquerda do apex (tratamos como «subdomínio» para exactMatch).
 */
export function apexForHost(host) {
  const h = String(host).trim().toLowerCase().replace(/\.$/, '');
  const apex = apexFor(h);
  if (!apex || h === apex) return 0;
  const prefix = h.endsWith(`.${apex}`) ? h.slice(0, -(apex.length + 1)) : '';
  const labels = prefix ? prefix.split('.').filter(Boolean) : [];
  return labels.length || 1;
}

export function orderDomainsFQDN(list) {
  const uniq = [...new Set(list.map((x) => String(x).trim().toLowerCase()).filter(Boolean))];
  uniq.sort((a, b) => {
    const ra = apexFor(a) || a;
    const rb = apexFor(b) || b;
    if (ra !== rb) return ra.localeCompare(rb);
    const ah = apexForHost(a);
    const bh = apexForHost(b);
    if (ah !== bh) return ah - bh;
    return a.localeCompare(b);
  });
  return uniq;
}
