import { UA } from '../config.js';
import { combineAbortSignals, fetchWithBackoff } from './http-utils.js';

/**
 * Passivo: Certificate Transparency via crt.sh
 */
export async function fetchCrtShSubdomains(
  domain,
  { signal = null, timeoutMs = 90000, fetchImpl = null } = {},
) {
  const url = `https://crt.sh/?q=%25.${encodeURIComponent(domain)}&output=json`;
  const res = await fetchWithBackoff(
    url,
    {
      headers: { 'User-Agent': UA, Accept: 'application/json' },
      signal: combineAbortSignals(signal, timeoutMs),
    },
    { fetchImpl },
  );
  if (!res.ok) throw new Error(`crt.sh HTTP ${res.status}`);
  const rows = await res.json();
  if (!Array.isArray(rows)) return [];

  const set = new Set();
  for (const row of rows) {
    const name = row.name_value;
    if (!name) continue;
    for (const part of String(name).split('\n')) {
      const h = part.trim().toLowerCase().replace(/^\*\./, '');
      if (h.endsWith(domain.toLowerCase()) || h === domain.toLowerCase()) {
        set.add(h);
      }
    }
  }
  return [...set].sort();
}
