import dns from 'node:dns/promises';
export { shodanHostSummary } from './shodan-client.mjs';

/**
 * Resolve IPv4 únicos para uma lista de hosts (amostra limitada).
 */
export async function collectUniqueIpv4(hosts, maxHosts = 12, maxIps = 10, opts = {}) {
  const signal = opts?.signal ?? null;
  const ips = new Set();
  for (const h of (hosts || []).slice(0, maxHosts)) {
    if (signal?.aborted) {
      const err = signal.reason instanceof Error
        ? signal.reason
        : Object.assign(new Error('DNS resolve cancelado'), { name: 'AbortError', code: 'PROCESS_ABORTED' });
      throw err;
    }
    if (!h || typeof h !== 'string') continue;
    try {
      const r4 = await dns.resolve4(h.trim(), signal ? { signal } : undefined);
      for (const ip of r4) {
        ips.add(ip);
        if (ips.size >= maxIps) return [...ips];
      }
    } catch (e) {
      if (signal?.aborted || e?.name === 'AbortError') throw e;
      /* ignore NXDOMAIN etc. */
    }
  }
  return [...ips];
}
