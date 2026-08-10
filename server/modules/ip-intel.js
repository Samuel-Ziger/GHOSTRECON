import dns from 'node:dns/promises';
export { shodanHostSummary } from './shodan-client.mjs';

/**
 * Resolve IPv4 únicos para uma lista de hosts (amostra limitada).
 */
export async function collectUniqueIpv4(hosts, maxHosts = 12, maxIps = 10) {
  const ips = new Set();
  for (const h of (hosts || []).slice(0, maxHosts)) {
    if (!h || typeof h !== 'string') continue;
    try {
      const r4 = await dns.resolve4(h.trim());
      for (const ip of r4) {
        ips.add(ip);
        if (ips.size >= maxIps) return [...ips];
      }
    } catch {
      /* ignore */
    }
  }
  return [...ips];
}
