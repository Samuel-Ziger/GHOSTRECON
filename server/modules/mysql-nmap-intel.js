/**
 * Normaliza inventário observado no Nmap em 3306/tcp (MySQL típico).
 * Não executa scans extra nem infere vulnerabilidade pela porta/versão.
 *
 * @param {Array<{ host?: string, port?: string, proto?: string, name?: string, product?: string, version?: string }>} rows
 * @returns {object[]}
 */
export function buildMysql3306IntelFindings(rows, { hostAllowed = () => true, signal = null } = {}) {
  const seen = new Set();
  const out = [];
  for (const row of (Array.isArray(rows) ? rows : []).slice(0, 10_000)) {
    if (signal?.aborted) {
      const error = signal.reason instanceof Error ? signal.reason : new Error('MySQL inventory cancelado');
      error.name = 'AbortError';
      error.code = 'PROCESS_ABORTED';
      throw error;
    }
    if (!row) continue;
    if (String(row.port) !== '3306') continue;
    if (String(row.proto || 'tcp').toLowerCase() !== 'tcp') continue;
    const host = String(row.host || '')
      .trim()
      .toLowerCase();
    if (!host || host === 'unknown') continue;
    if (host.length > 253 || /[\s/@\\?#]/.test(host)) continue;
    if (hostAllowed(host) !== true) continue;
    if (seen.has(host)) continue;
    seen.add(host);

    const svc = [row.name, row.product, row.version].filter(Boolean).join(' ').trim() || '3306/tcp aberto';
    const ver = row.version ? String(row.version).slice(0, 40) : '';
    const mysqlConfirmed = /(?:^|[^a-z0-9])(?:mysql|mariadb)(?:$|[^a-z0-9])/i
      .test([row.name, row.product].filter(Boolean).join(' '));

    out.push({
      type: 'service_inventory',
      prio: 'info',
      score: mysqlConfirmed ? 28 : 18,
      value: `${mysqlConfirmed ? 'MySQL/MariaDB identificado' : 'Serviço candidato a MySQL'} em ${host}:3306 — ${svc.slice(0, 96)}`,
      url: null,
      source: 'mysql_3306_intel',
      meta: {
        source: 'mysql_3306_intel',
        evidenceStatus: mysqlConfirmed ? 'inventory_confirmed_by_nmap_service' : 'candidate_by_port',
        host,
        port: 3306,
        protocol: 'tcp',
        service: String(row.name || ''),
        product: String(row.product || ''),
        version: ver || null,
        cpes: Array.isArray(row.cpes) ? row.cpes.slice(0, 8) : [],
        observedBy: 'nmap_service_detection',
        applicabilityVerified: false,
        note: 'Porta ou serviço exposto não prova vulnerabilidade',
      },
    });
  }
  return out;
}
