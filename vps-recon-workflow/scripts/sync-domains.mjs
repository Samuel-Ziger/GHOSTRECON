#!/usr/bin/env node
/**
 * Obtém domínios do Supabase e grava o ficheiro em WORKFLOW_DOMAINS_FILE (um FQDN por linha).
 */
import '../lib/env-bootstrap.mjs';
import fs from 'node:fs';
import { createClient } from '@supabase/supabase-js';
import { apexFor, apexForHost } from '../lib/domain-order.mjs';
import { resolveFromRoot, DEFAULT_WORKFLOW_DOMAINS_REL } from '../lib/paths.mjs';

const OUT = resolveFromRoot(process.env.WORKFLOW_DOMAINS_FILE || DEFAULT_WORKFLOW_DOMAINS_REL);

function supabaseKeys() {
  const url = String(process.env.SUPABASE_URL || '').trim();
  const key =
    String(process.env.SUPABASE_SERVICE_ROLE_KEY || '').trim() ||
    String(process.env.SUPABASE_ANON_KEY || '').trim() ||
    String(process.env.SUPABASE_KEY || '').trim();
  return { url, key };
}

/** @returns {Promise<string[]>} */
async function domainsFromDistinctRuns(sb) {
  const all = [];
  const pageSize = 1000;
  let from = 0;
  for (;;) {
    const { data, error } = await sb
      .from('runs')
      .select('target')
      .order('created_at', { ascending: false })
      .range(from, from + pageSize - 1);
    if (error) throw error;
    if (!data?.length) break;
    for (const row of data) {
      const t = String(row?.target ?? '').trim().toLowerCase();
      if (t) all.push(t);
    }
    if (data.length < pageSize) break;
    from += pageSize;
  }
  return [...new Set(all)].sort((a, b) => {
    const ar = apexFor(a) || a;
    const br = apexFor(b) || b;
    if (ar !== br) return ar.localeCompare(br);
    if (apexForHost(a) !== apexForHost(b)) return apexForHost(a) - apexForHost(b);
    return a.localeCompare(b);
  });
}

/** @returns {Promise<string[]>} */
async function domainsFromTable(sb) {
  const table = String(process.env.WORKFLOW_DOMAINS_TABLE || 'workflow_domains').trim();
  const col = String(process.env.WORKFLOW_DOMAIN_COLUMN || 'domain').trim();
  const rootCol = String(process.env.WORKFLOW_ROOT_DOMAIN_COLUMN || 'root_domain').trim();

  const selectCols =
    rootCol.toLowerCase() === 'omit' || rootCol === '-' ? col : `${col}, ${rootCol}`;

  const { data, error } = await sb.from(table).select(selectCols).limit(50000);
  if (error) throw error;

  /** @type {{ fqdn: string, root: string }[]} */
  const rows = [];

  const hasRoot = selectCols.includes(',');

  for (const row of data || []) {
    const d = String(row?.[col] ?? '').trim().toLowerCase();
    if (!d) continue;
    let root = '';
    if (hasRoot && row?.[rootCol] != null) {
      root = String(row[rootCol]).trim().toLowerCase();
    }
    if (!root) root = apexFor(d) || d;
    rows.push({ fqdn: d, root });
  }

  rows.sort((a, b) => {
    if (a.root !== b.root) return a.root.localeCompare(b.root);
    if (apexForHost(a.fqdn) !== apexForHost(b.fqdn)) return apexForHost(a.fqdn) - apexForHost(b.fqdn);
    return a.fqdn.localeCompare(b.fqdn);
  });

  return [...new Set(rows.map((x) => x.fqdn))];
}

async function main() {
  const { url, key } = supabaseKeys();
  if (!url || !key) {
    console.error('[sync-domains] Defina SUPABASE_URL e SUPABASE_SERVICE_ROLE_KEY (ou ANON)');
    process.exit(2);
  }

  const source = String(process.env.WORKFLOW_DOMAIN_SOURCE || 'table').trim().toLowerCase();
  const sb = createClient(url, key);

  let list =
    source === 'distinct_runs' || source === 'runs'
      ? await domainsFromDistinctRuns(sb)
      : await domainsFromTable(sb);

  const header =
    `# Gerado por ghostrecon-vps-workflow em ${new Date().toISOString()}\n` +
    `# source=${source}\n`;
  fs.mkdirSync(resolveFromRoot('.'), { recursive: true });

  fs.writeFileSync(
    OUT,
    `${header}\n${list.map((h) => h.trim()).filter(Boolean).join('\n')}\n`,
    'utf8',
  );
  console.log(`[sync-domains] ${list.length} FQDN → ${OUT}`);
}

main().catch((e) => {
  console.error('[sync-domains]', e.message || e);
  process.exit(1);
});
