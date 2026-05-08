#!/usr/bin/env node
/**
 * Lê o ficheiro de alvos (WORKFLOW_DOMAINS_FILE; por defeito ../subdomains.txt na raiz do repo) ordenado → recon → SQLite → IA → webhook.
 * Motor: cópia estática do servidor GHOSTRECON + `runPipeline` em processo (sem API HTTP).
 */
import '../lib/env-bootstrap.mjs';
import fs from 'node:fs';

process.env.GHOSTRECON_NO_HTTP_LISTEN ??= '1';

import { ghostreconRootPath } from '../lib/ghostrecon-root.mjs';
try {
  process.chdir(ghostreconRootPath());
} catch (e) {
  console.error(`[pipeline] aviso: não consegui chdir para ${ghostreconRootPath()}: ${e.message || e}`);
}

import { orderDomainsFQDN, apexForHost } from '../lib/domain-order.mjs';
import { executeReconDirect } from '../engine/direct-pipeline.mjs';
import { openStateDb, filterInsertNew, insertCycle, finalizeCycle } from '../lib/sqlite-state.mjs';
import { summarizeFindingsPortugueseWithMeta } from '../lib/gemini-summarize.mjs';
import { postWebhook } from '../lib/webhook.mjs';
import { resolveFromRoot, DEFAULT_WORKFLOW_DOMAINS_REL } from '../lib/paths.mjs';
import { resolveModulesForRun, resolvePlaybookProfile } from '../lib/playbook-modules.mjs';

function readLines(filePath) {
  const raw = fs.readFileSync(filePath, 'utf8');
  return raw.split(/\r?\n/).map((l) => l.trim()).filter(Boolean);
}

function reconOpts(domain, modules) {
  const mode = String(process.env.WORKFLOW_EXACT_MATCH || 'subdomain_only')
    .trim()
    .toLowerCase();
  let exactMatch = mode === 'always';
  if (mode === 'subdomain_only' || mode === 'auto') exactMatch = apexForHost(domain) !== 0;
  if (mode === 'never') exactMatch = false;

  const kaliRaw = process.env.WORKFLOW_KALI_MODE ?? '0';
  const kaliMode = String(kaliRaw).trim() === '1' || /^true$/i.test(String(kaliRaw));

  const confirmRaw = process.env.WORKFLOW_CONFIRM_ACTIVE ?? '1';
  const confirmActive = String(confirmRaw).trim() === '1';

  const envProfile = String(process.env.WORKFLOW_PROFILE || 'standard').trim().toLowerCase();
  /** Se o utilizador não forçar outro perfil, aplicamos o perfil declarado no playbook JSON. */
  let profile = envProfile;
  if (envProfile === 'standard' && playbookProfileMemo) {
    profile = playbookProfileMemo;
  }

  const opsec = String(process.env.WORKFLOW_OPSEC_PROFILE || 'standard').trim().toLowerCase();

  const engagementId = String(process.env.WORKFLOW_ENGAGEMENT_ID || '').trim();

  const operator =
    process.env.WORKFLOW_OPERATOR != null ? String(process.env.WORKFLOW_OPERATOR).trim() : '';

  return {
    domain,
    modules,
    exactMatch,
    kaliMode,
    profile,
    opsecProfile: opsec,
    outOfScope: String(process.env.WORKFLOW_OUT_OF_SCOPE || '').trim() || null,
    projectName: String(process.env.WORKFLOW_PROJECT_NAME || '').trim(),
    playbook: String(process.env.WORKFLOW_PLAYBOOK || 'subdomain-hunt').trim() || null,
    engagementId: engagementId || undefined,
    operator: operator || null,
    autoAiReports: String(process.env.WORKFLOW_AUTO_AI_REPORTS ?? '0').trim() === '1',
    confirmActive,
  };
}

let playbookProfileMemo = /** @type {string | null} */ (null);

async function scanOne(domain, modules, db) {
  console.error(`[pipeline] ▶ ${domain} (${modules.length} módulos)`);

  try {
    const result = await executeReconDirect(reconOpts(domain, modules));
    const fresh = Array.isArray(result.findings) ? result.findings : [];
    const newOnes = filterInsertNew(db, domain, fresh);
    if (result.errors?.length) {
      console.error(`[pipeline] aviso ${domain}:`, result.errors.slice(0, 3).join(' | '));
    }
    return {
      scanned: true,
      total: fresh.length,
      newCount: newOnes.length,
      newRows: newOnes,
    };
  } catch (e) {
    console.error(`[pipeline] erro em ${domain}: ${e.message || e}`);
    return { scanned: false, total: 0, newCount: 0, newRows: [] };
  }
}

async function main() {
  playbookProfileMemo = await resolvePlaybookProfile();

  const domainsFile = resolveFromRoot(process.env.WORKFLOW_DOMAINS_FILE || DEFAULT_WORKFLOW_DOMAINS_REL);
  if (!fs.existsSync(domainsFile)) {
    console.error(`[pipeline] Ficheiro em falta: ${domainsFile} — corra primeiro scripts/sync-domains.mjs`);
    process.exit(2);
  }

  const modules = await resolveModulesForRun();
  console.error(`[pipeline] ${modules.length} módulos efectivos`);

  const db = openStateDb(process.env.WORKFLOW_SQLITE_PATH);
  const cycleId = Number(insertCycle(db, `pid=${process.pid}`));

  const lines = readLines(domainsFile);
  const ordered = orderDomainsFQDN(lines.filter((x) => !String(x).trim().startsWith('#')));

  /** @typedef {{ fingerprint?: string, type?: string, targetBucket?: string }} F */
  /** @type F[] */
  const allNew = [];
  let targets = 0;

  for (const domain of ordered) {
    targets++;
    const r = await scanOne(domain, modules, db);
    console.error(`[pipeline] ◼ ${domain} — ${r.newCount} novo(s) / ${r.total} total`);
    for (const row of r.newRows) {
      allNew.push({ ...row, targetBucket: domain });
    }
  }

  finalizeCycle(db, cycleId, targets, allNew.length);
  db.close();

  const always = String(process.env.WORKFLOW_WEBHOOK_ALWAYS ?? '0').trim() === '1';
  let summaryPt = null;
  /** @type {'gemini' | 'openrouter' | null} */
  let aiSummarizer = null;

  if (allNew.length) {
    const meta = await summarizeFindingsPortugueseWithMeta(allNew, { targets: ordered });
    summaryPt = meta.text;
    aiSummarizer = meta.provider;
  }

  /** @type {Record<string, unknown>} */
  const payload = {
    source: 'ghostrecon-vps-workflow',
    cycle_id: cycleId,
    finished_at: new Date().toISOString(),
    targets_order: ordered,
    targets_processed: targets,
    new_findings_count: allNew.length,
    new_findings: allNew.slice(0, 500),
    ai_summary_pt: summaryPt,
    ai_summarizer: aiSummarizer,
  };

  try {
    if (allNew.length || always) {
      await postWebhook(payload);
      console.error(`[pipeline] webhook enviado (novos=${allNew.length}; always=${always})`);
    } else {
      console.error('[pipeline] webhook ignorado — zero novidades (WORKFLOW_WEBHOOK_ALWAYS=0)');
    }
  } catch (e) {
    console.error(`[pipeline] webhook erro: ${e.message || e}`);
    process.exit(4);
  }
}

main();
