/**
 * Engagement — metadata de campanha RT por engagement_id.
 *
 * Store: JSON em `.ghostrecon-engagements/engagements.json`.
 *
 * Schema:
 *   {
 *     engagements: [{
 *       id, client, scopeDomains, scopeIps, exclusions,
 *       window: { startsAt, endsAt, tz },
 *       sourceIps: ["X.X.X.X"],          // IPs do RT autorizados
 *       escalationContact: { name, email, phone },
 *       roeUrl, roeSigned, status: "active"|"paused"|"closed",
 *       notes: [{at, text, by}],
 *       runs: [{ runId, target, at, by }],
 *       createdAt, updatedAt, closedAt
 *     }]
 *   }
 *
 * Sem impacto em runs existentes — opt-in via flag --engagement <id>.
 */

import fs from 'node:fs/promises';
import path from 'node:path';
import { createHash } from 'node:crypto';
import { isIntrusive } from './opsec.mjs';
import {
  hostnameMatchesOutOfScope,
  hostnameMatchesDomainScopeRule,
  ipMatchesScopeRule,
} from './scope.js';

function storeDir() {
  return path.resolve(process.cwd(), process.env.GHOSTRECON_ENGAGEMENT_DIR || '.ghostrecon-engagements');
}
function storeFile() { return path.join(storeDir(), 'engagements.json'); }

async function loadStore() {
  try {
    const raw = await fs.readFile(storeFile(), 'utf8');
    const j = JSON.parse(raw);
    if (!Array.isArray(j.engagements)) j.engagements = [];
    return j;
  } catch {
    return { engagements: [] };
  }
}

async function saveStore(store) {
  await fs.mkdir(storeDir(), { recursive: true });
  await fs.writeFile(storeFile(), JSON.stringify(store, null, 2), 'utf8');
}

function normId(id) {
  const s = String(id || '').trim();
  if (!s || s.length > 120 || !/^[A-Za-z0-9._:@/-]+$/.test(s)) {
    throw new Error('engagement id inválido (use A-Z 0-9 . _ : @ / -)');
  }
  return s;
}

function stableAuthorizationValue(value) {
  if (Array.isArray(value)) return value.map(stableAuthorizationValue);
  if (!value || typeof value !== 'object') return value;
  return Object.fromEntries(
    Object.keys(value).sort().map((key) => [key, stableAuthorizationValue(value[key])]),
  );
}

function normalizedAuthorizationValues(values = []) {
  return [...new Set((Array.isArray(values) ? values : [])
    .map((value) => String(value || '').trim())
    .filter(Boolean))]
    .sort();
}

/**
 * Hash dos campos do engagement que concedem ou restringem autorização.
 * Notas, histórico de runs e metadados de apresentação não invalidam uma
 * aprovação; escopo, exclusões, janela, ROE, status e origem invalidam.
 */
export function computeEngagementAuthorizationBinding(
  engagement,
  requestedEngagementId = null,
) {
  if (!engagement) return null;
  const authorization = {
    schemaVersion: 1,
    requestedEngagementId: requestedEngagementId
      ? String(requestedEngagementId).trim()
      : null,
    id: String(engagement.id || '').trim(),
    status: String(engagement.status || '').trim().toLowerCase(),
    roeSigned: engagement.roeSigned === true,
    roeUrl: engagement.roeUrl ? String(engagement.roeUrl).trim() : null,
    scopeDomains: normalizedAuthorizationValues(engagement.scopeDomains),
    scopeIps: normalizedAuthorizationValues(engagement.scopeIps),
    exclusions: normalizedAuthorizationValues(engagement.exclusions),
    sourceIps: normalizedAuthorizationValues(engagement.sourceIps),
    window: engagement.window ? {
      startsAt: engagement.window.startsAt
        ? String(engagement.window.startsAt).trim()
        : null,
      endsAt: engagement.window.endsAt
        ? String(engagement.window.endsAt).trim()
        : null,
      tz: engagement.window.tz ? String(engagement.window.tz).trim() : null,
    } : null,
    closedAt: engagement.closedAt ? String(engagement.closedAt).trim() : null,
  };
  return createHash('sha256')
    .update(JSON.stringify(stableAuthorizationValue(authorization)))
    .digest('hex');
}

export async function listEngagements() {
  const s = await loadStore();
  return s.engagements.map((e) => ({
    id: e.id,
    client: e.client,
    status: e.status || 'active',
    scopeDomains: e.scopeDomains || [],
    scopeIps: e.scopeIps || [],
    runCount: (e.runs || []).length,
    window: e.window || null,
    updatedAt: e.updatedAt,
    createdAt: e.createdAt,
    closedAt: e.closedAt || null,
  }));
}

export async function getEngagement(id) {
  const s = await loadStore();
  return s.engagements.find((e) => e.id === String(id)) || null;
}

export async function upsertEngagement(input) {
  const id = normId(input.id);
  const s = await loadStore();
  const now = new Date().toISOString();
  const idx = s.engagements.findIndex((e) => e.id === id);
  const prev = idx >= 0 ? s.engagements[idx] : null;
  const merged = {
    id,
    client: input.client ?? prev?.client ?? '',
    scopeDomains: uniqStrings([...(prev?.scopeDomains || []), ...(input.scopeDomains || [])]),
    scopeIps: uniqStrings([...(prev?.scopeIps || []), ...(input.scopeIps || [])]),
    exclusions: uniqStrings([...(prev?.exclusions || []), ...(input.exclusions || [])]),
    window: input.window ?? prev?.window ?? null,
    sourceIps: uniqStrings([...(prev?.sourceIps || []), ...(input.sourceIps || [])]),
    escalationContact: input.escalationContact ?? prev?.escalationContact ?? null,
    roeUrl: input.roeUrl ?? prev?.roeUrl ?? null,
    roeSigned: input.roeSigned ?? prev?.roeSigned ?? false,
    status: input.status ?? prev?.status ?? 'active',
    notes: [...(prev?.notes || []), ...(input.notes || [])].slice(-500),
    runs: prev?.runs || [],
    createdAt: prev?.createdAt || now,
    updatedAt: now,
    closedAt: prev?.closedAt || null,
  };
  if (idx >= 0) s.engagements[idx] = merged;
  else s.engagements.push(merged);
  await saveStore(s);
  return merged;
}

export async function closeEngagement(id, { reason } = {}) {
  const s = await loadStore();
  const e = s.engagements.find((x) => x.id === String(id));
  if (!e) return null;
  e.status = 'closed';
  e.closedAt = new Date().toISOString();
  if (reason) e.notes = [...(e.notes || []), { at: e.closedAt, text: `[CLOSED] ${reason}` }].slice(-500);
  await saveStore(s);
  return e;
}

export async function attachRunToEngagement(id, { runId, target, by = null }) {
  if (!id || runId == null) return;
  const s = await loadStore();
  const e = s.engagements.find((x) => x.id === String(id));
  if (!e) return;
  e.runs = e.runs || [];
  e.runs.push({ runId, target, at: new Date().toISOString(), by });
  e.runs = e.runs.slice(-2000);
  e.updatedAt = new Date().toISOString();
  await saveStore(s);
}

/**
 * Pré-run checklist: valida alvo contra escopo + exclusões, detecta módulos intrusivos,
 * retorna { ok, errors, warnings }.
 */
export function preRunChecklist({
  engagement,
  target,
  modules = [],
  playbook = null,
  requireFormalAuthorization = false,
  intrusiveModules = null,
}) {
  const errors = [];
  const warnings = [];

  if (!engagement) {
    if (requireFormalAuthorization) {
      errors.push('engagement formal obrigatório para módulos intrusivos.');
    } else {
      warnings.push('sem engagement — rodando fora de ROE formal (ok para bug bounty passivo).');
    }
    return checkIntrusive({ errors, warnings, modules, playbook, intrusiveModules });
  }

  if (engagement.status !== 'active') {
    errors.push(
      engagement.status === 'closed'
        ? `engagement ${engagement.id} está CLOSED desde ${engagement.closedAt}.`
        : `engagement ${engagement.id} não está ativo (status=${engagement.status || 'desconhecido'}).`,
    );
  }

  // Janela de teste
  if (engagement.window) {
    const now = new Date();
    if (engagement.window.startsAt && new Date(engagement.window.startsAt) > now) {
      errors.push(`ainda fora da janela (start=${engagement.window.startsAt}).`);
    }
    if (engagement.window.endsAt && new Date(engagement.window.endsAt) < now) {
      errors.push(`fora da janela (end=${engagement.window.endsAt}).`);
    }
  }

  // ROE assinado
  if (!engagement.roeSigned) {
    if (requireFormalAuthorization) errors.push('ROE assinado obrigatório para módulos intrusivos.');
    else warnings.push('ROE não marcado como assinado (roeSigned=false).');
  }

  const scopeEntries =
    (engagement.scopeDomains?.length || 0) + (engagement.scopeIps?.length || 0);
  if (scopeEntries === 0) {
    errors.push(
      'engagement formal sem scopeDomains/scopeIps; defina uma allowlist antes de executar.',
    );
  }

  // Escopo
  if (target) {
    const inDomain = (engagement.scopeDomains || [])
      .some((rule) => hostnameMatchesDomainScopeRule(target, rule));
    const inIp = (engagement.scopeIps || [])
      .some((rule) => ipMatchesScopeRule(target, rule));
    const excluded = hostnameMatchesOutOfScope(target, engagement.exclusions || []);
    if (excluded) errors.push(`${target} está em exclusions do engagement.`);
    if (!inDomain && !inIp) {
      if (scopeEntries > 0) {
        errors.push(`${target} fora do escopo definido (scopeDomains/scopeIps).`);
      }
    }
  }

  return checkIntrusive({ errors, warnings, modules, playbook, intrusiveModules });
}

function checkIntrusive({ errors, warnings, modules, playbook, intrusiveModules = null }) {
  const declared = Array.isArray(intrusiveModules) ? intrusiveModules : [];
  const hits = [...new Set([
    ...declared,
    ...(modules || []).filter((moduleId) => isIntrusive(moduleId)),
  ].map(String).filter(Boolean))];
  if (hits.length) {
    warnings.push(`módulos INTRUSIVOS detectados: ${hits.join(', ')} — requer --confirm-active.`);
  }
  if (playbook && /aggress|kali|active/.test(String(playbook))) {
    warnings.push(`playbook "${playbook}" tem perfil agressivo.`);
  }
  return { ok: errors.length === 0, errors, warnings, intrusiveModules: hits };
}

/**
 * Gera relatório operacional (1 página) — markdown para compliance/blue team.
 */
export function buildOperationalReport(engagement, { runs = [], now = new Date() } = {}) {
  if (!engagement) throw new Error('engagement obrigatório');
  const lines = [];
  const title = `GHOSTRECON — Operational Report · ${engagement.id}`;
  lines.push(`# ${title}`);
  lines.push('');
  lines.push(`- **Cliente:** ${engagement.client || '-'}`);
  lines.push(`- **Status:** ${engagement.status || 'active'}${engagement.closedAt ? ` (closed ${engagement.closedAt})` : ''}`);
  if (engagement.window?.startsAt || engagement.window?.endsAt) {
    lines.push(`- **Janela:** ${engagement.window?.startsAt || '-'} → ${engagement.window?.endsAt || '-'} ${engagement.window?.tz || ''}`);
  }
  if (engagement.sourceIps?.length) lines.push(`- **IPs de origem RT:** ${engagement.sourceIps.join(', ')}`);
  if (engagement.escalationContact) {
    const c = engagement.escalationContact;
    lines.push(`- **Escalação:** ${c.name || '-'} · ${c.email || '-'} · ${c.phone || '-'}`);
  }
  if (engagement.roeUrl) lines.push(`- **ROE:** ${engagement.roeUrl} · assinado: ${engagement.roeSigned ? 'sim' : 'NÃO'}`);
  lines.push('');

  lines.push('## Escopo');
  lines.push(`- Domínios: ${(engagement.scopeDomains || []).join(', ') || '(vazio — qualquer alvo)'}`);
  lines.push(`- IPs: ${(engagement.scopeIps || []).join(', ') || '(vazio)'}`);
  lines.push(`- Exclusões: ${(engagement.exclusions || []).join(', ') || '(nenhuma)'}`);
  lines.push('');

  lines.push(`## Runs executados (${(engagement.runs || []).length})`);
  const allRuns = engagement.runs || [];
  const recent = allRuns.slice(-30).reverse();
  if (!recent.length) lines.push('_(nenhum run registrado ainda)_');
  for (const r of recent) {
    lines.push(`- #${r.runId} · ${r.target} · ${r.at}${r.by ? ` · by ${r.by}` : ''}`);
  }
  lines.push('');

  // Módulos executados (agregado de runs fornecidos)
  if (runs.length) {
    const moduleSet = new Set();
    let totalFindings = 0;
    const bySev = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
    for (const run of runs) {
      (run.modules || []).forEach((m) => moduleSet.add(m));
      for (const f of run.findings || []) {
        totalFindings++;
        const k = String(f.severity || 'info').toLowerCase();
        if (bySev[k] != null) bySev[k]++;
      }
    }
    lines.push('## Módulos executados (agregado)');
    lines.push(`- ${[...moduleSet].sort().join(', ') || '-'}`);
    lines.push('');
    lines.push('## Findings (agregado)');
    lines.push(`- Total: ${totalFindings}`);
    lines.push(`- Por severidade: critical=${bySev.critical} · high=${bySev.high} · medium=${bySev.medium} · low=${bySev.low} · info=${bySev.info}`);
    lines.push('');
  }

  lines.push('## Notas');
  const notes = (engagement.notes || []).slice(-10);
  if (!notes.length) lines.push('_(sem notas)_');
  for (const n of notes) lines.push(`- ${n.at}${n.by ? ` · ${n.by}` : ''} — ${n.text}`);
  lines.push('');

  lines.push('---');
  lines.push(`_Gerado por GHOSTRECON em ${now.toISOString()}_`);
  return lines.join('\n');
}

function uniqStrings(arr) {
  const seen = new Set();
  const out = [];
  for (const x of arr || []) {
    const s = String(x || '').trim();
    if (!s || seen.has(s)) continue;
    seen.add(s);
    out.push(s);
  }
  return out;
}
