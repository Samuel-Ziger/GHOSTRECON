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
export function preRunChecklist({ engagement, target, modules = [], playbook = null }) {
  const errors = [];
  const warnings = [];

  if (!engagement) {
    warnings.push('sem engagement — rodando fora de ROE formal (ok para bug bounty passivo).');
    return checkIntrusive({ errors, warnings, modules, playbook });
  }

  if (engagement.status === 'closed') {
    errors.push(`engagement ${engagement.id} está CLOSED desde ${engagement.closedAt}.`);
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
  if (!engagement.roeSigned) warnings.push('ROE não marcado como assinado (roeSigned=false).');

  // Escopo
  if (target) {
    const inDomain = (engagement.scopeDomains || []).some((r) => hostMatchesRule(target, r));
    const inIp = (engagement.scopeIps || []).some((r) => ipMatchesRule(target, r));
    const excluded = (engagement.exclusions || []).some((r) => hostMatchesRule(target, r) || ipMatchesRule(target, r));
    if (excluded) errors.push(`${target} está em exclusions do engagement.`);
    if (!inDomain && !inIp) {
      // Apenas aviso se scope vazio; erro se scope definido e não bateu.
      if ((engagement.scopeDomains?.length || 0) + (engagement.scopeIps?.length || 0) > 0) {
        errors.push(`${target} fora do escopo definido (scopeDomains/scopeIps).`);
      } else {
        warnings.push('engagement sem scopeDomains/scopeIps — qualquer alvo aceito.');
      }
    }
  }

  return checkIntrusive({ errors, warnings, modules, playbook });
}

function checkIntrusive({ errors, warnings, modules, playbook }) {
  const INTRUSIVE = new Set([
    'sqlmap', 'nuclei', 'nuclei-aggressive', 'wpscan', 'ffuf', 'feroxbuster',
    'dirsearch', 'gobuster', 'nmap-aggressive', 'nikto', 'wafwoof-active',
    'xss-verify', 'lfi-verify', 'sqli-verify', 'webshell-probe', 'kali-active',
  ]);
  const hits = (modules || []).filter((m) => INTRUSIVE.has(String(m).toLowerCase()));
  if (hits.length) {
    warnings.push(`módulos INTRUSIVOS detectados: ${hits.join(', ')} — requer --confirm-active.`);
  }
  if (playbook && /aggress|kali|active/.test(String(playbook))) {
    warnings.push(`playbook "${playbook}" tem perfil agressivo.`);
  }
  return { ok: errors.length === 0, errors, warnings, intrusiveModules: hits };
}

function hostMatchesRule(host, rule) {
  const h = String(host || '').toLowerCase();
  const r = String(rule || '').toLowerCase().trim();
  if (!h || !r) return false;
  if (r.startsWith('*.')) {
    const suffix = r.slice(1);
    return h.endsWith(suffix) && h.length > suffix.length;
  }
  return h === r;
}

function ipMatchesRule(host, rule) {
  const h = String(host || '').trim();
  const r = String(rule || '').trim();
  if (!h || !r) return false;
  if (r === h) return true;
  // CIDR básico /24 e /32
  const m = r.match(/^(\d+\.\d+\.\d+)\.(\d+)\/(\d+)$/);
  if (!m) return false;
  const prefix = Number(m[3]);
  if (prefix === 32) return r.split('/')[0] === h;
  if (prefix === 24) {
    const base = r.split('/')[0].split('.').slice(0, 3).join('.');
    const hb = h.split('.').slice(0, 3).join('.');
    return base === hb;
  }
  return false;
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
