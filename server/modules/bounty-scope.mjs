/**
 * Bug bounty scope fetcher + dedupe local de submissões já enviadas.
 *
 * Suporta normalização de scope a partir de:
 *   - HackerOne (h1): GET https://api.hackerone.com/v1/hackers/programs/<handle>/scopes
 *   - Bugcrowd: GET https://bugcrowd.com/<program>.json
 *   - Intigriti: shape similar (passar JSON cru)
 *   - Custom: array {asset, type, eligible}
 *
 * Não faz HTTP — caller injeta `fetcher(url, opts)`. Mantém um arquivo local
 * de hashes de findings já submetidos (anti-dupe).
 */

import fs from 'node:fs/promises';
import path from 'node:path';
import os from 'node:os';
import crypto from 'node:crypto';

function dir() {
  return process.env.GHOSTRECON_BOUNTY_DIR || path.join(os.tmpdir(), '.ghostrecon-bounty');
}

async function ensureDir() {
  await fs.mkdir(dir(), { recursive: true });
}

// ============================================================================
// Scope parsers — entrada já-baixada, sem rede
// ============================================================================

export function parseHackerOneScope(json) {
  const data = json?.data || [];
  return data.map((d) => {
    const a = d.attributes || {};
    return {
      platform: 'hackerone',
      asset: a.asset_identifier,
      type: a.asset_type, // URL, WILDCARD, OTHER
      eligible: a.eligible_for_submission !== false,
      eligibleForBounty: a.eligible_for_bounty !== false,
      severity_max: a.max_severity || null,
      raw: a,
    };
  });
}

export function parseBugcrowdScope(json) {
  // Estrutura comum: { target_groups: [{ in_scope: [{ uri, ... }] }] }
  const out = [];
  const groups = json?.target_groups || json?.targets_groups || [];
  for (const g of groups) {
    for (const t of g.in_scope || []) {
      out.push({
        platform: 'bugcrowd',
        asset: t.uri || t.target || t.name,
        type: t.category || 'website',
        eligible: true,
        eligibleForBounty: true,
        severity_max: null,
        raw: t,
      });
    }
    for (const t of g.out_of_scope || []) {
      out.push({ platform: 'bugcrowd', asset: t.uri || t.target, type: t.category, eligible: false, raw: t });
    }
  }
  return out;
}

export function parseIntigritiScope(json) {
  const out = [];
  const domains = json?.domains || json?.scope || [];
  for (const d of domains) {
    out.push({
      platform: 'intigriti',
      asset: d.endpoint || d.url || d.value,
      type: d.type || 'url',
      eligible: d.tier !== 'OUT_OF_SCOPE' && d.severity !== 'no-bounty',
      eligibleForBounty: !!d.tier,
      severity_max: d.tier || null,
      raw: d,
    });
  }
  return out;
}

/**
 * Normaliza qualquer fonte para o formato GHOSTRECON.
 */
export function normalizeScope(items, platform) {
  if (platform === 'hackerone') return parseHackerOneScope(items);
  if (platform === 'bugcrowd') return parseBugcrowdScope(items);
  if (platform === 'intigriti') return parseIntigritiScope(items);
  if (Array.isArray(items)) return items;
  return [];
}

/**
 * Confronta um run.findings contra o scope: separa in/out.
 * `host` extrai-se de evidence.target/host/url.
 */
export function applyScopeFilter(findings = [], scope = []) {
  const wildcards = scope.filter((s) => s.eligible && /[*]/.test(s.asset || ''));
  const exact = new Set(scope.filter((s) => s.eligible && s.asset && !/[*]/.test(s.asset)).map((s) => normalizeAsset(s.asset)));
  const exclusions = scope.filter((s) => s.eligible === false).map((s) => s.asset);

  const out = { inScope: [], outOfScope: [] };
  for (const f of findings) {
    const host = hostOf(f);
    if (!host) { out.inScope.push(f); continue; }
    if (matchesAny(host, exclusions)) { out.outOfScope.push({ ...f, scopeReason: 'excluded' }); continue; }
    if (exact.has(normalizeAsset(host))) { out.inScope.push(f); continue; }
    if (wildcards.some((w) => globMatch(w.asset, host))) { out.inScope.push(f); continue; }
    out.outOfScope.push({ ...f, scopeReason: 'no-match' });
  }
  return out;
}

function hostOf(f) {
  const cand = f.evidence?.target || f.evidence?.host || f.evidence?.url || f.target || null;
  if (!cand) return null;
  try { return new URL(cand.startsWith('http') ? cand : `https://${cand}`).hostname; }
  catch { return String(cand).split('/')[0]; }
}

function normalizeAsset(s) {
  return String(s || '').replace(/^https?:\/\//, '').replace(/\/$/, '').toLowerCase();
}

function matchesAny(host, patterns) {
  return patterns.some((p) => globMatch(p, host));
}

function globMatch(pattern, host) {
  if (!pattern) return false;
  pattern = normalizeAsset(pattern);
  if (pattern === host) return true;
  if (pattern.startsWith('*.')) {
    const tail = pattern.slice(2);
    return host === tail || host.endsWith(`.${tail}`);
  }
  if (pattern.includes('*')) {
    const re = new RegExp('^' + pattern.replace(/[.+?^${}()|[\]\\]/g, '\\$&').replace(/\*/g, '.*') + '$');
    return re.test(host);
  }
  return false;
}

// ============================================================================
// Dedupe local — armazena hashes de findings já reportados
// ============================================================================

export function fingerprintFinding(f) {
  const key = [
    String(f.category || '').toLowerCase(),
    hostOf(f) || '',
    String(f.title || '').toLowerCase().replace(/\s+/g, ' ').trim(),
  ].join('::');
  return crypto.createHash('sha1').update(key).digest('hex').slice(0, 16);
}

async function loadIndex() {
  await ensureDir();
  const fp = path.join(dir(), 'submitted.json');
  try { return JSON.parse(await fs.readFile(fp, 'utf8')); }
  catch { return { entries: [] }; }
}

async function saveIndex(idx) {
  await ensureDir();
  const fp = path.join(dir(), 'submitted.json');
  const tmp = `${fp}.tmp.${process.pid}`;
  await fs.writeFile(tmp, JSON.stringify(idx, null, 2), 'utf8');
  await fs.rename(tmp, fp);
}

export async function recordSubmission({ finding, platform, reportId = null, payout = null, status = 'submitted' }) {
  const idx = await loadIndex();
  idx.entries.push({
    fp: fingerprintFinding(finding),
    title: finding.title, category: finding.category, host: hostOf(finding),
    platform, reportId, payout, status, at: new Date().toISOString(),
  });
  await saveIndex(idx);
  return idx.entries[idx.entries.length - 1];
}

export async function listSubmissions() {
  const idx = await loadIndex();
  return idx.entries;
}

export async function dedupeFindings(findings = []) {
  const idx = await loadIndex();
  const known = new Set(idx.entries.map((e) => e.fp));
  const seen = new Set();
  const out = { fresh: [], duplicate: [] };
  for (const f of findings) {
    const fp = fingerprintFinding(f);
    if (known.has(fp) || seen.has(fp)) out.duplicate.push({ ...f, fp });
    else { seen.add(fp); out.fresh.push({ ...f, fp }); }
  }
  return out;
}
