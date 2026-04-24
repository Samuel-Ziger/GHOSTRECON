/**
 * Ecosystem export — Obsidian vault + normalized SIEM/team-server payload.
 *
 * Obsidian: markdown com YAML frontmatter (engagement, target, tags, date)
 * + wikilinks por finding para atravessar uma campanha inteira como graph.
 *
 * SIEM payload: schema fixo, estável, serializável — pensado para agregação
 * cross-operator num team server.
 */

const SEV_NUM = { info: 0, low: 1, medium: 2, high: 3, critical: 4 };

function slug(s) {
  return String(s || '').toLowerCase()
    .normalize('NFKD').replace(/[\u0300-\u036f]/g, '')
    .replace(/[^a-z0-9._-]+/g, '-')
    .replace(/^-+|-+$/g, '')
    .slice(0, 80) || 'x';
}

/**
 * Export Obsidian: retorna `{ files: [{path, content}] }` — vault recebe como unzip.
 *
 * Layout:
 *   <vault>/
 *     engagements/<engagementId>/index.md
 *     engagements/<engagementId>/runs/run-<id>-<target>.md
 *     engagements/<engagementId>/findings/<target>-<slug>.md
 *     targets/<target>.md
 */
export function exportToObsidian({ engagement = null, runs = [], vaultRoot = 'ghostrecon' } = {}) {
  const files = [];
  const engId = engagement?.id || 'default';
  const base = `${vaultRoot}/engagements/${engId}`;
  const tagBase = `#ghostrecon/${slug(engId)}`;

  // index.md
  const idxLines = [];
  idxLines.push('---');
  idxLines.push(`engagement: ${engId}`);
  idxLines.push(`client: ${engagement?.client || ''}`);
  idxLines.push(`status: ${engagement?.status || 'active'}`);
  idxLines.push(`generated: ${new Date().toISOString()}`);
  idxLines.push('tags:');
  idxLines.push(`  - ghostrecon`);
  idxLines.push(`  - engagement/${slug(engId)}`);
  idxLines.push('---');
  idxLines.push('');
  idxLines.push(`# Engagement ${engId}`);
  idxLines.push('');
  if (engagement) {
    idxLines.push(`- **Cliente:** ${engagement.client || '-'}`);
    idxLines.push(`- **Janela:** ${engagement.window?.startsAt || '-'} → ${engagement.window?.endsAt || '-'}`);
    idxLines.push(`- **Scope:** ${(engagement.scopeDomains || []).map((x) => `\`${x}\``).join(', ') || '(vazio)'}`);
    idxLines.push(`- **ROE assinado:** ${engagement.roeSigned ? 'sim' : 'não'}`);
    idxLines.push('');
  }
  idxLines.push('## Runs');
  idxLines.push('');
  for (const r of runs) {
    idxLines.push(`- [[run-${r.id}-${slug(r.target)}|#${r.id} ${r.target}]] — findings: ${(r.findings || []).length}`);
  }
  idxLines.push('');
  idxLines.push('## Targets');
  const targetsSeen = new Set();
  for (const r of runs) {
    if (targetsSeen.has(r.target)) continue;
    targetsSeen.add(r.target);
    idxLines.push(`- [[${slug(r.target)}|${r.target}]]`);
  }
  files.push({ path: `${base}/index.md`, content: idxLines.join('\n') });

  // Runs + findings
  for (const run of runs) {
    const runSlug = `run-${run.id}-${slug(run.target)}`;
    const rLines = [];
    rLines.push('---');
    rLines.push(`run_id: ${run.id}`);
    rLines.push(`target: ${run.target}`);
    rLines.push(`engagement: ${engId}`);
    rLines.push(`at: ${run.createdAt || new Date().toISOString()}`);
    rLines.push('tags:');
    rLines.push(`  - ghostrecon/run`);
    rLines.push(`  - engagement/${slug(engId)}`);
    rLines.push(`  - target/${slug(run.target)}`);
    rLines.push('---');
    rLines.push('');
    rLines.push(`# Run #${run.id} — ${run.target}`);
    rLines.push('');
    rLines.push(`Engagement: [[index|${engId}]] · Target: [[${slug(run.target)}|${run.target}]]`);
    rLines.push('');
    rLines.push(`## Findings (${(run.findings || []).length})`);
    const sorted = [...(run.findings || [])].sort((a, b) => (SEV_NUM[b.severity?.toLowerCase()] ?? 0) - (SEV_NUM[a.severity?.toLowerCase()] ?? 0));
    for (const f of sorted) {
      const fslug = `${slug(run.target)}-${slug(f.title || f.category || 'finding')}-${slug(f.severity || 'info')}`;
      rLines.push(`- [[${fslug}|[${(f.severity || 'info').toUpperCase()}] ${f.title || f.category}]]`);
      files.push({ path: `${base}/findings/${fslug}.md`, content: findingToMarkdown(f, run, engId, tagBase) });
    }
    files.push({ path: `${base}/runs/${runSlug}.md`, content: rLines.join('\n') });
  }

  // Targets (nota agregadora)
  for (const target of targetsSeen) {
    const lines = [];
    lines.push('---');
    lines.push(`target: ${target}`);
    lines.push('tags:');
    lines.push(`  - ghostrecon/target`);
    lines.push(`  - target/${slug(target)}`);
    lines.push('---');
    lines.push('');
    lines.push(`# ${target}`);
    lines.push('');
    lines.push('## Runs');
    for (const r of runs) {
      if (r.target !== target) continue;
      lines.push(`- [[run-${r.id}-${slug(r.target)}|#${r.id}]] em ${r.createdAt || '-'}`);
    }
    files.push({ path: `${vaultRoot}/targets/${slug(target)}.md`, content: lines.join('\n') });
  }

  return { files };
}

function findingToMarkdown(f, run, engId, tagBase) {
  const lines = [];
  lines.push('---');
  lines.push(`run_id: ${run.id}`);
  lines.push(`target: ${run.target}`);
  lines.push(`engagement: ${engId}`);
  lines.push(`severity: ${String(f.severity || 'info').toLowerCase()}`);
  if (f.category) lines.push(`category: ${f.category}`);
  if (f.owasp) lines.push(`owasp: ${[].concat(f.owasp).join(', ')}`);
  if (f.mitre) lines.push(`mitre: ${[].concat(f.mitre).join(', ')}`);
  if (f.cve) lines.push(`cve: ${[].concat(f.cve).join(', ')}`);
  lines.push('tags:');
  lines.push(`  - ghostrecon/finding`);
  lines.push(`  - severity/${String(f.severity || 'info').toLowerCase()}`);
  if (f.category) lines.push(`  - category/${slug(f.category)}`);
  lines.push('---');
  lines.push('');
  lines.push(`# [${(f.severity || 'info').toUpperCase()}] ${f.title || f.category || 'finding'}`);
  lines.push('');
  lines.push(`Run: [[run-${run.id}-${slug(run.target)}|#${run.id}]] · Target: [[${slug(run.target)}|${run.target}]]`);
  lines.push('');
  if (f.description || f.detail) { lines.push('## Descrição'); lines.push(''); lines.push(String(f.description || f.detail)); lines.push(''); }
  if (f.evidence) {
    lines.push('## Evidência');
    lines.push('```json');
    lines.push(JSON.stringify(f.evidence, null, 2));
    lines.push('```');
  }
  return lines.join('\n');
}

// ============================================================================
// Normalized SIEM / team-server payload
// ============================================================================

/**
 * Schema v1 — fixo, estável. Consumidor (team server) pode tipar contra ele.
 */
export function normalizeRunForSiem(run, { engagement = null, operator = null } = {}) {
  const at = run.createdAt || new Date().toISOString();
  return {
    schema: 'ghostrecon.run.v1',
    at,
    engagement: engagement ? {
      id: engagement.id, client: engagement.client || null, status: engagement.status || 'active',
    } : null,
    operator: operator || null,
    run: {
      id: run.id, target: run.target, createdAt: at,
      modules: Array.isArray(run.modules) ? [...run.modules] : [],
      durationMs: run.durationMs ?? null,
    },
    findings: (run.findings || []).map((f) => ({
      severity: String(f.severity || 'info').toLowerCase(),
      category: f.category || null,
      title: f.title || null,
      description: typeof f.description === 'string' ? f.description.slice(0, 2000) : null,
      owasp: toArray(f.owasp),
      mitre: toArray(f.mitre || f.mitreTechnique),
      cve: toArray(f.cve),
      evidence: {
        target: f.evidence?.target || run.target,
        url: f.evidence?.url || null,
        host: f.evidence?.host || null,
        ip: f.evidence?.ip || null,
      },
      signature: signatureOf(f),
    })),
    summary: summarize(run),
  };
}

function toArray(x) {
  if (!x) return [];
  return Array.isArray(x) ? [...x] : [String(x)];
}

function signatureOf(f) {
  // Hash estável para dedupe cross-run
  const base = `${String(f.severity || '').toLowerCase()}|${f.category || ''}|${f.title || ''}|${f.evidence?.target || ''}|${f.evidence?.url || ''}`;
  let h = 5381;
  for (let i = 0; i < base.length; i++) h = ((h << 5) + h + base.charCodeAt(i)) | 0;
  return `sig-${(h >>> 0).toString(16)}`;
}

function summarize(run) {
  const bySev = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  for (const f of run.findings || []) {
    const k = String(f.severity || 'info').toLowerCase();
    if (bySev[k] != null) bySev[k]++;
  }
  return { total: (run.findings || []).length, bySeverity: bySev };
}

// ============================================================================
// Inbound normalizers: naabu, httpx, ffuf
// ============================================================================

/**
 * naabu stdout (JSON per line): { ip, port, host, timestamp }
 * → finding open-port info/low
 */
export function normalizeNaabu(line) {
  const obj = typeof line === 'string' ? tryJson(line) : line;
  if (!obj || !obj.host || !obj.port) return null;
  return {
    source: 'naabu',
    severity: 'info',
    category: 'open-port',
    title: `Porta aberta ${obj.port}/tcp em ${obj.host}`,
    description: `naabu detectou porta ${obj.port} aberta.`,
    evidence: { target: obj.host, ip: obj.ip || null, port: obj.port, at: obj.timestamp || null },
  };
}

/**
 * httpx JSON: { url, status_code, title, tech, webserver, content_length, final_url }
 * → finding http-surface info/low/medium (se status=200 em endpoint sensível)
 */
export function normalizeHttpx(line) {
  const obj = typeof line === 'string' ? tryJson(line) : line;
  if (!obj || !obj.url) return null;
  const code = obj.status_code || obj.status || 0;
  const isInteresting = /admin|login|config|\.env|backup|debug|graphql/i.test(obj.url || '');
  const sev = isInteresting && code >= 200 && code < 400 ? 'medium' : 'info';
  return {
    source: 'httpx',
    severity: sev,
    category: 'http-surface',
    title: `${code} ${obj.title || obj.webserver || 'HTTP'} em ${obj.url}`,
    description: `httpx probe: ${code} · tech=${(obj.tech || obj.technologies || []).join?.(', ') || '-'}`,
    evidence: {
      target: tryHost(obj.url),
      url: obj.url,
      finalUrl: obj.final_url || null,
      statusCode: code,
      title: obj.title || null,
      tech: obj.tech || obj.technologies || [],
    },
  };
}

/**
 * ffuf result JSON: { url, status, length, words, lines, input }
 * → finding content-discovery low/medium dependendo do path.
 */
export function normalizeFfuf(line) {
  const obj = typeof line === 'string' ? tryJson(line) : line;
  if (!obj || !obj.url) return null;
  const code = obj.status || 0;
  const path = String(obj.url || '');
  const hot = /\.env|\.git|\.svn|backup|admin|config|\.sql|\.bak|dump|phpmyadmin|\.htpasswd/i.test(path);
  const sev = hot && code >= 200 && code < 400 ? 'high' : (code === 200 ? 'low' : 'info');
  return {
    source: 'ffuf',
    severity: sev,
    category: 'content-discovery',
    title: `${code} em ${path}`,
    description: `ffuf hit · len=${obj.length || '-'} · words=${obj.words || '-'}`,
    evidence: { target: tryHost(path), url: path, statusCode: code, length: obj.length || null },
  };
}

function tryJson(s) {
  try { return JSON.parse(s); } catch { return null; }
}
function tryHost(u) {
  try { return new URL(u).hostname; } catch { return null; }
}

/**
 * Dispatcher conveniente: detecta source a partir do shape do objeto.
 */
export function normalizeAuto(line) {
  const obj = typeof line === 'string' ? tryJson(line) : line;
  if (!obj) return null;
  if (obj.ip && obj.port && (obj.host || obj.ip)) return normalizeNaabu(obj);
  if (obj.url && (obj.status_code || obj.webserver || obj.tech || obj.technologies)) return normalizeHttpx(obj);
  if (obj.url && (obj.input || obj.words) && obj.status != null) return normalizeFfuf(obj);
  return null;
}
