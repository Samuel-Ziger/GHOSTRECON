/**
 * Workflow export — converte findings de um run em issues para Linear/Jira/GitHub
 * ou Markdown (para colar em HackerOne/Bugcrowd/Intigriti).
 *
 * Cada issue inclui:
 *   - título com severidade e categoria
 *   - severidade (label/prioridade)
 *   - OWASP / MITRE tags se presentes no finding
 *   - link para o run no Reporter (se GHOSTRECON_REPORTER_BASE definido)
 *   - bloco reproduzível: host, URL, evidência
 */

import https from 'node:https';
import http from 'node:http';

const SEV_ORDER = { info: 0, low: 1, medium: 2, high: 3, critical: 4 };
function sev(s) { return SEV_ORDER[String(s || '').toLowerCase()] ?? 0; }

function reporterLink(runId) {
  const base = (process.env.GHOSTRECON_REPORTER_BASE || '').replace(/\/+$/, '');
  if (!base || runId == null) return null;
  return `${base}/reporte.html?run=${encodeURIComponent(runId)}`;
}

function filterBySeverity(findings, minSeverity) {
  const floor = sev(minSeverity);
  return (findings || []).filter((f) => sev(f.severity) >= floor);
}

function severityLabel(s) { return String(s || 'info').toLowerCase(); }

function buildIssueBody(run, f) {
  const lines = [];
  lines.push(`**Severidade:** ${severityLabel(f.severity)}`);
  if (f.category) lines.push(`**Categoria:** ${f.category}`);
  if (f.owasp) lines.push(`**OWASP:** ${Array.isArray(f.owasp) ? f.owasp.join(', ') : f.owasp}`);
  if (f.mitre || f.mitreTactic) lines.push(`**MITRE:** ${f.mitre || f.mitreTactic}`);
  if (f.cve) lines.push(`**CVE:** ${Array.isArray(f.cve) ? f.cve.join(', ') : f.cve}`);
  const evidence = f.evidence || {};
  if (evidence.target || evidence.host) lines.push(`**Alvo:** \`${evidence.target || evidence.host}\``);
  if (evidence.url) lines.push(`**URL:** ${evidence.url}`);
  if (f.description || f.detail) lines.push('', String(f.description || f.detail).slice(0, 4000));
  if (evidence.snippet) lines.push('', '```', String(evidence.snippet).slice(0, 2000), '```');
  if (evidence.request) lines.push('', '**Request:**', '```http', String(evidence.request).slice(0, 2000), '```');
  if (evidence.response) lines.push('', '**Response:**', '```http', String(evidence.response).slice(0, 2000), '```');
  if (evidence.screenshot) lines.push('', `Screenshot: ${evidence.screenshot}`);

  lines.push('', '---');
  lines.push(`Run: #${run.id} · Target: \`${run.target}\` · Gerado por GHOSTRECON`);
  const rep = reporterLink(run.id);
  if (rep) lines.push(`Reporter: ${rep}`);
  return lines.join('\n');
}

function buildIssueTitle(run, f) {
  const sevTag = severityLabel(f.severity).toUpperCase();
  const cat = f.category || f.type || 'finding';
  const host = f.evidence?.target || f.evidence?.host || run.target;
  const title = f.title || `${cat} em ${host}`;
  return `[${sevTag}] ${title}`.slice(0, 180);
}

// ==========================================================================
// Markdown (local / HackerOne-ready)
// ==========================================================================
export function exportToMarkdown(run, { minSeverity = 'medium' } = {}) {
  const findings = filterBySeverity(run.findings, minSeverity);
  const out = [];
  out.push(`# GHOSTRECON report — ${run.target} (run #${run.id})`);
  out.push('');
  out.push(`Geração: ${new Date().toISOString()} · findings ≥ ${minSeverity}: **${findings.length}**`);
  const rep = reporterLink(run.id);
  if (rep) out.push(`Reporter: ${rep}`);
  out.push('');
  for (const f of findings) {
    out.push(`## ${buildIssueTitle(run, f)}`);
    out.push('');
    out.push(buildIssueBody(run, f));
    out.push('');
  }
  return out.join('\n');
}

// ==========================================================================
// GitHub Issues
// ==========================================================================
export async function exportToGithubIssues(run, { repo, token, minSeverity = 'medium', labels = [], dryRun = false }) {
  const findings = filterBySeverity(run.findings, minSeverity);
  const result = { created: [], skipped: [], errors: [], dryRun, preview: [] };
  for (const f of findings) {
    const issue = {
      title: buildIssueTitle(run, f),
      body: buildIssueBody(run, f),
      labels: uniqueStrings([...labels, `severity:${severityLabel(f.severity)}`, 'ghostrecon']),
    };
    if (dryRun) {
      result.preview.push({ repo, ...issue });
      continue;
    }
    try {
      const res = await jsonRequest(`https://api.github.com/repos/${repo}/issues`, {
        method: 'POST',
        headers: {
          authorization: `token ${token}`,
          accept: 'application/vnd.github+json',
          'user-agent': 'GHOSTRECON-export/1.0',
        },
        body: issue,
      });
      if (res.ok) {
        result.created.push({ number: res.body?.number, url: res.body?.html_url });
      } else {
        result.errors.push({ status: res.statusCode, body: res.body, title: issue.title });
      }
    } catch (e) {
      result.errors.push({ error: e.message, title: issue.title });
    }
  }
  return result;
}

// ==========================================================================
// Linear (GraphQL)
// ==========================================================================
export async function exportToLinear(run, { teamId, token, minSeverity = 'medium', dryRun = false }) {
  const findings = filterBySeverity(run.findings, minSeverity);
  const result = { created: [], skipped: [], errors: [], dryRun, preview: [] };
  for (const f of findings) {
    const title = buildIssueTitle(run, f);
    const description = buildIssueBody(run, f);
    const priorityMap = { critical: 1, high: 2, medium: 3, low: 4, info: 0 };
    const priority = priorityMap[severityLabel(f.severity)] ?? 3;
    const mutation = `
      mutation IssueCreate($input: IssueCreateInput!) {
        issueCreate(input: $input) { success issue { id identifier url } }
      }`;
    const variables = { input: { teamId, title, description, priority } };
    if (dryRun) { result.preview.push({ teamId, title, priority }); continue; }
    try {
      const res = await jsonRequest('https://api.linear.app/graphql', {
        method: 'POST',
        headers: { authorization: token, 'content-type': 'application/json' },
        body: { query: mutation, variables },
      });
      const issue = res.body?.data?.issueCreate?.issue;
      if (res.ok && issue) result.created.push({ id: issue.id, identifier: issue.identifier, url: issue.url });
      else result.errors.push({ status: res.statusCode, body: res.body, title });
    } catch (e) {
      result.errors.push({ error: e.message, title });
    }
  }
  return result;
}

// ==========================================================================
// Jira Cloud (REST v3)
// ==========================================================================
export async function exportToJira(run, { baseUrl, project, user, token, minSeverity = 'medium', dryRun = false }) {
  const findings = filterBySeverity(run.findings, minSeverity);
  const result = { created: [], skipped: [], errors: [], dryRun, preview: [] };
  const auth = `Basic ${Buffer.from(`${user}:${token}`).toString('base64')}`;
  for (const f of findings) {
    const title = buildIssueTitle(run, f);
    const description = buildIssueBody(run, f);
    const priorityMap = { critical: 'Highest', high: 'High', medium: 'Medium', low: 'Low', info: 'Lowest' };
    const priority = priorityMap[severityLabel(f.severity)] || 'Medium';
    const body = {
      fields: {
        project: { key: project },
        summary: title,
        description,
        issuetype: { name: 'Bug' },
        priority: { name: priority },
        labels: [`severity-${severityLabel(f.severity)}`, 'ghostrecon'],
      },
    };
    if (dryRun) { result.preview.push(body); continue; }
    try {
      const url = `${String(baseUrl).replace(/\/+$/, '')}/rest/api/3/issue`;
      const res = await jsonRequest(url, {
        method: 'POST',
        headers: { authorization: auth, accept: 'application/json' },
        body,
      });
      if (res.ok) result.created.push({ key: res.body?.key, url: `${baseUrl.replace(/\/+$/, '')}/browse/${res.body?.key}` });
      else result.errors.push({ status: res.statusCode, body: res.body, title });
    } catch (e) {
      result.errors.push({ error: e.message, title });
    }
  }
  return result;
}

// ==========================================================================
// HTTP helper
// ==========================================================================
function jsonRequest(urlStr, { method = 'GET', headers = {}, body = null, timeoutMs = 20_000 } = {}) {
  const url = new URL(urlStr);
  const mod = url.protocol === 'https:' ? https : http;
  const payload = body ? Buffer.from(JSON.stringify(body), 'utf8') : null;
  const finalHeaders = {
    'content-type': 'application/json; charset=utf-8',
    accept: 'application/json',
    'user-agent': 'GHOSTRECON-export/1.0',
    ...headers,
  };
  if (payload) finalHeaders['content-length'] = String(payload.length);
  return new Promise((resolve, reject) => {
    const req = mod.request(
      {
        method,
        hostname: url.hostname,
        port: url.port || (url.protocol === 'https:' ? 443 : 80),
        path: url.pathname + url.search,
        headers: finalHeaders,
      },
      (res) => {
        let buf = '';
        res.setEncoding('utf8');
        res.on('data', (c) => (buf += c));
        res.on('end', () => {
          let parsed = buf;
          try { parsed = JSON.parse(buf); } catch { /* keep raw */ }
          resolve({
            ok: res.statusCode >= 200 && res.statusCode < 300,
            statusCode: res.statusCode,
            body: parsed,
          });
        });
        res.on('error', reject);
      },
    );
    req.setTimeout(timeoutMs, () => req.destroy(new Error(`HTTP timeout > ${timeoutMs}ms`)));
    req.on('error', reject);
    if (payload) req.write(payload);
    req.end();
  });
}

function uniqueStrings(arr) {
  const seen = new Set();
  const out = [];
  for (const x of arr) {
    const s = String(x || '').trim();
    if (!s || seen.has(s)) continue;
    seen.add(s);
    out.push(s);
  }
  return out;
}
