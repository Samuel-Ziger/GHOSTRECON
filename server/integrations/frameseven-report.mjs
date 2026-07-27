import fs from 'node:fs/promises';
import { constants as fsConstants } from 'node:fs';
import { randomUUID } from 'node:crypto';
import path from 'node:path';

import { redactAutoText, redactAutoValue } from '../auto-agent/redaction.mjs';

const DEFAULT_MAX_REPORT_BYTES = 16 * 1024 * 1024;
const MAX_FINDINGS = 10_000;
const MAX_VALUE_LENGTH = 16_384;
const MAX_URL_LENGTH = 4_096;
const MAX_EVIDENCE_LENGTH = 16_384;
const MAX_EVIDENCE_REQUEST_LENGTH = 4_096;
const MAX_EVIDENCE_RESPONSE_LENGTH = 8_192;
const MAX_EVIDENCE_EXTRACTED_LENGTH = 4_096;
const MAX_EVIDENCE_ITEMS = 8;
const MAX_SOURCES = 24;
const DEFAULT_MAX_PUBLIC_REPORT_BYTES = 32 * 1024 * 1024;
const PUBLIC_REPORT_PHYSICAL_FILES = Object.freeze({
  'report.html': 'public-report.html',
  'report.json': 'public-report.json',
  'report.md': 'public-report.md',
});
const REPORT_ACCESS_FILE = 'report-access.json';

function boundedByteLimit(value, fallback = DEFAULT_MAX_REPORT_BYTES) {
  const parsed = Number(value);
  if (!Number.isFinite(parsed) || parsed < 1) return fallback;
  return Math.min(100 * 1024 * 1024, Math.floor(parsed));
}

function sameOpenedFile(left, right) {
  return left.dev === right.dev
    && left.ino === right.ino
    && left.size === right.size
    && left.mtimeMs === right.mtimeMs;
}

/**
 * Opens a final path with O_NOFOLLOW and validates/reads through that same
 * descriptor. This avoids the lstat/realpath -> readFile race.
 */
export async function openFrameSevenRegularFile(filePath, {
  maxBytes = DEFAULT_MAX_REPORT_BYTES,
} = {}) {
  const resolved = path.resolve(String(filePath || ''));
  const limit = boundedByteLimit(maxBytes);
  const noFollow = Number(fsConstants.O_NOFOLLOW || 0);
  let handle;
  try {
    handle = await fs.open(resolved, fsConstants.O_RDONLY | noFollow);
    const stat = await handle.stat();
    if (!stat.isFile() || stat.size < 0 || stat.size > limit) {
      throw new Error('FrameSeven file is invalid or exceeds the size limit');
    }
    return {
      path: resolved,
      handle,
      stat,
      size: stat.size,
      maxBytes: limit,
    };
  } catch (error) {
    await handle?.close().catch(() => {});
    throw error;
  }
}

export async function readFrameSevenRegularFile(filePath, {
  maxBytes = DEFAULT_MAX_REPORT_BYTES,
  encoding = null,
} = {}) {
  const opened = await openFrameSevenRegularFile(filePath, { maxBytes });
  try {
    const value = await opened.handle.readFile(encoding ? { encoding } : undefined);
    const after = await opened.handle.stat();
    if (!sameOpenedFile(opened.stat, after)) {
      throw new Error('FrameSeven file changed while it was being read');
    }
    const bytes = Buffer.isBuffer(value) ? value.byteLength : Buffer.byteLength(value, encoding || 'utf8');
    if (bytes > opened.maxBytes) throw new Error('FrameSeven file exceeds the size limit');
    return value;
  } finally {
    await opened.handle.close().catch(() => {});
  }
}

async function assertSafeOutputDirectory(outputDir) {
  const resolved = path.resolve(String(outputDir || ''));
  const stat = await fs.lstat(resolved);
  if (!stat.isDirectory() || stat.isSymbolicLink()) {
    throw new Error('FrameSeven output directory is invalid');
  }
  return resolved;
}

async function atomicRestrictedWrite(directory, fileName, data) {
  const dir = await assertSafeOutputDirectory(directory);
  const destination = path.join(dir, fileName);
  const temporary = path.join(dir, `.${fileName}.${process.pid}.${randomUUID()}.tmp`);
  let handle;
  try {
    handle = await fs.open(temporary, 'wx', 0o600);
    await handle.writeFile(data);
    await handle.sync();
    await handle.close();
    handle = null;
    await fs.rename(temporary, destination);
    if (process.platform !== 'win32') await fs.chmod(destination, 0o600);
    return destination;
  } finally {
    await handle?.close().catch(() => {});
    await fs.rm(temporary, { force: true }).catch(() => {});
  }
}

function normalizedAccessTarget(value) {
  const parsed = parsedHttpUrl(value);
  if (!parsed) throw new Error('FrameSeven report access target is invalid');
  parsed.search = '';
  parsed.hash = '';
  return {
    target: parsed.toString(),
    origin: parsed.origin,
  };
}

export async function writeFrameSevenReportAccessMetadata({
  outputDir,
  ownerSub = null,
  engagementId = null,
  target,
  authenticated = false,
  privateReport = authenticated === true,
  createdAt = new Date().toISOString(),
} = {}) {
  const targetData = normalizedAccessTarget(target);
  const metadata = {
    schemaVersion: 1,
    ownerSub: limitedText(ownerSub, 256) || null,
    engagementId: limitedText(engagementId, 256) || null,
    ...targetData,
    authenticated: authenticated === true,
    private: privateReport === true || authenticated === true,
    createdAt: new Date(createdAt).toISOString(),
  };
  await atomicRestrictedWrite(outputDir, REPORT_ACCESS_FILE, `${JSON.stringify(metadata, null, 2)}\n`);
  return metadata;
}

export async function readFrameSevenReportAccessMetadata(outputDir, {
  maxBytes = 64 * 1024,
} = {}) {
  const source = await readFrameSevenRegularFile(
    path.join(path.resolve(String(outputDir || '')), REPORT_ACCESS_FILE),
    { maxBytes, encoding: 'utf8' },
  );
  const parsed = JSON.parse(source);
  if (
    parsed?.schemaVersion !== 1
    || typeof parsed.target !== 'string'
    || typeof parsed.origin !== 'string'
    || typeof parsed.authenticated !== 'boolean'
    || typeof parsed.private !== 'boolean'
    || !Number.isFinite(Date.parse(parsed.createdAt))
  ) {
    throw new Error('FrameSeven report access metadata is invalid');
  }
  const targetData = normalizedAccessTarget(parsed.target);
  if (targetData.origin !== parsed.origin) {
    throw new Error('FrameSeven report access metadata origin mismatch');
  }
  return {
    schemaVersion: 1,
    ownerSub: limitedText(parsed.ownerSub, 256) || null,
    engagementId: limitedText(parsed.engagementId, 256) || null,
    ...targetData,
    authenticated: parsed.authenticated,
    private: parsed.private,
    createdAt: new Date(parsed.createdAt).toISOString(),
  };
}

export function frameSevenPublicPhysicalFile(fileName) {
  return PUBLIC_REPORT_PHYSICAL_FILES[String(fileName || '').trim()] || null;
}

const SEVERITY_SCORE = Object.freeze({
  critical: 95,
  high: 82,
  medium: 62,
  low: 40,
  info: 20,
});

function limitedText(value, maxLength) {
  return redactAutoText(String(value ?? '')).slice(0, maxLength);
}

function normalizedSeverity(value) {
  const severity = String(value || '').trim().toLowerCase();
  if (severity === 'med') return 'medium';
  if (severity === 'informational') return 'info';
  return Object.hasOwn(SEVERITY_SCORE, severity) ? severity : 'info';
}

function normalizedType(value) {
  const type = String(value || 'frameseven')
    .trim()
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, '_')
    .replace(/^_+|_+$/g, '')
    .slice(0, 96);
  return type || 'frameseven';
}

function boundedScore(value, severity) {
  const score = Number(value);
  if (!Number.isFinite(score)) return SEVERITY_SCORE[severity];
  return Math.max(0, Math.min(100, Math.round(score)));
}

function parsedHttpUrl(value, base = null) {
  try {
    const parsed = base ? new URL(String(value || ''), base) : new URL(String(value || ''));
    if (!['http:', 'https:'].includes(parsed.protocol)) return null;
    if (parsed.username || parsed.password) return null;
    return parsed;
  } catch {
    return null;
  }
}

function sameOriginOrEmpty(value, target) {
  const candidate = String(value ?? '').trim();
  if (!candidate) return '';
  const expected = target ? parsedHttpUrl(target) : null;
  const parsed = parsedHttpUrl(candidate, expected || undefined);
  if (!parsed || (target && !expected)) return '';
  if (expected && parsed.origin !== expected.origin) return '';
  return limitedText(parsed.toString(), MAX_URL_LENGTH);
}

function requestEndpoint(request, target) {
  const firstLine = String(request || '').split(/\r?\n/, 1)[0]?.trim() || '';
  const match = firstLine.match(/^[A-Z]+\s+(\S+)\s+HTTP\/\d(?:\.\d)?$/i);
  if (!match || match[1] === '*') return '';
  if (!match[1].startsWith('/') && !/^https?:\/\//i.test(match[1])) return '';
  return sameOriginOrEmpty(match[1], target);
}

function normalizeEvidence(rawEvidence) {
  if (rawEvidence == null) {
    return { request: '', response: '', extracted: '' };
  }
  if (typeof rawEvidence === 'string') {
    return {
      request: '',
      response: '',
      extracted: limitedText(rawEvidence, MAX_EVIDENCE_EXTRACTED_LENGTH),
    };
  }
  if (typeof rawEvidence !== 'object' || Array.isArray(rawEvidence)) {
    return { request: '', response: '', extracted: '' };
  }
  return {
    request: limitedText(rawEvidence.request, MAX_EVIDENCE_REQUEST_LENGTH),
    response: limitedText(rawEvidence.response, MAX_EVIDENCE_RESPONSE_LENGTH),
    extracted: limitedText(rawEvidence.extracted, MAX_EVIDENCE_EXTRACTED_LENGTH),
  };
}

function evidenceSummary(evidence) {
  return [
    evidence.request ? `request:\n${evidence.request}` : '',
    evidence.response ? `response:\n${evidence.response}` : '',
    evidence.extracted ? `extracted:\n${evidence.extracted}` : '',
  ].filter(Boolean).join('\n\n').slice(0, MAX_EVIDENCE_LENGTH);
}

function normalizedStringArray(value, { maxItems = 64, maxLength = 2_048 } = {}) {
  if (!Array.isArray(value)) return [];
  return value
    .slice(0, maxItems)
    .map((item) => limitedText(item, maxLength))
    .filter(Boolean);
}

function normalizedReportEndpoints(report, target) {
  const candidates = [
    ...(Array.isArray(report?.surface?.endpoints) ? report.surface.endpoints : []),
    ...(Array.isArray(report?.surface?.params)
      ? report.surface.params.map((item) => item?.endpoint)
      : []),
    ...(Array.isArray(report?.surface?.sensitive_files) ? report.surface.sensitive_files : []),
  ];
  return [...new Set(candidates
    .map((value) => sameOriginOrEmpty(value, target))
    .filter(Boolean))].slice(0, MAX_FINDINGS);
}

export function normalizeFrameSevenFinding(finding, {
  target = '',
} = {}) {
  if (!finding || typeof finding !== 'object' || Array.isArray(finding)) return null;
  const moduleId = normalizedType(finding.module || finding.moduleId || finding.type);
  const severity = normalizedSeverity(finding.severity || finding.prio);
  const evidenceDetails = normalizeEvidence(finding.evidence);
  const value = limitedText(
    finding.title
      || finding.value
      || finding.description
      || evidenceDetails.extracted
      || `${moduleId} finding`,
    MAX_VALUE_LENGTH,
  );
  if (!value) return null;
  const description = limitedText(finding.description, MAX_EVIDENCE_LENGTH);
  const evidence = evidenceSummary(evidenceDetails);
  const explicitUrl = sameOriginOrEmpty(finding.endpoint || finding.url, target);
  const url = explicitUrl || requestEndpoint(evidenceDetails.request, target);
  const nextSteps = normalizedStringArray(finding.next_steps || finding.nextSteps);
  const owasp = limitedText(finding.owasp, 512);
  const cwe = limitedText(finding.cwe, 128);
  const cvss = Number(finding.cvss);
  const confidence = Number(finding.confidence);

  return {
    type: moduleId,
    prio: severity,
    score: boundedScore(finding.score ?? (Number.isFinite(cvss) ? cvss * 10 : null), severity),
    value,
    url,
    description,
    evidence,
    meta: {
      source: 'frameseven',
      reportSchema: 'v1',
      moduleId,
      ...(owasp ? { owasp } : {}),
      ...(cwe ? { cwe } : {}),
      ...(Number.isFinite(cvss) ? { cvss } : {}),
      ...(Number.isFinite(confidence) ? { confidence: Math.max(0, Math.min(1, confidence)) } : {}),
      ...(nextSteps.length ? { nextSteps } : {}),
      evidence: evidence ? [evidenceDetails] : [],
      sources: [{ engine: 'frameseven', moduleId }],
    },
    provenance: {
      how: `FrameSeven CLI v1 (${moduleId})`,
      relation: url ? 'same-origin request evidence' : 'same-origin scan report',
    },
    sourceEngine: 'frameseven',
    moduleId,
  };
}

export function normalizeFrameSevenReport(report, { target = '' } = {}) {
  if (!report || typeof report !== 'object' || Array.isArray(report)) {
    throw new Error('FrameSeven report must be a JSON object');
  }
  if (report.findings != null && !Array.isArray(report.findings)) {
    throw new Error('FrameSeven report findings must be an array');
  }
  if (report.errors != null && !Array.isArray(report.errors)) {
    throw new Error('FrameSeven report errors must be an array');
  }
  if (report.schema_version !== 'v1') {
    throw new Error('FrameSeven report schema_version must be v1');
  }
  const requestedTarget = sameOriginOrEmpty(target, target);
  if (target && !requestedTarget) {
    throw new Error('FrameSeven target must be an HTTP(S) URL without userinfo');
  }
  const reportTarget = sameOriginOrEmpty(report.target || requestedTarget, requestedTarget);
  if (report.target && !reportTarget) {
    throw new Error('FrameSeven report target does not match the requested origin');
  }
  const effectiveTarget = reportTarget || requestedTarget;
  const endpoints = normalizedReportEndpoints(report, effectiveTarget);
  const findings = (report.findings || [])
    .slice(0, MAX_FINDINGS)
    .map((finding) => normalizeFrameSevenFinding(finding, {
      target: effectiveTarget,
    }))
    .filter(Boolean);
  return {
    schemaVersion: 'v1',
    target: effectiveTarget,
    endpoints,
    findings,
    errors: Array.isArray(report.errors)
      ? report.errors.slice(0, 1_000).map((error) => ({
          module: normalizedType(error?.module),
          message: limitedText(error?.message, 2_048),
        }))
      : [],
    truncated: (report.findings?.length || 0) > MAX_FINDINGS,
  };
}

function familyFromUrl(urlLike) {
  try {
    const parsed = new URL(String(urlLike || ''));
    return `${parsed.pathname.toLowerCase()}?${[...new Set(
      [...parsed.searchParams.keys()].map((key) => key.toLowerCase()),
    )].sort().join(',')}`;
  } catch {
    return String(urlLike || '').toLowerCase().slice(0, 180);
  }
}

function findingFamilyKey(finding) {
  const type = normalizedType(finding?.type || finding?.moduleId);
  if (finding?.url) return `${type}:${familyFromUrl(finding.url)}`;
  return `${type}:${String(finding?.value || '').trim().toLowerCase().slice(0, 240)}`;
}

function uniqueObjects(items, maxItems) {
  const seen = new Set();
  const output = [];
  for (const item of items) {
    if (!item || typeof item !== 'object' || Array.isArray(item)) continue;
    const safe = redactAutoValue(item);
    const key = JSON.stringify(safe);
    if (seen.has(key)) continue;
    seen.add(key);
    output.push(safe);
    if (output.length >= maxItems) break;
  }
  return output;
}

function sourcesFor(finding) {
  const metaSources = finding?.meta && typeof finding.meta === 'object'
    ? finding.meta.sources
    : [];
  const direct = finding?.sourceEngine
    ? [{
        engine: normalizedType(finding.sourceEngine),
        moduleId: normalizedType(finding.moduleId || finding.type),
      }]
    : [];
  return uniqueObjects([...(Array.isArray(metaSources) ? metaSources : []), ...direct], MAX_SOURCES);
}

function evidenceFor(finding) {
  const structured = finding?.meta && typeof finding.meta === 'object'
    && Array.isArray(finding.meta.evidence)
    ? finding.meta.evidence
    : [];
  const legacy = structured.length === 0 && typeof finding?.evidence === 'string' && finding.evidence
    ? [{ extracted: limitedText(finding.evidence, MAX_EVIDENCE_EXTRACTED_LENGTH) }]
    : [];
  return uniqueObjects([...structured, ...legacy], MAX_EVIDENCE_ITEMS);
}

function mergeFindingEvidence(current, incoming) {
  const currentScore = Number(current?.compositeScore ?? current?.score ?? 0);
  const incomingScore = Number(incoming?.compositeScore ?? incoming?.score ?? 0);
  const best = incomingScore > currentScore ? incoming : current;
  const other = best === current ? incoming : current;
  const bestMeta = best?.meta && typeof best.meta === 'object' && !Array.isArray(best.meta)
    ? best.meta
    : {};
  const otherMeta = other?.meta && typeof other.meta === 'object' && !Array.isArray(other.meta)
    ? other.meta
    : {};
  const sources = uniqueObjects([...sourcesFor(current), ...sourcesFor(incoming)], MAX_SOURCES);
  const evidence = uniqueObjects([...evidenceFor(current), ...evidenceFor(incoming)], MAX_EVIDENCE_ITEMS);
  return {
    ...best,
    meta: {
      ...otherMeta,
      ...bestMeta,
      sources,
      evidence,
      ...(typeof current?.meta === 'string' || typeof incoming?.meta === 'string'
        ? {
            legacyMeta: [
              typeof current?.meta === 'string' ? limitedText(current.meta, 4_096) : '',
              typeof incoming?.meta === 'string' ? limitedText(incoming.meta, 4_096) : '',
            ].filter(Boolean),
          }
        : {}),
    },
    provenance: {
      how: sources.map((source) => `${source.engine}:${source.moduleId}`).join(', ').slice(0, 2_048),
      relation: 'semantic family with aggregated evidence',
    },
    evidence: evidence
      .map((item) => evidenceSummary(item))
      .filter(Boolean)
      .join('\n\n---\n\n')
      .slice(0, MAX_EVIDENCE_LENGTH),
  };
}

function mergeFindings(findings) {
  const buckets = new Map();
  const mergedFindings = [];
  let merged = 0;
  for (const finding of findings) {
    if (!finding || typeof finding !== 'object') continue;
    const key = findingFamilyKey(finding);
    const index = buckets.get(key);
    if (index == null) {
      buckets.set(key, mergedFindings.length);
      mergedFindings.push(finding);
      continue;
    }
    mergedFindings[index] = mergeFindingEvidence(mergedFindings[index], finding);
    merged += 1;
  }
  return { findings: mergedFindings, merged };
}

function publicFinding(finding) {
  const type = normalizedType(finding?.type || finding?.moduleId);
  const prio = normalizedSeverity(finding?.prio || finding?.severity);
  let publicUrl = '';
  const parsed = parsedHttpUrl(finding?.url);
  if (parsed) {
    parsed.search = '';
    parsed.hash = '';
    publicUrl = limitedText(parsed.toString(), MAX_URL_LENGTH);
  }
  return redactAutoValue({
    type,
    prio,
    score: boundedScore(finding?.score, prio),
    summary: `${type} (${prio})`,
    url: publicUrl,
    sourceEngine: normalizedType(finding?.sourceEngine || 'frameseven'),
    moduleId: normalizedType(finding?.moduleId || finding?.type),
  });
}

function escapeHtml(value) {
  return String(value ?? '')
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

function markdownText(value) {
  return String(value ?? '')
    .replace(/[\r\n]+/g, ' ')
    .replace(/\|/g, '\\|')
    .trim();
}

export async function writeFrameSevenPublicArtifacts({
  outputDir,
  target,
  findings = [],
  incomplete = false,
  createdAt = new Date().toISOString(),
} = {}) {
  const targetData = normalizedAccessTarget(target);
  const publicFindings = (Array.isArray(findings) ? findings : [])
    .slice(0, MAX_FINDINGS)
    .map(publicFinding);
  const document = {
    schemaVersion: 1,
    engine: 'frameseven',
    target: targetData.target,
    generatedAt: new Date(createdAt).toISOString(),
    incomplete: incomplete === true,
    findingCount: publicFindings.length,
    findings: publicFindings,
  };
  const json = `${JSON.stringify(document, null, 2)}\n`;
  const markdownRows = publicFindings.map((finding) => (
    `| ${markdownText(finding.prio)} | ${markdownText(finding.type)} | `
      + `${markdownText(finding.summary)} | ${markdownText(finding.url)} |`
  ));
  const markdown = [
    '# FrameSeven — relatório sanitizado',
    '',
    `Alvo: ${markdownText(document.target)}`,
    `Gerado em: ${markdownText(document.generatedAt)}`,
    `Achados: ${document.findingCount}`,
    '',
    '| Severidade | Tipo | Resumo | URL |',
    '| --- | --- | --- | --- |',
    ...markdownRows,
    '',
    '> Evidências brutas, cookies, cabeçalhos de autenticação e dados de sessão não são incluídos.',
    '',
  ].join('\n');
  const htmlRows = publicFindings.map((finding) => (
    '<tr>'
      + `<td>${escapeHtml(finding.prio)}</td>`
      + `<td>${escapeHtml(finding.type)}</td>`
      + `<td>${escapeHtml(finding.summary)}</td>`
      + `<td>${escapeHtml(finding.url)}</td>`
      + '</tr>'
  )).join('');
  const html = '<!doctype html><html lang="pt-BR"><head><meta charset="utf-8">'
    + '<meta name="referrer" content="no-referrer"><title>FrameSeven — relatório sanitizado</title>'
    + '<style>body{font-family:system-ui,sans-serif;margin:2rem;color:#18202a}'
    + 'table{border-collapse:collapse;width:100%}th,td{border:1px solid #ccd3da;padding:.5rem;text-align:left}'
    + 'th{background:#eef2f5}</style></head><body>'
    + '<h1>FrameSeven — relatório sanitizado</h1>'
    + `<p>Alvo: ${escapeHtml(document.target)}</p>`
    + `<p>Gerado em: ${escapeHtml(document.generatedAt)} · Achados: ${document.findingCount}</p>`
    + '<table><thead><tr><th>Severidade</th><th>Tipo</th><th>Resumo</th><th>URL</th></tr></thead>'
    + `<tbody>${htmlRows}</tbody></table>`
    + '<p>Evidências brutas e dados de sessão foram omitidos.</p></body></html>';

  const [jsonPath, markdownPath, htmlPath] = await Promise.all([
    atomicRestrictedWrite(outputDir, PUBLIC_REPORT_PHYSICAL_FILES['report.json'], json),
    atomicRestrictedWrite(outputDir, PUBLIC_REPORT_PHYSICAL_FILES['report.md'], markdown),
    atomicRestrictedWrite(outputDir, PUBLIC_REPORT_PHYSICAL_FILES['report.html'], html),
  ]);
  return {
    jsonPath,
    markdownPath,
    htmlPath,
    findingCount: publicFindings.length,
  };
}

export async function readAndMergeFrameSevenReport({
  outputDir,
  target = '',
  existingFindings = [],
  maxBytes = DEFAULT_MAX_REPORT_BYTES,
  accessMetadata = null,
} = {}) {
  const safeOutputDir = await assertSafeOutputDirectory(outputDir);
  const reportPath = path.join(safeOutputDir, 'report.json');
  let report;
  try {
    report = JSON.parse(await readFrameSevenRegularFile(reportPath, {
      maxBytes,
      encoding: 'utf8',
    }));
  } catch (error) {
    throw new Error(`FrameSeven report JSON is invalid: ${error?.message || String(error)}`);
  }

  const normalized = normalizeFrameSevenReport(report, { target });
  const baseline = mergeFindings(
    Array.isArray(existingFindings) ? existingFindings.filter(Boolean) : [],
  );
  const incomingKeys = new Set(normalized.findings.map(findingFamilyKey));
  const merged = mergeFindings([...baseline.findings, ...normalized.findings]);
  const newFindings = merged.findings.filter((finding) => incomingKeys.has(findingFamilyKey(finding)));
  const incomplete = normalized.errors.length > 0 || normalized.truncated;
  const reportAccess = accessMetadata
    ? await writeFrameSevenReportAccessMetadata({
        ...accessMetadata,
        outputDir: safeOutputDir,
        target: normalized.target,
      })
    : null;
  const publicArtifacts = await writeFrameSevenPublicArtifacts({
    outputDir: safeOutputDir,
    target: normalized.target,
    findings: merged.findings,
    incomplete,
  });

  return {
    reportPath,
    target: normalized.target,
    endpoints: normalized.endpoints,
    reportErrors: normalized.errors,
    incomplete,
    incomingFindings: normalized.findings,
    mergedFindings: merged.findings,
    newFindings,
    inputCount: baseline.findings.length + normalized.findings.length,
    outputCount: merged.findings.length,
    mergedCount: baseline.merged + merged.merged,
    truncated: normalized.truncated,
    publicArtifacts,
    reportAccess,
  };
}

export function serializeFrameSevenMergedFindings(findings = []) {
  return findings.map((finding) => {
    const stringMeta = typeof finding?.meta === 'string' ? finding.meta : '';
    const structuredEvidence = evidenceFor(finding);
    return {
      title: limitedText(finding?.value || finding?.title || 'GHOSTRECON finding', MAX_VALUE_LENGTH),
      module: normalizedType(
        finding?.moduleId
        || stringMeta.match(/source=([^\s]+)/)?.[1]
        || finding?.sourceEngine
        || finding?.type
        || 'ghostrecon',
      ),
      severity: normalizedSeverity(finding?.prio || finding?.severity),
      description: limitedText(
        finding?.description || stringMeta || finding?.meta?.description,
        MAX_EVIDENCE_LENGTH,
      ),
      endpoint: sameOriginOrEmpty(finding?.url, finding?.url),
      evidence: limitedText(
        finding?.evidence || structuredEvidence.map(evidenceSummary).filter(Boolean).join('\n\n---\n\n'),
        MAX_EVIDENCE_LENGTH,
      ),
    };
  });
}
