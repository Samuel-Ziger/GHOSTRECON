import fs from 'node:fs/promises';
import path from 'node:path';
import { createHash, randomBytes } from 'node:crypto';
import { fileURLToPath } from 'node:url';
import { cosineSimilarity, localTextEmbedding } from './semantic-ranker.mjs';
import { redactAutoText, redactAutoValue } from './redaction.mjs';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const DEFAULT_ROOT = path.resolve(__dirname, '..', '..');

function slug(value, fallback = 'item') {
  const s = String(value || '')
    .toLowerCase()
    .replace(/https?:\/\//g, '')
    .replace(/[^a-z0-9._-]+/g, '-')
    .replace(/^-+|-+$/g, '')
    .slice(0, 80);
  return s || fallback;
}

function timestamp(d = new Date()) {
  return d.toISOString().replace(/[:.]/g, '-');
}

function yamlString(value) {
  return JSON.stringify(redactAutoText(String(value ?? '')));
}

function mdList(list) {
  const arr = Array.isArray(list) ? list : [];
  return arr.length
    ? arr.slice(0, 500).map((x) => `- ${redactAutoText(String(x)).slice(0, 2000)}`).join('\n')
    : '- none';
}

function codeJson(value, maxChars = 160_000) {
  const safe = redactAutoValue(value ?? null);
  let json = JSON.stringify(safe, null, 2);
  if (json.length > maxChars) {
    json = JSON.stringify({
      truncated: true,
      originalChars: json.length,
      preview: json.slice(0, Math.max(1000, maxChars - 2000)),
    }, null, 2);
  }
  return `\`\`\`json\n${json}\n\`\`\``;
}

const MEMORY_FOLDERS = Object.freeze({
  decisions: 'decisions',
  lessons: 'lessons',
  notes: 'notes',
  cursorTasks: 'cursor-tasks',
  forgeRequests: 'forge-requests',
});
const folderWriteLocks = new Map();

function clampLimit(value, fallback = 20, max = 200) {
  return Math.max(1, Math.min(max, Number(value) || fallback));
}

function clampBytes(value, fallback = 512 * 1024, min = 4096, max = 4 * 1024 * 1024) {
  const parsed = Number(value);
  return Math.max(min, Math.min(max, Number.isFinite(parsed) && parsed > 0 ? Math.floor(parsed) : fallback));
}

function ragLimits(env = process.env) {
  const ttlDaysRaw = Number(env.GHOSTRECON_AUTO_RAG_TTL_DAYS ?? 30);
  const ttlDays = Number.isFinite(ttlDaysRaw)
    ? Math.max(0, Math.min(3650, Math.floor(ttlDaysRaw)))
    : 30;
  return {
    maxFileBytes: clampBytes(env.GHOSTRECON_AUTO_RAG_MAX_FILE_BYTES),
    maxReadBytes: clampBytes(env.GHOSTRECON_AUTO_RAG_MAX_READ_BYTES || env.GHOSTRECON_AUTO_RAG_MAX_FILE_BYTES),
    maxFilesPerFolder: clampLimit(env.GHOSTRECON_AUTO_RAG_MAX_FILES_PER_FOLDER, 2000, 20_000),
    // 0 = sem expiração; default 30 dias.
    ttlMs: ttlDays > 0 ? ttlDays * 86_400_000 : 0,
  };
}

function parseMemoryCreatedAt(text = '', fileName = '') {
  const fromFrontmatter = /^created:\s*["']?([^"'\n]+)["']?/m.exec(String(text || ''));
  if (fromFrontmatter?.[1]) {
    const parsed = Date.parse(fromFrontmatter[1]);
    if (Number.isFinite(parsed)) return parsed;
  }
  const fromName = /^(\d{4}-\d{2}-\d{2})/.exec(String(fileName || ''));
  if (fromName?.[1]) {
    const parsed = Date.parse(fromName[1]);
    if (Number.isFinite(parsed)) return parsed;
  }
  return null;
}

function isWithinRagTtl(createdMs, ttlMs, nowMs = Date.now()) {
  if (!ttlMs || ttlMs <= 0) return true;
  // Sem timestamp confiável, fail-closed: não recupera memória sob TTL.
  if (!Number.isFinite(createdMs)) return false;
  return (nowMs - createdMs) <= ttlMs;
}

async function resolveMemoryCreatedMs(filePath, text, fileName) {
  const fromMeta = parseMemoryCreatedAt(text, fileName);
  if (Number.isFinite(fromMeta)) return fromMeta;
  try {
    const st = await fs.stat(filePath);
    const mtime = Number(st.mtimeMs);
    return Number.isFinite(mtime) ? mtime : null;
  } catch {
    return null;
  }
}

function normalizeTags(tags) {
  return [...new Set(['ghostrecon', 'auto-mode', ...(Array.isArray(tags) ? tags : [])]
    .map((t) => redactAutoText(String(t || '')).trim().slice(0, 100))
    .filter(Boolean))];
}

function stripFrontmatter(text) {
  return String(text || '').replace(/^---[\s\S]*?---\s*/m, '').trim();
}

function safeHeading(value, fallback) {
  return redactAutoText(String(value || fallback || 'Auto memory'))
    .replace(/[\r\n\t]+/g, ' ')
    .trim()
    .slice(0, 300) || fallback;
}

function truncateUtf8(value, maxBytes) {
  const text = String(value ?? '');
  const bytes = Buffer.byteLength(text);
  if (bytes <= maxBytes) return text;
  const marker = `\n\n[TRUNCATED: original_bytes=${bytes}]\n`;
  const markerBytes = Buffer.byteLength(marker);
  const prefix = Buffer.from(text).subarray(0, Math.max(0, maxBytes - markerBytes)).toString('utf8');
  return `${prefix}${marker}`;
}

async function chmodRestricted(filePath, mode) {
  await fs.chmod(filePath, mode).catch(() => {});
}

async function ensureRestrictedDir(dir) {
  await fs.mkdir(dir, { recursive: true, mode: 0o700 });
  await chmodRestricted(dir, 0o700);
}

async function atomicWriteRestricted(filePath, text, { maxBytes } = {}) {
  const safeText = truncateUtf8(text, maxBytes || ragLimits().maxFileBytes);
  const dir = path.dirname(filePath);
  await ensureRestrictedDir(dir);
  const tmp = path.join(dir, `.${path.basename(filePath)}.${process.pid}.${randomBytes(6).toString('hex')}.tmp`);
  let handle;
  try {
    handle = await fs.open(tmp, 'wx', 0o600);
    await handle.writeFile(safeText, 'utf8');
    await handle.sync();
    await handle.close();
    handle = null;
    await fs.rename(tmp, filePath);
    await chmodRestricted(filePath, 0o600);
  } catch (error) {
    await handle?.close().catch(() => {});
    await fs.rm(tmp, { force: true }).catch(() => {});
    throw error;
  }
}

async function readUtf8Limited(filePath, maxBytes) {
  const handle = await fs.open(filePath, 'r');
  try {
    const stat = await handle.stat();
    const length = Math.min(stat.size, maxBytes + 8192);
    const buffer = Buffer.alloc(length);
    const { bytesRead } = await handle.read(buffer, 0, length, 0);
    const suffix = stat.size > maxBytes ? `\n[TRUNCATED: original_bytes=${stat.size}]` : '';
    return truncateUtf8(
      redactAutoText(`${buffer.subarray(0, bytesRead).toString('utf8')}${suffix}`),
      maxBytes,
    );
  } finally {
    await handle.close();
  }
}

async function folderHasCapacity(dir, limit) {
  const entries = await fs.readdir(dir, { withFileTypes: true }).catch(() => []);
  return entries.filter((entry) => entry.isFile() && entry.name.toLowerCase().endsWith('.md')).length < limit;
}

async function writeMemoryFileWithLimit({ dir, filePath, text, limits }) {
  const previous = folderWriteLocks.get(dir) || Promise.resolve();
  const current = previous.catch(() => {}).then(async () => {
    if (!await folderHasCapacity(dir, limits.maxFilesPerFolder)) return false;
    await atomicWriteRestricted(filePath, text, { maxBytes: limits.maxFileBytes });
    return true;
  });
  folderWriteLocks.set(dir, current);
  try {
    return await current;
  } finally {
    if (folderWriteLocks.get(dir) === current) folderWriteLocks.delete(dir);
  }
}

function folderForKind(kind = '') {
  const k = String(kind || '').trim().toLowerCase();
  if (['lesson', 'lessons'].includes(k)) return MEMORY_FOLDERS.lessons;
  if (['note', 'notes'].includes(k)) return MEMORY_FOLDERS.notes;
  if (['cursor', 'cursor-task', 'cursor_tasks', 'cursor-tasks'].includes(k)) return MEMORY_FOLDERS.cursorTasks;
  if (['forge', 'module-forge', 'forge-request', 'forge-requests'].includes(k)) return MEMORY_FOLDERS.forgeRequests;
  return MEMORY_FOLDERS.decisions;
}

function safeMemoryRef(name) {
  const raw = String(name || '').trim().replace(/\\/g, '/');
  const parts = raw.split('/').filter(Boolean);
  const file = path.basename(parts.pop() || '');
  const folder = parts.length ? parts[parts.length - 1] : MEMORY_FOLDERS.decisions;
  if (!file || !file.toLowerCase().endsWith('.md')) throw new Error('nome de memoria invalido');
  const allowed = new Set(Object.values(MEMORY_FOLDERS));
  if (!allowed.has(folder)) throw new Error('pasta de memoria invalida');
  return { folder, file, ref: `${folder}/${file}` };
}

export function resolveAutoRagPartitionKey({
  principalId = '',
  engagementId = '',
  target = '',
} = {}) {
  const principal = slug(principalId, 'anon');
  const engagement = slug(engagementId, 'no-engagement');
  const targetSlug = slug(target, 'no-target');
  const digest = createHash('sha256')
    .update(`${principal}\0${engagement}\0${targetSlug}`)
    .digest('hex')
    .slice(0, 16);
  return `p-${principal}/e-${engagement}/t-${targetSlug}-${digest}`;
}

export function resolveAutoRagDir({
  root = DEFAULT_ROOT,
  env = process.env,
  principalId = '',
  engagementId = '',
  target = '',
  partition = null,
} = {}) {
  const raw = String(env.GHOSTRECON_AUTO_RAG_DIR || '').trim();
  const base = raw ? path.resolve(raw) : path.join(root, 'data', 'auto-rag');
  const partitionEnabled = !/^(0|false|no|off)$/i.test(
    String(env.GHOSTRECON_AUTO_RAG_PARTITION ?? '1').trim(),
  );
  const part = partition
    || (partitionEnabled && (principalId || engagementId || target)
      ? resolveAutoRagPartitionKey({ principalId, engagementId, target })
      : null);
  return part ? path.join(base, 'tenants', part) : base;
}

export async function ensureAutoRagDirs(opts = {}) {
  const base = resolveAutoRagDir(opts);
  const dirs = { base };
  await ensureRestrictedDir(base);
  for (const [key, folder] of Object.entries(MEMORY_FOLDERS)) {
    dirs[key] = path.join(base, folder);
    await ensureRestrictedDir(dirs[key]);
  }
  return dirs;
}

export async function writeAutoDecisionMarkdown({
  root = DEFAULT_ROOT,
  env = process.env,
  requestRunId = '',
  target = '',
  kind = 'decision',
  title = '',
  summary = '',
  plan = null,
  evaluation = null,
  providers = null,
  catalog = null,
  events = [],
  tags = [],
  principalId = '',
  engagementId = '',
} = {}) {
  if (/^(0|false|no|off)$/i.test(String(env.GHOSTRECON_AUTO_RAG_ENABLED || '1').trim())) {
    return null;
  }
  const dirs = await ensureAutoRagDirs({
    root,
    env,
    principalId,
    engagementId,
    target,
  });
  const limits = ragLimits(env);
  const now = new Date();
  const safeKind = slug(kind, 'decision');
  const safeTarget = slug(redactAutoText(target), 'target');
  const safeRun = slug(redactAutoText(requestRunId || timestamp(now)), 'run');
  const filename = `${timestamp(now)}-${safeTarget}-${safeKind}-${safeRun}-${randomBytes(3).toString('hex')}.md`;
  const filePath = path.join(dirs.decisions, filename);
  const safeEvents = Array.isArray(events) ? events : [];
  const eventStats = {
    total: safeEvents.length,
    findings: safeEvents.filter((e) => e?.type === 'finding').length,
    errors: safeEvents.filter((e) => e?.type === 'error').length,
    warnings: safeEvents.filter((e) => e?.type === 'log' && e.level === 'warn').length,
  };
  const frontmatter = [
    '---',
    `type: ${yamlString('ghostrecon-auto-decision')}`,
    `kind: ${yamlString(kind)}`,
    `target: ${yamlString(target)}`,
    `requestRunId: ${yamlString(requestRunId)}`,
    `sessionId: ${yamlString(plan?.sessionId || '')}`,
    `created: ${yamlString(now.toISOString())}`,
    `tags: [${normalizeTags(tags).map((t) => yamlString(t)).join(', ')}]`,
    '---',
  ].join('\n');

  const body = [
    frontmatter,
    '',
    `# ${safeHeading(title, `GHOSTRECON Auto ${kind}`)}`,
    '',
    '## Summary',
    '',
    redactAutoText(summary || 'Decision generated by GHOSTRECON Auto Mode.').slice(0, 20_000),
    '',
    '## Target',
    '',
    `- Target: \`${redactAutoText(target || 'unknown').slice(0, 2000)}\``,
    `- Request run: \`${redactAutoText(requestRunId || 'unknown').slice(0, 500)}\``,
    `- Kind: \`${redactAutoText(kind).slice(0, 100)}\``,
    '',
    '## Commander Roles',
    '',
    plan?.commanders?.roles
      ? mdList(Object.entries(plan.commanders.roles).map(([k, v]) => `${k}: ${v}`))
      : '- none',
    '',
    '## Selected Modules',
    '',
    mdList(plan?.modules || []),
    '',
    '## Event Stats',
    '',
    mdList(Object.entries(eventStats).map(([k, v]) => `${k}: ${v}`)),
    '',
    '## Evaluation',
    '',
    evaluation ? codeJson(evaluation) : '_Not available yet._',
    '',
    '## Plan',
    '',
    plan ? codeJson(plan) : '_Not available._',
    '',
    '## Providers',
    '',
    providers ? codeJson(providers) : '_Not available._',
    '',
    '## Catalog Snapshot',
    '',
    catalog ? codeJson(catalog) : '_Not available._',
    '',
  ].join('\n');

  const written = await writeMemoryFileWithLimit({
    dir: dirs.decisions,
    filePath,
    text: redactAutoText(body),
    limits,
  });
  if (!written) {
    return { skipped: true, reason: 'rag_file_limit', folder: MEMORY_FOLDERS.decisions, limit: limits.maxFilesPerFolder, baseDir: dirs.base };
  }
  await updateAutoRagIndex({ root, env, principalId, engagementId, target });
  return { filePath, filename, baseDir: dirs.base };
}

export async function writeAutoRagNote({
  root = DEFAULT_ROOT,
  env = process.env,
  kind = 'note',
  title = '',
  body = '',
  target = '',
  tags = [],
  metadata = null,
  principalId = '',
  engagementId = '',
} = {}) {
  if (/^(0|false|no|off)$/i.test(String(env.GHOSTRECON_AUTO_RAG_ENABLED || '1').trim())) {
    return null;
  }
  const dirs = await ensureAutoRagDirs({ root, env, principalId, engagementId, target });
  const limits = ragLimits(env);
  const now = new Date();
  const folder = folderForKind(kind);
  const dirKey = folder === MEMORY_FOLDERS.cursorTasks ? 'cursorTasks'
    : folder === MEMORY_FOLDERS.forgeRequests ? 'forgeRequests'
      : folder;
  const safeTitle = slug(redactAutoText(title || kind), kind);
  const filename = `${timestamp(now)}-${safeTitle}-${randomBytes(3).toString('hex')}.md`;
  const filePath = path.join(dirs[dirKey], filename);
  const frontmatter = [
    '---',
    `type: ${yamlString('ghostrecon-auto-memory')}`,
    `kind: ${yamlString(kind)}`,
    `target: ${yamlString(target)}`,
    `created: ${yamlString(now.toISOString())}`,
    `tags: [${normalizeTags([kind, ...tags]).map((t) => yamlString(t)).join(', ')}]`,
    '---',
  ].join('\n');
  const text = [
    frontmatter,
    '',
    `# ${safeHeading(title, `Auto ${kind}`)}`,
    '',
    redactAutoText(body || '_No body provided._'),
    '',
    metadata ? '## Metadata' : '',
    metadata ? codeJson(metadata) : '',
  ].filter((line, idx, arr) => line !== '' || arr[idx - 1] !== '').join('\n');
  const written = await writeMemoryFileWithLimit({
    dir: dirs[dirKey],
    filePath,
    text: redactAutoText(text),
    limits,
  });
  if (!written) {
    return { skipped: true, reason: 'rag_file_limit', folder, limit: limits.maxFilesPerFolder, baseDir: dirs.base };
  }
  await updateAutoRagIndex({ root, env, principalId, engagementId, target });
  return { filePath, filename, name: `${folder}/${filename}`, kind, baseDir: dirs.base };
}

export async function writeAutoLesson({
  root = DEFAULT_ROOT,
  env = process.env,
  target = '',
  problem = '',
  decision = '',
  outcome = '',
  modules = [],
  commanders = null,
  confidence = '',
  tags = [],
  metadata = null,
  principalId = '',
  engagementId = '',
} = {}) {
  const title = `Lesson - ${target || slug(problem, 'auto')}`;
  const body = [
    '## Problem',
    '',
    problem || '_Not provided._',
    '',
    '## Decision',
    '',
    decision || '_Not provided._',
    '',
    '## Outcome',
    '',
    outcome || '_Pending._',
    '',
    '## Modules',
    '',
    mdList(modules),
    '',
    '## Commanders',
    '',
    commanders ? codeJson(commanders) : '_Not provided._',
    '',
    '## Confidence',
    '',
    confidence || '_Not provided._',
  ].join('\n');
  return writeAutoRagNote({
    root,
    env,
    kind: 'lesson',
    title,
    body,
    target,
    tags: ['lesson', ...tags],
    metadata,
    principalId,
    engagementId,
  });
}

export async function listAutoRagMarkdown({
  root = DEFAULT_ROOT,
  env = process.env,
  limit = 20,
  principalId = '',
  engagementId = '',
  target = '',
} = {}) {
  const dirs = await ensureAutoRagDirs({ root, env, principalId, engagementId, target });
  const limits = ragLimits(env);
  const files = [];
  for (const [key, folder] of Object.entries({
    decisions: dirs.decisions,
    lessons: dirs.lessons,
    notes: dirs.notes,
    'cursor-tasks': dirs.cursorTasks,
    'forge-requests': dirs.forgeRequests,
  })) {
    const entries = await fs.readdir(folder, { withFileTypes: true }).catch(() => []);
    for (const e of entries) {
      if (e.isFile() && e.name.toLowerCase().endsWith('.md')) {
        files.push({ folder: key, name: e.name, path: path.join(folder, e.name) });
      }
    }
  }
  const ranked = files.sort((a, b) => b.name.localeCompare(a.name));
  const out = [];
  const nowMs = Date.now();
  for (const item of ranked) {
    if (out.length >= clampLimit(limit, 20, 500)) break;
    const text = await readUtf8Limited(item.path, limits.maxReadBytes).catch(() => '');
    const createdMs = await resolveMemoryCreatedMs(item.path, text, item.name);
    if (!isWithinRagTtl(createdMs, limits.ttlMs, nowMs)) continue;
    const firstHeading = /^#\s+(.+)$/m.exec(text)?.[1] || item.name;
    out.push({
      name: `${item.folder}/${item.name}`,
      file: item.name,
      folder: item.folder,
      path: item.path,
      title: redactAutoText(firstHeading).slice(0, 300),
      preview: redactAutoText(stripFrontmatter(text)).slice(0, 900),
      createdAt: Number.isFinite(createdMs) ? new Date(createdMs).toISOString() : null,
    });
  }
  return out;
}

/**
 * Remove arquivos de memória fora do TTL. Retorna contagem/caminhos removidos.
 * Não atravessa partições: exige o mesmo escopo de list/search.
 */
export async function pruneExpiredAutoRagMarkdown({
  root = DEFAULT_ROOT,
  env = process.env,
  principalId = '',
  engagementId = '',
  target = '',
  dryRun = false,
} = {}) {
  const dirs = await ensureAutoRagDirs({ root, env, principalId, engagementId, target });
  const limits = ragLimits(env);
  if (!limits.ttlMs) return { removed: 0, paths: [], dryRun: Boolean(dryRun) };
  const removed = [];
  const nowMs = Date.now();
  for (const folder of Object.values({
    decisions: dirs.decisions,
    lessons: dirs.lessons,
    notes: dirs.notes,
    'cursor-tasks': dirs.cursorTasks,
    'forge-requests': dirs.forgeRequests,
  })) {
    const entries = await fs.readdir(folder, { withFileTypes: true }).catch(() => []);
    for (const e of entries) {
      if (!e.isFile() || !e.name.toLowerCase().endsWith('.md')) continue;
      const filePath = path.join(folder, e.name);
      const text = await readUtf8Limited(filePath, limits.maxReadBytes).catch(() => '');
      const createdMs = await resolveMemoryCreatedMs(filePath, text, e.name);
      if (isWithinRagTtl(createdMs, limits.ttlMs, nowMs)) continue;
      if (!dryRun) await fs.unlink(filePath).catch(() => null);
      removed.push(filePath);
    }
  }
  if (!dryRun && removed.length) {
    await updateAutoRagIndex({ root, env, principalId, engagementId, target }).catch(() => null);
  }
  return { removed: removed.length, paths: removed, dryRun: Boolean(dryRun) };
}

export async function readAutoRagMarkdown(name, {
  root = DEFAULT_ROOT,
  env = process.env,
  principalId = '',
  engagementId = '',
  target = '',
} = {}) {
  const dirs = await ensureAutoRagDirs({ root, env, principalId, engagementId, target });
  const limits = ragLimits(env);
  const safe = safeMemoryRef(name);
  const dirKey = safe.folder === MEMORY_FOLDERS.cursorTasks ? 'cursorTasks'
    : safe.folder === MEMORY_FOLDERS.forgeRequests ? 'forgeRequests'
      : safe.folder;
  const filePath = path.join(dirs[dirKey], safe.file);
  const text = await readUtf8Limited(filePath, limits.maxReadBytes);
  const createdMs = await resolveMemoryCreatedMs(filePath, text, safe.file);
  if (!isWithinRagTtl(createdMs, limits.ttlMs)) {
    const error = new Error(`memória RAG expirada: ${safe.ref}`);
    error.code = 'AUTO_RAG_EXPIRED';
    throw error;
  }
  return {
    name: safe.ref,
    file: safe.file,
    folder: safe.folder,
    path: filePath,
    text,
  };
}

export async function searchAutoRagMarkdown({
  query = '',
  target = '',
  technologies = [],
  modules = [],
  decisionType = '',
  root = DEFAULT_ROOT,
  env = process.env,
  limit = 8,
  scanLimit = 120,
  principalId = '',
  engagementId = '',
} = {}) {
  const limits = ragLimits(env);
  const q = [query, target, decisionType, ...(technologies || []), ...(modules || [])].join(' ').trim().toLowerCase();
  const terms = q
    .split(/[^a-z0-9._-]+/i)
    .map((x) => x.trim().toLowerCase())
    .filter((x) => x.length >= 2);
  const items = await listAutoRagMarkdown({
    root, env, limit: scanLimit, principalId, engagementId, target,
  });
  if (!terms.length) return items.slice(0, clampLimit(limit, 8, 50));

  const scored = [];
  const semanticEnabled = !/^(0|false|no|off)$/i.test(String(env.GHOSTRECON_AUTO_SEMANTIC_RAG || '1'));
  const queryEmbedding = semanticEnabled ? localTextEmbedding(q) : null;
  for (const item of items) {
    const text = await readUtf8Limited(item.path, limits.maxReadBytes).catch(() => '');
    const hay = `${item.name}\n${item.title}\n${text}`.toLowerCase();
    let score = 0;
    for (const term of terms) {
      const matches = hay.split(term).length - 1;
      score += matches * (item.title.toLowerCase().includes(term) ? 3 : 1);
    }
    const targetTerm = String(target || '').toLowerCase();
    if (targetTerm && hay.includes(targetTerm)) score += 20;
    for (const technology of technologies || []) if (hay.includes(String(technology).toLowerCase())) score += 5;
    for (const moduleId of modules || []) if (hay.includes(String(moduleId).toLowerCase())) score += 7;
    if (decisionType && hay.includes(String(decisionType).toLowerCase())) score += 4;
    if (queryEmbedding) score += Math.max(0, cosineSimilarity(queryEmbedding, localTextEmbedding(`${item.title}\n${stripFrontmatter(text).slice(0, 6000)}`))) * 12;
    if (item.folder === 'lessons' && /outcome|resultado|conclu|success|failed|falha/i.test(text)) score += 6;
    const date = Date.parse(item.name.slice(item.name.indexOf('/') + 1, item.name.indexOf('/') + 11));
    if (Number.isFinite(date)) score += Math.max(0, 3 - ((Date.now() - date) / 86_400_000) / 30);
    if (score > 0) {
      scored.push({
        ...item,
        score,
        preview: redactAutoText(stripFrontmatter(text)).slice(0, 1400),
      });
    }
  }
  return scored
    .sort((a, b) => b.score - a.score || b.name.localeCompare(a.name))
    .slice(0, clampLimit(limit, 8, 50));
}

export async function loadAutoRagContext({
  root = DEFAULT_ROOT,
  env = process.env,
  limit = 6,
  target = '',
  technologies = [],
  modules = [],
  decisionType = 'plan',
  principalId = '',
  engagementId = '',
} = {}) {
  const ragOpts = { root, env, principalId, engagementId, target };
  const targeted = target
    ? await searchAutoRagMarkdown({ ...ragOpts, query: target, technologies, modules, decisionType, limit })
    : [];
  const recent = target ? [] : await listAutoRagMarkdown({ ...ragOpts, limit });
  const byName = new Map([...targeted, ...recent].map((item) => [item.name, item]));
  const items = [...byName.values()].slice(0, clampLimit(limit, 6, 50));
  return {
    dir: resolveAutoRagDir(ragOpts),
    partition: resolveAutoRagPartitionKey({ principalId, engagementId, target }),
    items: items.map((item) => ({
      name: item.name,
      folder: item.folder,
      title: item.title,
      preview: item.preview,
    })),
  };
}

export async function updateAutoRagIndex({
  root = DEFAULT_ROOT,
  env = process.env,
  principalId = '',
  engagementId = '',
  target = '',
} = {}) {
  const dirs = await ensureAutoRagDirs({ root, env, principalId, engagementId, target });
  const items = await listAutoRagMarkdown({
    root, env, limit: 200, principalId, engagementId, target,
  });
  const indexPath = path.join(dirs.base, 'README.md');
  const byFolder = new Map();
  for (const item of items) {
    if (!byFolder.has(item.folder)) byFolder.set(item.folder, []);
    byFolder.get(item.folder).push(item);
  }
  const section = (folder, title) => [
    `## ${title}`,
    '',
    ...(byFolder.get(folder) || []).map((item) => `- [[${item.name.replace(/\.md$/i, '')}]] - ${item.title}`),
    '',
  ];
  const text = [
    '# GHOSTRECON Auto RAG',
    '',
    'Markdown memory generated by GHOSTRECON Auto Mode. Open this folder as an Obsidian vault or add it to an existing vault.',
    '',
    ...section('decisions', 'Decisions'),
    ...section('lessons', 'Lessons'),
    ...section('notes', 'Notes'),
    ...section('cursor-tasks', 'Cursor Tasks'),
    ...section('forge-requests', 'Module Forge Requests'),
  ].join('\n');
  await atomicWriteRestricted(indexPath, redactAutoText(text), { maxBytes: ragLimits(env).maxFileBytes });
  return { indexPath, count: items.length };
}
