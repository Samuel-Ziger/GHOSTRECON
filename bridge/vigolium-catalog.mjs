import fs from 'node:fs/promises';
import path from 'node:path';
import { ghostreconRoot } from './vigolium-config.mjs';

const MODULE_KINDS = ['active', 'passive'];

function unquoteGoString(raw) {
  const s = String(raw || '').trim();
  if (!s) return '';
  if (s.startsWith('`') && s.endsWith('`')) return s.slice(1, -1).trim();
  if (s.startsWith('"') && s.endsWith('"')) {
    try {
      return JSON.parse(s);
    } catch {
      return s.slice(1, -1);
    }
  }
  return s;
}

function extractConst(text, name) {
  const re = new RegExp(`${name}\\s*=\\s*("([^"\\\\]|\\\\.)*"|\`[\\s\\S]*?\`)`);
  const m = re.exec(text);
  return m ? unquoteGoString(m[1]) : '';
}

function extractSeverity(text, name) {
  const re = new RegExp(`${name}\\s*=\\s*severity\\.([A-Za-z0-9_]+)`);
  const m = re.exec(text);
  return m ? m[1].toLowerCase() : '';
}

function extractTags(text) {
  const m = /ModuleTags\s*=\s*\[\]string\s*\{([\s\S]*?)\}/.exec(text);
  if (!m) return [];
  const tags = [];
  const re = /"([^"]+)"/g;
  let hit;
  while ((hit = re.exec(m[1]))) tags.push(hit[1]);
  return [...new Set(tags.map((s) => s.trim()).filter(Boolean))];
}

function descSummary(desc) {
  const text = String(desc || '')
    .replace(/\*\*/g, '')
    .replace(/\s+/g, ' ')
    .trim();
  return text.length > 240 ? `${text.slice(0, 240)}...` : text;
}

async function parseModuleMetadata({ root, kind, dirName }) {
  const moduleDir = path.join(root, 'vigolium', 'pkg', 'modules', kind, dirName);
  const metadataPath = path.join(moduleDir, 'metadata.go');
  let text = '';
  try {
    text = await fs.readFile(metadataPath, 'utf8');
  } catch {
    return {
      id: dirName.replaceAll('_', '-'),
      name: dirName.replaceAll('_', ' '),
      short: '',
      description: '',
      descriptionSummary: '',
      severity: '',
      confidence: '',
      tags: [],
      kind,
      dirName,
      metadataPath,
    };
  }

  const id = extractConst(text, 'ModuleID') || dirName.replaceAll('_', '-');
  const name = extractConst(text, 'ModuleName') || id;
  const short = extractConst(text, 'ModuleShort');
  const description = extractConst(text, 'ModuleDesc');
  const confirmation = extractConst(text, 'ModuleConfirmation');
  return {
    id,
    name,
    short,
    description,
    descriptionSummary: descSummary(description || short),
    confirmation,
    severity: extractSeverity(text, 'ModuleSeverity'),
    confidence: extractSeverity(text, 'ModuleConfidence'),
    tags: extractTags(text),
    kind,
    dirName,
    metadataPath,
  };
}

function matchesFilter(mod, { kind, tag, q } = {}) {
  if (kind && mod.kind !== kind) return false;
  if (tag) {
    const want = String(tag).toLowerCase();
    if (!mod.tags.some((t) => String(t).toLowerCase() === want)) return false;
  }
  if (q) {
    const needle = String(q).toLowerCase();
    const hay = [
      mod.id,
      mod.name,
      mod.short,
      mod.descriptionSummary,
      mod.severity,
      mod.confidence,
      ...(mod.tags || []),
    ].join(' ').toLowerCase();
    if (!hay.includes(needle)) return false;
  }
  return true;
}

export async function listVigoliumModules(opts = {}) {
  const root = opts.root || opts.ghostRoot || ghostreconRoot();
  const modules = [];
  const errors = [];

  for (const kind of MODULE_KINDS) {
    const dir = path.join(root, 'vigolium', 'pkg', 'modules', kind);
    let entries = [];
    try {
      entries = await fs.readdir(dir, { withFileTypes: true });
    } catch (e) {
      errors.push({ kind, dir, error: e?.message || String(e) });
      continue;
    }
    for (const entry of entries) {
      if (!entry.isDirectory()) continue;
      modules.push(await parseModuleMetadata({ root, kind, dirName: entry.name }));
    }
  }

  modules.sort((a, b) => `${a.kind}:${a.id}`.localeCompare(`${b.kind}:${b.id}`));
  const filtered = modules.filter((m) => matchesFilter(m, opts));
  const tags = [...new Set(modules.flatMap((m) => m.tags || []))].sort();
  const counts = {
    total: modules.length,
    filtered: filtered.length,
    active: modules.filter((m) => m.kind === 'active').length,
    passive: modules.filter((m) => m.kind === 'passive').length,
  };

  return {
    ok: errors.length === 0 || modules.length > 0,
    root,
    counts,
    tags,
    modules: filtered,
    errors,
  };
}

