/**
 * Playbooks — perfis nomeados que pré-selecionam módulos e parâmetros de pipeline.
 *
 * Formato: JSON em `playbooks/*.json` ou YAML-ish (subset simples) em `playbooks/*.yaml`.
 * Não queremos puxar dependência de YAML — usamos JSON como fonte canônica.
 * Ficheiros .yaml são tolerados por um parser minimalista (key: value / listas "- ").
 *
 * Campos suportados em cada playbook:
 *   name         string  (obrigatório, único)
 *   description  string
 *   modules      string[]
 *   profile      "standard" | "stealth" | "aggressive"
 *   limits       object   (merge em config.js no server — futuro)
 *   tags         string[]
 *   targetHint   string   (regex/glob sugerido, apenas documental)
 */

import fs from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const DEFAULT_DIR = path.resolve(__dirname, '..', '..', '..', 'playbooks');

function playbookDirs() {
  const extras = (process.env.GHOSTRECON_PLAYBOOKS_DIR || '')
    .split(/[;:]/)
    .map((s) => s.trim())
    .filter(Boolean);
  return [DEFAULT_DIR, ...extras];
}

export async function listPlaybooks() {
  const out = new Map(); // name → playbook (primeira ocorrência vence)
  for (const dir of playbookDirs()) {
    let files;
    try {
      files = await fs.readdir(dir);
    } catch {
      continue;
    }
    for (const f of files) {
      if (!/\.(json|ya?ml)$/i.test(f)) continue;
      try {
        const pb = await loadPlaybookFile(path.join(dir, f));
        if (pb?.name && !out.has(pb.name)) out.set(pb.name, pb);
      } catch {
        // ignore broken playbook files — user verá quando invocar "show"
      }
    }
  }
  return [...out.values()].sort((a, b) => a.name.localeCompare(b.name));
}

export async function resolvePlaybook(name) {
  const n = String(name || '').trim().toLowerCase();
  if (!n) throw new Error('playbook vazio');
  for (const dir of playbookDirs()) {
    for (const ext of ['json', 'yaml', 'yml']) {
      const candidate = path.join(dir, `${n}.${ext}`);
      try {
        const pb = await loadPlaybookFile(candidate);
        if (pb) return normalize(pb);
      } catch {
        /* ignore, tenta próximo */
      }
    }
  }
  // fallback: procura por name interno
  const all = await listPlaybooks();
  const match = all.find((p) => p.name.toLowerCase() === n);
  if (match) return normalize(match);
  throw new Error(`playbook não encontrado: ${name}`);
}

async function loadPlaybookFile(file) {
  const raw = await fs.readFile(file, 'utf8');
  if (/\.json$/i.test(file)) return JSON.parse(raw);
  return parseMinimalYaml(raw);
}

function normalize(pb) {
  return {
    name: String(pb.name || '').trim(),
    description: String(pb.description || '').trim(),
    modules: Array.isArray(pb.modules) ? pb.modules.map(String) : [],
    profile: pb.profile ? String(pb.profile) : 'standard',
    limits: pb.limits && typeof pb.limits === 'object' ? pb.limits : {},
    tags: Array.isArray(pb.tags) ? pb.tags.map(String) : [],
    targetHint: pb.targetHint ? String(pb.targetHint) : '',
  };
}

/**
 * Parser YAML mínimo — suficiente para playbooks triviais:
 *   name: api-first
 *   modules:
 *     - crtsh
 *     - http
 *
 * Não suporta indentação aninhada complexa, multilinhas, âncoras, etc.
 * Exportado para testes.
 */
export function parseMinimalYaml(text) {
  const lines = String(text || '').split(/\r?\n/);
  const out = {};
  let currentList = null;
  for (const line of lines) {
    const raw = line.replace(/#.*$/, '');
    const trimmed = raw.trim();
    if (!trimmed) continue;

    if (trimmed.startsWith('- ')) {
      if (currentList) currentList.push(parseScalar(trimmed.slice(2).trim()));
      continue;
    }
    const m = /^([A-Za-z_][A-Za-z0-9_-]*)\s*:\s*(.*)$/.exec(trimmed);
    if (!m) continue;
    const key = m[1];
    const rest = m[2];
    if (!rest) {
      out[key] = [];
      currentList = out[key];
      continue;
    }
    currentList = null;
    if (rest.startsWith('[') && rest.endsWith(']')) {
      out[key] = rest
        .slice(1, -1)
        .split(',')
        .map((s) => parseScalar(s.trim()))
        .filter((v) => v !== '');
    } else {
      out[key] = parseScalar(rest);
    }
  }
  return out;
}

function parseScalar(v) {
  if (v == null) return v;
  const s = String(v).trim();
  if (/^['"].*['"]$/.test(s)) return s.slice(1, -1);
  if (/^-?\d+$/.test(s)) return Number(s);
  if (/^-?\d+\.\d+$/.test(s)) return Number(s);
  if (s === 'true') return true;
  if (s === 'false') return false;
  if (s === 'null') return null;
  return s;
}
