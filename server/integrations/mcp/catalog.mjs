import fs from 'node:fs/promises';
import path from 'node:path';
import os from 'node:os';

const ID = /^(?:codex:)?[a-zA-Z0-9][a-zA-Z0-9._-]{0,79}$/;

export const BUILTIN_CODEX_MCPS = Object.freeze([
  {
    id: 'ghostrecon',
    label: 'GHOSTRECON',
    description: 'Pipelines, catálogo, escopo e evidências do GHOSTRECON.',
    codexOnly: true,
    risk: 'gated',
  },
  {
    id: 'hexstrike',
    label: 'HexStrike',
    description: 'Ferramentas HexStrike pelo launcher MCP local.',
    codexOnly: true,
    risk: 'intrusive',
  },
  {
    id: 'msfvenom',
    label: 'msfvenom · via HexStrike',
    description: 'Ativa o MCP HexStrike, que expõe a ferramenta msfvenom_generate.',
    codexOnly: true,
    risk: 'intrusive',
    transportServer: 'hexstrike',
  },
  {
    id: 'playwright',
    label: 'Playwright',
    description: 'Navegador isolado e headless para validação web.',
    codexOnly: true,
    risk: 'active',
  },
]);

export function normalizeMcpSelection(value, { max = 16 } = {}) {
  const input = Array.isArray(value) ? value : [];
  const output = [];
  for (const raw of input) {
    const id = String(raw || '').trim();
    if (!ID.test(id)) throw new Error(`MCP inválido: ${id.slice(0, 80)}`);
    if (!output.includes(id)) output.push(id);
    if (output.length > max) throw new Error(`no máximo ${max} MCPs podem ser selecionados`);
  }
  return output;
}

function codexConfigPath(env = process.env) {
  const base = String(env.CODEX_HOME || path.join(os.homedir(), '.codex'));
  return path.join(base, 'config.toml');
}

export async function discoverCodexMcpNames({ env = process.env } = {}) {
  const source = await fs.readFile(codexConfigPath(env), 'utf8').catch(() => '');
  const names = [];
  for (const match of source.matchAll(/^\s*\[mcp_servers\.([A-Za-z0-9_-]+)]\s*$/gm)) {
    if (!names.includes(match[1])) names.push(match[1]);
  }
  return names;
}

export async function listCodexMcpCatalog({ root, env = process.env } = {}) {
  const personal = await discoverCodexMcpNames({ env });
  const rows = personal.map((name) => ({
    id: `codex:${name}`,
    name,
    label: name === 'mind' ? 'Mind · Codex pessoal' : `${name} · Codex pessoal`,
    description: 'Importado da configuração pessoal do Codex; credenciais permanecem no CODEX_HOME.',
    origin: 'codex-user-config',
    available: true,
    codexOnly: true,
    risk: 'external',
  }));
  const availability = {
    ghostrecon: await fs.access(path.join(root, 'mcp', 'ghostrecon-mcp.mjs')).then(() => true).catch(() => false),
    hexstrike: await fs.access(path.join(root, 'mcp', 'hexstrike-mcp-launcher.mjs')).then(() => true).catch(() => false),
    msfvenom: await fs.access(path.join(root, 'mcp', 'hexstrike-mcp-launcher.mjs')).then(() => true).catch(() => false),
    playwright: true,
  };
  return [
    ...rows,
    ...BUILTIN_CODEX_MCPS.map((item) => ({
      ...item,
      origin: 'ghostrecon-managed',
      available: availability[item.id] === true,
    })),
  ];
}

export async function validateCodexMcpSelection({ root, selected, env = process.env } = {}) {
  const normalized = normalizeMcpSelection(selected);
  const catalog = await listCodexMcpCatalog({ root, env });
  const byId = new Map(catalog.map((item) => [item.id, item]));
  for (const id of normalized) {
    const item = byId.get(id);
    if (!item) throw new Error(`MCP não cadastrado no Codex/GHOSTRECON: ${id}`);
    if (item.available !== true) throw new Error(`MCP indisponível nesta instalação: ${id}`);
  }
  return normalized;
}

export function codexManagedMcpServers(root, selected) {
  const ids = new Set(normalizeMcpSelection(selected));
  const servers = {};
  if (ids.has('ghostrecon')) {
    servers.ghostrecon = { command: 'node', args: [path.join(root, 'mcp', 'ghostrecon-mcp.mjs')] };
  }
  if (ids.has('hexstrike') || ids.has('msfvenom')) {
    servers['hexstrike-ai'] = { command: 'node', args: [path.join(root, 'mcp', 'hexstrike-mcp-launcher.mjs')] };
  }
  if (ids.has('playwright')) {
    servers.playwright = { command: 'npx', args: ['-y', '@playwright/mcp@latest', '--headless', '--isolated'] };
  }
  return servers;
}

