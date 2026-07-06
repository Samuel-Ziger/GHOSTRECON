import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';
import { HexstrikeClient, resolveHexstrikeBaseUrl } from '../integrations/hexstrike-client.mjs';

function defaultGhostRoot() {
  return path.join(path.dirname(fileURLToPath(import.meta.url)), '..', '..');
}

function dirExists(p) {
  try {
    return fs.statSync(p).isDirectory();
  } catch {
    return false;
  }
}

function fileExists(p) {
  try {
    return fs.statSync(p).isFile();
  } catch {
    return false;
  }
}

export function resolveHexstrikeHome(ghostRoot = defaultGhostRoot()) {
  const raw = String(process.env.GHOSTRECON_HEXSTRIKE_HOME || process.env.HEXSTRIKE_HOME || '').trim();
  if (raw) return path.resolve(raw);

  const candidates = [
    path.join(ghostRoot, 'IAs', 'hexstrike-ai'),
    path.join(ghostRoot, 'ghost-local-v5', 'hexstrike-ai'),
  ];
  return candidates.find((candidate) => fileExists(path.join(candidate, 'hexstrike_server.py'))) || candidates[0];
}

function summarizeHealth(data) {
  const toolsStatus = data && typeof data === 'object' ? data.tools_status || {} : {};
  const categoryStats = data && typeof data === 'object' ? data.category_stats || {} : {};
  return {
    status: data?.status || '',
    version: data?.version || '',
    totalToolsAvailable: Number(data?.total_tools_available || 0),
    totalToolsCount: Number(data?.total_tools_count || Object.keys(toolsStatus).length || 0),
    allEssentialToolsAvailable: Boolean(data?.all_essential_tools_available),
    categoryStats,
    tools: toolsStatus,
  };
}

export async function getHexstrikeCapabilities(opts = {}) {
  const ghostRoot = opts.ghostRoot || defaultGhostRoot();
  const home = resolveHexstrikeHome(ghostRoot);
  const baseUrl = opts.baseUrl || resolveHexstrikeBaseUrl();
  const checks = {
    home: dirExists(home),
    server: fileExists(path.join(home, 'hexstrike_server.py')),
    mcp: fileExists(path.join(home, 'hexstrike_mcp.py')),
    requirements: fileExists(path.join(home, 'requirements.txt')),
  };

  const client = opts.client || new HexstrikeClient({
    baseUrl,
    fetchImpl: opts.fetchImpl,
    timeoutMs: Number(opts.timeoutMs || 3000),
  });

  const ping = await client.telemetry({ timeoutMs: Number(opts.timeoutMs || 3000) });
  const reachable = Boolean(ping.ok);

  let health = null;
  const deepHealth = opts.deepHealth ?? String(process.env.GHOSTRECON_HEXSTRIKE_HEALTH_DEEP || '').trim() === '1';
  if (reachable && deepHealth) {
    const healthResponse = await client.health({ timeoutMs: Number(opts.healthTimeoutMs || 45_000) });
    health = healthResponse.ok ? summarizeHealth(healthResponse.data) : { error: healthResponse.data?.error || 'health failed' };
  }

  const missing = [];
  if (!checks.home) missing.push(`pasta HexStrike ausente: ${home}`);
  if (!checks.server) missing.push('hexstrike_server.py nao encontrado');
  if (!checks.mcp) missing.push('hexstrike_mcp.py nao encontrado');
  if (!checks.requirements) missing.push('requirements.txt nao encontrado');
  if (!reachable) missing.push(`HexStrike nao respondeu em ${baseUrl}`);

  return {
    ok: checks.server && reachable,
    installed: checks.server,
    reachable,
    home,
    baseUrl,
    checks,
    message: missing.length ? missing.join(' · ') : 'HexStrike instalado e respondendo.',
    http: {
      configured: Boolean(baseUrl),
      telemetry: reachable,
      healthDeepEnabled: Boolean(deepHealth),
      health,
    },
    mcp: {
      installed: checks.mcp,
      commandHint: checks.mcp ? `python3 ${path.join(home, 'hexstrike_mcp.py')} --server ${baseUrl}` : '',
    },
    prepHints: {
      install: 'cd IAs/hexstrike-ai && python3 -m venv hexstrike-env && ./hexstrike-env/bin/pip install -r requirements.txt',
      start: `cd ${home} && python3 hexstrike_server.py --port 8888`,
      deepHealth: 'Defina GHOSTRECON_HEXSTRIKE_HEALTH_DEEP=1 para enumerar ferramentas via /health.',
    },
  };
}

