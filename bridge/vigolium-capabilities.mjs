import { spawn } from 'node:child_process';
import fs from 'node:fs';
import path from 'node:path';
import {
  ghostreconRoot,
  resolveVigoliumBinary,
  vigoliumBinaryCandidates,
} from './vigolium-config.mjs';
import { resolveVigoliumServerConfig } from './vigolium-server-client.mjs';

const VERSION_TIMEOUT_MS = 3_000;

function countModuleDirs(root) {
  const counts = {};
  for (const kind of ['active', 'passive']) {
    const dir = path.join(root, 'vigolium', 'pkg', 'modules', kind);
    try {
      counts[kind] = fs.readdirSync(dir, { withFileTypes: true }).filter((d) => d.isDirectory()).length;
    } catch {
      counts[kind] = null;
    }
  }
  const values = Object.values(counts).filter((n) => Number.isFinite(n));
  return {
    ...counts,
    total: values.length ? values.reduce((sum, n) => sum + n, 0) : null,
  };
}

/**
 * @param {{ ghostRoot?: string }} opts
 */
export async function getVigoliumCapabilities(opts = {}) {
  const root = opts.ghostRoot || ghostreconRoot();
  const { bin, source } = await resolveVigoliumBinary(root);
  const moduleCounts = countModuleDirs(root);
  const serverCfg = resolveVigoliumServerConfig();
  const base = {
    installed: Boolean(bin),
    binary: bin,
    resolveSource: source,
    candidates: vigoliumBinaryCandidates(root),
    moduleCount: moduleCounts.total ?? 273,
    moduleCounts,
    strategies: ['lite', 'balanced', 'deep'],
    agents: ['query', 'audit', 'swarm', 'autopilot'],
    repoPath: `${root}/vigolium`,
    server: {
      configured: serverCfg.configured,
      baseUrl: serverCfg.baseUrl || null,
      authConfigured: Boolean(serverCfg.apiKey),
    },
  };

  if (!bin) {
    return {
      ...base,
      ok: false,
      version: null,
      message: 'Binário não encontrado — instale vigolium ou compile em vigolium/ (make build)',
    };
  }

  const version = await new Promise((resolve) => {
    const p = spawn(bin, ['version'], { stdio: ['ignore', 'pipe', 'pipe'] });
    let out = '';
    let settled = false;
    const finish = (value) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      resolve(value);
    };
    const timer = setTimeout(() => {
      try { p.kill('SIGKILL'); } catch {}
      finish(null);
    }, VERSION_TIMEOUT_MS);
    p.stdout?.on('data', (d) => {
      out += String(d);
    });
    p.on('error', () => finish(null));
    p.on('close', () => {
      const m = out.match(/Version:\s*(\S+)/i);
      finish(m ? m[1] : out.trim().split('\n')[0] || null);
    });
  });

  return {
    ...base,
    ok: true,
    version,
    message: version ? `Vigolium ${version}` : 'Vigolium disponível',
  };
}
