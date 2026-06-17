import { spawn } from 'node:child_process';
import {
  ghostreconRoot,
  resolveVigoliumBinary,
  vigoliumBinaryCandidates,
} from './vigolium-config.mjs';

/**
 * @param {{ ghostRoot?: string }} opts
 */
export async function getVigoliumCapabilities(opts = {}) {
  const root = opts.ghostRoot || ghostreconRoot();
  const { bin, source } = await resolveVigoliumBinary(root);
  const base = {
    installed: Boolean(bin),
    binary: bin,
    resolveSource: source,
    candidates: vigoliumBinaryCandidates(root),
    moduleCount: 273,
    strategies: ['lite', 'balanced', 'deep'],
    agents: ['query', 'audit', 'swarm', 'autopilot'],
    repoPath: `${root}/vigolium`,
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
    p.stdout?.on('data', (d) => {
      out += String(d);
    });
    p.on('error', () => resolve(null));
    p.on('close', () => {
      const m = out.match(/Version:\s*(\S+)/i);
      resolve(m ? m[1] : out.trim().split('\n')[0] || null);
    });
  });

  return {
    ...base,
    ok: true,
    version,
    message: version ? `Vigolium ${version}` : 'Vigolium disponível',
  };
}
