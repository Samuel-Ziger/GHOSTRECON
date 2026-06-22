import path from 'node:path';

/**
 * Perfil operacional alinhado ao vigolium.sh da VPS:
 * -S stateless, scope-origin strict, skip external-harvest, deep, html+sqlite+jsonl inline.
 * Sem Discord nem relatório IA (fica para o finalize do GhostRecon).
 */

export function shouldUseVigoliumVpsProfile(ctx = {}) {
  if (ctx.vigoliumVpsProfile === false) return false;
  const env = String(process.env.GHOSTRECON_VIGOLIUM_VPS_PROFILE ?? '').trim().toLowerCase();
  if (env === '0' || env === 'false' || env === 'no' || env === 'off') return false;
  if (env === '1' || env === 'true' || env === 'yes' || env === 'on') return true;
  const mods = ctx.modules || [];
  return mods.includes('vigolium_dast');
}

export function shouldSkipVigoliumExternalHarvest(ctx = {}) {
  if (ctx.vigoliumSkipExternalHarvest === false) return false;
  const env = String(process.env.GHOSTRECON_VIGOLIUM_SKIP_EXTERNAL_HARVEST ?? '1').trim().toLowerCase();
  if (env === '0' || env === 'false' || env === 'no' || env === 'off') return false;
  return shouldUseVigoliumVpsProfile(ctx);
}

export function vigoliumVpsDefaultStrategy(ctx = {}) {
  return shouldUseVigoliumVpsProfile(ctx) ? 'deep' : null;
}

export function slugForVigoliumOutput(value) {
  return String(value || 'target')
    .replace(/^https?:\/\//i, '')
    .replace(/[\\/:*?"<>|\s]+/g, '-')
    .replace(/^-+|-+$/g, '')
    .slice(0, 80) || 'target';
}

export function buildVigoliumOutputBase(root, target) {
  const stamp = new Date().toISOString().replace(/[:.]/g, '-');
  const dir = path.join(root, '.runtime', 'vigolium-reports');
  return path.join(dir, `${slugForVigoliumOutput(target)}-${stamp}`);
}

export function vigoliumArtifactPaths(outputBase) {
  const base = String(outputBase || '').trim();
  return {
    jsonl: `${base}.jsonl`,
    html: `${base}.html`,
    sqlite: `${base}.sqlite`,
    logHint: base,
  };
}

export function appendVigoliumVpsScanFlags(args, ctx = {}) {
  if (!shouldUseVigoliumVpsProfile(ctx)) return args;
  if (!args.includes('-S')) args.push('-S');
  if (!args.some((a, i) => a === '--scope-origin' && args[i + 1] === 'strict')) {
    args.push('--scope-origin', 'strict');
  }
  if (shouldSkipVigoliumExternalHarvest(ctx) && !args.includes('external-harvest')) {
    args.push('--skip', 'external-harvest');
  }
  return args;
}

export function vigoliumReportPublicUrl(reportPath) {
  const file = path.basename(String(reportPath || '').trim());
  if (!file) return null;
  const port = Number(process.env.PORT || 3847);
  let host = String(process.env.HOST || '127.0.0.1').trim() || '127.0.0.1';
  if (host === '0.0.0.0') host = '127.0.0.1';
  return `http://${host}:${port}/api/vigolium/reports/${encodeURIComponent(file)}`;
}
