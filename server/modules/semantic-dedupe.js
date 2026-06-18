function familyFromUrl(urlLike) {
  try {
    const u = new URL(String(urlLike || ''));
    return `${u.pathname.toLowerCase()}?${[...new Set([...u.searchParams.keys()].map((k) => k.toLowerCase()))].sort().join(',')}`;
  } catch {
    return String(urlLike || '').toLowerCase().slice(0, 180);
  }
}

function sourceModuleKey(f) {
  if (String(f?.sourceEngine || '').toLowerCase() === 'vigolium' && f?.moduleId) {
    return `vigolium:${String(f.moduleId).toLowerCase()}`;
  }
  const meta = typeof f?.meta === 'string' ? f.meta : '';
  const m = meta.match(/source=vigolium:([^\s]+)/i);
  return m ? `vigolium:${m[1].toLowerCase()}` : '';
}

function findingFamilyKey(f) {
  const t = String(f?.type || '');
  const val = String(f?.value || '').toLowerCase();
  const moduleKey = sourceModuleKey(f);
  // Plataforma Cloudflare repetida em tech/intel ("Server: cloudflare",
  // "Cloudflare (CF-Ray presente)", "Banner Server exposto: cloudflare") → 1 achado.
  if ((t === 'tech' || t === 'intel') && /\bcloudflare\b|cf-ray/.test(val)) {
    return 'platform:cloudflare';
  }
  if (t === 'param') {
    const v = String(f.value || '').toLowerCase();
    return `param:${v.replace(/[?=]/g, '')}`;
  }
  /** `nmap` com `url` http(s) colapsava todas as portas 80/443 do mesmo host num só achado. Chave = linha completa. */
  if (t === 'nmap') {
    return `nmap:${String(f?.value || '').toLowerCase()}`;
  }
  if (f?.url || /^https?:\/\//i.test(String(f?.value || ''))) {
    return `${t}:${moduleKey ? `${moduleKey}:` : ''}${familyFromUrl(f.url || f.value)}`;
  }
  return `${t}:${moduleKey ? `${moduleKey}:` : ''}${String(f?.value || '').toLowerCase().slice(0, 120)}`;
}

function pickBestFinding(a, b) {
  const as = Number(a.compositeScore ?? a.score ?? 0);
  const bs = Number(b.compositeScore ?? b.score ?? 0);
  if (bs !== as) return bs > as ? b : a;
  const ar = a.prio === 'high' ? 3 : a.prio === 'med' ? 2 : 1;
  const br = b.prio === 'high' ? 3 : b.prio === 'med' ? 2 : 1;
  return br > ar ? b : a;
}

export function dedupeBySemanticFamily(findings = []) {
  const bucket = new Map();
  const kept = [];
  let merged = 0;

  for (const f of findings) {
    const key = findingFamilyKey(f);
    const cur = bucket.get(key);
    if (!cur) {
      bucket.set(key, f);
      kept.push(f);
      continue;
    }
    const best = pickBestFinding(cur, f);
    if (best !== cur) {
      const idx = kept.indexOf(cur);
      if (idx >= 0) kept[idx] = best;
      bucket.set(key, best);
    }
    merged += 1;
  }

  return { findings: kept, merged };
}
