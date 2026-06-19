const DEFAULT_TIMEOUT_MS = 15_000;

export function resolveVigoliumServerConfig(env = process.env) {
  const baseUrl = String(env.GHOSTRECON_VIGOLIUM_SERVER || env.VIGOLIUM_SERVER || '').trim().replace(/\/+$/, '');
  const apiKey = String(env.GHOSTRECON_VIGOLIUM_API_KEY || env.VIGOLIUM_API_KEY || '').trim();
  return {
    configured: Boolean(baseUrl),
    baseUrl,
    apiKey,
  };
}

function queryString(query = {}) {
  const params = new URLSearchParams();
  for (const [k, v] of Object.entries(query || {})) {
    if (v == null || v === '') continue;
    if (Array.isArray(v)) {
      for (const item of v) params.append(k, String(item));
    } else {
      params.set(k, String(v));
    }
  }
  const s = params.toString();
  return s ? `?${s}` : '';
}

export async function vigoliumServerFetch(pathname, opts = {}) {
  const cfg = opts.config || resolveVigoliumServerConfig(opts.env);
  if (!cfg.configured) {
    return { ok: false, configured: false, status: 0, error: 'GHOSTRECON_VIGOLIUM_SERVER nao configurado' };
  }
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), opts.timeoutMs || DEFAULT_TIMEOUT_MS);
  const headers = {
    Accept: 'application/json',
    ...(opts.body != null ? { 'Content-Type': 'application/json' } : {}),
    ...(cfg.apiKey ? { Authorization: `Bearer ${cfg.apiKey}` } : {}),
    ...(opts.headers || {}),
  };
  const url = `${cfg.baseUrl}${pathname.startsWith('/') ? pathname : `/${pathname}`}${queryString(opts.query)}`;
  try {
    const res = await fetch(url, {
      method: opts.method || (opts.body != null ? 'POST' : 'GET'),
      headers,
      body: opts.body != null ? JSON.stringify(opts.body) : undefined,
      signal: controller.signal,
    });
    const text = await res.text();
    let data = null;
    try {
      data = text ? JSON.parse(text) : null;
    } catch {
      data = text;
    }
    return {
      ok: res.ok,
      configured: true,
      status: res.status,
      data,
      url,
    };
  } catch (e) {
    return {
      ok: false,
      configured: true,
      status: 0,
      error: e?.name === 'AbortError' ? 'timeout' : e?.message || String(e),
      url,
    };
  } finally {
    clearTimeout(timer);
  }
}

export async function getVigoliumServerStatus(opts = {}) {
  const cfg = resolveVigoliumServerConfig(opts.env);
  if (!cfg.configured) return { ok: false, configured: false, message: 'GHOSTRECON_VIGOLIUM_SERVER nao configurado' };
  const out = await vigoliumServerFetch('/api/modules', { ...opts, config: cfg, query: { limit: 1 } });
  return {
    ...out,
    configured: true,
    baseUrl: cfg.baseUrl,
    message: out.ok ? 'Vigolium server online' : (out.error || `HTTP ${out.status}`),
  };
}

export function serverEndpointFor(kind) {
  const map = {
    modules: '/api/modules',
    'http-records': '/api/http-records',
    findings: '/api/findings',
    scans: '/api/scans',
    oast: '/api/oast-interactions',
    'oast-interactions': '/api/oast-interactions',
    agents: '/api/agent/status/list',
    'agent-status': '/api/agent/status',
    'agent-sessions': '/api/agent/sessions',
  };
  return map[kind] || null;
}
