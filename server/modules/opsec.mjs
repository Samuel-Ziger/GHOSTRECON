/**
 * OPSEC — perfis de rede + gates intrusivos + watermarking.
 *
 * Tudo puro/stateless (exceto PROXY_POOL em memória). Sem side-effects nos
 * módulos existentes — `applyOpsec(options, profile)` devolve options enriquecidas
 * para quem quiser usar.
 *
 * Perfis (profile preset):
 *   - passive    : concurrency 2, jitter 2000-4000ms, no proxy rotation, no active mods
 *   - stealth    : concurrency 3, jitter 1500-3500ms, rotate proxies, watermark opt-in
 *   - standard   : concurrency 6, jitter 500-1200ms, no restrictions
 *   - aggressive : concurrency 16, jitter 50-200ms, parallel phases
 *
 * Intrusive gating: modules marcados requerem double-confirm (env ou CLI flag).
 */

import crypto from 'node:crypto';

export const PROFILES = {
  passive: {
    name: 'passive',
    concurrency: { dns: 4, http: 2, tls: 2, kali: 0 },
    jitterMs: [2000, 4000],
    allowIntrusive: false,
    allowProxyRotation: false,
    maxDurationMs: 15 * 60_000,
  },
  stealth: {
    name: 'stealth',
    concurrency: { dns: 6, http: 3, tls: 3, kali: 1 },
    jitterMs: [1500, 3500],
    allowIntrusive: false,
    allowProxyRotation: true,
    maxDurationMs: 30 * 60_000,
  },
  standard: {
    name: 'standard',
    concurrency: { dns: 8, http: 6, tls: 6, kali: 2 },
    jitterMs: [500, 1200],
    allowIntrusive: true,
    allowProxyRotation: true,
    maxDurationMs: 45 * 60_000,
  },
  aggressive: {
    name: 'aggressive',
    concurrency: { dns: 24, http: 16, tls: 16, kali: 6 },
    jitterMs: [50, 200],
    allowIntrusive: true,
    allowProxyRotation: true,
    maxDurationMs: 90 * 60_000,
  },
};

export function getProfile(name) {
  const p = PROFILES[String(name || 'standard').toLowerCase()];
  if (!p) throw new Error(`perfil OPSEC desconhecido: ${name}`);
  return p;
}

/**
 * Módulos marcados como intrusivos — require double-confirm para perfis
 * `passive`/`stealth` ou quando `allowIntrusive: false`.
 */
export const INTRUSIVE_MODULES = new Set([
  'sqlmap', 'nuclei', 'nuclei-aggressive', 'wpscan', 'ffuf', 'feroxbuster',
  'dirsearch', 'gobuster', 'nmap-aggressive', 'nmap-port-scan', 'nikto',
  'xss-verify', 'lfi-verify', 'sqli-verify', 'webshell-probe', 'kali-active',
  'naabu-active', 'masscan',
]);

export function isIntrusive(mod) {
  return INTRUSIVE_MODULES.has(String(mod || '').toLowerCase());
}

/**
 * Gate: dada a lista de módulos e o perfil, retorna {ok, blocked, needsConfirm}.
 * `confirm` = ack explícito (ex: --confirm-active ou env GHOSTRECON_CONFIRM_ACTIVE=1).
 */
export function gateModules({ modules = [], profile, confirm = false, engagement = null }) {
  const p = typeof profile === 'string' ? getProfile(profile) : (profile || PROFILES.standard);
  const hits = (modules || []).filter((m) => isIntrusive(m));
  if (hits.length === 0) return { ok: true, blocked: [], needsConfirm: false, profile: p.name };

  // Perfis sem intrusivos permitidos → bloqueio rígido, mesmo com confirm.
  if (!p.allowIntrusive) {
    return {
      ok: false,
      blocked: hits,
      needsConfirm: false,
      profile: p.name,
      reason: `perfil "${p.name}" proíbe módulos intrusivos: ${hits.join(', ')}`,
    };
  }

  // Engagement com ROE não assinado → requer confirm mesmo em standard/aggressive.
  if (engagement && !engagement.roeSigned) {
    if (!confirm) return { ok: false, blocked: hits, needsConfirm: true, profile: p.name, reason: 'ROE não assinado — require --confirm-active' };
  }

  // Modo stealth/standard: requer confirm para intrusivos.
  if ((p.name === 'stealth' || p.name === 'standard') && !confirm) {
    return { ok: false, blocked: hits, needsConfirm: true, profile: p.name, reason: `requer --confirm-active para: ${hits.join(', ')}` };
  }

  return { ok: true, blocked: [], needsConfirm: false, profile: p.name, acknowledged: hits };
}

// ============================================================================
// Proxy rotation
// ============================================================================

/**
 * Pool circular thread-safe (single process). Aceita HTTP e SOCKS.
 */
export function createProxyPool(proxies) {
  const list = Array.isArray(proxies) ? [...proxies].filter(Boolean) : [];
  let idx = 0;
  const pool = {
    get size() { return list.length; },
    next() {
      if (list.length === 0) return null;
      const p = list[idx % list.length];
      idx++;
      return p;
    },
    all() { return [...list]; },
    /** Remove proxy com falha recente. */
    banish(proxy) {
      const i = list.indexOf(proxy);
      if (i >= 0) list.splice(i, 1);
    },
  };
  return pool;
}

/**
 * Lê lista de proxies de env `GHOSTRECON_PROXY_POOL="http://1.1.1.1:8080,socks5://2.2.2.2:1080"`.
 */
export function loadProxyPoolFromEnv(env = process.env) {
  const raw = env.GHOSTRECON_PROXY_POOL || '';
  const list = raw.split(',').map((s) => s.trim()).filter(Boolean);
  return createProxyPool(list);
}

// ============================================================================
// Jitter
// ============================================================================

/**
 * Promise que resolve após delay aleatório em [min,max].
 */
export function jitter(profile) {
  const p = typeof profile === 'string' ? getProfile(profile) : (profile || PROFILES.standard);
  const [min, max] = p.jitterMs;
  const d = min + Math.floor(Math.random() * Math.max(1, max - min));
  return new Promise((r) => setTimeout(r, d));
}

// ============================================================================
// Watermark (correlação em logs do alvo)
// ============================================================================

/**
 * Gera watermark estável por engagement — ajuda o blue team a correlacionar
 * pedidos no log com o engagement declarado.
 *
 * Retorna { header, value, cookie } — user escolhe como injetar.
 *
 * Header padrão: X-Engagement-Id
 * Cookie padrão: gr_eng=<hash>
 *
 * O valor é um HMAC truncado sobre (engagementId || 'anon'), chaveado com
 * GHOSTRECON_WATERMARK_KEY. Se não houver key, usa hash simples SHA-1.
 */
export function buildWatermark({ engagementId = null, operator = null, key = null } = {}) {
  const base = `${engagementId || 'anon'}::${operator || '-'}`;
  const secret = key || process.env.GHOSTRECON_WATERMARK_KEY || 'ghostrecon-default';
  const mac = crypto.createHmac('sha1', secret).update(base).digest('hex').slice(0, 12);
  return {
    engagementId: engagementId || null,
    operator: operator || null,
    header: 'X-Engagement-Id',
    value: `${engagementId || 'anon'}:${mac}`,
    cookie: `gr_eng=${mac}`,
    asHeaders: { 'X-Engagement-Id': `${engagementId || 'anon'}:${mac}` },
  };
}

/**
 * Conveniência: injeta watermark headers em objeto de headers existente.
 * Não sobrescreve headers explícitos do operador.
 */
export function applyWatermarkHeaders(headers, { engagementId, operator } = {}) {
  if (!engagementId) return headers; // opt-in: sem engagement = sem watermark
  const wm = buildWatermark({ engagementId, operator });
  const out = { ...(headers || {}) };
  if (!out['X-Engagement-Id']) out['X-Engagement-Id'] = wm.value;
  if (!out['User-Agent']) out['User-Agent'] = `GHOSTRECON/1.0 (engagement=${engagementId})`;
  return out;
}
