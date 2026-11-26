import net from 'node:net';

/** Hostname / IP para usar em https:// ou http:// (IPv6 precisa de []). */
export function hostLiteralForUrl(host) {
  const h = String(host ?? '').trim();
  if (!h) return h;
  if (net.isIPv6(h)) return `[${h}]`;
  return h;
}

export function targetIsIp(host) {
  const h = String(host ?? '').trim();
  return net.isIPv4(h) || net.isIPv6(h);
}

const DOMAIN_KEY_RE = /^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+$/i;

function looksLikeBareIpv6(s) {
  return typeof s === 'string' && s.includes(':') && !s.includes('://') && !s.startsWith('[');
}

function bareTargetResult(target) {
  const normalized = String(target || '').toLowerCase();
  return {
    ok: true,
    target: normalized,
    hostname: normalized,
    explicitUrl: false,
    scheme: null,
    port: null,
    authority: hostLiteralForUrl(normalized),
    origin: null,
    pathname: '/',
    basePath: '/',
    search: '',
    targetUrl: null,
  };
}

function explicitUrlResult(url) {
  const hostname = url.hostname.replace(/^\[|\]$/g, '').toLowerCase();
  const pathname = url.pathname || '/';
  // Fragmentos nunca são enviados ao servidor. Query faz parte do alvo
  // explicitamente indicado e deve sobreviver até o primeiro probe/Vigolium.
  const targetUrl = `${url.origin}${pathname}${url.search || ''}`;
  return {
    ok: true,
    target: hostname,
    hostname,
    explicitUrl: true,
    scheme: url.protocol.slice(0, -1).toLowerCase(),
    port: url.port || (url.protocol === 'https:' ? '443' : '80'),
    authority: url.host.toLowerCase(),
    origin: url.origin.toLowerCase(),
    pathname,
    basePath: pathname,
    search: url.search || '',
    targetUrl,
  };
}

/**
 * Aceita domínio, URL http(s) com host, IPv4 ou IPv6 (com ou sem []).
 *
 * `target` permanece o hostname canónico para compatibilidade com DNS/escopo.
 * Quando o operador forneceu uma URL, `targetUrl`/`origin`/`port`/`pathname`
 * preservam a origem exata para o pipeline e para engines externas.
 *
 * @returns {{ ok: true, target: string, hostname: string, explicitUrl: boolean,
 *   scheme: string|null, port: string|null, authority: string, origin: string|null,
 *   pathname: string, basePath: string, search: string, targetUrl: string|null }
 *   | { ok: false, message: string }}
 */
export function parseReconTarget(raw) {
  const s0 = String(raw ?? '').trim();
  if (!s0) return { ok: false, message: 'Alvo vazio' };

  if (net.isIPv4(s0)) return bareTargetResult(s0);
  if (net.isIPv6(s0)) return bareTargetResult(s0);

  if (/^\[[0-9a-f:]+\]$/i.test(s0)) {
    const inner = s0.slice(1, -1);
    if (net.isIPv6(inner)) return bareTargetResult(inner);
  }

  const explicitUrl = /^[a-z][a-z0-9+.-]*:\/\//i.test(s0);
  let candidate = s0;
  if (!explicitUrl) {
    candidate = `https://${candidate}`;
  }
  try {
    const u = new URL(candidate);
    if (!['http:', 'https:'].includes(u.protocol)) {
      return { ok: false, message: 'Apenas URLs HTTP(S) são aceites' };
    }
    if (u.username || u.password) {
      return { ok: false, message: 'Credenciais embutidas na URL não são aceites' };
    }
    const host = u.hostname.replace(/^\[|\]$/g, '');
    if (!host) return { ok: false, message: 'Alvo sem hostname válido' };
    if (!net.isIP(host) && !DOMAIN_KEY_RE.test(host.toLowerCase())) {
      return { ok: false, message: 'Domínio ou IP inválido' };
    }
    if (explicitUrl) return explicitUrlResult(u);

    // Alvo bare mantém o comportamento histórico (probe HTTPS+HTTP). Paths,
    // portas e queries sem scheme são ambíguos e não ganham uma origem
    // implícita; para preservar origem exata o operador deve informar http(s).
    if (u.pathname !== '/' || u.search || u.port) {
      return {
        ok: false,
        message: 'Use uma URL HTTP(S) completa ao informar porta, path ou query',
      };
    }
    if (net.isIPv4(host)) return bareTargetResult(host);
    if (net.isIPv6(host)) return bareTargetResult(host);
    const lower = host.toLowerCase();
    return bareTargetResult(lower);
  } catch {
    if (looksLikeBareIpv6(s0) && net.isIPv6(s0)) return bareTargetResult(s0);
    return { ok: false, message: 'URL ou alvo inválido' };
  }
}

/** Chave normalizada para disco / validações (domínio ou IP). */
export function isReconTargetStorageKey(s) {
  const t = String(s ?? '').trim().toLowerCase();
  if (!t) return false;
  if (net.isIPv4(t) || net.isIPv6(t)) return true;
  return /^[a-z0-9]([a-z0-9.-]*[a-z0-9])?$/.test(t);
}
