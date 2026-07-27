import fs from 'node:fs/promises';
import path from 'node:path';
import { randomUUID } from 'node:crypto';
import { ghostreconRoot } from './vigolium-config.mjs';

const HEADER_NAME_RE = /^[!#$%&'*+\-.^_`|~0-9A-Za-z]{1,128}$/;
const MAX_HEADER_VALUE_LENGTH = 64 * 1024;
const MAX_SESSIONS = 64;
const MAX_HEADERS_PER_SESSION = 128;

function cleanName(value, fallback) {
  const s = String(value || '').trim();
  return (s || fallback).replace(/[^a-zA-Z0-9_.-]/g, '_').slice(0, 80);
}

function validatedHeader(name, value) {
  const headerName = String(name || '').trim();
  const headerValue = String(value ?? '').trim();
  if (!HEADER_NAME_RE.test(headerName)) {
    throw new Error('nome de header inválido na configuração Vigolium');
  }
  if (!headerValue || /[\r\n\0]/.test(headerValue) || headerValue.length > MAX_HEADER_VALUE_LENGTH) {
    throw new Error('valor de header inválido na configuração Vigolium');
  }
  return [headerName, headerValue];
}

function parseHeaderLines(lines) {
  const out = {};
  for (const line of Array.isArray(lines) ? lines : String(lines || '').split(/\r?\n/)) {
    const s = String(line || '').trim();
    if (!s) continue;
    const idx = s.indexOf(':');
    if (idx <= 0) continue;
    const [key, value] = validatedHeader(s.slice(0, idx), s.slice(idx + 1));
    out[key] = value;
  }
  return out;
}

function normalizeSession(input = {}, index = 0) {
  const name = cleanName(input.name, index === 0 ? 'primary' : `compare_${index}`);
  const role = String(input.role || (index === 0 ? 'primary' : 'compare')).trim().toLowerCase() === 'primary'
    ? 'primary'
    : 'compare';
  const headers = parseHeaderLines(input.headerLines || input.headersText);
  if (input.headers && typeof input.headers === 'object') {
    for (const [rawName, rawValue] of Object.entries(input.headers)) {
      if (rawValue == null || !String(rawValue).trim()) continue;
      const [headerName, headerValue] = validatedHeader(rawName, rawValue);
      headers[headerName] = headerValue;
    }
  }
  const cookie = String(input.cookie || '').trim();
  const bearer = String(input.bearer || input.token || '').trim();
  if (cookie) {
    const [headerName, headerValue] = validatedHeader('Cookie', cookie);
    headers[headerName] = headerValue;
  }
  if (bearer && !headers.Authorization) {
    const [headerName, headerValue] = validatedHeader(
      'Authorization',
      bearer.startsWith('Bearer ') ? bearer : `Bearer ${bearer}`,
    );
    headers[headerName] = headerValue;
  }
  if (Object.keys(headers).length > MAX_HEADERS_PER_SESSION) {
    throw new Error(`limite de ${MAX_HEADERS_PER_SESSION} headers por sessão Vigolium excedido`);
  }

  const session = {
    name,
    role,
    headers,
  };
  if (input.login && typeof input.login === 'object') session.login = input.login;
  if (input.login_request) session.login_request = String(input.login_request);
  return session;
}

export function buildVigoliumAuthConfig(input = {}) {
  const rawSessions = Array.isArray(input.sessions) ? input.sessions : [];
  if (rawSessions.length > MAX_SESSIONS) {
    throw new Error(`limite de ${MAX_SESSIONS} sessões Vigolium excedido`);
  }
  const sessions = rawSessions.map((s, i) => normalizeSession(s, i)).filter((s) => Object.keys(s.headers || {}).length || s.login || s.login_request);

  if (!sessions.some((s) => s.role === 'primary') && sessions.length) sessions[0].role = 'primary';

  const config = {
    sessions,
    scanning_strategy: {
      session: {
        use_in_discovery: input.useInDiscovery !== false,
        compare_enabled: input.compareEnabled !== false,
      },
    },
  };
  if (Array.isArray(input.reauthOnStatus) && input.reauthOnStatus.length) {
    config.scanning_strategy.session.reauth_on_status = input.reauthOnStatus
      .map(Number)
      .filter((n) => Number.isInteger(n) && n >= 100 && n <= 599);
  }
  return config;
}

/**
 * Visão segura para API/NDJSON. Valores de autenticação e payloads de login
 * nunca atravessam a fronteira pública; somente capacidades e nomes de
 * headers ficam disponíveis para confirmação do operador.
 */
export function publicVigoliumAuthConfig(config = {}) {
  const sessions = (Array.isArray(config.sessions) ? config.sessions : []).map((session) => {
    const headers = session?.headers && typeof session.headers === 'object'
      ? session.headers
      : {};
    const headerNames = Object.keys(headers)
      .map((name) => String(name).trim())
      .filter(Boolean)
      .sort((left, right) => left.localeCompare(right));
    return {
      name: cleanName(session?.name, 'session'),
      role: session?.role === 'primary' ? 'primary' : 'compare',
      headerNames,
      hasCookie: headerNames.some((name) => name.toLowerCase() === 'cookie'),
      hasAuthorization: headerNames.some((name) => name.toLowerCase() === 'authorization'),
      hasLogin: Boolean(session?.login),
      hasLoginRequest: Boolean(session?.login_request),
    };
  });
  return {
    sessions,
    sessionCount: sessions.length,
    scanning_strategy: {
      session: {
        use_in_discovery: config?.scanning_strategy?.session?.use_in_discovery !== false,
        compare_enabled: config?.scanning_strategy?.session?.compare_enabled !== false,
        ...(Array.isArray(config?.scanning_strategy?.session?.reauth_on_status)
          ? {
              reauth_on_status: config.scanning_strategy.session.reauth_on_status
                .map(Number)
                .filter((value) => Number.isInteger(value) && value >= 100 && value <= 599),
            }
          : {}),
      },
    },
  };
}

export async function saveVigoliumAuthConfig(input = {}, opts = {}) {
  const root = opts.root || opts.ghostRoot || ghostreconRoot();
  const config = buildVigoliumAuthConfig(input);
  const name = cleanName(input.name || input.target || 'auth-config', 'auth-config');
  const dir = path.join(root, '.runtime', 'vigolium-sessions');
  await fs.mkdir(dir, { recursive: true, mode: 0o700 });
  const dirStat = await fs.lstat(dir);
  if (!dirStat.isDirectory() || dirStat.isSymbolicLink()) {
    throw new Error('diretorio de sessoes Vigolium invalido');
  }
  await fs.chmod(dir, 0o700);
  const filePath = path.join(dir, `${name}.json`);
  const tempPath = path.join(dir, `.${name}.${process.pid}.${randomUUID()}.tmp`);
  let handle = null;
  try {
    handle = await fs.open(tempPath, 'wx', 0o600);
    await handle.writeFile(`${JSON.stringify(config, null, 2)}\n`, 'utf8');
    await handle.sync();
    await handle.close();
    handle = null;
    await fs.chmod(tempPath, 0o600);
    await fs.rename(tempPath, filePath);
    await fs.chmod(filePath, 0o600);
  } catch (error) {
    await handle?.close().catch(() => {});
    await fs.rm(tempPath, { force: true }).catch(() => {});
    throw error;
  }
  return {
    ok: true,
    filePath,
    file: path.basename(filePath),
    config,
  };
}
