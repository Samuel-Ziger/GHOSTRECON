import fs from 'node:fs/promises';
import path from 'node:path';
import { ghostreconRoot } from './vigolium-config.mjs';

function cleanName(value, fallback) {
  const s = String(value || '').trim();
  return (s || fallback).replace(/[^a-zA-Z0-9_.-]/g, '_').slice(0, 80);
}

function parseHeaderLines(lines) {
  const out = {};
  for (const line of Array.isArray(lines) ? lines : String(lines || '').split(/\r?\n/)) {
    const s = String(line || '').trim();
    if (!s) continue;
    const idx = s.indexOf(':');
    if (idx <= 0) continue;
    const k = s.slice(0, idx).trim();
    const v = s.slice(idx + 1).trim();
    if (k && v) out[k] = v;
  }
  return out;
}

function normalizeSession(input = {}, index = 0) {
  const name = cleanName(input.name, index === 0 ? 'primary' : `compare_${index}`);
  const role = String(input.role || (index === 0 ? 'primary' : 'compare')).trim().toLowerCase() === 'primary'
    ? 'primary'
    : 'compare';
  const headers = {
    ...parseHeaderLines(input.headerLines || input.headersText),
    ...(input.headers && typeof input.headers === 'object' ? input.headers : {}),
  };
  const cookie = String(input.cookie || '').trim();
  const bearer = String(input.bearer || input.token || '').trim();
  if (cookie) headers.Cookie = cookie;
  if (bearer && !headers.Authorization) headers.Authorization = bearer.startsWith('Bearer ') ? bearer : `Bearer ${bearer}`;

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

export async function saveVigoliumAuthConfig(input = {}, opts = {}) {
  const root = opts.root || opts.ghostRoot || ghostreconRoot();
  const config = buildVigoliumAuthConfig(input);
  const name = cleanName(input.name || input.target || 'auth-config', 'auth-config');
  const dir = path.join(root, '.runtime', 'vigolium-sessions');
  await fs.mkdir(dir, { recursive: true });
  const filePath = path.join(dir, `${name}.json`);
  await fs.writeFile(filePath, `${JSON.stringify(config, null, 2)}\n`, 'utf8');
  return { ok: true, filePath, config };
}

