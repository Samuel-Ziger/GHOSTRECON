import crypto from 'node:crypto';
import { constants as fsConstants } from 'node:fs';
import fs from 'node:fs/promises';
import path from 'node:path';

const contexts = new Map();
const DEFAULT_TTL_MS = 30 * 60_000;
const MAX_SESSION_FILE_BYTES = 1024 * 1024;
const MAX_AUTH_HEADERS = 64;
const MAX_HEADER_NAME_BYTES = 128;
const MAX_HEADER_VALUE_BYTES = 64 * 1024;
const MAX_AUTH_COOKIES = 128;
const MAX_COOKIE_BYTES = 64 * 1024;
const MAX_AUTH_ENDPOINTS = 256;
const MAX_ENDPOINT_BYTES = 4_096;
const HEADER_NAME_RE = /^[!#$%&'*+\-.^_`|~0-9A-Za-z]+$/;
const BLOCKED_AUTH_HEADERS = new Set([
  'connection',
  'content-length',
  'cookie',
  'expect',
  'forwarded',
  'host',
  'keep-alive',
  'proxy-authenticate',
  'proxy-authorization',
  'set-cookie',
  'te',
  'trailer',
  'transfer-encoding',
  'upgrade',
  'x-forwarded-for',
  'x-forwarded-host',
  'x-forwarded-port',
  'x-forwarded-proto',
]);

function id() { return `fs-auth-${crypto.randomBytes(12).toString('hex')}`; }

function normalizedAuthTarget(value) {
  const target = new URL(String(value || ''));
  if (!['http:', 'https:'].includes(target.protocol)
    || target.username
    || target.password) {
    throw new Error('FrameSeven auth target must be HTTP(S) and must not contain userinfo');
  }
  return target;
}

function publicContext(context) {
  if (!context) return null;
  const { secret: _secret, filePath: _filePath, expiryTimer: _expiryTimer, ...safe } = context;
  return safe;
}

function expired(context) {
  return !context || Date.now() >= Date.parse(context.expiresAt);
}

function discardContext(contextId, { removeFile = true } = {}) {
  const key = String(contextId || '');
  const context = contexts.get(key);
  if (!context) return false;
  if (context.expiryTimer) clearTimeout(context.expiryTimer);
  context.secret = null;
  contexts.delete(key);
  if (removeFile && context.filePath) {
    void fs.rm(context.filePath, { force: true }).catch(() => {});
  }
  return true;
}

function normalizeAuthHeaders(rawHeaders) {
  if (rawHeaders == null) return {};
  if (typeof rawHeaders !== 'object' || Array.isArray(rawHeaders)) {
    throw new Error('FrameSeven auth headers must be an object');
  }
  const entries = Object.entries(rawHeaders);
  if (entries.length > MAX_AUTH_HEADERS) {
    throw new Error('FrameSeven auth headers exceed the entry limit');
  }
  const normalized = {};
  const seen = new Set();
  for (const [rawName, rawValue] of entries) {
    const name = String(rawName || '').trim();
    const lowerName = name.toLowerCase();
    if (!name
      || Buffer.byteLength(name) > MAX_HEADER_NAME_BYTES
      || !HEADER_NAME_RE.test(name)
      || BLOCKED_AUTH_HEADERS.has(lowerName)
      || seen.has(lowerName)) {
      throw new Error(`FrameSeven auth header is not allowed: ${name || '(empty)'}`);
    }
    if (typeof rawValue !== 'string'
      || Buffer.byteLength(rawValue) > MAX_HEADER_VALUE_BYTES
      || /[\r\n\0]/.test(rawValue)) {
      throw new Error(`FrameSeven auth header value is invalid: ${name}`);
    }
    seen.add(lowerName);
    normalized[name] = rawValue;
  }
  return normalized;
}

function normalizeAuthCookies(rawCookies) {
  if (rawCookies == null) return [];
  if (!Array.isArray(rawCookies) || rawCookies.length > MAX_AUTH_COOKIES) {
    throw new Error('FrameSeven auth cookies are invalid or exceed the entry limit');
  }
  let totalBytes = 0;
  return rawCookies.map((rawCookie) => {
    if (typeof rawCookie !== 'string' || /[\r\n\0]/.test(rawCookie)) {
      throw new Error('FrameSeven auth cookie is invalid');
    }
    totalBytes += Buffer.byteLength(rawCookie);
    if (totalBytes > MAX_COOKIE_BYTES) {
      throw new Error('FrameSeven auth cookies exceed the size limit');
    }
    return rawCookie.trim();
  }).filter(Boolean);
}

function normalizeAuthEndpoints(rawEndpoints, expectedOrigin) {
  if (rawEndpoints == null) return [];
  if (!Array.isArray(rawEndpoints) || rawEndpoints.length > MAX_AUTH_ENDPOINTS) {
    throw new Error('FrameSeven auth endpoints are invalid or exceed the entry limit');
  }
  return rawEndpoints.map((rawEndpoint) => {
    if (typeof rawEndpoint !== 'string'
      || Buffer.byteLength(rawEndpoint) > MAX_ENDPOINT_BYTES
      || /[\r\n\0]/.test(rawEndpoint)) {
      throw new Error('FrameSeven auth endpoint is invalid');
    }
    try {
      const endpoint = new URL(rawEndpoint);
      if (endpoint.username || endpoint.password) {
        throw new Error('FrameSeven auth endpoint must not contain userinfo');
      }
      return endpoint.origin === expectedOrigin ? endpoint.toString() : null;
    } catch (error) {
      if (/userinfo/i.test(error?.message || '')) throw error;
      return null;
    }
  }).filter(Boolean);
}

export function createFrameSevenAuthContext({
  target,
  ttlMs = DEFAULT_TTL_MS,
  filePath = null,
} = {}) {
  const normalizedTarget = normalizedAuthTarget(target);
  const boundFilePath = filePath ? path.resolve(filePath) : null;
  const contextId = id();
  const ttl = Number.isFinite(Number(ttlMs)) ? Math.max(1, Number(ttlMs)) : DEFAULT_TTL_MS;
  const expiresAt = Date.now() + ttl;
  const context = {
    contextId,
    target: normalizedTarget.toString(),
    createdAt: new Date().toISOString(),
    expiresAt: new Date(expiresAt).toISOString(),
    status: 'pending',
    // Segredos ficam somente no processo e nunca são serializados em snapshots.
    secret: null,
    filePath: boundFilePath,
    expiryTimer: null,
  };
  context.expiryTimer = setTimeout(() => discardContext(contextId), ttl);
  context.expiryTimer.unref?.();
  contexts.set(contextId, context);
  return publicContext(context);
}

export function markFrameSevenAuthReady(contextId, secret = null) {
  const context = contexts.get(String(contextId || ''));
  if (expired(context) || context.status !== 'pending') {
    if (context) discardContext(contextId);
    return false;
  }
  context.status = 'ready';
  context.secret = secret;
  return true;
}

export async function loadFrameSevenAuthSession(contextId, filePath) {
  const context = contexts.get(String(contextId || ''));
  if (expired(context) || context.status !== 'pending') {
    if (context) discardContext(contextId);
    return false;
  }
  const resolvedFile = path.resolve(filePath);
  if (context.filePath && resolvedFile !== context.filePath) {
    throw new Error('FrameSeven auth session file does not match the bound context');
  }
  const parent = await fs.lstat(path.dirname(resolvedFile));
  if (!parent.isDirectory()
    || (process.platform !== 'win32' && (parent.mode & 0o077) !== 0)
    || (typeof process.getuid === 'function'
      && Number.isInteger(parent.uid)
      && parent.uid !== process.getuid())) {
    throw new Error('FrameSeven auth session directory is invalid');
  }
  const noFollow = process.platform === 'win32' ? 0 : (fsConstants.O_NOFOLLOW || 0);
  let handle;
  let stat;
  let text;
  try {
    handle = await fs.open(resolvedFile, fsConstants.O_RDONLY | noFollow);
    stat = await handle.stat();
    if (!stat.isFile()
      || stat.size <= 0
      || stat.size > MAX_SESSION_FILE_BYTES
      || (Number.isInteger(stat.nlink) && stat.nlink !== 1)) {
      throw new Error('FrameSeven auth session file is invalid');
    }
    if (process.platform !== 'win32' && (stat.mode & 0o077) !== 0) {
      throw new Error('FrameSeven auth session file permissions are too broad');
    }
    if (typeof process.getuid === 'function'
      && Number.isInteger(stat.uid)
      && stat.uid !== process.getuid()) {
      throw new Error('FrameSeven auth session file owner is invalid');
    }
    text = await handle.readFile({ encoding: 'utf8' });
  } finally {
    await handle?.close().catch(() => {});
  }
  const raw = JSON.parse(text);
  const expected = normalizedAuthTarget(context.target);
  const actual = normalizedAuthTarget(raw.target);
  if (raw.version !== 'v1' || expected.origin !== actual.origin) {
    throw new Error('FrameSeven auth session does not match target origin');
  }
  const cookies = normalizeAuthCookies(raw.cookies);
  const headers = normalizeAuthHeaders(raw.headers);
  const current = await fs.lstat(resolvedFile);
  if (!current.isFile() || current.dev !== stat.dev || current.ino !== stat.ino) {
    throw new Error('FrameSeven auth session file changed while it was being consumed');
  }
  await fs.rm(resolvedFile, { force: true });
  context.status = 'ready';
  context.secret = {
    cookie: cookies.join('; '),
    headers,
    endpoints: normalizeAuthEndpoints(raw.endpoints, expected.origin),
  };
  context.filePath = null;
  return true;
}

export function getFrameSevenAuthContext(contextId) {
  const context = contexts.get(String(contextId || ''));
  if (expired(context)) {
    if (context) discardContext(contextId);
    return null;
  }
  return publicContext(context);
}

export function consumeFrameSevenAuthSecret(contextId) {
  const context = contexts.get(String(contextId || ''));
  if (expired(context)) {
    if (context) discardContext(contextId);
    return null;
  }
  if (context.status !== 'ready' || !context.secret) return null;
  const secret = context.secret;
  context.secret = null;
  context.status = 'consumed';
  return secret;
}

export async function cleanupFrameSevenAuthContext(contextId, filePath = null) {
  const context = contexts.get(String(contextId || ''));
  const files = new Set([filePath, context?.filePath].filter(Boolean).map((value) => path.resolve(value)));
  if (context?.expiryTimer) clearTimeout(context.expiryTimer);
  if (context) {
    context.secret = null;
    context.status = 'cleaned';
    contexts.delete(String(contextId || ''));
  }
  await Promise.all([...files].map((value) => fs.rm(value, { force: true }).catch(() => {})));
  return Boolean(context);
}
