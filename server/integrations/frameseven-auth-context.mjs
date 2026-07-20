import crypto from 'node:crypto';
import fs from 'node:fs/promises';
import path from 'node:path';

const contexts = new Map();

function id() { return `fs-auth-${crypto.randomBytes(12).toString('hex')}`; }

export function createFrameSevenAuthContext({ target, ttlMs = 30 * 60_000 } = {}) {
  const contextId = id();
  const expiresAt = Date.now() + Math.max(60_000, ttlMs);
  const context = {
    contextId,
    target: String(target || ''),
    createdAt: new Date().toISOString(),
    expiresAt: new Date(expiresAt).toISOString(),
    status: 'pending',
    // Segredos ficam somente no processo e nunca são serializados em snapshots.
    secret: null,
  };
  contexts.set(contextId, context);
  return { ...context, secret: undefined };
}

export function markFrameSevenAuthReady(contextId, secret = null) {
  const context = contexts.get(String(contextId || ''));
  if (!context || Date.now() >= Date.parse(context.expiresAt)) return false;
  context.status = 'ready';
  context.secret = secret;
  return true;
}

export async function loadFrameSevenAuthSession(contextId, filePath) {
  const context = contexts.get(String(contextId || ''));
  if (!context || Date.now() >= Date.parse(context.expiresAt)) return false;
  const raw = JSON.parse(await fs.readFile(filePath, 'utf8'));
  const expected = new URL(context.target);
  const actual = new URL(String(raw.target || ''));
  if (raw.version !== 'v1' || expected.origin !== actual.origin) throw new Error('FrameSeven auth session does not match target origin');
  const cookies = Array.isArray(raw.cookies) ? raw.cookies.map(String).filter(Boolean) : [];
  const headers = raw.headers && typeof raw.headers === 'object' ? Object.fromEntries(Object.entries(raw.headers).map(([key, value]) => [String(key), String(value)])) : {};
  context.status = 'ready';
  context.secret = {
    cookie: cookies.join('; '),
    headers,
    endpoints: Array.isArray(raw.endpoints) ? raw.endpoints.map(String).filter((value) => {
      try { return new URL(value).origin === expected.origin; } catch { return false; }
    }) : [],
  };
  return true;
}

export function getFrameSevenAuthContext(contextId) {
  const context = contexts.get(String(contextId || ''));
  if (!context || Date.now() >= Date.parse(context.expiresAt)) {
    contexts.delete(String(contextId || ''));
    return null;
  }
  return { ...context, secret: undefined };
}

export function consumeFrameSevenAuthSecret(contextId) {
  const context = contexts.get(String(contextId || ''));
  if (!context || context.status !== 'ready' || Date.now() >= Date.parse(context.expiresAt)) return null;
  return context.secret;
}

export async function cleanupFrameSevenAuthContext(contextId, filePath = null) {
  const context = contexts.get(String(contextId || ''));
  if (!context) {
    if (filePath) await fs.rm(path.resolve(filePath), { force: true }).catch(() => {});
    return false;
  }
  context.secret = null;
  context.status = 'cleaned';
  contexts.delete(String(contextId || ''));
  if (filePath) await fs.rm(path.resolve(filePath), { force: true }).catch(() => {});
  return true;
}
