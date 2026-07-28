import fs from 'node:fs/promises';
import { constants as fsConstants } from 'node:fs';
import { createHash } from 'node:crypto';
import os from 'node:os';
import path from 'node:path';
import {
  resolveVigoliumAuthEntries,
  resolveVigoliumAuthFiles,
} from './vigolium-config.mjs';

const HEADER_NAME_RE = /^[!#$%&'*+\-.^_`|~0-9A-Za-z]{1,128}$/;
const MAX_HEADER_VALUE_LENGTH = 64 * 1024;
const MAX_SESSIONS = 64;
const MAX_AUTH_FILES = 64;
const MAX_AUTH_FILE_BYTES = 1024 * 1024;
const MAX_SECRET_WALK_DEPTH = 12;
const AUTH_FILE_IDENTITY_KEYS = Object.freeze([
  'sha256',
  'size',
  'dev',
  'ino',
  'mtimeMs',
  'mode',
  'uid',
  'nlink',
]);

function authTransportError(code, message) {
  const error = new Error(message);
  error.code = code;
  return error;
}

function samePath(left, right) {
  const normalize = (value) => path.resolve(value);
  return process.platform === 'win32'
    ? normalize(left).toLowerCase() === normalize(right).toLowerCase()
    : normalize(left) === normalize(right);
}

function pathInsideRoot(filePath, rootPath) {
  const relative = path.relative(rootPath, filePath);
  return relative === '' || (
    relative !== '..'
    && !relative.startsWith(`..${path.sep}`)
    && !path.isAbsolute(relative)
  );
}

async function resolveAllowedAuthRoots(allowedRoots) {
  const roots = [...new Set(
    (Array.isArray(allowedRoots) ? allowedRoots : [])
      .map((value) => String(value || '').trim())
      .filter(Boolean)
      .map((value) => path.resolve(value)),
  )];
  if (!roots.length) {
    throw authTransportError(
      'VIGOLIUM_AUTH_ROOT_REQUIRED',
      'raiz permitida para auth-file Vigolium não foi configurada',
    );
  }
  const resolved = [];
  for (const root of roots) {
    let real;
    try {
      real = await fs.realpath(root);
    } catch {
      throw authTransportError(
        'VIGOLIUM_AUTH_ROOT_INVALID',
        'raiz permitida para auth-file Vigolium não existe',
      );
    }
    if (!samePath(real, root)) {
      throw authTransportError(
        'VIGOLIUM_AUTH_ROOT_SYMLINK',
        'raiz permitida para auth-file Vigolium não pode conter symlink',
      );
    }
    const stat = await fs.lstat(real);
    const currentUid = typeof process.getuid === 'function' ? process.getuid() : null;
    if (!stat.isDirectory()) {
      throw authTransportError(
        'VIGOLIUM_AUTH_ROOT_NOT_DIRECTORY',
        'raiz permitida para auth-file Vigolium precisa ser diretório',
      );
    }
    if (process.platform !== 'win32' && (Number(stat.mode) & 0o077) !== 0) {
      throw authTransportError(
        'VIGOLIUM_AUTH_ROOT_PERMISSIONS',
        'raiz permitida para auth-file Vigolium deve ser privada (0700)',
      );
    }
    if (
      currentUid != null
      && Number.isFinite(Number(stat.uid))
      && Number(stat.uid) !== currentUid
    ) {
      throw authTransportError(
        'VIGOLIUM_AUTH_ROOT_OWNER',
        'raiz permitida para auth-file Vigolium pertence a outro usuário',
      );
    }
    resolved.push(real);
  }
  return resolved;
}

function statIdentity(stat, bytes) {
  return Object.freeze({
    sha256: createHash('sha256').update(bytes).digest('hex'),
    size: Number(stat.size),
    dev: Number(stat.dev),
    ino: Number(stat.ino),
    mtimeMs: Number(stat.mtimeMs),
    mode: Number(stat.mode),
    uid: Number.isFinite(Number(stat.uid)) ? Number(stat.uid) : null,
    nlink: Number(stat.nlink),
  });
}

function sameFileStat(before, after) {
  return ['size', 'dev', 'ino', 'mtimeMs', 'mode', 'uid', 'nlink']
    .every((key) => Number(before[key]) === Number(after[key]));
}

async function readValidatedAuthFile(filePath, {
  allowedRoots,
  maxBytes = MAX_AUTH_FILE_BYTES,
  signal = null,
} = {}) {
  signal?.throwIfAborted?.();
  const raw = String(filePath || '').trim();
  if (!raw || /[\r\n\0]/.test(raw)) {
    throw authTransportError('VIGOLIUM_AUTH_FILE_INVALID', 'auth-file Vigolium inválido');
  }
  const resolvedPath = path.resolve(raw);
  const roots = await resolveAllowedAuthRoots(allowedRoots);
  signal?.throwIfAborted?.();
  let realPath;
  try {
    realPath = await fs.realpath(resolvedPath);
  } catch {
    throw authTransportError(
      'VIGOLIUM_AUTH_FILE_UNAVAILABLE',
      'auth-file Vigolium não está disponível',
    );
  }
  if (!samePath(realPath, resolvedPath)) {
    throw authTransportError(
      'VIGOLIUM_AUTH_FILE_SYMLINK',
      'auth-file Vigolium ou diretório ancestral não pode ser symlink',
    );
  }
  if (!roots.some((root) => pathInsideRoot(realPath, root))) {
    throw authTransportError(
      'VIGOLIUM_AUTH_FILE_OUTSIDE_ROOT',
      'auth-file Vigolium está fora da raiz permitida',
    );
  }

  const noFollow = typeof fsConstants.O_NOFOLLOW === 'number' ? fsConstants.O_NOFOLLOW : 0;
  let handle;
  try {
    handle = await fs.open(realPath, fsConstants.O_RDONLY | noFollow);
    const before = await handle.stat();
    const openedRealPath = await fs.realpath(resolvedPath);
    const openedPathStat = await fs.stat(openedRealPath);
    if (
      !samePath(openedRealPath, realPath)
      || !roots.some((root) => pathInsideRoot(openedRealPath, root))
      || Number(openedPathStat.dev) !== Number(before.dev)
      || Number(openedPathStat.ino) !== Number(before.ino)
    ) {
      throw authTransportError(
        'VIGOLIUM_AUTH_FILE_PATH_CHANGED',
        'caminho do auth-file Vigolium mudou durante a abertura',
      );
    }
    const currentUid = typeof process.getuid === 'function' ? process.getuid() : null;
    if (!before.isFile()) {
      throw authTransportError(
        'VIGOLIUM_AUTH_FILE_NOT_REGULAR',
        'auth-file Vigolium precisa ser um arquivo regular',
      );
    }
    if (Number(before.nlink) !== 1) {
      throw authTransportError(
        'VIGOLIUM_AUTH_FILE_LINKED',
        'auth-file Vigolium não pode ter hardlinks',
      );
    }
    if ((Number(before.mode) & 0o077) !== 0) {
      throw authTransportError(
        'VIGOLIUM_AUTH_FILE_PERMISSIONS',
        'auth-file Vigolium deve ter permissões restritas ao proprietário',
      );
    }
    if (
      currentUid != null
      && Number.isFinite(Number(before.uid))
      && Number(before.uid) !== currentUid
    ) {
      throw authTransportError(
        'VIGOLIUM_AUTH_FILE_OWNER',
        'auth-file Vigolium pertence a outro usuário',
      );
    }
    if (before.size < 0 || before.size > maxBytes) {
      throw authTransportError(
        'VIGOLIUM_AUTH_FILE_TOO_LARGE',
        'auth-file Vigolium excede o limite permitido',
      );
    }
    const bytes = await handle.readFile();
    signal?.throwIfAborted?.();
    const after = await handle.stat();
    const finalRealPath = await fs.realpath(resolvedPath);
    const finalPathStat = await fs.stat(finalRealPath);
    if (
      !sameFileStat(before, after)
      || bytes.length !== Number(before.size)
      || !samePath(finalRealPath, realPath)
      || Number(finalPathStat.dev) !== Number(after.dev)
      || Number(finalPathStat.ino) !== Number(after.ino)
    ) {
      throw authTransportError(
        'VIGOLIUM_AUTH_FILE_CHANGED',
        'auth-file Vigolium mudou durante a leitura',
      );
    }
    return {
      bytes,
      identity: statIdentity(after, bytes),
      extension: ['.json', '.yaml', '.yml'].includes(path.extname(realPath).toLowerCase())
        ? path.extname(realPath).toLowerCase()
        : '.auth',
    };
  } finally {
    await handle?.close().catch(() => {});
  }
}

export async function inspectVigoliumAuthFileIdentity(filePath, options = {}) {
  const { identity } = await readValidatedAuthFile(filePath, options);
  return identity;
}

export async function inspectVigoliumAuthFileIdentities(filePaths, options = {}) {
  const paths = Array.isArray(filePaths) ? filePaths : [];
  if (paths.length > MAX_AUTH_FILES) {
    throw authTransportError(
      'VIGOLIUM_AUTH_FILE_LIMIT',
      `limite de ${MAX_AUTH_FILES} auth-files Vigolium excedido`,
    );
  }
  const identities = [];
  for (const filePath of paths) {
    options.signal?.throwIfAborted?.();
    identities.push(await inspectVigoliumAuthFileIdentity(filePath, options));
  }
  return Object.freeze(identities);
}

export function assertVigoliumAuthFileIdentity(actual, expected) {
  if (!actual || !expected || typeof actual !== 'object' || typeof expected !== 'object') {
    throw authTransportError(
      'VIGOLIUM_AUTH_FILE_IDENTITY_REQUIRED',
      'identidade esperada do auth-file Vigolium está ausente',
    );
  }
  const matches = AUTH_FILE_IDENTITY_KEYS.every((key) => (
    String(actual[key] ?? '') === String(expected[key] ?? '')
  ));
  if (!matches) {
    throw authTransportError(
      'VIGOLIUM_AUTH_FILE_IDENTITY_MISMATCH',
      'auth-file Vigolium mudou depois da aprovação',
    );
  }
}

function safeSessionName(value, fallback) {
  const raw = String(value || '').trim();
  if (!raw || /[\r\n\0]/.test(raw)) return fallback;
  return raw.replace(/[^A-Za-z0-9_.-]/g, '_').slice(0, 80) || fallback;
}

function normalizeHeader(name, value) {
  const headerName = String(name || '').trim();
  const headerValue = String(value ?? '').trim();
  if (!HEADER_NAME_RE.test(headerName)) {
    throw new Error('nome de header inválido no contexto de autenticação Vigolium');
  }
  if (!headerValue || /[\r\n\0]/.test(headerValue) || headerValue.length > MAX_HEADER_VALUE_LENGTH) {
    throw new Error('valor de header inválido no contexto de autenticação Vigolium');
  }
  return [headerName, headerValue];
}

function parseInlineEntry(value, index) {
  const raw = String(value || '').trim();
  const first = raw.indexOf(':');
  const second = first < 0 ? -1 : raw.indexOf(':', first + 1);
  if (first <= 0 || second <= first + 1) {
    throw new Error(`entrada de autenticação Vigolium inválida na posição ${index + 1}`);
  }
  const name = safeSessionName(raw.slice(0, first), `session_${index + 1}`);
  const [headerName, headerValue] = normalizeHeader(
    raw.slice(first + 1, second),
    raw.slice(second + 1),
  );
  return { name, headerName, headerValue };
}

function collectSessions(ctx = {}) {
  const sessionsByName = new Map();

  const addHeader = (sessionName, headerName, headerValue) => {
    const name = safeSessionName(sessionName, `session_${sessionsByName.size + 1}`);
    let session = sessionsByName.get(name);
    if (!session) {
      if (sessionsByName.size >= MAX_SESSIONS) {
        throw new Error(`limite de ${MAX_SESSIONS} sessões de autenticação Vigolium excedido`);
      }
      session = { name, headers: {} };
      sessionsByName.set(name, session);
    }
    session.headers[headerName] = headerValue;
  };

  const sharedAuth = ctx.auth && typeof ctx.auth === 'object' ? ctx.auth : null;
  if (sharedAuth) {
    const sharedName = safeSessionName(sharedAuth.name, 'ghostrecon');
    if (sharedAuth.headers && typeof sharedAuth.headers === 'object') {
      for (const [name, value] of Object.entries(sharedAuth.headers)) {
        if (value == null || !String(value).trim()) continue;
        const [headerName, headerValue] = normalizeHeader(name, value);
        addHeader(sharedName, headerName, headerValue);
      }
    }
    if (sharedAuth.cookie != null && String(sharedAuth.cookie).trim()) {
      const [headerName, headerValue] = normalizeHeader('Cookie', sharedAuth.cookie);
      addHeader(sharedName, headerName, headerValue);
    }
  }

  const inlineEntries = resolveVigoliumAuthEntries(ctx);
  inlineEntries.forEach((entry, index) => {
    const parsed = parseInlineEntry(entry, index);
    addHeader(parsed.name, parsed.headerName, parsed.headerValue);
  });

  return {
    sessions: [...sessionsByName.values()],
    inlineCount: inlineEntries.length,
  };
}

function collectSensitiveStrings(value, {
  depth = 0,
  key = '',
  inHeaders = false,
  out = [],
  seen = new WeakSet(),
} = {}) {
  if (depth > MAX_SECRET_WALK_DEPTH || value == null) return out;
  if (typeof value === 'string') {
    const normalizedKey = String(key).toLowerCase().replace(/[^a-z0-9]/g, '');
    if (
      inHeaders
      || /(?:authorization|cookie|token|secret|password|passwd|passphrase|credential|loginrequest)/i.test(normalizedKey)
    ) {
      const text = value.trim();
      if (text) out.push(text);
    }
    return out;
  }
  if (Array.isArray(value)) {
    if (seen.has(value)) return out;
    seen.add(value);
    for (const item of value) {
      collectSensitiveStrings(item, {
        depth: depth + 1,
        key,
        inHeaders,
        out,
        seen,
      });
    }
    return out;
  }
  if (typeof value !== 'object') return out;
  if (seen.has(value)) return out;
  seen.add(value);
  for (const [childKey, childValue] of Object.entries(value)) {
    collectSensitiveStrings(childValue, {
      depth: depth + 1,
      key: childKey,
      inHeaders: inHeaders || String(childKey).toLowerCase() === 'headers',
      out,
      seen,
    });
  }
  return out;
}

function collectSensitiveStringsFromText(text) {
  const out = [];
  const pattern =
    /["']?(?:authorization|proxy-authorization|cookie|set-cookie|x-api-key|x-auth-token|token|secret|password|passwd|passphrase|credential)["']?\s*:\s*["']?([^\r\n"',}]{1,65536})/gi;
  let match;
  while ((match = pattern.exec(String(text || ''))) != null) {
    const value = String(match[1] || '').trim();
    if (value) out.push(value);
  }
  return out;
}

function normalizeExistingAuthFiles(ctx) {
  const files = resolveVigoliumAuthFiles(ctx);
  if (files.length > MAX_AUTH_FILES) {
    throw new Error(`limite de ${MAX_AUTH_FILES} auth-files Vigolium excedido`);
  }
  return files.map((value) => {
    const file = String(value || '').trim();
    if (!file || /[\r\n\0]/.test(file)) {
      throw new Error('caminho de auth-file Vigolium inválido');
    }
    return file;
  });
}

function buildSecretRedactor(sessions, {
  extraSecrets = [],
  localPaths = [],
} = {}) {
  const secretCandidates = [];
  for (const rawSecret of extraSecrets) {
    const secret = String(rawSecret || '').trim();
    if (!secret) continue;
    secretCandidates.push(secret);
    const bearer = secret.replace(/^(?:bearer|basic)\s+/i, '').trim();
    if (bearer !== secret && bearer.length >= 8) secretCandidates.push(bearer);
    const separator = secret.indexOf('=');
    const cookieValue = separator >= 0 ? secret.slice(separator + 1).trim() : '';
    if (cookieValue.length >= 8) secretCandidates.push(cookieValue);
  }
  for (const session of sessions) {
    for (const [headerNameRaw, headerValueRaw] of Object.entries(session.headers || {})) {
      const headerName = String(headerNameRaw || '').trim().toLowerCase();
      const headerValue = String(headerValueRaw || '').trim();
      if (!headerValue) continue;
      secretCandidates.push(headerValue);

      if (headerName === 'authorization' || headerName === 'proxy-authorization') {
        const token = headerValue.replace(/^(?:bearer|basic)\s+/i, '').trim();
        if (token.length >= 8) secretCandidates.push(token);
      }
      if (headerName === 'cookie' || headerName === 'set-cookie') {
        for (const part of headerValue.split(';')) {
          const pair = part.trim();
          if (!pair) continue;
          secretCandidates.push(pair);
          const separator = pair.indexOf('=');
          const cookieValue = separator >= 0 ? pair.slice(separator + 1).trim() : '';
          if (cookieValue.length >= 8) secretCandidates.push(cookieValue);
        }
      }
    }
  }

  const secrets = [...new Set(
    secretCandidates
      .flatMap((secret) => {
        const encoded = encodeURIComponent(secret);
        return encoded !== secret ? [secret, encoded] : [secret];
      })
      .filter(Boolean),
  )].sort((left, right) => right.length - left.length);
  const paths = [...new Set(
    localPaths
      .map((value) => String(value || '').trim())
      .filter(Boolean),
  )].sort((left, right) => right.length - left.length);

  return (input) => {
    let output = String(input ?? '');
    for (const localPath of paths) {
      output = output.split(localPath).join('[LOCAL_PATH]');
    }
    for (const secret of secrets) {
      output = output.split(secret).join('<redacted>');
    }
    return output
      .replace(/(Authorization\s*:\s*)([^\r\n]+)/gi, '$1<redacted>')
      .replace(/((?:Proxy-Authorization|Cookie|Set-Cookie|X-Api-Key|X-Auth-Token)\s*:\s*)([^\r\n]+)/gi, '$1<redacted>');
  };
}

async function removeRestrictedDir(dirPath) {
  if (!dirPath) return;
  await fs.rm(dirPath, { recursive: true, force: true });
  try {
    await fs.lstat(dirPath);
  } catch (error) {
    if (error?.code === 'ENOENT') return;
    throw error;
  }
  throw new Error('cleanup do contexto temporário Vigolium não removeu o diretório');
}

/**
 * Materializa cookies/headers inline num bundle de sessão consumível por
 * `--auth-file`. O retorno nunca contém os valores sensíveis.
 */
export async function createVigoliumAuthTransport(ctx = {}, opts = {}) {
  const existingFiles = normalizeExistingAuthFiles(ctx);
  const { sessions, inlineCount } = collectSessions(ctx);
  const expectedIdentities = Array.isArray(ctx.vigoliumExpectedAuthFileIdentities)
    ? ctx.vigoliumExpectedAuthFileIdentities
    : Array.isArray(opts.expectedAuthFileIdentities)
      ? opts.expectedAuthFileIdentities
      : [];
  const strictSnapshot = ctx.vigoliumRuntimeConfigFrozen === true
    || expectedIdentities.length > 0;
  if (strictSnapshot && expectedIdentities.length !== existingFiles.length) {
    throw authTransportError(
      'VIGOLIUM_AUTH_FILE_IDENTITY_COUNT_MISMATCH',
      'quantidade de identidades dos auth-files Vigolium não corresponde ao plano',
    );
  }
  const allowedRoots = Array.isArray(opts.allowedRoots)
    ? opts.allowedRoots
    : ctx.vigoliumAuthAllowedRoots;
  const tempRoot = path.resolve(opts.tempRoot || os.tmpdir());
  let dirPath = null;
  try {
    const ensureRestrictedDir = async () => {
      if (dirPath) return dirPath;
      dirPath = await fs.mkdtemp(path.join(tempRoot, 'ghostrecon-vig-auth-'));
      await fs.chmod(dirPath, 0o700);
      return dirPath;
    };
    const transportFiles = [];
    const fileSecrets = [];
    if (existingFiles.length) {
      await ensureRestrictedDir();
      for (let index = 0; index < existingFiles.length; index += 1) {
        const snapshot = await readValidatedAuthFile(existingFiles[index], {
          allowedRoots,
          signal: ctx.signal || opts.signal || null,
        });
        if (strictSnapshot) {
          assertVigoliumAuthFileIdentity(snapshot.identity, expectedIdentities[index]);
        }
        const snapshotPath = path.join(
          dirPath,
          `auth-${String(index + 1).padStart(2, '0')}${snapshot.extension}`,
        );
        await fs.writeFile(snapshotPath, snapshot.bytes, {
          mode: 0o600,
          flag: 'wx',
        });
        await fs.chmod(snapshotPath, 0o600);
        transportFiles.push(snapshotPath);
        const text = snapshot.bytes.toString('utf8');
        try {
          fileSecrets.push(...collectSensitiveStrings(JSON.parse(text)));
        } catch {
          fileSecrets.push(...collectSensitiveStringsFromText(text));
        }
      }
    }

    let ephemeralFile = null;
    if (sessions.length) {
      await ensureRestrictedDir();
      ephemeralFile = path.join(dirPath, 'sessions.json');
      const payload = `${JSON.stringify({ sessions })}\n`;
      await fs.writeFile(ephemeralFile, payload, {
        encoding: 'utf8',
        mode: 0o600,
        flag: 'wx',
      });
      await fs.chmod(ephemeralFile, 0o600);
      transportFiles.push(ephemeralFile);
    }
    const redact = buildSecretRedactor(sessions, {
      extraSecrets: fileSecrets,
      localPaths: [
        ...existingFiles,
        ...transportFiles,
        dirPath,
      ].filter(Boolean),
    });
    const privateDbPath = dirPath ? path.join(dirPath, 'runtime.sqlite') : null;

    let cleaned = false;
    return {
      authFiles: transportFiles,
      ephemeralFile,
      // Agentes sem suporte a `--stateless` recebem este banco temporário por
      // `--db`; ele vive no mesmo diretório 0700 e é removido no cleanup.
      privateDbPath,
      inlineCount,
      sessionCount: sessions.length,
      redact,
      cleanup: async () => {
        if (cleaned) return;
        if (dirPath) await removeRestrictedDir(dirPath);
        cleaned = true;
      },
    };
  } catch (error) {
    await removeRestrictedDir(dirPath);
    throw error;
  }
}

/** Formata argv para telemetria sem revelar auth inline, headers ou paths. */
export function vigoliumArgsForLog(args = []) {
  const output = [];
  const secretValueFlags = new Set(['--auth', '-H', '--header']);
  const localPathFlags = new Set(['-o', '--output', '--db', '--source', '-T']);
  for (let index = 0; index < args.length; index += 1) {
    const value = String(args[index]);
    if (secretValueFlags.has(value)) {
      output.push(value, '<redacted>');
      index += 1;
      continue;
    }
    if (value === '--auth-file') {
      output.push(value, '<restricted-file>');
      index += 1;
      continue;
    }
    if (localPathFlags.has(value)) {
      output.push(value, '<local-path>');
      index += 1;
      continue;
    }
    if (/^(?:--auth|--header|-H)=/i.test(value)) {
      output.push(`${value.slice(0, value.indexOf('='))}=<redacted>`);
      continue;
    }
    output.push(value);
  }
  return output;
}
