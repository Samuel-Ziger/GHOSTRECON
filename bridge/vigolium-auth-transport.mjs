import fs from 'node:fs/promises';
import { constants as fsConstants } from 'node:fs';
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
    for (const item of value.slice(0, MAX_SESSIONS)) {
      collectSensitiveStrings(item, { depth: depth + 1, key, inHeaders, out });
    }
    return out;
  }
  if (typeof value !== 'object') return out;
  for (const [childKey, childValue] of Object.entries(value).slice(0, 500)) {
    collectSensitiveStrings(childValue, {
      depth: depth + 1,
      key: childKey,
      inHeaders: inHeaders || String(childKey).toLowerCase() === 'headers',
      out,
    });
  }
  return out;
}

function collectSensitiveStringsFromText(text) {
  const out = [];
  const pattern =
    /["']?(?:authorization|proxy-authorization|cookie|set-cookie|x-api-key|x-auth-token|token|secret|password|passwd|passphrase|credential)["']?\s*:\s*["']?([^\r\n"',}]{1,65536})/gi;
  let match;
  while ((match = pattern.exec(String(text || ''))) != null && out.length < 500) {
    const value = String(match[1] || '').trim();
    if (value) out.push(value);
  }
  return out;
}

async function secretsFromAuthFile(filePath) {
  const resolved = path.resolve(filePath);
  const noFollow = typeof fsConstants.O_NOFOLLOW === 'number' ? fsConstants.O_NOFOLLOW : 0;
  let handle;
  try {
    handle = await fs.open(resolved, fsConstants.O_RDONLY | noFollow);
    const stat = await handle.stat();
    if (!stat.isFile() || stat.size > MAX_AUTH_FILE_BYTES) return [];
    const raw = await handle.readFile('utf8');
    try {
      return collectSensitiveStrings(JSON.parse(raw));
    } catch {
      return collectSensitiveStringsFromText(raw);
    }
  } catch {
    // O binário continuará responsável por reportar um auth-file inexistente
    // ou inválido. Aqui a leitura serve apenas à redação de defesa em profundidade.
    return [];
  } finally {
    await handle?.close().catch(() => {});
  }
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
  const secretCandidates = [...extraSecrets];
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
  const fileSecrets = (
    await Promise.all(existingFiles.map((file) => secretsFromAuthFile(file)))
  ).flat();
  if (!sessions.length) {
    const redact = buildSecretRedactor(sessions, {
      extraSecrets: fileSecrets,
      localPaths: existingFiles,
    });
    return {
      authFiles: existingFiles,
      ephemeralFile: null,
      inlineCount,
      sessionCount: 0,
      redact,
      cleanup: async () => {},
    };
  }

  const tempRoot = path.resolve(opts.tempRoot || os.tmpdir());
  let dirPath = null;
  try {
    dirPath = await fs.mkdtemp(path.join(tempRoot, 'ghostrecon-vig-auth-'));
    await fs.chmod(dirPath, 0o700);
    const filePath = path.join(dirPath, 'sessions.json');
    const payload = `${JSON.stringify({ sessions })}\n`;
    await fs.writeFile(filePath, payload, { encoding: 'utf8', mode: 0o600, flag: 'wx' });
    await fs.chmod(filePath, 0o600);
    const redact = buildSecretRedactor(sessions, {
      extraSecrets: fileSecrets,
      localPaths: [...existingFiles, dirPath, filePath],
    });

    let cleaned = false;
    return {
      authFiles: [...existingFiles, filePath],
      ephemeralFile: filePath,
      inlineCount,
      sessionCount: sessions.length,
      redact,
      cleanup: async () => {
        if (cleaned) return;
        await removeRestrictedDir(dirPath);
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
