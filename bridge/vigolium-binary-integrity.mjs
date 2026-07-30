import fs from 'node:fs/promises';
import { constants as fsConstants } from 'node:fs';
import { createHash } from 'node:crypto';

const SHA256_RE = /^[a-f0-9]{64}$/i;

function identityError(message) {
  const error = new Error(message);
  error.code = 'VIGOLIUM_BINARY_IDENTITY_MISMATCH';
  return error;
}

export function assertVigoliumBinaryIdentityShape(expectedIdentity) {
  if (
    !expectedIdentity
    || typeof expectedIdentity !== 'object'
    || Array.isArray(expectedIdentity)
    || expectedIdentity.algorithm !== 'sha256'
    || !SHA256_RE.test(String(expectedIdentity.sha256 || ''))
    || !Number.isSafeInteger(Number(expectedIdentity.size))
    || Number(expectedIdentity.size) < 0
  ) {
    throw identityError('identidade esperada do Vigolium é inválida');
  }
  for (const key of ['dev', 'ino', 'mode']) {
    if (
      expectedIdentity[key] != null
      && (
        !Number.isSafeInteger(Number(expectedIdentity[key]))
        || Number(expectedIdentity[key]) < 0
      )
    ) {
      throw identityError(`identidade esperada do Vigolium possui ${key} inválido`);
    }
  }
  if (
    expectedIdentity.mtimeMs != null
    && (
      !Number.isFinite(Number(expectedIdentity.mtimeMs))
      || Number(expectedIdentity.mtimeMs) < 0
    )
  ) {
    throw identityError('identidade esperada do Vigolium possui mtimeMs inválido');
  }
  return expectedIdentity;
}

async function hashFileHandle(handle) {
  const hash = createHash('sha256');
  const buffer = Buffer.allocUnsafe(64 * 1024);
  let position = 0;
  while (true) {
    const { bytesRead } = await handle.read(buffer, 0, buffer.length, position);
    if (!bytesRead) break;
    hash.update(buffer.subarray(0, bytesRead));
    position += bytesRead;
  }
  return hash.digest('hex');
}

/**
 * Revalida o executável imediatamente antes do spawn. O catálogo/plano Auto
 * fornece a identidade esperada; o bridge nunca promove uma identidade nova.
 */
export async function assertVigoliumBinaryIdentity(binary, expectedIdentity) {
  if (!expectedIdentity) return null;
  assertVigoliumBinaryIdentityShape(expectedIdentity);

  const actual = await inspectVigoliumBinaryIdentity(binary);
  if (
    actual.sha256 !== String(expectedIdentity.sha256).toLowerCase()
    || actual.size !== Number(expectedIdentity.size)
    || (expectedIdentity.dev != null && actual.dev !== Number(expectedIdentity.dev))
    || (expectedIdentity.ino != null && actual.ino !== Number(expectedIdentity.ino))
    || (expectedIdentity.mtimeMs != null && actual.mtimeMs !== Number(expectedIdentity.mtimeMs))
    || (expectedIdentity.mode != null && actual.mode !== Number(expectedIdentity.mode))
  ) {
    throw identityError('executável Vigolium diverge do plano aprovado');
  }
  return actual;
}

export async function inspectVigoliumBinaryIdentity(binary) {
  const noFollow = process.platform === 'win32' ? 0 : fsConstants.O_NOFOLLOW;
  let handle;
  try {
    handle = await fs.open(
      binary,
      fsConstants.O_RDONLY | noFollow,
    );
    const before = await handle.stat();
    if (!before.isFile()) throw identityError('executável Vigolium não é arquivo regular');
    const sha256 = await hashFileHandle(handle);
    const after = await handle.stat();
    if (
      before.dev !== after.dev
      || before.ino !== after.ino
      || before.size !== after.size
      || before.mtimeMs !== after.mtimeMs
    ) {
      throw identityError('executável Vigolium mudou durante a revalidação');
    }
    return {
      algorithm: 'sha256',
      sha256,
      size: after.size,
      dev: after.dev,
      ino: after.ino,
      mtimeMs: after.mtimeMs,
    };
  } catch (error) {
    if (error?.code === 'VIGOLIUM_BINARY_IDENTITY_MISMATCH') throw error;
    throw identityError(`não foi possível revalidar o executável Vigolium: ${error?.message || error}`);
  } finally {
    await handle?.close().catch(() => {});
  }
}
