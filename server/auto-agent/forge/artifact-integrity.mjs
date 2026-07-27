import { createHash } from 'node:crypto';
import fs from 'node:fs/promises';
import path from 'node:path';

const FORGE_ARTIFACT_FILES = Object.freeze([
  'forge-request.json',
  'manifest.json',
  'module.mjs',
  'module.test.js',
]);

const MAX_FILE_BYTES = Object.freeze({
  'forge-request.json': 64 * 1024,
  'manifest.json': 64 * 1024,
  'module.mjs': 256 * 1024,
  'module.test.js': 256 * 1024,
});

function sha256(value) {
  return createHash('sha256').update(value).digest('hex');
}

export async function computeForgeArtifactIntegrity(dir) {
  const hash = createHash('sha256');
  hash.update('ghostrecon-forge-artifact-integrity:v1\0');
  const files = {};

  for (const name of FORGE_ARTIFACT_FILES) {
    const value = await fs.readFile(path.join(dir, name));
    const limit = MAX_FILE_BYTES[name];
    if (value.length > limit) {
      throw new Error(`${name} excede o limite de integridade Forge`);
    }
    const fileSha256 = sha256(value);
    files[name] = Object.freeze({
      bytes: value.length,
      sha256: fileSha256,
    });
    hash.update(name);
    hash.update('\0');
    hash.update(String(value.length));
    hash.update('\0');
    hash.update(value);
    hash.update('\0');
  }

  return Object.freeze({
    schemaVersion: 1,
    algorithm: 'sha256',
    artifactSha256: hash.digest('hex'),
    files: Object.freeze(files),
  });
}

export function isForgeArtifactIntegrity(value) {
  return Boolean(
    value
    && value.schemaVersion === 1
    && value.algorithm === 'sha256'
    && /^[a-f0-9]{64}$/.test(String(value.artifactSha256 || '')),
  );
}

export function sameForgeArtifactIntegrity(left, right) {
  return isForgeArtifactIntegrity(left)
    && isForgeArtifactIntegrity(right)
    && left.artifactSha256 === right.artifactSha256;
}

