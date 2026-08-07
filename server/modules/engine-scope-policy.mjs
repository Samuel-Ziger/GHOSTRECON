/**
 * Transporte selado de scopePolicy para engines externos (FrameSeven / Vigolium).
 * Até o CLI impor a política, o Auto falha fechado.
 */

import { createHash, randomBytes } from 'node:crypto';
import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';

export function sealEngineScopePolicy(scopePolicy) {
  if (!scopePolicy) return null;
  if (!scopePolicy || typeof scopePolicy !== 'object' || scopePolicy.schemaVersion !== 1) {
    throw new Error('scopePolicy inválida para selagem de engine');
  }
  const sealed = Object.freeze({
    schemaVersion: 1,
    kind: 'ghostrecon.engine.scope_policy',
    rootDomain: String(scopePolicy.rootDomain || '').trim().toLowerCase(),
    engagementId: String(scopePolicy.engagementId || '').trim(),
    authorizationBinding: String(scopePolicy.authorizationBinding || '').trim(),
    scopeDomains: Object.freeze([...(scopePolicy.scopeDomains || [])].map(String).sort()),
    scopeIps: Object.freeze([...(scopePolicy.scopeIps || [])].map(String).sort()),
    exclusions: Object.freeze([...(scopePolicy.exclusions || [])].map(String).sort()),
  });
  const hash = createHash('sha256').update(JSON.stringify(sealed)).digest('hex');
  return Object.freeze({ ...sealed, policyHash: hash });
}

/**
 * Engines Auto só executam com política selada quando o runtime declara suporte.
 * Override explícito de laboratório: GHOSTRECON_ENGINE_SCOPE_SUPPORT=1
 */
export function assertEngineScopeEnforcementAvailable({
  engine,
  sealedPolicy,
  env = process.env,
  engineDeclaresSupport = false,
} = {}) {
  if (!sealedPolicy) return;
  const override = /^(1|true|yes|on)$/i.test(String(env.GHOSTRECON_ENGINE_SCOPE_SUPPORT || ''));
  if (override || engineDeclaresSupport === true) return;
  throw Object.assign(
    new Error(
      `${engine} não consegue impor scopePolicy selada (${sealedPolicy.policyHash.slice(0, 12)}…); `
      + 'execução Auto bloqueada até o engine declarar suporte',
    ),
    { code: 'ENGINE_SCOPE_UNSUPPORTED', engine, policyHash: sealedPolicy.policyHash },
  );
}

export function scopePolicyPublicPayload(sealedPolicy) {
  if (!sealedPolicy) return null;
  return {
    schemaVersion: sealedPolicy.schemaVersion,
    rootDomain: sealedPolicy.rootDomain,
    engagementId: sealedPolicy.engagementId,
    scopeDomains: sealedPolicy.scopeDomains,
    scopeIps: sealedPolicy.scopeIps,
    exclusions: sealedPolicy.exclusions,
    policyHash: sealedPolicy.policyHash,
    // binding autenticador não vai para o filho
  };
}

export function scopePolicyEnvBindings(sealedPolicy, { policyFile = null } = {}) {
  if (!sealedPolicy) return Object.freeze({});
  const bindings = {
    GHOSTRECON_SCOPE_POLICY_HASH: sealedPolicy.policyHash,
    GHOSTRECON_SCOPE_POLICY_JSON: JSON.stringify(scopePolicyPublicPayload(sealedPolicy)),
  };
  if (policyFile) bindings.GHOSTRECON_SCOPE_POLICY_FILE = String(policyFile);
  return Object.freeze(bindings);
}

/**
 * Escreve JSON selado em arquivo temporário 0600 (dir 0700).
 * Retorna { filePath, dirPath, close } para cleanup.
 */
export async function writeSealedScopePolicyFile(sealedPolicy, {
  tmpDir = os.tmpdir(),
  prefix = 'ghostrecon-scope-',
} = {}) {
  if (!sealedPolicy) return null;
  const dirPath = await fs.mkdtemp(path.join(tmpDir, prefix));
  try {
    await fs.chmod(dirPath, 0o700);
  } catch { /* Windows */ }
  const filePath = path.join(dirPath, `scope-${sealedPolicy.policyHash.slice(0, 16)}-${randomBytes(3).toString('hex')}.json`);
  const payload = `${JSON.stringify(scopePolicyPublicPayload(sealedPolicy), null, 2)}\n`;
  await fs.writeFile(filePath, payload, { encoding: 'utf8', mode: 0o600, flag: 'wx' });
  try {
    await fs.chmod(filePath, 0o600);
  } catch { /* Windows */ }
  return {
    filePath,
    dirPath,
    policyHash: sealedPolicy.policyHash,
    async close() {
      await fs.rm(dirPath, { recursive: true, force: true }).catch(() => {});
    },
  };
}
