import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, readFile, stat } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { SensitiveEvidenceVault } from '../modules/sensitive-evidence-vault.mjs';

test('vault exige opt-in e chave AES-256', () => {
  assert.throws(() => new SensitiveEvidenceVault({ root: '/tmp/fixture', key: Buffer.alloc(32) }), /opt-in/i);
  assert.throws(() => new SensitiveEvidenceVault({ root: '/tmp/fixture', key: Buffer.alloc(16), optIn: true }), /32 bytes/i);
});

test('vault cifra, usa 0600, audita por ref e recupera somente com locator', async () => {
  const parent = await mkdtemp(path.join(os.tmpdir(), 'ghost-vault-'));
  const root = path.join(parent, 'evidence');
  const events = [];
  const raw = 'fixture-jwt-pan-cvv-aws-secret-never-plaintext';
  const vault = new SensitiveEvidenceVault({
    root,
    key: Buffer.alloc(32, 7),
    optIn: true,
    audit: (event) => events.push(event),
  });
  const stored = await vault.put(raw, { kind: 'jwt_hmac_signing_key' });
  const target = path.join(root, stored.locator);
  const disk = await readFile(target, 'utf8');
  assert.doesNotMatch(disk, new RegExp(raw));
  assert.match(stored.secretRef, /^vault:sha256:/);
  if (process.platform !== 'win32') assert.equal((await stat(target)).mode & 0o777, 0o600);
  const recovered = await vault.get(stored);
  assert.equal(recovered.toString(), raw);
  recovered.fill(0);
  await vault.delete(stored);
  assert.deepEqual(events.map((event) => event.action), ['put', 'get', 'delete']);
  assert.doesNotMatch(JSON.stringify(events), new RegExp(raw));
  vault.close();
  await assert.rejects(vault.get(stored), /fechado/);
});
