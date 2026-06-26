import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';

import {
  authorizeGhostCommandRequest,
  closeGhostCommandGate,
  createGhostCommandRunner,
  isAllowedIp,
  loadGhostCommandGate,
  normalizeIp,
  openGhostCommandGate,
} from '../modules/ghostcommand.mjs';
import { sanitizeVpsReconModules } from '../modules/vps-recon-policy.mjs';

test('ghostcommand: normalizeIp handles IPv4-mapped IPv6', () => {
  assert.equal(normalizeIp('::ffff:162.243.54.185'), '162.243.54.185');
});

test('ghostcommand: allowed IP is exact', () => {
  assert.equal(isAllowedIp('162.243.54.185', ['162.243.54.185']), true);
  assert.equal(isAllowedIp('162.243.54.186', ['162.243.54.185']), false);
});

test('ghostcommand: request auth checks IP and mobile key', () => {
  const req = {
    socket: { remoteAddress: '::ffff:162.243.54.185' },
    headers: { 'x-ghostcommand-key': 'abc123' },
  };
  assert.equal(authorizeGhostCommandRequest(req, { allowedIps: ['162.243.54.185'], apiKey: 'abc123' }).ok, true);
  assert.equal(authorizeGhostCommandRequest(req, { allowedIps: ['1.1.1.1'], apiKey: 'abc123' }).code, 'ip_blocked');
  assert.equal(authorizeGhostCommandRequest(req, { allowedIps: ['162.243.54.185'], apiKey: 'bad' }).code, 'mobile_key_invalid');
});

test('ghostcommand: gate open and close persists', async () => {
  const dir = await fs.mkdtemp(path.join(os.tmpdir(), 'ghostcommand-'));
  assert.equal((await loadGhostCommandGate(dir)).open, false);
  assert.equal((await openGhostCommandGate({ reason: 'test', by: 'unit' }, dir)).open, true);
  assert.equal((await loadGhostCommandGate(dir)).open, true);
  assert.equal((await closeGhostCommandGate({ reason: 'done', by: 'unit' }, dir)).open, false);
});

test('ghostcommand: runner rejects closed gate and accepts one target', async () => {
  const dir = await fs.mkdtemp(path.join(os.tmpdir(), 'ghostcommand-'));
  const runner = createGhostCommandRunner({
    config: { stateDir: dir, allowedIps: ['162.243.54.185'], apiKey: '', webhook: '', playbook: 'full-recon' },
    runPipeline: async () => {},
  });
  assert.equal((await runner.submit({ target: 'example.com' })).status, 423);
  await openGhostCommandGate({ reason: 'test', by: 'unit' }, dir);
  const accepted = await runner.submit({ target: 'example.com' });
  assert.equal(accepted.ok, true);
  assert.equal(accepted.job.target, 'example.com');
});

test('ghostcommand: runner rejects second target while running', async () => {
  const dir = await fs.mkdtemp(path.join(os.tmpdir(), 'ghostcommand-'));
  let release;
  const blocked = new Promise((resolve) => {
    release = resolve;
  });
  const runner = createGhostCommandRunner({
    config: { stateDir: dir, allowedIps: ['162.243.54.185'], apiKey: '', webhook: '', playbook: 'full-recon' },
    runPipeline: async () => blocked,
  });
  await openGhostCommandGate({ reason: 'test', by: 'unit' }, dir);
  assert.equal((await runner.submit({ target: 'one.example.com' })).ok, true);
  const second = await runner.submit({ target: 'two.example.com' });
  assert.equal(second.status, 409);
  assert.equal(second.running.target, 'one.example.com');
  release();
});

test('ghostcommand: VPS policy blocks forbidden modules but allows vigolium_dast', () => {
  assert.deepEqual(
    sanitizeVpsReconModules(['http', 'tor', 'navegation', 'shannon_whitebox', 'vigolium_audit', 'vigolium_dast']),
    ['http', 'vigolium_dast'],
  );
});
