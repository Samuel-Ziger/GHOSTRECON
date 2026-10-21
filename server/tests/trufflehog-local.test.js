import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { parseTrufflehogNdjson, runTrufflehogLocal } from '../modules/trufflehog-local.mjs';

test('parseTrufflehogNdjson remove material cru da saída serializável', () => {
  const raw = 'sk-live-abcdefghijklmnopqrstuvwxyz123456';
  const text = JSON.stringify({
    DetectorName: 'Synthetic',
    Raw: raw,
    SourceMetadata: { Data: { Filesystem: { file: '/tmp/repo/.env' } } },
  });
  const findings = parseTrufflehogNdjson(text, { repoUrl: 'https://github.com/acme/repo' });
  assert.equal(findings.length, 1);
  assert.doesNotMatch(JSON.stringify(findings), new RegExp(raw));
  assert.equal(findings[0].meta.verificationDisabled, true);
});

test('runTrufflehogLocal força filesystem e --no-verification', async () => {
  const dir = await fs.mkdtemp(path.join(os.tmpdir(), 'ghostrecon-th-test-'));
  let captured;
  try {
    const result = await runTrufflehogLocal({
      directory: dir,
      env: { GHOSTRECON_TRUFFLEHOG_LOCAL_ENABLED: '1', GHOSTRECON_TRUFFLEHOG_BIN: 'trufflehog-test' },
      executor: async (command, args, opts) => {
        captured = { command, args, opts };
        return { code: 0, timedOut: false, stdout: '', stderr: '' };
      },
    });
    assert.equal(result.ok, true);
    assert.equal(captured.command, 'trufflehog-test');
    assert.equal(captured.args[0], 'filesystem');
    assert.ok(captured.args.includes('--no-verification'));
    assert.ok(captured.args.includes('--no-update'));
    assert.ok(captured.args.includes('--results=unverified,unknown'));
    assert.ok(captured.args.includes('--concurrency=2'));
    assert.equal(captured.opts.spawnOpts.env.GITHUB_TOKEN, undefined);
  } finally {
    await fs.rm(dir, { recursive: true, force: true });
  }
});
