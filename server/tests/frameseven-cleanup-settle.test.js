import test from 'node:test';
import assert from 'node:assert/strict';
import { EventEmitter } from 'node:events';
import { PassThrough } from 'node:stream';
import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';

import {
  inspectFrameSevenBinaryIdentity,
  resolveFrameSevenBinary,
  runFrameSeven,
} from '../integrations/frameseven-adapter.mjs';

function fakeProcess(onInput) {
  const child = new EventEmitter();
  child.stdout = new PassThrough();
  child.stderr = new PassThrough();
  child.stdin = {
    write: (value) => onInput?.(value, child),
    end: () => {},
  };
  child.kill = (signal) => {
    child.emit('exit', null, signal || 'SIGTERM');
    return true;
  };
  return child;
}

async function tempRoot(t) {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), 'ghostrecon-fs-cleanup-'));
  t.after(() => fs.rm(root, { recursive: true, force: true }));
  const binary = resolveFrameSevenBinary(root, {});
  await fs.mkdir(path.dirname(binary), { recursive: true });
  await fs.writeFile(binary, 'fixture-binary');
  await fs.chmod(binary, 0o755);
  return root;
}

test('FrameSeven await cleanup auth temp antes de resolver done', async (t) => {
  const root = await tempRoot(t);
  const expectedBinaryIdentity = await inspectFrameSevenBinaryIdentity(
    resolveFrameSevenBinary(root, {}),
  );
  let authDir = null;
  let authGoneBeforeResolve = false;

  const resultPromise = runFrameSeven({
    root,
    target: 'https://example.com',
    outputDir: 'reports/cleanup-settle',
    authBrowser: true,
    expectedBinaryIdentity,
    waitForAuth: async () => true,
    beforeScan: async () => {},
    spawnImpl: (_binary, args) => {
      const authFile = args[args.indexOf('-auth-session-out') + 1];
      authDir = path.dirname(authFile);
      const child = fakeProcess((_value, proc) => {
        // exit só após scanReleased (stdin write pós-beforeScan).
        queueMicrotask(() => proc.emit('exit', 0, null));
      });
      queueMicrotask(async () => {
        await fs.writeFile(authFile, JSON.stringify({
          version: 'v1',
          target: 'https://example.com/',
          cookies: [],
          headers: {},
          endpoints: [],
        }), { mode: 0o600 });
        child.stdout.write('FRAMESEVEN_AUTH_READY_V1\n');
      });
      return child;
    },
  });

  const result = await resultPromise;
  assert.equal(result.status, 'done');
  assert.ok(authDir);
  // Se cleanup não fosse awaitado, o dir ainda poderia existir neste ponto.
  await assert.rejects(fs.access(authDir), { code: 'ENOENT' });
  authGoneBeforeResolve = true;
  assert.equal(authGoneBeforeResolve, true);
});
