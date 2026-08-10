import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';

import {
  inspectFrameSevenBinaryIdentity,
  resolveFrameSevenBinary,
  runFrameSeven,
} from '../integrations/frameseven-adapter.mjs';

test('FrameSeven falha fechado sob Tor estrito', async () => {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), 'ghostrecon-fs-tor-'));
  try {
    const binary = resolveFrameSevenBinary(root, {});
    await fs.mkdir(path.dirname(binary), { recursive: true });
    await fs.writeFile(binary, 'fixture');
    await fs.chmod(binary, 0o755);
    const identity = await inspectFrameSevenBinaryIdentity(binary);
    await assert.rejects(
      runFrameSeven({
        root,
        target: 'https://example.com',
        outputDir: 'reports/tor',
        expectedBinaryIdentity: identity,
        env: { GHOSTRECON_TOR_STRICT: '1' },
        spawnImpl: () => {
          throw new Error('spawn não deveria ocorrer');
        },
      }),
      (error) => error?.code === 'FRAMESEVEN_TOR_UNSUPPORTED',
    );
  } finally {
    await fs.rm(root, { recursive: true, force: true });
  }
});
