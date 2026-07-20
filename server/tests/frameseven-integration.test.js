import test from 'node:test';
import assert from 'node:assert/strict';
import { EventEmitter } from 'node:events';
import { PassThrough } from 'node:stream';
import fs from 'node:fs/promises';
import { runFrameSeven, redactFrameSevenOutput } from '../integrations/frameseven-adapter.mjs';

function fakeProcess(onInput) {
  const child = new EventEmitter();
  child.stdout = new PassThrough();
  child.stderr = new PassThrough();
  child.stdin = { write: (value) => onInput?.(value, child) };
  child.kill = () => child.emit('exit', null, 'SIGTERM');
  return child;
}

test('unauthenticated FrameSeven never receives auth browser flags', async () => {
  let receivedArgs;
  const result = await runFrameSeven({
    root: process.cwd(), target: 'https://example.com', authBrowser: false,
    spawnImpl: (_binary, args) => {
      receivedArgs = args;
      const child = fakeProcess();
      queueMicrotask(() => child.emit('exit', 0, null));
      return child;
    },
  });
  assert.equal(result.code, 0);
  assert.equal(receivedArgs.includes('-auth-browser'), false);
  assert.equal(receivedArgs.includes('-auth-session-out'), false);
});

test('authenticated FrameSeven pauses for GhostRecon and shares captured session only in memory', async () => {
  const order = [];
  let receivedArgs;
  let writes = 0;
  await runFrameSeven({
    root: process.cwd(), target: 'https://example.com', authBrowser: true,
    waitForAuth: async () => { order.push('approved'); return true; },
    beforeScan: async (auth) => {
      order.push('ghostrecon-vigolium');
      assert.equal(auth.cookie, 'sid=secret');
      assert.equal(auth.headers.Authorization, 'Bearer secret-token');
    },
    spawnImpl: (_binary, args) => {
      receivedArgs = args;
      const child = fakeProcess(async (_value, proc) => {
        writes += 1;
        if (writes === 1) {
          const file = args[args.indexOf('-auth-session-out') + 1];
          await fs.writeFile(file, JSON.stringify({
            version: 'v1', target: 'https://example.com/', cookies: ['sid=secret'],
            headers: { Authorization: 'Bearer secret-token' }, endpoints: ['https://example.com/api/me'],
          }), { mode: 0o600 });
          proc.stdout.write('FRAMESEVEN_AUTH_READY_V1\n');
        } else {
          order.push('frameseven');
          proc.emit('exit', 0, null);
        }
      });
      return child;
    },
  });
  assert.equal(receivedArgs.includes('-auth-browser'), true);
  assert.deepEqual(order, ['approved', 'ghostrecon-vigolium', 'frameseven']);
});

test('FrameSeven output redacts headers, bearer tokens, and passwords', () => {
  const output = redactFrameSevenOutput('Authorization: Bearer abc.def\nCookie: sid=secret\npassword=hunter2');
  assert.equal(output.includes('abc.def'), false);
  assert.equal(output.includes('sid=secret'), false);
  assert.equal(output.includes('hunter2'), false);
});
