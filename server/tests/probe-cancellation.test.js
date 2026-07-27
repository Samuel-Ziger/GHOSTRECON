import test from 'node:test';
import assert from 'node:assert/strict';

import { probeHttp } from '../modules/probe.js';

test('probe HTTP propaga cancelamento da fase à requisição pendente', async () => {
  const controller = new AbortController();
  let requestSignal = null;
  let markFetchStarted;
  const fetchStarted = new Promise((resolve) => { markFetchStarted = resolve; });
  const pendingFetch = (_url, init) => {
    requestSignal = init.signal;
    markFetchStarted();
    return new Promise((_resolve, reject) => {
      init.signal.addEventListener('abort', () => reject(init.signal.reason), { once: true });
    });
  };

  const running = probeHttp('https://example.test/', {
    signal: controller.signal,
    fetchImpl: pendingFetch,
  });
  await fetchStarted;
  const reason = new Error('phase timeout');
  controller.abort(reason);

  await assert.rejects(running, (error) => error === reason);
  assert.equal(requestSignal.aborted, true);
});
