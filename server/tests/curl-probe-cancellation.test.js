import test from 'node:test';
import assert from 'node:assert/strict';

import { runCurlProbeModule } from '../modules/curl-probe.mjs';

function abortError(signal, fallback = 'cancelado') {
  const error = signal?.reason instanceof Error ? signal.reason : new Error(fallback);
  error.name = 'AbortError';
  error.code = 'PROCESS_ABORTED';
  return error;
}

test('curl_probe recusa sinal já cancelado sem iniciar executor', async () => {
  const controller = new AbortController();
  controller.abort(new Error('operator stop'));
  let calls = 0;

  await assert.rejects(
    runCurlProbeModule({
      target: 'fixture.invalid',
      signal: controller.signal,
      execCurlImpl: async () => {
        calls += 1;
        return {};
      },
    }),
    (error) => error?.code === 'PROCESS_ABORTED',
  );
  assert.equal(calls, 0);
});

test('curl_probe propaga cancelamento do executor e não inicia probes seguintes', async () => {
  const controller = new AbortController();
  let calls = 0;
  const execCurlImpl = ({ signal }) =>
    new Promise((resolve, reject) => {
      calls += 1;
      if (signal?.aborted) {
        reject(abortError(signal));
        return;
      }
      signal?.addEventListener('abort', () => reject(abortError(signal)), { once: true });
    });

  const pending = runCurlProbeModule({
    target: 'fixture.invalid',
    signal: controller.signal,
    execCurlImpl,
  });
  setTimeout(() => controller.abort(new Error('phase timeout')), 20);

  await assert.rejects(pending, (error) => error?.code === 'PROCESS_ABORTED');
  assert.equal(calls, 1);
});
