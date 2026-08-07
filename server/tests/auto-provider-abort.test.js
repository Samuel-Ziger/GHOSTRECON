import test from 'node:test';
import assert from 'node:assert/strict';
import { detectAutoProviders } from '../auto-agent/provider-detector.mjs';

test('detectAutoProviders repropaga AbortSignal', async () => {
  const controller = new AbortController();
  controller.abort(new Error('client_disconnected'));
  await assert.rejects(
    () => detectAutoProviders({
      selected: ['codex'],
      signal: controller.signal,
      fetchImpl: async () => {
        throw new Error('não deve chamar fetch após abort');
      },
      execFileImpl: async () => {
        throw new Error('não deve chamar exec após abort');
      },
    }),
    /client_disconnected|cancelada/,
  );
});
