import test from 'node:test';
import assert from 'node:assert/strict';

import { fingerprintLovable } from '../modules/lovable-fingerprint.js';
import {
  discoverSupabaseFromTarget,
  runSupabaseRlsAudit,
} from '../modules/supabase-rls-audit.mjs';
import {
  discoverFirebaseFromTarget,
  runFirebaseAudit,
} from '../modules/firebase-audit.mjs';
import { runSupabaseAudit } from '../modules/supabase-audit.mjs';
import { runFingerprintPhase } from '../pipeline/phases/fingerprint.mjs';

function pendingRequest(onStart) {
  return async (_url, { signal } = {}) =>
    new Promise((_resolve, reject) => {
      onStart?.(signal);
      const onAbort = () => reject(signal.reason);
      signal.addEventListener('abort', onAbort, { once: true });
      if (signal.aborted) onAbort();
    });
}

test('módulos de fingerprint não iniciam I/O quando o sinal pai já foi cancelado', async () => {
  const controller = new AbortController();
  const reason = new Error('operator cancelled fingerprint');
  controller.abort(reason);
  let calls = 0;
  const fetchImpl = async () => {
    calls += 1;
    throw new Error('fetch não deveria executar');
  };
  const requestImpl = async () => {
    calls += 1;
    throw new Error('request não deveria executar');
  };

  const cases = [
    () => fingerprintLovable('https://app.example.test/', {
      signal: controller.signal,
      fetch: fetchImpl,
    }),
    () => discoverSupabaseFromTarget('https://app.example.test/', {
      signal: controller.signal,
      fetchImpl,
    }),
    () => discoverFirebaseFromTarget('https://app.example.test/', {
      signal: controller.signal,
      fetchImpl,
    }),
    () => runSupabaseAudit(
      { supabaseUrl: 'https://project.example.test', anonKey: 'anon-key' },
      { signal: controller.signal, requestImpl },
    ),
    () => runFirebaseAudit(
      { databaseURL: 'https://firebase.example.test' },
      { signal: controller.signal, requestImpl },
    ),
    () => runFingerprintPhase({
      signal: controller.signal,
      domain: 'app.example.test',
      modules: [],
      outOfScopeList: [],
    }),
  ];

  for (const run of cases) {
    await assert.rejects(run(), (error) => error === reason);
  }
  assert.equal(calls, 0);
});

test('Lovable combina o cancelamento pai com o deadline do fetch em curso', async () => {
  const controller = new AbortController();
  const reason = new Error('fingerprint deadline');
  let requestSignal = null;
  let markStarted;
  const started = new Promise((resolve) => {
    markStarted = resolve;
  });

  const running = fingerprintLovable('https://app.example.test/', {
    signal: controller.signal,
    fetch: async (_url, init) => {
      requestSignal = init.signal;
      markStarted();
      return new Promise((_resolve, reject) => {
        init.signal.addEventListener('abort', () => reject(init.signal.reason), { once: true });
      });
    },
  });

  await started;
  controller.abort(reason);

  await assert.rejects(running, (error) => error === reason);
  assert.equal(requestSignal.aborted, true);
});

test('auditorias Supabase e Firebase não engolem cancelamento de request injetado', async () => {
  for (const run of [
    (signal, requestImpl) => runSupabaseRlsAudit(
      {
        supabaseUrl: 'https://project.example.test',
        anonKey: 'anon-key',
        bundleText: 'fixture',
      },
      {
        signal,
        requestImpl,
        tables: ['profiles'],
        writeProbes: false,
      },
    ),
    (signal, requestImpl) => runFirebaseAudit(
      { databaseURL: 'https://firebase.example.test' },
      { signal, requestImpl, writeProbes: false },
    ),
  ]) {
    const controller = new AbortController();
    const reason = new Error('module deadline');
    let receivedSignal = null;
    let markStarted;
    const started = new Promise((resolve) => {
      markStarted = resolve;
    });
    const requestImpl = pendingRequest((signal) => {
      receivedSignal = signal;
      markStarted();
    });

    const running = run(controller.signal, requestImpl);
    await started;
    controller.abort(reason);

    await assert.rejects(running, (error) => error === reason);
    assert.equal(receivedSignal, controller.signal);
    assert.equal(receivedSignal.aborted, true);
  }
});

test('auditorias descobertas fora do escopo não chegam ao executor de rede', async () => {
  let calls = 0;
  const requestImpl = async () => {
    calls += 1;
    return { status: 403, headers: {}, body: '', error: null };
  };
  const urlAllowed = (url) => new URL(url).hostname.endsWith('.example.test');

  await runSupabaseRlsAudit(
    {
      supabaseUrl: 'https://project.supabase.co',
      anonKey: 'anon-key',
      bundleText: 'fixture',
    },
    {
      requestImpl,
      urlAllowed,
      tables: ['profiles'],
      writeProbes: false,
    },
  );
  await runFirebaseAudit(
    {
      apiKey: `AIza${'A'.repeat(35)}`,
      projectId: 'outside-project',
    },
    {
      requestImpl,
      urlAllowed,
      writeProbes: false,
    },
  );

  assert.equal(calls, 0);
});
