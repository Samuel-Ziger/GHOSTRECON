import test from 'node:test';
import assert from 'node:assert/strict';

import { fetchArchiveToolUrls } from '../modules/archive-tools.js';
import { resolveArchiveToolSelection } from '../pipeline/phases/content-discovery.mjs';

test('Auto executa apenas a ferramenta de arquivo explicitamente aprovada', () => {
  assert.deepEqual(
    resolveArchiveToolSelection({
      autoModeExecution: true,
      runtimeProfile: { includeCliArchives: true },
      modules: ['gau'],
    }),
    { runGau: true, runWaybackurls: false },
  );
  assert.deepEqual(
    resolveArchiveToolSelection({
      autoModeExecution: true,
      runtimeProfile: { includeCliArchives: true },
      modules: ['waybackurls'],
    }),
    { runGau: false, runWaybackurls: true },
  );
  assert.deepEqual(
    resolveArchiveToolSelection({
      autoModeExecution: true,
      runtimeProfile: { includeCliArchives: true },
      modules: [],
    }),
    { runGau: false, runWaybackurls: false },
  );
});

test('RUN manual deep preserva gau e waybackurls implícitos', () => {
  assert.deepEqual(
    resolveArchiveToolSelection({
      autoModeExecution: false,
      runtimeProfile: { includeCliArchives: true },
      modules: [],
    }),
    { runGau: true, runWaybackurls: true },
  );
  assert.deepEqual(
    resolveArchiveToolSelection({
      autoModeExecution: false,
      runtimeProfile: { includeCliArchives: false },
      modules: ['gau'],
    }),
    { runGau: true, runWaybackurls: false },
  );
});

test('fetchArchiveToolUrls não consulta nem executa ferramenta não selecionada', async () => {
  const calls = [];
  const executor = {
    async commandExists(command, { signal }) {
      assert.equal(signal, null);
      calls.push(['exists', command]);
      return true;
    },
    async run(command, args, { timeoutMs, signal }) {
      calls.push(['run', command, args, timeoutMs, signal]);
      return {
        code: 0,
        stdout: [
          'https://example.com/from-gau',
          'https://sub.example.com/also-in-scope',
          'https://outside.invalid/rejected',
        ].join('\n'),
      };
    },
  };

  const urls = await fetchArchiveToolUrls('example.com', null, {
    runGau: true,
    runWaybackurls: false,
    executor,
  });

  assert.deepEqual(calls.map((call) => call.slice(0, 2)), [
    ['exists', 'gau'],
    ['run', 'gau'],
  ]);
  assert.deepEqual(urls, [
    'https://example.com/from-gau',
    'https://sub.example.com/also-in-scope',
  ]);
});

test('fetchArchiveToolUrls propaga cancelamento e não inicia a próxima ferramenta', async () => {
  const controller = new AbortController();
  const calls = [];
  const abort = new Error('parar archive fixture');
  abort.name = 'AbortError';
  abort.code = 'PROCESS_ABORTED';
  const executor = {
    async commandExists(command) {
      calls.push(['exists', command]);
      return true;
    },
    async run(command) {
      calls.push(['run', command]);
      controller.abort(abort);
      throw abort;
    },
  };

  await assert.rejects(
    fetchArchiveToolUrls('example.com', null, {
      runGau: true,
      runWaybackurls: true,
      signal: controller.signal,
      executor,
    }),
    (error) => error === abort,
  );
  assert.deepEqual(calls, [
    ['exists', 'gau'],
    ['run', 'gau'],
  ]);
});

test('fetchArchiveToolUrls recusa imediatamente signal já abortado', async () => {
  const controller = new AbortController();
  controller.abort(new Error('cancelado antes de começar'));
  let called = false;

  await assert.rejects(
    fetchArchiveToolUrls('example.com', null, {
      signal: controller.signal,
      executor: {
        async commandExists() {
          called = true;
          return true;
        },
        async run() {
          called = true;
          return { code: 0, stdout: '' };
        },
      },
    }),
    (error) => error?.name === 'AbortError' && error?.code === 'PROCESS_ABORTED',
  );
  assert.equal(called, false);
});
