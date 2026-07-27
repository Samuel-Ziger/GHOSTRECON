import test from 'node:test';
import assert from 'node:assert/strict';

import {
  abortableDelay,
  combineAbortSignals,
  fetchWithBackoff,
} from '../modules/http-utils.js';
import { fetchCrtShSubdomains } from '../modules/subdomains.js';
import { fetchWaybackUrls } from '../modules/wayback.js';
import { fetchCommonCrawlUrls } from '../modules/commoncrawl.js';
import { runHighPrioHttpRecheck } from '../modules/recheck-high.js';
import { runOptionalPlaywrightXssProbe } from '../modules/browser-xss-verify.js';

test('sinal combinado preserva o cancelamento pai e delay abortável termina imediatamente', async () => {
  const controller = new AbortController();
  const combined = combineAbortSignals(controller.signal, 10_000);
  const reason = new Error('pipeline cancelled');
  const waiting = abortableDelay(10_000, combined);

  controller.abort(reason);

  await assert.rejects(waiting, (error) => error === reason);
  assert.equal(combined.aborted, true);
  assert.equal(combined.reason, reason);
});

test('fetchWithBackoff não repete uma requisição abortada durante o backoff', async () => {
  const controller = new AbortController();
  const reason = new Error('phase timeout');
  let calls = 0;

  const running = fetchWithBackoff(
    'https://example.test/',
    { signal: controller.signal },
    {
      retries: 3,
      fetchImpl: async () => {
        calls += 1;
        queueMicrotask(() => controller.abort(reason));
        return { status: 503 };
      },
    },
  );

  await assert.rejects(running, (error) => error === reason);
  assert.equal(calls, 1);
});

test('fontes passivas respeitam AbortSignal pai sem iniciar fetch após cancelamento', async () => {
  const cases = [
    (options) => fetchCrtShSubdomains('example.test', options),
    (options) => fetchWaybackUrls('example.test', options),
    (options) => fetchCommonCrawlUrls('example.test', options),
  ];

  for (const run of cases) {
    const controller = new AbortController();
    const reason = new Error('operator stop');
    let calls = 0;
    controller.abort(reason);

    await assert.rejects(
      run({
        signal: controller.signal,
        fetchImpl: async () => {
          calls += 1;
          throw new Error('fetch não deveria executar');
        },
      }),
      (error) => error === reason,
    );
    assert.equal(calls, 0);
  }
});

test('fontes passivas mantêm parsing retrocompatível com fetch injetado', async () => {
  const crt = await fetchCrtShSubdomains('example.test', {
    fetchImpl: async () =>
      new Response(JSON.stringify([{ name_value: '*.example.test\napi.example.test' }]), {
        status: 200,
      }),
  });
  assert.deepEqual(crt, ['api.example.test', 'example.test']);

  const wayback = await fetchWaybackUrls('example.test', {
    fetchImpl: async () =>
      new Response(JSON.stringify([['original'], ['https://example.test/a']]), {
        status: 200,
      }),
  });
  assert.deepEqual(wayback, ['https://example.test/a']);

  let commonCalls = 0;
  const common = await fetchCommonCrawlUrls('example.test', {
    fetchImpl: async () => {
      commonCalls += 1;
      if (commonCalls === 1) {
        return new Response(
          JSON.stringify([
            {
              id: 'CC-MAIN-TEST',
              'cdx-api': 'https://index.example.test/CC-MAIN-TEST-index',
            },
          ]),
          { status: 200 },
        );
      }
      return new Response(
        `${JSON.stringify({ url: 'https://example.test/a' })}\n${JSON.stringify({
          url: 'https://example.test/b',
        })}\n`,
        { status: 200 },
      );
    },
  });
  assert.deepEqual(common, ['https://example.test/a', 'https://example.test/b']);
  assert.equal(commonCalls, 2);
});

test('recheck HIGH propaga cancelamento pai à requisição em curso', async () => {
  const controller = new AbortController();
  const reason = new Error('phase deadline');
  let requestSignal = null;
  let markStarted;
  const started = new Promise((resolve) => {
    markStarted = resolve;
  });

  const running = runHighPrioHttpRecheck({
    findings: [
      {
        type: 'endpoint',
        prio: 'high',
        value: 'https://example.test/?id=1',
        url: 'https://example.test/?id=1',
      },
    ],
    signal: controller.signal,
    fetchImpl: async (_url, init) => {
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

test('Playwright opcional fecha página/browser ao cancelar navegação', async () => {
  const previous = process.env.GHOSTRECON_PLAYWRIGHT_XSS;
  process.env.GHOSTRECON_PLAYWRIGHT_XSS = '1';
  const controller = new AbortController();
  const reason = new Error('operator stop');
  let pageCloseCalls = 0;
  let browserCloseCalls = 0;
  let markGotoStarted;
  const gotoStarted = new Promise((resolve) => {
    markGotoStarted = resolve;
  });

  const page = {
    goto() {
      markGotoStarted();
      return new Promise(() => {});
    },
    async content() {
      return '<html></html>';
    },
    async close() {
      pageCloseCalls += 1;
    },
  };
  const browser = {
    async newPage() {
      return page;
    },
    async close() {
      browserCloseCalls += 1;
    },
  };

  try {
    const running = runOptionalPlaywrightXssProbe({
      findings: [
        {
          type: 'endpoint',
          url: 'https://example.test/?q=fixture',
        },
      ],
      signal: controller.signal,
      chromiumImpl: {
        async launch() {
          return browser;
        },
      },
    });

    await gotoStarted;
    controller.abort(reason);

    await assert.rejects(running, (error) => error === reason);
    assert.equal(pageCloseCalls >= 1, true);
    assert.equal(browserCloseCalls >= 1, true);
  } finally {
    if (previous == null) delete process.env.GHOSTRECON_PLAYWRIGHT_XSS;
    else process.env.GHOSTRECON_PLAYWRIGHT_XSS = previous;
  }
});
