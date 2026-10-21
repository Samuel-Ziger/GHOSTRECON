import test from 'node:test';
import assert from 'node:assert/strict';
import { access } from 'node:fs/promises';
import { dirname } from 'node:path';
import {
  runFfufDiscovery,
  runDirsearchAll,
  runKaliAggressiveScan,
  summarizeDirectoryDiscoveryOutcomes,
  executeInfoDisclosureHunter,
} from '../modules/kali-scan.js';

for (const [name, run, outputFlag] of [
  ['ffuf', runFfufDiscovery, '-o'],
  ['dirsearch', runDirsearchAll, '--json-report'],
]) {
  test(`${name}: distingue sucesso sem achados, falha, timeout e indisponibilidade`, async () => {
    const cases = [
      { label: 'empty', proc: { code: 0 }, raw: '{"results":[]}', state: 'done' },
      { label: 'nonzero', proc: { code: 2 }, raw: '{"results":[]}', state: 'failed' },
      { label: 'invalid_json', proc: { code: 0 }, raw: '{', state: 'failed' },
      { label: 'invalid_schema', proc: { code: 0 }, raw: '{}', state: 'failed' },
      { label: 'timeout_result', proc: { code: 124, timedOut: true }, state: 'timeout' },
      { label: 'timeout_error', error: Object.assign(new Error('fixture timeout'), { code: 'PROCESS_TIMEOUT' }), state: 'timeout' },
    ];
    for (const row of cases) {
      let outputPath;
      let readCount = 0;
      const result = await run('https://example.test/', () => {}, {}, {
        findWordlist: () => '/fixture/wordlist',
        executor: async (cmd, args) => {
          assert.equal(cmd, name);
          outputPath = args[args.indexOf(outputFlag) + 1];
          if (row.error) throw row.error;
          return row.proc;
        },
        outputReader: async () => { readCount += 1; return row.raw; },
      });
      assert.equal(result.state, row.state, row.label);
      assert.deepEqual(result.results, [], row.label);
      if (row.proc?.code !== 0) assert.equal(readCount, 0, row.label);
      await assert.rejects(access(dirname(outputPath)), { code: 'ENOENT' });
    }
    const unavailable = await run('https://example.test/', () => {}, {}, {
      findWordlist: () => null,
      executor: async () => assert.fail('scanner não deve ser iniciado'),
    });
    assert.equal(unavailable.state, 'skipped');
    assert.equal(unavailable.reason, 'wordlist_unavailable');
  });

  test(`${name}: preserva inventário válido e propaga cancelamento/falha fatal`, async () => {
    const positive = await run('https://example.test/', () => {}, {}, {
      findWordlist: () => '/fixture/wordlist',
      executor: async () => ({ code: 0 }),
      outputReader: async () => JSON.stringify({ results: [
        { url: 'https://example.test/login', status: 401, length: 30 },
        { url: 'https://outside.test/login', status: 200, length: 30 },
      ] }),
    });
    assert.equal(positive.state, 'done');
    assert.equal(positive.results.length, 1);
    assert.equal(positive.results[0].status, 401);

    const controller = new AbortController();
    controller.abort(new Error('fixture cancelled'));
    await assert.rejects(run('https://example.test/', () => {}, { signal: controller.signal }, {
      executor: async () => assert.fail('scanner não deve ser iniciado'),
    }), /fixture cancelled/);

    for (const code of ['PROCESS_ABORTED', 'PROCESS_UNTERMINATED']) {
      let outputPath;
      await assert.rejects(run('https://example.test/', () => {}, {}, {
        findWordlist: () => '/fixture/wordlist',
        executor: async (_cmd, args) => {
          outputPath = args[args.indexOf(outputFlag) + 1];
          throw Object.assign(new Error('fixture terminal'), { code });
        },
      }), { code });
      await assert.rejects(access(dirname(outputPath)), { code: 'ENOENT' });
    }
  });
}

test('agregado preserva estado parcial e não promove falha a done', () => {
  assert.deepEqual(summarizeDirectoryDiscoveryOutcomes([
    { state: 'done', results: [{ url: 'https://example.test/login' }] },
    { state: 'timeout', results: [] },
  ]), { state: 'timeout', partial: true, resultCount: 1, attempted: 2 });
  assert.equal(summarizeDirectoryDiscoveryOutcomes([]).state, 'skipped');
});

test('pipeline emite failed/timeout reais e done apenas para saída válida', async () => {
  for (const failureMode of ['failed', 'timeout']) {
    const events = [];
    await runKaliAggressiveScan({
      domain: 'example.test', subdomainsAlive: [],
      cap: { tools: { ffuf: true, dirsearch: true } },
      runFfuf: true, runDirsearch: true,
      log: () => {}, addFinding: () => {}, emit: (event) => events.push(event),
      directoryDiscoveryDeps: {
        findWordlist: () => '/fixture/wordlist',
        executor: async (cmd) => {
          if (cmd === 'dirsearch') return { code: 0 };
          if (failureMode === 'timeout') throw Object.assign(new Error('fixture'), { code: 'PROCESS_TIMEOUT' });
          return { code: 2 };
        },
        outputReader: async () => '{"results":[]}',
      },
    });
    const ffufStates = events.filter((event) => event.type === 'pipe' && event.name === 'ffuf').map((event) => event.state);
    assert.deepEqual(ffufStates, ['active', failureMode]);
    assert.equal(events.find((event) => event.type === 'module_outcome' && event.moduleId === 'kali_ffuf')?.status, failureMode);
    assert.equal(events.find((event) => event.type === 'module_outcome' && event.moduleId === 'kali_dirsearch')?.status, 'done');
  }
});

test('pipeline cancelado não emite done nem inicia a próxima ferramenta', async () => {
  const events = [];
  await assert.rejects(runKaliAggressiveScan({
    domain: 'example.test', subdomainsAlive: [],
    cap: { tools: { ffuf: true, dirsearch: true } },
    runFfuf: true, runDirsearch: true,
    log: () => {}, addFinding: () => {}, emit: (event) => events.push(event),
    directoryDiscoveryDeps: {
      findWordlist: () => '/fixture/wordlist',
      executor: async (cmd) => {
        assert.equal(cmd, 'ffuf');
        throw Object.assign(new Error('fixture cancelled'), { code: 'PROCESS_ABORTED' });
      },
    },
  }), { code: 'PROCESS_ABORTED' });
  assert.deepEqual(events.filter((event) => event.type === 'pipe' && event.name === 'ffuf').map((event) => event.state), ['active', 'cancelled']);
  assert.equal(events.some((event) => event.name === 'dirsearch' && event.state === 'active'), false);
});

test('InfoHunter: saída/timeout/exit code não viram sucesso nem vazam stdout', async () => {
  for (const [proc, raw, expected] of [
    [{ code: 0 }, '{"achados":[]}', 'done'],
    [{ code: 2, stdout: 'Cookie: fixture-private' }, '{"achados":[]}', 'failed'],
    [{ code: 0 }, '{', 'failed'],
    [{ code: 0 }, '{}', 'failed'],
    [{ code: 124, timedOut: true }, '', 'timeout'],
  ]) {
    const out = await executeInfoDisclosureHunter({
      targetUrl: 'https://example.test/',
      cap: { tools: { python3: true } },
      executor: async () => proc,
      outputReader: async () => raw,
    });
    assert.equal(out.state, expected);
    assert.equal(out.ok, expected === 'done');
    assert.doesNotMatch(JSON.stringify(out), /fixture-private/);
  }
});

test('InfoHunter: pipeline emite falha/cancelamento real para errors e hunter', async () => {
  for (const cancelled of [false, true]) {
    const events = [];
    const run = runKaliAggressiveScan({
      domain: 'example.test', subdomainsAlive: [],
      cap: { tools: { info_disclosure_hunter: true, python3: true } },
      runInfoDisclosureHunter: true, runInfoDisclosureErrors: true,
      log: () => {}, addFinding: () => {}, emit: (event) => events.push(event),
      infoDisclosureDeps: {
        executor: async () => {
          if (cancelled) throw Object.assign(new Error('fixture cancelled'), { code: 'PROCESS_ABORTED' });
          return { code: 2 };
        },
        outputReader: async () => assert.fail('não deve ler saída de falha'),
      },
    });
    if (cancelled) await assert.rejects(run, { code: 'PROCESS_ABORTED' });
    else await run;
    for (const name of ['info_disclosure_hunter', 'info_disclosure_errors']) {
      assert.deepEqual(events.filter((event) => event.type === 'pipe' && event.name === name).map((event) => event.state),
        ['active', cancelled ? 'cancelled' : 'failed']);
    }
  }
});
