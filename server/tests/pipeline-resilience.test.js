import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import {
  PipelinePhaseUnsettledError,
  runPipelinePhases,
} from '../pipeline/phase-executor.mjs';

function makeState(events, signal = null) {
  return {
    signal,
    emit(event) {
      events.push(event);
    },
    log(msg, level = 'info') {
      events.push({ type: 'log', msg, level });
    },
    throwIfAborted() {
      if (this.signal?.aborted) throw this.signal.reason || new Error('cancelado');
    },
  };
}

describe('pipeline phase resilience', () => {
  it('registra sucesso e preserva a ordem das fases', async () => {
    const events = [];
    const order = [];
    const state = makeState(events);

    await runPipelinePhases(
      state,
      [
        { name: 'one', run: async () => order.push('one') },
        { name: 'two', run: async () => order.push('two') },
      ],
      {
        enabled: true,
        continueOnPhaseError: true,
        phaseTimeouts: { default: 100 },
        phaseSettleGraceMs: 20,
      },
    );

    assert.deepEqual(order, ['one', 'two']);
    assert.deepEqual(
      events.filter((event) => event.type === 'phase_outcome').map((event) => event.status),
      ['done', 'done'],
    );
  });

  it('erro assentado é recuperável somente no modo opt-in', async () => {
    const events = [];
    const order = [];
    const state = makeState(events);

    await runPipelinePhases(
      state,
      [
        {
          name: 'recoverable',
          run: async () => {
            order.push('recoverable');
            throw new Error('fixture failure');
          },
        },
        { name: 'next', run: async () => order.push('next') },
      ],
      {
        enabled: true,
        continueOnPhaseError: true,
        phaseTimeouts: { default: 100 },
        phaseSettleGraceMs: 20,
      },
    );

    assert.deepEqual(order, ['recoverable', 'next']);
    const failed = events.find(
      (event) => event.type === 'phase_outcome' && event.phase === 'recoverable',
    );
    assert.equal(failed.status, 'failed');
    assert.equal(failed.recoverable, true);
    assert.equal(failed.settled, true);

    const failFastEvents = [];
    const failFastOrder = [];
    await assert.rejects(
      runPipelinePhases(
        makeState(failFastEvents),
        [
          {
            name: 'legacy',
            run: async () => {
              failFastOrder.push('legacy');
              throw new Error('legacy failure');
            },
          },
          { name: 'never', run: async () => failFastOrder.push('never') },
        ],
        { enabled: false, continueOnPhaseError: true },
      ),
      /legacy failure/,
    );
    assert.deepEqual(failFastOrder, ['legacy']);
    assert.equal(failFastEvents.some((event) => event.type === 'phase_outcome'), false);
  });

  it('timeout cooperativo aborta a fase, registra timeout e segue', async () => {
    const events = [];
    const order = [];
    let receivedAbort = false;
    const state = makeState(events);

    await runPipelinePhases(
      state,
      [
        {
          name: 'cooperative',
          run: (phaseState) =>
            new Promise((resolve) => {
              phaseState.signal.addEventListener(
                'abort',
                () => {
                  receivedAbort = true;
                  order.push('cooperative-aborted');
                  resolve();
                },
                { once: true },
              );
            }),
        },
        { name: 'next', run: async () => order.push('next') },
      ],
      {
        enabled: true,
        continueOnPhaseError: true,
        phaseTimeouts: { cooperative: 15, next: 100 },
        phaseSettleGraceMs: 50,
      },
    );

    assert.equal(receivedAbort, true);
    assert.deepEqual(order, ['cooperative-aborted', 'next']);
    const timeout = events.find(
      (event) => event.type === 'phase_outcome' && event.phase === 'cooperative',
    );
    assert.equal(timeout.status, 'timeout');
    assert.equal(timeout.settled, true);
    assert.equal(timeout.recoverable, true);
    assert.ok(
      events.some(
        (event) =>
          event.type === 'pipe' && event.name === 'cooperative' && event.state === 'timeout',
      ),
    );
  });

  it('timeout não cooperativo falha fechado e não inicia a próxima fase', async () => {
    const events = [];
    let nextStarted = false;
    let pendingTimer = null;
    const state = makeState(events);

    try {
      await assert.rejects(
        runPipelinePhases(
          state,
          [
            {
              name: 'unsettled',
              run: () =>
                new Promise((resolve) => {
                  pendingTimer = setTimeout(resolve, 5_000);
                }),
            },
            {
              name: 'never',
              run: async () => {
                nextStarted = true;
              },
            },
          ],
          {
            enabled: true,
            continueOnPhaseError: true,
            phaseTimeouts: { unsettled: 10, never: 100 },
            phaseSettleGraceMs: 20,
          },
        ),
        (error) =>
          error instanceof PipelinePhaseUnsettledError &&
          error.code === 'PIPELINE_PHASE_UNSETTLED',
      );
    } finally {
      clearTimeout(pendingTimer);
    }

    assert.equal(nextStarted, false);
    const timeout = events.find(
      (event) => event.type === 'phase_outcome' && event.phase === 'unsettled',
    );
    assert.equal(timeout.status, 'timeout');
    assert.equal(timeout.settled, false);
    assert.equal(timeout.recoverable, false);
  });

  it('cancelamento do operador sempre interrompe o pipeline', async () => {
    const events = [];
    const controller = new AbortController();
    let nextStarted = false;
    const state = makeState(events, controller.signal);
    const stopTimer = setTimeout(
      () => controller.abort(new Error('operator stop requested')),
      15,
    );

    try {
      await assert.rejects(
        runPipelinePhases(
          state,
          [
            {
              name: 'running',
              run: (phaseState) =>
                new Promise((resolve) => {
                  phaseState.signal.addEventListener('abort', resolve, { once: true });
                }),
            },
            {
              name: 'never',
              run: async () => {
                nextStarted = true;
              },
            },
          ],
          {
            enabled: true,
            continueOnPhaseError: true,
            phaseTimeouts: { default: 200 },
            phaseSettleGraceMs: 30,
          },
        ),
        /operator stop requested/,
      );
    } finally {
      clearTimeout(stopTimer);
    }

    assert.equal(nextStarted, false);
    const cancelled = events.find(
      (event) => event.type === 'phase_outcome' && event.phase === 'running',
    );
    assert.equal(cancelled.status, 'cancelled');
    assert.equal(cancelled.recoverable, false);
  });

  it('fase crítica continua fail-fast mesmo com recuperação habilitada', async () => {
    let nextStarted = false;
    await assert.rejects(
      runPipelinePhases(
        makeState([]),
        [
          {
            name: 'critical',
            recoverable: false,
            run: async () => {
              throw new Error('critical failure');
            },
          },
          {
            name: 'never',
            run: async () => {
              nextStarted = true;
            },
          },
        ],
        {
          enabled: true,
          continueOnPhaseError: true,
          phaseTimeouts: { default: 100 },
          phaseSettleGraceMs: 20,
        },
      ),
      /critical failure/,
    );
    assert.equal(nextStarted, false);
  });

  it('falhas fatais Vigolium nunca viram fase recuperável nem iniciam a próxima', async () => {
    const cases = [
      { code: 'PROCESS_ABORTED', name: 'Error' },
      { code: 'PROCESS_UNTERMINATED', name: 'Error', unterminated: true },
      { code: 'VIGOLIUM_BINARY_IDENTITY_MISMATCH', name: 'Error' },
      { code: null, name: 'AbortError' },
    ];

    for (const fixture of cases) {
      const events = [];
      let nextStarted = false;
      const fatal = new Error(`fatal fixture ${fixture.code || fixture.name}`);
      fatal.name = fixture.name;
      if (fixture.code) fatal.code = fixture.code;
      if (fixture.unterminated) fatal.unterminated = true;

      await assert.rejects(
        runPipelinePhases(
          makeState(events),
          [
            {
              name: 'go_engine',
              recoverable: true,
              run: async () => {
                throw fatal;
              },
            },
            {
              name: 'never',
              run: async () => {
                nextStarted = true;
              },
            },
          ],
          {
            enabled: true,
            continueOnPhaseError: true,
            phaseTimeouts: { default: 100 },
            phaseSettleGraceMs: 20,
          },
        ),
        (error) => error === fatal,
      );

      assert.equal(nextStarted, false);
      const outcome = events.find(
        (event) => event.type === 'phase_outcome' && event.phase === 'go_engine',
      );
      assert.equal(outcome?.status, 'failed');
      assert.equal(outcome?.recoverable, false);
      assert.equal(outcome?.settled, true);
    }
  });
});
