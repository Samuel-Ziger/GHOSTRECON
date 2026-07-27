import { randomUUID } from 'node:crypto';

export const STRONG_FORGE_SANDBOX_CAPABILITIES = Object.freeze({
  schemaVersion: 1,
  enforcement: 'os_sandbox',
  network: 'deny_all',
  filesystem: 'read_only',
  processIsolation: true,
});

const FORGE_SANDBOX_ATTESTATION_SCHEMA = 1;

function abortError(reason, fallback = 'Forge cancelado') {
  if (reason instanceof Error) return reason;
  const error = new Error(reason ? String(reason) : fallback);
  error.name = 'AbortError';
  error.code = 'AUTO_FORGE_CANCELLED';
  return error;
}

async function withinGrace(promise, graceMs, fallback) {
  let timer = null;
  try {
    return await Promise.race([
      promise,
      new Promise((resolve) => {
        timer = setTimeout(() => resolve(fallback), graceMs);
      }),
    ]);
  } finally {
    if (timer) clearTimeout(timer);
  }
}

export function createForgeSandboxOperationAttestation({
  operation,
  operationId,
  challenge,
  runner = 'os_sandbox',
} = {}) {
  if (!['runtime', 'test'].includes(operation)) {
    throw new Error('operação Forge inválida para atestação');
  }
  if (!operationId || !challenge) {
    throw new Error('atestação Forge exige operationId e challenge');
  }
  return Object.freeze({
    strong: true,
    verified: true,
    attestationSchemaVersion: FORGE_SANDBOX_ATTESTATION_SCHEMA,
    ...STRONG_FORGE_SANDBOX_CAPABILITIES,
    operation,
    operationId: String(operationId),
    challenge: String(challenge),
    runner: String(runner || 'os_sandbox').slice(0, 120),
    processSettled: true,
  });
}

export function validateForgeSandboxOperationAttestation(
  value,
  {
    operation,
    operationId,
    challenge,
  } = {},
) {
  const valid = Boolean(
    value?.strong === true
    && value?.verified === true
    && value?.attestationSchemaVersion === FORGE_SANDBOX_ATTESTATION_SCHEMA
    && value?.schemaVersion === STRONG_FORGE_SANDBOX_CAPABILITIES.schemaVersion
    && value?.enforcement === STRONG_FORGE_SANDBOX_CAPABILITIES.enforcement
    && value?.network === STRONG_FORGE_SANDBOX_CAPABILITIES.network
    && value?.filesystem === STRONG_FORGE_SANDBOX_CAPABILITIES.filesystem
    && value?.processIsolation === STRONG_FORGE_SANDBOX_CAPABILITIES.processIsolation
    && value?.processSettled === true
    && value?.operation === operation
    && String(value?.operationId || '') === String(operationId || '')
    && String(value?.challenge || '') === String(challenge || '')
  );
  return valid
    ? {
        ok: true,
        attestation: {
          ...createForgeSandboxOperationAttestation({
            operation,
            operationId,
            challenge,
            runner: value.runner,
          }),
        },
      }
    : { ok: false, reason: 'strong_network_sandbox_attestation_invalid' };
}

export function validateStrongForgeSandboxRunner(runner, operation) {
  const method = operation === 'runtime' ? 'runModule' : 'runTests';
  if (!runner || typeof runner !== 'object' || typeof runner[method] !== 'function') {
    return { ok: false, reason: 'strong_network_sandbox_required' };
  }
  const capabilities = runner.capabilities;
  if (
    capabilities?.schemaVersion !== STRONG_FORGE_SANDBOX_CAPABILITIES.schemaVersion
    || capabilities?.enforcement !== STRONG_FORGE_SANDBOX_CAPABILITIES.enforcement
    || capabilities?.network !== STRONG_FORGE_SANDBOX_CAPABILITIES.network
    || capabilities?.filesystem !== STRONG_FORGE_SANDBOX_CAPABILITIES.filesystem
    || capabilities?.processIsolation !== STRONG_FORGE_SANDBOX_CAPABILITIES.processIsolation
  ) {
    return { ok: false, reason: 'strong_network_sandbox_capabilities_invalid' };
  }
  return {
    ok: true,
    method,
    capabilities: { ...STRONG_FORGE_SANDBOX_CAPABILITIES },
  };
}

/**
 * Impõe um deadline no lado do GHOSTRECON mesmo quando um runner injetado
 * implementa seu próprio timeout. O runner recebe um sinal combinado e deve
 * encerrar seu processo/sandbox ao abortar.
 */
export async function runStrongForgeSandboxOperation(
  runner,
  operation,
  args,
  {
    signal = null,
    timeoutMs = 30_000,
    label = 'Forge sandbox',
    settleGraceMs = 2_000,
  } = {},
) {
  const validation = validateStrongForgeSandboxRunner(runner, operation);
  if (!validation.ok) {
    const error = new Error(validation.reason);
    error.code = 'AUTO_FORGE_STRONG_SANDBOX_REQUIRED';
    throw error;
  }
  if (signal?.aborted) throw abortError(signal.reason);

  const deadlineMs = Math.max(100, Math.min(900_000, Number(timeoutMs) || 30_000));
  const graceMs = Math.max(50, Math.min(30_000, Number(settleGraceMs) || 2_000));
  const controller = new AbortController();
  const operationId = randomUUID();
  const attestationChallenge = randomUUID();
  let timer = null;
  let externalAbort = null;
  let abortResolver = null;

  if (signal) {
    externalAbort = () => controller.abort(signal.reason);
    signal.addEventListener('abort', externalAbort, { once: true });
  }

  const timeoutError = new Error(`${label} timeout (${deadlineMs}ms)`);
  timeoutError.code = 'AUTO_FORGE_TIMEOUT';
  timer = setTimeout(() => controller.abort(timeoutError), deadlineMs);

  const aborted = new Promise((resolve) => {
    abortResolver = () => resolve({ aborted: true, reason: controller.signal.reason });
    controller.signal.addEventListener('abort', abortResolver, { once: true });
  });
  const operationPromise = Promise.resolve().then(() => runner[validation.method]({
    ...(args || {}),
    operationId,
    attestationChallenge,
    timeoutMs: deadlineMs,
    signal: controller.signal,
  }));
  const settledOperation = operationPromise.then(
    (value) => ({ settled: true, ok: true, value }),
    (error) => ({ settled: true, ok: false, error }),
  );

  try {
    const first = await Promise.race([settledOperation, aborted]);
    if (first?.aborted) {
      let settled = await withinGrace(
        settledOperation,
        graceMs,
        { settled: false },
      );
      if (!settled?.settled && typeof runner.terminateOperation === 'function') {
        const acknowledgement = await withinGrace(
          Promise.resolve()
            .then(() => runner.terminateOperation({
              operation,
              operationId,
              reason: controller.signal.reason,
              graceMs,
            }))
            .catch(() => null),
          graceMs,
          null,
        );
        if (
          acknowledgement?.acknowledged === true
          && acknowledgement?.settled === true
          && String(acknowledgement?.operationId || '') === operationId
        ) {
          settled = await withinGrace(
            settledOperation,
            graceMs,
            { settled: false },
          );
        }
      }
      if (!settled?.settled) {
        const fatal = new Error(`${label} não confirmou encerramento após abort/timeout`);
        fatal.code = 'AUTO_FORGE_SANDBOX_UNTERMINATED';
        fatal.cause = abortError(first.reason);
        fatal.operationId = operationId;
        throw fatal;
      }
      throw abortError(first.reason);
    }
    if (!first.ok) throw first.error;
    const attestation = validateForgeSandboxOperationAttestation(
      first.value?.sandboxAttestation,
      {
        operation,
        operationId,
        challenge: attestationChallenge,
      },
    );
    if (!attestation.ok) {
      const error = new Error(attestation.reason);
      error.code = 'AUTO_FORGE_SANDBOX_ATTESTATION_INVALID';
      throw error;
    }
    return {
      ...first.value,
      sandboxAttestation: attestation.attestation,
    };
  } finally {
    clearTimeout(timer);
    if (signal && externalAbort) signal.removeEventListener('abort', externalAbort);
    if (abortResolver) controller.signal.removeEventListener('abort', abortResolver);
  }
}

export function forgeSandboxAttestation(validation, actual = null, {
  operation = 'test',
} = {}) {
  if (
    validation?.ok === true
    && actual?.strong === true
    && actual?.verified === true
    && actual?.operation === operation
    && actual?.processSettled === true
  ) {
    return {
      ...actual,
      challenge: '[verified-and-redacted]',
      operationId: '[verified-and-redacted]',
    };
  }
  return {
    strong: false,
    verified: false,
    reason: validation?.reason || 'strong_network_sandbox_attestation_invalid',
  };
}

export function isStrongForgeSandboxAttestation(value) {
  return Boolean(
    value?.strong === true
    && value?.verified === true
    && value?.attestationSchemaVersion === FORGE_SANDBOX_ATTESTATION_SCHEMA
    && value?.schemaVersion === STRONG_FORGE_SANDBOX_CAPABILITIES.schemaVersion
    && value?.enforcement === STRONG_FORGE_SANDBOX_CAPABILITIES.enforcement
    && value?.network === STRONG_FORGE_SANDBOX_CAPABILITIES.network
    && value?.filesystem === STRONG_FORGE_SANDBOX_CAPABILITIES.filesystem
    && value?.processIsolation === STRONG_FORGE_SANDBOX_CAPABILITIES.processIsolation
    && value?.processSettled === true
    && value?.operation === 'test'
  );
}
