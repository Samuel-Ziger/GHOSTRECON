import {
  Worker,
  isMainThread,
  parentPort,
  workerData,
} from 'node:worker_threads';
import { parseDocument } from 'yaml';

const MAX_INPUT_BYTES = 2_000_000;
const MAX_OUTPUT_NODES = 250_000;
const MAX_OUTPUT_DEPTH = 64;
const MAX_ALIAS_COUNT = 50;

function workerError(code) {
  const error = new Error(code);
  error.name = 'ApiContractParserError';
  error.code = code;
  return error;
}

function normalizeJsonValue(root) {
  let nodes = 0;

  function visit(value, depth) {
    nodes += 1;
    if (nodes > MAX_OUTPUT_NODES) throw workerError('JSON_NODE_LIMIT');
    if (depth > MAX_OUTPUT_DEPTH) throw workerError('JSON_DEPTH_LIMIT');
    if (value == null || typeof value === 'string' || typeof value === 'boolean') return value;
    if (typeof value === 'number') {
      if (!Number.isFinite(value)) throw workerError('JSON_INVALID_NUMBER');
      return value;
    }
    if (Array.isArray(value)) return value.map((item) => visit(item, depth + 1));
    if (typeof value !== 'object') throw workerError('JSON_UNSUPPORTED_VALUE');

    const output = Object.create(null);
    for (const [key, item] of Object.entries(value)) {
      if (key.includes('\0')) throw workerError('JSON_INVALID_KEY');
      output[key] = visit(item, depth + 1);
    }
    return output;
  }

  return visit(root, 0);
}

function assertJsonUniqueKeys(source) {
  const containers = [];
  for (let index = 0; index < source.length; index += 1) {
    const char = source[index];
    if (char === '{') {
      containers.push({ type: 'object', keys: new Set() });
      continue;
    }
    if (char === '[') {
      containers.push({ type: 'array' });
      continue;
    }
    if (char === '}' || char === ']') {
      containers.pop();
      continue;
    }
    if (char !== '"') continue;

    const start = index;
    let closed = false;
    for (index += 1; index < source.length; index += 1) {
      if (source[index] === '\\') {
        index += 1;
        continue;
      }
      if (source[index] === '"') {
        closed = true;
        break;
      }
    }
    if (!closed) throw workerError('JSON_PARSE_ERROR');
    let next = index + 1;
    // JSON permits exactly SP, HTAB, CR and LF as insignificant whitespace.
    // Using `\s` here would accept additional Unicode separators that the
    // actual JSON grammar rejects.
    while (/[ \t\r\n]/u.test(source[next] || '')) next += 1;
    const container = containers.at(-1);
    if (source[next] !== ':' || container?.type !== 'object') continue;
    let key;
    try {
      key = JSON.parse(source.slice(start, index + 1));
    } catch {
      throw workerError('JSON_PARSE_ERROR');
    }
    if (container.keys.has(key)) throw workerError('JSON_DUPLICATE_KEY');
    container.keys.add(key);
  }
}

function parseJsonStrict(source) {
  if (typeof source !== 'string' || Buffer.byteLength(source, 'utf8') > MAX_INPUT_BYTES) {
    throw workerError('JSON_INPUT_LIMIT');
  }
  const normalizedSource = source.charCodeAt(0) === 0xFEFF ? source.slice(1) : source;
  assertJsonUniqueKeys(normalizedSource);
  try {
    return normalizeJsonValue(JSON.parse(normalizedSource));
  } catch (error) {
    if (String(error?.code || '').startsWith('JSON_')) throw error;
    throw workerError('JSON_PARSE_ERROR');
  }
}

export function parseJsonDocumentStrict(source) {
  if (!isMainThread) throw new Error('strict parser is only exposed on the main thread');
  return parseJsonStrict(source);
}

function normalizeYamlValue(root) {
  let nodes = 0;

  function visit(value, depth) {
    nodes += 1;
    if (nodes > MAX_OUTPUT_NODES) throw workerError('YAML_NODE_LIMIT');
    if (depth > MAX_OUTPUT_DEPTH) throw workerError('YAML_DEPTH_LIMIT');
    if (value == null || typeof value === 'string' || typeof value === 'boolean') return value;
    if (typeof value === 'number') {
      if (!Number.isFinite(value)) throw workerError('YAML_INVALID_NUMBER');
      return value;
    }
    if (Array.isArray(value)) return value.map((item) => visit(item, depth + 1));
    if (!(value instanceof Map)) throw workerError('YAML_UNSUPPORTED_VALUE');

    const output = Object.create(null);
    for (const [key, item] of value.entries()) {
      if (typeof key !== 'string' || key.includes('\0')) throw workerError('YAML_INVALID_KEY');
      // Merge keys are deliberately unsupported. With `merge: false` the
      // library would otherwise expose `<<` as an ordinary key.
      if (key === '<<') throw workerError('YAML_MERGE_KEY_DISABLED');
      if (Object.hasOwn(output, key)) throw workerError('YAML_DUPLICATE_KEY');
      output[key] = visit(item, depth + 1);
    }
    return output;
  }

  return visit(root, 0);
}

function parseYamlStrict(source) {
  if (typeof source !== 'string' || Buffer.byteLength(source, 'utf8') > MAX_INPUT_BYTES) {
    throw workerError('YAML_INPUT_LIMIT');
  }
  const document = parseDocument(source, {
    version: '1.2',
    schema: 'core',
    strict: true,
    uniqueKeys: true,
    stringKeys: true,
    merge: false,
    resolveKnownTags: false,
    customTags: [],
    prettyErrors: false,
    logLevel: 'error',
  });
  if (document.errors.length > 0) throw workerError('YAML_PARSE_ERROR');
  // Unknown/unresolved tags are outside the accepted transport profile.
  // Explicit tags from YAML 1.2 core (for example `!!str`) remain valid.
  if (document.warnings.length > 0) throw workerError('YAML_UNSUPPORTED_TAG');
  const value = document.toJS({
    mapAsMap: true,
    maxAliasCount: MAX_ALIAS_COUNT,
  });
  return normalizeYamlValue(value);
}

if (!isMainThread) {
  try {
    const value = workerData?.encoding === 'json'
      ? parseJsonStrict(workerData?.source)
      : parseYamlStrict(workerData?.source);
    parentPort?.postMessage({ ok: true, value });
  } catch (error) {
    parentPort?.postMessage({
      ok: false,
      code: String(error?.code || 'YAML_PARSE_ERROR').slice(0, 80),
    });
  }
}

function abortReason(signal) {
  return signal?.reason || new DOMException('The operation was aborted', 'AbortError');
}

function parseDocumentInWorker(source, { signal = null, encoding = 'yaml' } = {}) {
  if (!isMainThread) throw new Error('parser worker cannot spawn recursively');
  if (signal?.aborted) return Promise.reject(abortReason(signal));
  if (typeof source !== 'string' || Buffer.byteLength(source, 'utf8') > MAX_INPUT_BYTES) {
    return Promise.reject(workerError(encoding === 'json' ? 'JSON_INPUT_LIMIT' : 'YAML_INPUT_LIMIT'));
  }

  return new Promise((resolve, reject) => {
    const worker = new Worker(new URL(import.meta.url), {
      workerData: { source, encoding },
      // Parsing must not inherit caller-only flags such as --input-type,
      // --test or debugger settings. The file URL and package type already
      // determine ESM semantics for this isolated worker.
      execArgv: [],
      resourceLimits: {
        maxOldGenerationSizeMb: 64,
        maxYoungGenerationSizeMb: 16,
        stackSizeMb: 4,
      },
    });
    let settled = false;
    let terminating = false;

    const cleanup = () => signal?.removeEventListener('abort', onAbort);
    const finish = (callback, value) => {
      if (settled) return;
      settled = true;
      cleanup();
      callback(value);
    };
    const terminateThen = (callback, value) => {
      if (settled || terminating) return;
      terminating = true;
      let termination;
      try {
        termination = worker.terminate();
      } catch {
        finish(callback, value);
        return;
      }
      Promise.resolve(termination).then(
        () => finish(callback, value),
        () => finish(callback, value),
      );
    };
    const onAbort = () => terminateThen(reject, abortReason(signal));

    worker.once('message', (message) => {
      if (terminating) return;
      if (message?.ok) finish(resolve, message.value);
      else finish(reject, workerError(
        message?.code || (encoding === 'json' ? 'JSON_PARSE_ERROR' : 'YAML_PARSE_ERROR'),
      ));
    });
    worker.once('error', () => {
      if (!terminating) finish(reject, workerError(
        encoding === 'json' ? 'JSON_WORKER_FAILED' : 'YAML_WORKER_FAILED',
      ));
    });
    worker.once('exit', (code) => {
      if (!settled && !terminating) finish(reject, workerError(
        code === 0
          ? `${encoding === 'json' ? 'JSON' : 'YAML'}_WORKER_NO_RESULT`
          : `${encoding === 'json' ? 'JSON' : 'YAML'}_WORKER_FAILED`,
      ));
    });
    signal?.addEventListener('abort', onAbort, { once: true });
    if (signal?.aborted) onAbort();
  });
}

export function parseYamlDocumentInWorker(source, { signal = null } = {}) {
  return parseDocumentInWorker(source, { signal, encoding: 'yaml' });
}

export function parseJsonDocumentInWorker(source, { signal = null } = {}) {
  return parseDocumentInWorker(source, { signal, encoding: 'json' });
}
