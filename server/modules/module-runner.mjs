import { spawn } from 'node:child_process';

export function positiveIntEnv(name, fallback, { min = 1, max = Number.MAX_SAFE_INTEGER } = {}) {
  const n = Number(process.env[name]);
  if (!Number.isFinite(n)) return fallback;
  return Math.min(max, Math.max(min, Math.floor(n)));
}

export function createCappedOutputCollector({
  maxBytes = 1024 * 1024,
  mode = 'head',
  encoding = 'utf8',
  marker = '\n[ghostrecon: output truncated]\n',
} = {}) {
  const limit = Math.max(0, Number(maxBytes) || 0);
  const chunks = [];
  let capturedBytes = 0;
  let totalBytes = 0;
  let truncated = false;

  const appendHead = (buf) => {
    if (capturedBytes >= limit) {
      truncated = true;
      return;
    }
    const remaining = limit - capturedBytes;
    if (buf.length <= remaining) {
      chunks.push(buf);
      capturedBytes += buf.length;
      return;
    }
    chunks.push(buf.subarray(0, remaining));
    capturedBytes += remaining;
    truncated = true;
  };

  const appendTail = (buf) => {
    if (limit <= 0) {
      truncated = true;
      return;
    }
    if (buf.length >= limit) {
      chunks.length = 0;
      chunks.push(buf.subarray(buf.length - limit));
      capturedBytes = limit;
      truncated = true;
      return;
    }
    chunks.push(buf);
    capturedBytes += buf.length;
    while (capturedBytes > limit && chunks.length) {
      const over = capturedBytes - limit;
      const first = chunks[0];
      if (first.length <= over) {
        chunks.shift();
        capturedBytes -= first.length;
      } else {
        chunks[0] = first.subarray(over);
        capturedBytes -= over;
      }
      truncated = true;
    }
  };

  return {
    append(chunk) {
      const buf = Buffer.isBuffer(chunk) ? chunk : Buffer.from(String(chunk ?? ''), encoding);
      totalBytes += buf.length;
      if (buf.length === 0) return;
      if (mode === 'tail') appendTail(buf);
      else appendHead(buf);
    },
    toString() {
      const text = Buffer.concat(chunks, capturedBytes).toString(encoding);
      return truncated ? `${text}${marker}` : text;
    },
    stats() {
      return { totalBytes, capturedBytes, truncated };
    },
  };
}

export async function mapPool(items, concurrency, fn, opts = {}) {
  const list = Array.isArray(items) ? items : [];
  const width = Math.max(1, Math.min(Number(concurrency) || 1, list.length || 1));
  const results = new Array(list.length);
  const { timeoutMs = 0, label = 'mapPool item' } = opts;
  let next = 0;

  async function runOne(item, idx) {
    if (!timeoutMs || timeoutMs <= 0) return fn(item, idx);
    let timer = null;
    try {
      return await Promise.race([
        fn(item, idx),
        new Promise((_, reject) => {
          timer = setTimeout(() => reject(new Error(`${label} timeout (${timeoutMs}ms)`)), timeoutMs);
        }),
      ]);
    } finally {
      if (timer) clearTimeout(timer);
    }
  }

  async function worker() {
    while (next < list.length) {
      const idx = next++;
      results[idx] = await runOne(list[idx], idx);
    }
  }

  await Promise.all(Array.from({ length: width }, () => worker()));
  return results;
}

export function runProcess(cmd, args = [], opts = {}) {
  const {
    timeoutMs = 60_000,
    spawnOpts = {},
    stdoutMaxBytes = positiveIntEnv('GHOSTRECON_TOOL_STDOUT_MAX_BYTES', 16 * 1024 * 1024, {
      max: 128 * 1024 * 1024,
    }),
    stderrMaxBytes = positiveIntEnv('GHOSTRECON_TOOL_STDERR_MAX_BYTES', 2 * 1024 * 1024, {
      max: 32 * 1024 * 1024,
    }),
    rejectOnError = true,
    rejectOnTimeout = true,
    wrapCommand = null,
    label = cmd,
  } = opts;

  let finalCmd = cmd;
  let finalArgs = Array.isArray(args) ? args : [];
  if (typeof wrapCommand === 'function') {
    const wrapped = wrapCommand(finalCmd, finalArgs);
    if (wrapped?.refuse) return Promise.reject(new Error(wrapped.reason || `${finalCmd} refused`));
    finalCmd = wrapped?.cmd || finalCmd;
    finalArgs = Array.isArray(wrapped?.args) ? wrapped.args : finalArgs;
  }

  return new Promise((resolve, reject) => {
    const child = spawn(finalCmd, finalArgs, {
      stdio: ['ignore', 'pipe', 'pipe'],
      ...spawnOpts,
    });
    const out = createCappedOutputCollector({
      maxBytes: stdoutMaxBytes,
      mode: 'head',
      marker: '\n[ghostrecon: stdout truncated]\n',
    });
    const err = createCappedOutputCollector({
      maxBytes: stderrMaxBytes,
      mode: 'tail',
      marker: '\n[ghostrecon: stderr truncated]\n',
    });
    let settled = false;

    const finish = (result) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      resolve(result);
    };
    const fail = (error) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      reject(error);
    };
    const resultFor = (extra = {}) => ({
      code: extra.code ?? null,
      signal: extra.signal ?? null,
      ok: extra.ok ?? extra.code === 0,
      stdout: out.toString(),
      stderr: err.toString(),
      stdoutStats: out.stats(),
      stderrStats: err.stats(),
      timedOut: Boolean(extra.timedOut),
      cmd: finalCmd,
      args: finalArgs,
    });

    const timer = setTimeout(() => {
      try {
        child.kill('SIGKILL');
      } catch {
        // ignore
      }
      const error = new Error(`${label} timeout (${timeoutMs}ms)`);
      error.result = resultFor({ code: 124, ok: false, timedOut: true });
      if (rejectOnTimeout) fail(error);
      else finish(error.result);
    }, Math.max(1, Number(timeoutMs) || 60_000));

    child.stdout.on('data', (d) => out.append(d));
    child.stderr.on('data', (d) => err.append(d));
    child.on('error', (e) => {
      const result = resultFor({ code: -1, ok: false });
      if (rejectOnError) fail(e);
      else finish({ ...result, stderr: `${result.stderr}\n${e?.message || e}`.trim() });
    });
    child.on('close', (code, signal) => {
      finish(resultFor({ code, signal, ok: code === 0, timedOut: false }));
    });
  });
}

export async function readResponseSnippet(res, maxBytes) {
  const limit = Math.max(0, Number(maxBytes) || 0);
  if (!res?.body || limit <= 0) return '';

  const chunks = [];
  let total = 0;
  const reader = res.body.getReader?.();
  if (!reader) {
    const buf = await res.arrayBuffer();
    const slice = buf.byteLength > limit ? buf.slice(0, limit) : buf;
    return new TextDecoder('utf-8', { fatal: false }).decode(slice);
  }

  try {
    while (total < limit) {
      const { done, value } = await reader.read();
      if (done) break;
      const buf = Buffer.from(value);
      const remaining = limit - total;
      if (buf.length <= remaining) {
        chunks.push(buf);
        total += buf.length;
      } else {
        chunks.push(buf.subarray(0, remaining));
        total += remaining;
        break;
      }
    }
    if (total >= limit) await reader.cancel().catch(() => {});
  } finally {
    try {
      reader.releaseLock?.();
    } catch {
      // ignore
    }
  }

  return Buffer.concat(chunks, total).toString('utf8');
}
