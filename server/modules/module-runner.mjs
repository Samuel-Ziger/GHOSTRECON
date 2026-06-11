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
