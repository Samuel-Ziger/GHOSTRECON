export type NdjsonFrame<T> =
  | { ok: true; value: T; raw: string }
  | { ok: false; error: Error; raw: string };

export class NdjsonDecoder<T = unknown> {
  #buffer = '';
  #decoder = new TextDecoder();

  push(chunk: Uint8Array | string, final = false): NdjsonFrame<T>[] {
    this.#buffer += typeof chunk === 'string'
      ? chunk
      : this.#decoder.decode(chunk, { stream: !final });
    if (final && typeof chunk === 'string') this.#buffer += this.#decoder.decode();
    if (final && this.#buffer.trim() && !this.#buffer.endsWith('\n')) this.#buffer += '\n';

    const frames: NdjsonFrame<T>[] = [];
    let newline = this.#buffer.indexOf('\n');
    while (newline >= 0) {
      const raw = this.#buffer.slice(0, newline).trim();
      this.#buffer = this.#buffer.slice(newline + 1);
      if (raw) {
        try {
          frames.push({ ok: true, value: JSON.parse(raw) as T, raw });
        } catch (cause) {
          frames.push({
            ok: false,
            error: new Error('evento NDJSON inválido', { cause }),
            raw,
          });
        }
      }
      newline = this.#buffer.indexOf('\n');
    }
    return frames;
  }

  finish(): NdjsonFrame<T>[] {
    return this.push(new Uint8Array(), true);
  }

  get pending(): string {
    return this.#buffer;
  }
}

export async function* readNdjson<T = unknown>(
  response: Pick<Response, 'body' | 'ok' | 'status'>,
  { signal, strict = false }: { signal?: AbortSignal; strict?: boolean } = {},
): AsyncGenerator<NdjsonFrame<T>, void, void> {
  if (!response.ok) throw new Error(`stream NDJSON recusado (HTTP ${response.status})`);
  if (!response.body) throw new Error('stream NDJSON sem body');
  const reader = response.body.getReader();
  const decoder = new NdjsonDecoder<T>();
  let aborted = false;
  const abort = () => {
    aborted = true;
    void reader.cancel(signal?.reason).catch(() => {});
  };
  signal?.addEventListener('abort', abort, { once: true });

  try {
    while (true) {
      if (signal?.aborted) throw signal.reason || new DOMException('Abortado', 'AbortError');
      const { done, value } = await reader.read();
      const frames = done ? decoder.finish() : decoder.push(value);
      for (const frame of frames) {
        if (strict && !frame.ok) throw frame.error;
        yield frame;
      }
      if (done) break;
    }
    if (aborted || signal?.aborted) {
      throw signal?.reason || new DOMException('Abortado', 'AbortError');
    }
  } finally {
    signal?.removeEventListener('abort', abort);
    reader.releaseLock();
  }
}
