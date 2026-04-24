/**
 * Cliente HTTP para o API GHOSTRECON. Gere CSRF, stream NDJSON e auto-spawn do server.
 *
 * O cliente NÃO mexe em nada do pipeline — apenas fala com /api/*.
 */

import http from 'node:http';
import { spawn } from 'node:child_process';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const SERVER_ENTRY = path.resolve(__dirname, '..', '..', 'index.js');

/**
 * Parser NDJSON incremental (linha-por-linha). Tolera \r\n, linhas em branco,
 * JSON malformado (gera evento {type:'parse-error'}). Retorna handle com feed/end.
 *
 * Extraído para unit-test sem precisar de HTTP round-trip.
 */
export function createNdjsonParser(onEvent) {
  let remain = '';
  let lines = 0;
  let lastEvent = null;
  return {
    feed(chunk) {
      remain += typeof chunk === 'string' ? chunk : String(chunk);
      // Normalize CRLF → LF early so tests can feed either.
      if (remain.includes('\r')) remain = remain.replace(/\r\n/g, '\n').replace(/\r/g, '\n');
      const parts = remain.split('\n');
      remain = parts.pop() || '';
      for (const part of parts) {
        if (!part.trim()) continue;
        lines++;
        try {
          const evt = JSON.parse(part);
          lastEvent = evt;
          onEvent?.(evt);
        } catch (e) {
          onEvent?.({ type: 'parse-error', raw: part, error: e?.message });
        }
      }
    },
    end() {
      if (remain.trim()) {
        try {
          const evt = JSON.parse(remain);
          lastEvent = evt;
          onEvent?.(evt);
          lines++;
        } catch { /* ignore trailing */ }
      }
      remain = '';
      return { lines, lastEvent };
    },
    get lines() { return lines; },
    get lastEvent() { return lastEvent; },
  };
}

export class GhostClient {
  constructor({ server = 'http://127.0.0.1:3847', timeoutMs = 30_000 } = {}) {
    this.baseUrl = String(server || '').replace(/\/+$/, '');
    this.timeoutMs = timeoutMs;
    this._csrf = null;
    this._csrfExpiresAt = 0;
  }

  async isAlive() {
    try {
      const res = await this._fetch('/api/health', { timeoutMs: 2500 });
      return res.ok;
    } catch {
      return false;
    }
  }

  /** Garante server vivo; spawn background se necessário. Devolve handler para shutdown. */
  async ensureServer({ autoStart = false, quiet = false } = {}) {
    if (await this.isAlive()) return { spawned: false, child: null };
    if (!autoStart) {
      throw new Error(
        `server não acessível em ${this.baseUrl}. Use --start-server para auto-spawn ou inicie com "npm run start:api".`,
      );
    }

    const child = spawn(process.execPath, [SERVER_ENTRY], {
      stdio: quiet ? 'ignore' : ['ignore', 'pipe', 'pipe'],
      detached: false,
      env: { ...process.env },
    });

    if (!quiet) {
      child.stdout?.on('data', (buf) => process.stderr.write(`[server] ${buf}`));
      child.stderr?.on('data', (buf) => process.stderr.write(`[server:err] ${buf}`));
    }

    const started = await this._waitForHealth(30_000);
    if (!started) {
      try { child.kill('SIGTERM'); } catch { /* ignore */ }
      throw new Error('server não ficou vivo em 30s.');
    }
    return { spawned: true, child };
  }

  async _waitForHealth(totalMs) {
    const start = Date.now();
    while (Date.now() - start < totalMs) {
      if (await this.isAlive()) return true;
      await new Promise((r) => setTimeout(r, 500));
    }
    return false;
  }

  async getCsrfToken(force = false) {
    const now = Date.now();
    if (!force && this._csrf && this._csrfExpiresAt - now > 5000) return this._csrf;
    const res = await this._fetch('/api/csrf-token', { timeoutMs: 8000 });
    if (!res.ok) throw new Error(`CSRF fetch falhou: HTTP ${res.statusCode}`);
    const body = JSON.parse(res.body);
    this._csrf = String(body.token || '');
    this._csrfExpiresAt = now + Number(body.expiresInMs || 600_000);
    if (!this._csrf) throw new Error('CSRF vazio');
    return this._csrf;
  }

  async listRuns() {
    const res = await this._fetch('/api/runs', { timeoutMs: 10_000 });
    if (!res.ok) throw new Error(`/api/runs HTTP ${res.statusCode}`);
    return JSON.parse(res.body);
  }

  async getRun(id) {
    const res = await this._fetch(`/api/runs/${encodeURIComponent(id)}`, { timeoutMs: 15_000 });
    if (!res.ok) throw new Error(`/api/runs/${id} HTTP ${res.statusCode}`);
    return JSON.parse(res.body);
  }

  async diffRuns(baselineId, newerId) {
    const res = await this._fetch(
      `/api/runs/${encodeURIComponent(newerId)}/diff/${encodeURIComponent(baselineId)}`,
      { timeoutMs: 20_000 },
    );
    if (!res.ok) throw new Error(`diff HTTP ${res.statusCode}`);
    return JSON.parse(res.body);
  }

  /**
   * Stream NDJSON de /api/recon/stream. `onEvent` é chamado por linha parseada.
   * Returns { lines, lastEvent, elapsedMs }.
   */
  async streamRecon(body, onEvent, { timeoutMs = 1_800_000 } = {}) {
    const csrf = await this.getCsrfToken();
    const url = new URL(`${this.baseUrl}/api/recon/stream`);
    const payload = Buffer.from(JSON.stringify(body), 'utf8');

    return new Promise((resolve, reject) => {
      const req = http.request(
        {
          method: 'POST',
          hostname: url.hostname,
          port: url.port,
          path: url.pathname,
          headers: {
            'content-type': 'application/json; charset=utf-8',
            'content-length': String(payload.length),
            'x-csrf-token': csrf,
            origin: url.origin,
          },
        },
        (res) => {
          if (res.statusCode !== 200) {
            let buf = '';
            res.setEncoding('utf8');
            res.on('data', (c) => (buf += c));
            res.on('end', () => reject(new Error(`stream HTTP ${res.statusCode}: ${buf.slice(0, 500)}`)));
            return;
          }
          res.setEncoding('utf8');
          const parser = createNdjsonParser((evt) => onEvent?.(evt));
          const start = Date.now();

          res.on('data', (chunk) => parser.feed(chunk));
          res.on('end', () => {
            const { lines, lastEvent } = parser.end();
            resolve({ lines, lastEvent, elapsedMs: Date.now() - start });
          });
          res.on('error', reject);
        },
      );
      req.setTimeout(timeoutMs, () => {
        req.destroy(new Error(`stream timeout > ${timeoutMs}ms`));
      });
      req.on('error', reject);
      req.write(payload);
      req.end();
    });
  }

  async postJson(pathname, body, { csrf = true, timeoutMs = 15_000 } = {}) {
    const headers = { 'content-type': 'application/json; charset=utf-8' };
    if (csrf) headers['x-csrf-token'] = await this.getCsrfToken();
    const res = await this._fetch(pathname, { method: 'POST', body, headers, timeoutMs });
    if (!res.ok) throw new Error(`POST ${pathname} HTTP ${res.statusCode}: ${res.body.slice(0, 400)}`);
    try {
      return JSON.parse(res.body);
    } catch {
      return { raw: res.body };
    }
  }

  _fetch(pathname, { method = 'GET', body = null, headers = {}, timeoutMs = 10_000 } = {}) {
    const url = new URL(`${this.baseUrl}${pathname}`);
    const payload = body ? Buffer.from(typeof body === 'string' ? body : JSON.stringify(body), 'utf8') : null;
    const finalHeaders = { ...headers };
    if (payload && !finalHeaders['content-length']) finalHeaders['content-length'] = String(payload.length);
    if (payload && !finalHeaders['content-type']) finalHeaders['content-type'] = 'application/json; charset=utf-8';

    return new Promise((resolve, reject) => {
      const req = http.request(
        {
          method,
          hostname: url.hostname,
          port: url.port,
          path: url.pathname + url.search,
          headers: finalHeaders,
        },
        (res) => {
          let buf = '';
          res.setEncoding('utf8');
          res.on('data', (c) => (buf += c));
          res.on('end', () => {
            resolve({
              ok: res.statusCode >= 200 && res.statusCode < 300,
              statusCode: res.statusCode,
              headers: res.headers,
              body: buf,
            });
          });
          res.on('error', reject);
        },
      );
      req.setTimeout(timeoutMs, () => {
        req.destroy(new Error(`HTTP timeout > ${timeoutMs}ms on ${pathname}`));
      });
      req.on('error', reject);
      if (payload) req.write(payload);
      req.end();
    });
  }
}

/** Opções globais partilhadas por subcomandos. */
export const GLOBAL_OPTS = [
  { name: 'server', type: 'string', default: process.env.GHOSTRECON_SERVER || 'http://127.0.0.1:3847' },
  { name: 'start-server', type: 'bool', default: false },
  { name: 'quiet', type: 'bool', default: false },
  { name: 'verbose', type: 'bool', default: false },
  { name: 'help', type: 'bool', default: false, alias: 'h' },
];
