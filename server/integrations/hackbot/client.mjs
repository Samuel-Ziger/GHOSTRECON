const DEFAULT_BASE_URL = 'http://127.0.0.1:8791';
const DEFAULT_RUN_TIMEOUT_SECONDS = 30 * 60;
const MAX_RUN_TIMEOUT_SECONDS = 2 * 60 * 60;
const RUN_TIMEOUT_GRACE_MS = 30_000;

export function resolveHackbotRunTimeoutMs(env = process.env) {
  const parsed = Number.parseInt(String(env.GHOSTRECON_HACKBOT_RUN_TIMEOUT || ''), 10);
  const seconds = Number.isFinite(parsed) ? parsed : DEFAULT_RUN_TIMEOUT_SECONDS;
  return Math.max(10, Math.min(seconds, MAX_RUN_TIMEOUT_SECONDS)) * 1_000
    + RUN_TIMEOUT_GRACE_MS;
}

export class HackbotClient {
  constructor({
    baseUrl = process.env.GHOSTRECON_HACKBOT_URL || DEFAULT_BASE_URL,
    serviceToken = process.env.GHOSTRECON_HACKBOT_SERVICE_TOKEN || '',
    fetchImpl = globalThis.fetch,
    runTimeoutMs = resolveHackbotRunTimeoutMs(),
  } = {}) {
    this.baseUrl = String(baseUrl).replace(/\/+$/, '');
    this.serviceToken = String(serviceToken);
    this.fetchImpl = fetchImpl;
    this.runTimeoutMs = Number(runTimeoutMs);
  }

  async request(pathname, { method = 'GET', body, timeout = 10_000 } = {}) {
    const response = await this.fetchImpl(`${this.baseUrl}${pathname}`, {
      method,
      headers: {
        'X-GHOSTRECON-Service-Token': this.serviceToken,
        ...(body === undefined ? {} : { 'Content-Type': 'application/json' }),
      },
      body: body === undefined ? undefined : JSON.stringify(body),
      signal: AbortSignal.timeout(timeout),
    });
    const data = await response.json().catch(() => ({}));
    if (!response.ok) {
      const error = new Error(String(data.detail || data.error || `HackBot HTTP ${response.status}`));
      error.status = response.status;
      throw error;
    }
    return data;
  }

  status() { return this.request('/v1/status'); }
  session(id) { return this.request(`/v1/sessions/${encodeURIComponent(id)}`); }
  deleteSession(id) { return this.request(`/v1/sessions/${encodeURIComponent(id)}`, { method: 'DELETE' }); }
  run(body) { return this.request('/v1/runs', { method: 'POST', body, timeout: this.runTimeoutMs }); }
}

export function createHackbotClient(options) {
  return new HackbotClient(options);
}
