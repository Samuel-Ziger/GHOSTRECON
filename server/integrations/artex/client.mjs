import fs from 'node:fs/promises';
import path from 'node:path';

const DEFAULT_BASE_URL = 'http://127.0.0.1:8787';

function normalizeBaseUrl(raw) {
  const value = String(raw || DEFAULT_BASE_URL).trim().replace(/\/+$/, '');
  const parsed = new URL(value);
  const loopback = ['127.0.0.1', 'localhost', '::1', '[::1]'].includes(parsed.hostname);
  if (!loopback && !/^(1|true|yes|on)$/i.test(String(process.env.GHOSTRECON_ARTEX_ALLOW_REMOTE || ''))) {
    throw new Error('Artex remoto bloqueado; configure GHOSTRECON_ARTEX_ALLOW_REMOTE=1 conscientemente');
  }
  if (!['http:', 'https:'].includes(parsed.protocol)) throw new Error('ARTEX_BASE_URL precisa usar http(s)');
  return value;
}

async function bodyFrom(response) {
  const text = await response.text();
  if (!text) return {};
  try { return JSON.parse(text); } catch { return { raw: text.slice(0, 2_000) }; }
}

export class ArtexClient {
  constructor({ root, baseUrl = process.env.ARTEX_BASE_URL, fetchImpl = fetch, timeoutMs = 20_000 } = {}) {
    this.root = root;
    this.baseUrl = normalizeBaseUrl(baseUrl);
    this.fetchImpl = fetchImpl;
    this.timeoutMs = timeoutMs;
    this.token = '';
    this.tokenAt = 0;
  }

  async password() {
    const fromEnv = String(process.env.ARTEX_ADMIN_PASSWORD || '').trim();
    if (fromEnv) return fromEnv;
    if (!this.root) throw new Error('ROOT não informado para ler a credencial runtime do Artex');
    const file = path.join(this.root, '.runtime', 'artex', 'admin-password');
    try {
      return String(await fs.readFile(file, 'utf8')).trim();
    } catch {
      throw new Error('Artex ainda não foi inicializado pelo stack (admin-password ausente)');
    }
  }

  async raw(pathname, {
    method = 'GET', body, auth = true, timeoutMs = this.timeoutMs, retryAuth = true,
  } = {}) {
    if (auth && (!this.token || Date.now() - this.tokenAt > 6 * 24 * 60 * 60 * 1_000)) await this.login();
    const headers = { accept: 'application/json' };
    if (body !== undefined) headers['content-type'] = 'application/json';
    if (auth && this.token) headers.authorization = `Bearer ${this.token}`;
    const response = await this.fetchImpl(`${this.baseUrl}${pathname}`, {
      method,
      headers,
      body: body === undefined ? undefined : JSON.stringify(body),
      signal: AbortSignal.timeout(timeoutMs),
    });
    const data = await bodyFrom(response);
    if (auth && response.status === 401 && this.token && retryAuth) {
      this.token = '';
      return this.raw(pathname, { method, body, auth, timeoutMs, retryAuth: false });
    }
    if (!response.ok) {
      const error = new Error(String(data?.error || data?.message || `Artex HTTP ${response.status}`));
      error.status = response.status;
      throw error;
    }
    return data;
  }

  health() { return this.raw('/api/health', { auth: false, timeoutMs: 3_000 }); }
  authStatus() { return this.raw('/api/auth/status', { auth: false, timeoutMs: 5_000 }); }

  async login() {
    const password = await this.password();
    const data = await this.raw('/api/auth/login', {
      method: 'POST', auth: false, body: { username: 'ARTEX', password }, timeoutMs: 10_000,
    });
    const token = String(data?.token || '').trim();
    if (!token) throw new Error('Artex não devolveu token de sessão');
    this.token = token;
    this.tokenAt = Date.now();
    return token;
  }

  listProfiles() { return this.raw('/api/llm/profiles'); }
  saveProfile(profile) { return this.raw('/api/llm/profiles', { method: 'POST', body: profile }); }
  activateProfile(id) { return this.raw('/api/llm/profiles/active', { method: 'POST', body: { id: Number(id) } }); }
  deleteProfile(id) { return this.raw(`/api/llm/profiles/${encodeURIComponent(id)}`, { method: 'DELETE' }); }
  listModels(config) {
    return this.raw('/api/llm/models', { method: 'POST', body: config, timeoutMs: 45_000 });
  }
  testProfile(profile) {
    return this.raw('/api/llm/test', { method: 'POST', body: profile, timeoutMs: 45_000 });
  }
  chatGptPlanStatus() { return this.raw('/api/chatgpt-plan/status'); }
  chatGptPlanConnect() { return this.raw('/api/chatgpt-plan/connect', { method: 'POST', body: {} }); }
  chatGptPlanModels() { return this.raw('/api/chatgpt-plan/models'); }
  listMcp() { return this.raw('/api/mcp'); }
  saveMcp(server) { return this.raw('/api/mcp', { method: 'POST', body: server, timeoutMs: 60_000 }); }
  refreshMcp(id) { return this.raw(`/api/mcp/${encodeURIComponent(id)}/refresh`, { method: 'POST', body: {}, timeoutMs: 60_000 }); }
  listAgents() { return this.raw('/api/agents'); }
  getAgent(key) { return this.raw(`/api/agents/${encodeURIComponent(key)}`); }
  createAgent(agent) { return this.raw('/api/agents', { method: 'POST', body: agent }); }
  saveAgentPrompt(key, template) {
    return this.raw(`/api/agents/${encodeURIComponent(key)}/prompt`, {
      method: 'PUT', body: { template, note: 'GHOSTRECON integration prompt' },
    });
  }
  saveAgentConfig(key, config) {
    return this.raw(`/api/agents/${encodeURIComponent(key)}/config`, { method: 'PUT', body: config });
  }
  getAgentVisibility(key) { return this.raw(`/api/agents/${encodeURIComponent(key)}/visibility`); }
  setAgentVisibility(key, body) {
    return this.raw(`/api/agents/${encodeURIComponent(key)}/visibility`, { method: 'PUT', body });
  }
  listConversations() { return this.raw('/api/conversations'); }
  createConversation(body) { return this.raw('/api/conversations', { method: 'POST', body }); }
  conversationMessages(id, since = 0) {
    return this.raw(`/api/conversations/${encodeURIComponent(id)}/messages?since=${Number(since) || 0}&limit=1000`);
  }
  conversationMessageDetail(id, seq) {
    return this.raw(`/api/conversations/${encodeURIComponent(id)}/messages/${encodeURIComponent(seq)}`);
  }
  deleteConversation(id) {
    return this.raw(`/api/conversations/${encodeURIComponent(id)}`, { method: 'DELETE' });
  }
  sendConversationMessage(id, message) {
    return this.raw(`/api/conversations/${encodeURIComponent(id)}/messages`, { method: 'POST', body: { message } });
  }
  stopConversation(id) {
    return this.raw(`/api/conversations/${encodeURIComponent(id)}/stop`, { method: 'POST', body: {} });
  }
  createTask(body) { return this.raw('/api/tasks', { method: 'POST', body, timeoutMs: 60_000 }); }
  getTask(id) { return this.raw(`/api/tasks/${encodeURIComponent(id)}`); }
  controlTask(id, action) {
    return this.raw(`/api/tasks/${encodeURIComponent(id)}/control`, { method: 'POST', body: { action } });
  }
  findings({ taskId = '', page = 1, limit = 200 } = {}) {
    const query = new URLSearchParams({ page: String(page), limit: String(limit) });
    if (taskId) query.set('task', String(taskId));
    return this.raw(`/api/exploration/findings?${query}`);
  }
}

let sharedClient = null;

export function getArtexClient({ root, ...options } = {}) {
  if (!sharedClient || sharedClient.root !== root) sharedClient = new ArtexClient({ root, ...options });
  return sharedClient;
}

export function resetArtexClientForTests() {
  sharedClient = null;
}
