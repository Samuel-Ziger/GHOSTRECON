import { spawn } from 'node:child_process';
import readline from 'node:readline';
import { parseAgentDecisionText, validateAgentDecision } from '../decision-contract.mjs';
import { availableCatalogIds, availableEvidenceRefs, buildAgentPrompt } from './shared.mjs';
import { codexChildEnv } from './codex.mjs';

class CodexAppServerClient {
  constructor({ command = 'codex', root, env, signal, spawnImpl = spawn } = {}) {
    this.root = root;
    this.nextId = 1;
    this.pending = new Map();
    this.turns = new Map();
    this.orphanTurnMessages = new Map();
    this.proc = spawnImpl(command, ['app-server', '--listen', 'stdio://'], {
      cwd: root, env: codexChildEnv(env), stdio: ['pipe', 'pipe', 'pipe'], windowsHide: true,
    });
    this.stderr = '';
    this.proc.stderr?.on('data', (chunk) => { this.stderr = `${this.stderr}${chunk}`.slice(-8000); });
    this.proc.once('error', (error) => this.rejectAll(error));
    this.proc.once('exit', (code) => this.rejectAll(new Error(`codex app-server encerrou (${code}): ${this.stderr}`)));
    this.lines = readline.createInterface({ input: this.proc.stdout });
    this.lines.on('line', (line) => this.onLine(line));
    signal?.addEventListener('abort', () => this.close(), { once: true });
  }

  rejectAll(error) {
    for (const item of this.pending.values()) item.reject(error);
    for (const item of this.turns.values()) item.reject(error);
    this.pending.clear();
    this.turns.clear();
  }

  send(message) { this.proc.stdin.write(`${JSON.stringify(message)}\n`); }

  request(method, params, timeoutMs = 30_000) {
    const id = this.nextId++;
    return new Promise((resolve, reject) => {
      const timer = setTimeout(() => { this.pending.delete(id); reject(new Error(`${method}: timeout`)); }, timeoutMs);
      this.pending.set(id, {
        resolve: (value) => { clearTimeout(timer); resolve(value); },
        reject: (error) => { clearTimeout(timer); reject(error); },
      });
      this.send({ method, id, params });
    });
  }

  onLine(line) {
    let message;
    try { message = JSON.parse(line); } catch { return; }
    if (message.id != null && this.pending.has(message.id)) {
      const pending = this.pending.get(message.id);
      this.pending.delete(message.id);
      if (message.error) pending.reject(new Error(message.error.message || 'erro app-server'));
      else pending.resolve(message.result);
      return;
    }
    const turnId = message.params?.turn?.id || message.params?.turnId;
    const turn = turnId ? this.turns.get(turnId) : null;
    if (!turn) {
      if (turnId) {
        if (!this.orphanTurnMessages.has(turnId)) this.orphanTurnMessages.set(turnId, []);
        this.orphanTurnMessages.get(turnId).push(message);
      }
      return;
    }
    this.applyTurnMessage(turnId, turn, message);
  }

  applyTurnMessage(turnId, turn, message) {
    if (message.method === 'item/agentMessage/delta') turn.text += String(message.params?.delta || '');
    if (message.method === 'item/completed' && message.params?.item?.type === 'agentMessage') {
      turn.text = String(message.params.item.text || message.params.item.content || turn.text);
    }
    if (message.method === 'turn/completed') {
      this.turns.delete(turnId);
      this.orphanTurnMessages.delete(turnId);
      const status = message.params?.turn?.status;
      if (status && !['completed', 'success'].includes(status)) turn.reject(new Error(`turno Codex: ${status}`));
      else turn.resolve(turn.text);
    }
  }

  async initialize() {
    if (this.initialized) return;
    await this.request('initialize', { clientInfo: { name: 'ghostrecon_auto', title: 'GHOSTRECON Auto', version: '1.0.0' } });
    this.send({ method: 'initialized', params: {} });
    this.initialized = true;
  }

  async ensureThread(model) {
    await this.initialize();
    if (this.threadId) return this.threadId;
    const result = await this.request('thread/start', { ...(model ? { model } : {}) });
    this.threadId = result?.thread?.id;
    if (!this.threadId) throw new Error('thread/start não retornou threadId');
    return this.threadId;
  }

  async turn({ prompt, model, timeoutMs, signal }) {
    const threadId = await this.ensureThread(model);
    const result = await this.request('turn/start', {
      threadId,
      cwd: this.root,
      approvalPolicy: 'never',
      sandboxPolicy: { type: 'readOnly' },
      input: [{ type: 'text', text: prompt }],
    }, Math.min(timeoutMs, 30_000));
    const turnId = result?.turn?.id;
    if (!turnId) throw new Error('turn/start não retornou turnId');
    return new Promise((resolve, reject) => {
      const timer = setTimeout(() => {
        this.send({ method: 'turn/interrupt', id: this.nextId++, params: { threadId, turnId } });
        this.turns.delete(turnId);
        reject(new Error(`codex app-server: timeout (${timeoutMs}ms)`));
      }, timeoutMs);
      const done = (fn) => (value) => { clearTimeout(timer); fn(value); };
      this.turns.set(turnId, { text: '', resolve: done(resolve), reject: done(reject) });
      const turn = this.turns.get(turnId);
      for (const message of this.orphanTurnMessages.get(turnId) || []) this.applyTurnMessage(turnId, turn, message);
      this.orphanTurnMessages.delete(turnId);
      signal?.addEventListener('abort', () => {
        this.send({ method: 'turn/interrupt', id: this.nextId++, params: { threadId, turnId } });
      }, { once: true });
    });
  }

  close() {
    this.lines?.close();
    this.proc?.kill('SIGTERM');
  }
}

export async function decideWithCodexAppServer(opts = {}) {
  const { session, env = process.env, root, catalog, ragContext, observationBundle } = opts;
  if (!session) throw new Error('sessão ausente para Codex App Server');
  session.resources ||= [];
  if (!session.codexAppServer) {
    session.codexAppServer = new CodexAppServerClient({
      command: String(env.GHOSTRECON_CODEX_COMMAND || 'codex'), root, env, signal: session.signal,
    });
    session.resources.push(session.codexAppServer);
  }
  const startedAt = Date.now();
  const text = await session.codexAppServer.turn({
    prompt: buildAgentPrompt({ ...opts, maxContextChars: session.limits.maxContextChars }),
    model: env.GHOSTRECON_CODEX_MODEL || undefined,
    timeoutMs: session.limits.agentTimeoutMs,
    signal: session.signal,
  });
  const parsed = parseAgentDecisionText(text);
  const validated = validateAgentDecision(parsed, {
    catalogModuleIds: availableCatalogIds(catalog),
    availableEvidenceRefs: availableEvidenceRefs({ ragContext, observationBundle }),
  });
  if (!validated.ok) throw new Error(`decisão Codex App Server rejeitada: ${validated.errors.join('; ')}`);
  return {
    ok: true, provider: 'codex', role: opts.role, iteration: opts.iteration,
    latencyMs: Date.now() - startedAt, decision: validated.decision,
    transport: { command: 'codex app-server', persistent: true, threadId: session.codexAppServer.threadId },
  };
}

export { CodexAppServerClient };
