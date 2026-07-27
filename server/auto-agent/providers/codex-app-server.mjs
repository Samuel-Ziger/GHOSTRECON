import { spawn } from 'node:child_process';
import readline from 'node:readline';
import { normalizeAndValidateAgentDecision, parseAgentDecisionText } from '../decision-contract.mjs';
import { availableCatalogIds, availableEvidenceRefs, buildAgentPrompt } from './shared.mjs';
import { codexChildEnv } from './codex.mjs';

const IS_POSIX = process.platform !== 'win32';
const APP_SERVER_KILL_GRACE_MS = 1_500;

function abortError(reason, fallback = 'Codex App Server cancelado') {
  if (reason instanceof Error) return reason;
  const error = new Error(reason ? String(reason) : fallback);
  error.name = 'AbortError';
  return error;
}

class CodexAppServerClient {
  constructor({ command = 'codex', root, env, signal, spawnImpl = spawn } = {}) {
    this.root = root;
    this.nextId = 1;
    this.pending = new Map();
    this.turns = new Map();
    this.orphanTurnMessages = new Map();
    this.closed = false;
    this.exited = false;
    this.killTimer = null;
    this.parentSignal = signal || null;
    this.onParentAbort = () => this.close(abortError(this.parentSignal?.reason, 'sessão AUTO cancelada'));
    this.proc = spawnImpl(command, ['app-server', '--listen', 'stdio://'], {
      cwd: root, env: codexChildEnv(env), stdio: ['pipe', 'pipe', 'pipe'], windowsHide: true,
      // Em POSIX isto cria um process group próprio. Assim o watchdog encerra
      // também subprocessos do App Server, e não apenas o processo pai.
      detached: IS_POSIX,
    });
    this.stderr = '';
    this.proc.stderr?.on('data', (chunk) => { this.stderr = `${this.stderr}${chunk}`.slice(-8000); });
    this.proc.once('error', (error) => {
      this.markExited();
      this.rejectAll(error);
    });
    this.proc.once('exit', (code, childSignal) => {
      this.markExited();
      if (!this.closed || this.pending.size || this.turns.size) {
        this.rejectAll(new Error(
          `codex app-server encerrou (${code ?? childSignal ?? 'unknown'}): ${this.stderr}`,
        ));
      }
    });
    this.lines = readline.createInterface({ input: this.proc.stdout });
    this.lines.on('line', (line) => this.onLine(line));
    signal?.addEventListener('abort', this.onParentAbort, { once: true });
    if (signal?.aborted) this.onParentAbort();
  }

  markExited() {
    this.exited = true;
    if (this.killTimer) clearTimeout(this.killTimer);
    this.killTimer = null;
    this.parentSignal?.removeEventListener('abort', this.onParentAbort);
    try { this.lines?.close(); } catch { /* já encerrado */ }
  }

  rejectAll(error) {
    for (const item of this.pending.values()) item.reject(error);
    for (const item of this.turns.values()) item.reject(error);
    this.pending.clear();
    this.turns.clear();
    this.orphanTurnMessages.clear();
  }

  send(message) {
    if (this.closed || !this.proc?.stdin?.writable || this.proc.stdin.destroyed) {
      throw new Error('codex app-server não está disponível');
    }
    this.proc.stdin.write(`${JSON.stringify(message)}\n`);
  }

  request(method, params, timeoutMs = 30_000) {
    const id = this.nextId++;
    return new Promise((resolve, reject) => {
      const timer = setTimeout(() => {
        this.pending.delete(id);
        const error = Object.assign(new Error(`${method}: timeout`), {
          code: 'CODEX_APP_SERVER_REQUEST_TIMEOUT',
          method,
        });
        reject(error);
        // Se uma chamada RPC básica travou, a conexão stdio inteira deixou de
        // ser confiável. Encerrá-la impede que o fallback rode em paralelo com
        // um App Server órfão.
        this.close(error);
      }, timeoutMs);
      this.pending.set(id, {
        resolve: (value) => { clearTimeout(timer); resolve(value); },
        reject: (error) => { clearTimeout(timer); reject(error); },
      });
      try {
        this.send({ method, id, params });
      } catch (error) {
        this.pending.delete(id);
        clearTimeout(timer);
        reject(error);
        this.close(error);
      }
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
        const queued = this.orphanTurnMessages.get(turnId);
        queued.push(message);
        if (queued.length > 128) queued.shift();
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
      let settled = false;
      let onAbort = null;
      const finish = (fn, value) => {
        if (settled) return;
        settled = true;
        clearTimeout(timer);
        if (onAbort) signal?.removeEventListener('abort', onAbort);
        this.turns.delete(turnId);
        fn(value);
      };
      const timer = setTimeout(() => {
        try { this.send({ method: 'turn/interrupt', id: this.nextId++, params: { threadId, turnId } }); } catch { /* processo já encerrado */ }
        // O interrupt é best-effort: o timeout não pode depender da resposta do App Server.
        const error = Object.assign(new Error(`codex app-server: timeout (${timeoutMs}ms)`), {
          code: 'CODEX_APP_SERVER_TURN_TIMEOUT',
          turnId,
        });
        finish(reject, error);
        this.close(error);
      }, timeoutMs);
      this.turns.set(turnId, {
        text: '',
        resolve: (value) => finish(resolve, value),
        reject: (error) => finish(reject, error),
      });
      onAbort = () => {
        try { this.send({ method: 'turn/interrupt', id: this.nextId++, params: { threadId, turnId } }); } catch { /* ignore */ }
        const error = abortError(signal?.reason, 'sessão AUTO cancelada');
        finish(reject, error);
        this.close(error);
      };
      signal?.addEventListener('abort', onAbort, { once: true });
      if (signal?.aborted) {
        onAbort();
        return;
      }
      const turn = this.turns.get(turnId);
      for (const message of this.orphanTurnMessages.get(turnId) || []) this.applyTurnMessage(turnId, turn, message);
      this.orphanTurnMessages.delete(turnId);
    });
  }

  signalProcess(signalName) {
    if (!this.proc || this.exited) return;
    const pid = Number(this.proc.pid);
    if (IS_POSIX && Number.isInteger(pid) && pid > 1 && pid !== process.pid) {
      try {
        process.kill(-pid, signalName);
        return;
      } catch {
        // O spawn injetado por testes ou uma plataforma sem grupo próprio cai
        // no kill do processo individual.
      }
    }
    try { this.proc.kill(signalName); } catch { /* já encerrado */ }
  }

  close(reason = new Error('codex app-server encerrado')) {
    if (this.closed) return;
    this.closed = true;
    this.parentSignal?.removeEventListener('abort', this.onParentAbort);
    try { this.proc?.stdin?.end(); } catch { /* já encerrado */ }
    try { this.lines?.close(); } catch { /* já encerrado */ }
    this.rejectAll(abortError(reason));
    if (this.exited) return;
    this.signalProcess('SIGTERM');
    this.killTimer = setTimeout(() => {
      if (!this.exited) this.signalProcess('SIGKILL');
    }, APP_SERVER_KILL_GRACE_MS);
    this.killTimer.unref?.();
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
  const rawParsed = parseAgentDecisionText(text);
  const validated = normalizeAndValidateAgentDecision(rawParsed, {
    repairEnvelope: true,
    repairOptions: { objective: `authorized_recon:${opts.target || 'target'}` },
    catalogModuleIds: availableCatalogIds(catalog, {
      allowIntrusive: opts.allowIntrusive === true,
      autonomyLevel: opts.autonomyLevel,
    }),
    availableEvidenceRefs: availableEvidenceRefs({ ragContext, observationBundle }),
  });
  if (!validated.ok) throw new Error(`decisão Codex App Server rejeitada: ${validated.errors.join('; ')}`);
  return {
    ok: true, provider: 'codex', role: opts.role, iteration: opts.iteration,
    latencyMs: Date.now() - startedAt, decision: validated.decision,
    transport: {
      command: 'codex app-server', persistent: true, threadId: session.codexAppServer.threadId,
      repaired: rawParsed?.action == null || rawParsed?.objective == null || rawParsed?.confidence == null,
    },
  };
}

export { CodexAppServerClient };
