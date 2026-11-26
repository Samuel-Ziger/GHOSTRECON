import { spawn as nodeSpawn } from 'node:child_process';
import { randomUUID } from 'node:crypto';
import { EventEmitter } from 'node:events';
import fs from 'node:fs/promises';
import fsSync from 'node:fs';
import path from 'node:path';
import { redactAutoText, redactAutoValue } from '../../auto-agent/redaction.mjs';
import { codexManagedMcpServers, discoverCodexMcpNames, normalizeMcpSelection, validateCodexMcpSelection } from '../mcp/catalog.mjs';

const ACTIVE = new Set(['starting', 'recon', 'planning', 'exploiting', 'validating', 'chaining', 'paused']);
const REPL_MODES = new Set(['run', 'whitebox', 'greybox']);
const MODES = new Set(['run', 'whitebox', 'greybox', 'host', 'aitest', 'mobile', 'container', 'skills']);
const MAX_FEED = 2_000;
const MAX_LINE = 16_000;
const ANSI_RE = /\x1b\[[0-9;]*[A-Za-z]/g;

function cleanLine(value) {
  return redactAutoText(String(value || '').replace(ANSI_RE, '').slice(0, MAX_LINE), process.env, { cloud: false });
}

function oneLine(value, max = 2_000) {
  return String(value || '').replace(/[\r\n\0]+/g, ' ').trim().slice(0, max);
}

function boundedInt(value, fallback, min, max) {
  const number = Number(value);
  return Number.isFinite(number) ? Math.max(min, Math.min(max, Math.floor(number))) : fallback;
}

function runtimePaths(root) {
  const dir = path.join(root, '.runtime', 'neurosploit');
  return {
    dir,
    jobs: path.join(dir, 'jobs'),
    engine: path.join(root, 'engines', 'neurosploit'),
    binary: path.join(root, 'engines', 'neurosploit', 'neurosploit-rs', 'target', 'release', process.platform === 'win32' ? 'neurosploit.exe' : 'neurosploit'),
  };
}

async function writeJson(file, value) {
  await fs.mkdir(path.dirname(file), { recursive: true, mode: 0o700 });
  const temporary = `${file}.${process.pid}.tmp`;
  await fs.writeFile(temporary, `${JSON.stringify(redactAutoValue(value), null, 2)}\n`, { mode: 0o600 });
  await fs.rename(temporary, file);
  await fs.chmod(file, 0o600).catch(() => {});
}

function publicFinding(finding) {
  if (!finding || typeof finding !== 'object') return null;
  const safe = redactAutoValue(finding);
  delete safe.secret;
  return safe;
}

function publicJob(job, { includeFeed = false } = {}) {
  const snapshot = {
    id: job.id,
    owner: job.owner,
    mode: job.mode,
    target: job.target,
    repository: job.repository,
    engagementId: job.engagementId,
    authorizationReference: job.authorizationReference,
    autoSessionId: job.autoSessionId || null,
    autoPlanHash: job.autoPlanHash || null,
    profileId: job.profileId,
    profileName: job.profileName,
    model: job.model,
    codexCli: job.codexCli === true,
    mcpServers: job.mcpServers || [],
    phase: job.phase,
    done: job.done,
    exitCode: job.exitCode,
    interrupted: job.interrupted,
    resumable: job.resumable,
    runId: job.runId,
    reportReady: Boolean(job.reportReady),
    cortex: job.cortex || null,
    startedAt: job.startedAt,
    updatedAt: job.updatedAt,
    finishedAt: job.finishedAt || null,
    agents: job.agents,
    agentsDone: job.agentsDone,
    findings: job.findings.map(publicFinding).filter(Boolean),
  };
  if (includeFeed) snapshot.feed = job.feed.slice(-MAX_FEED);
  return snapshot;
}

function ingestLine(manager, job, rawLine) {
  const line = cleanLine(rawLine);
  if (!line) return;
  const norm = line.replace(/^\s*[^\w/{(]*\s*/u, '').replace(/^testing\s+/i, '');
  const low = line.toLowerCase();
  const lown = norm.toLowerCase();
  manager.push(job, { type: 'log', line });

  if (low.includes('paused by operator') || low.includes('run is paused')) job.phase = 'paused';
  else if (low.includes('resumed by operator') || low.includes('▶ resumed')) job.phase = 'exploiting';
  else if (lown.startsWith('recon') || lown.startsWith('ai-recon') || low.includes('recon round') || lown.startsWith('probe:')) job.phase = 'recon';
  else if (low.includes('selected') && low.includes('agent')) {
    job.phase = 'planning';
    const count = line.match(/selected\s+(\d+)/i);
    if (count) job.agents = Number(count[1]);
  } else if (lown.startsWith('exploit') || lown.startsWith('test ') || low.includes('launching agent')) job.phase = 'exploiting';
  else if (lown.startsWith('vote') || low.includes('validating')) job.phase = 'validating';
  else if (lown.startsWith('chain')) job.phase = 'chaining';

  if (/candidate\(s\)/.test(lown) && /^(exploit|test|analyze|review)\b/.test(lown)) job.agentsDone += 1;
  const findingMatch = norm.match(/^finding_json:\s*(.+)$/);
  if (findingMatch) {
    try {
      const finding = publicFinding(JSON.parse(findingMatch[1]));
      if (finding) {
        const index = job.findings.findIndex((item) => String(item.id || '') === String(finding.id || ''));
        if (index >= 0) job.findings[index] = finding;
        else job.findings.push(finding);
        manager.push(job, { type: 'finding', finding });
      }
    } catch { /* malformed engine marker remains visible in the redacted log */ }
  }
  const runMatch = line.match(/run id\s*:\s*(\S+)/i);
  if (runMatch && /^ns-[A-Za-z0-9._-]+$/.test(runMatch[1])) job.runId = runMatch[1];
  if (/report:\s*file:\/\//i.test(line)) job.reportReady = true;

  if (low.includes('phase complete') || low.includes('validated finding(s)')) {
    job.phase = 'completed';
    if (!job.done) manager.finish(job, 0, 'completed');
    if (job.repl && job.child?.stdin?.writable) job.child.stdin.write('/exit\n');
  }
}

function replScript(input, model) {
  const lines = [];
  if (input.mode === 'whitebox') lines.push(`/repo ${oneLine(input.repository || input.target)}`);
  else {
    lines.push(`/target ${oneLine(input.target)}`);
    if (input.mode === 'greybox') lines.push(`/repo ${oneLine(input.repository)}`);
  }
  lines.push(`/model ${input.codexCli ? 'openai' : 'litellm'}:${oneLine(model, 400)}`);
  lines.push(input.codexCli ? '/sub on' : '/sub off', input.codexCli && input.mcpServers?.length ? '/mcp on' : '/mcp off');
  lines.push(`/votes ${boundedInt(input.votes, 2, 1, 5)}`);
  lines.push(`/chain ${boundedInt(input.chainDepth, 2, 0, 6)}`);
  lines.push(`/recon ${boundedInt(input.recon, 3, 1, 4)}`);
  if (Number(input.maxAgents) > 0) lines.push(`/agents ${boundedInt(input.maxAgents, 0, 1, 64)}`);
  if (input.focus) lines.push(`/focus ${oneLine(input.focus, 2_000)}`);
  if (input.objective) lines.push(`/objective ${oneLine(input.objective, 2_000)}`);
  if (input.outOfScope) lines.push(`/scope-out ${oneLine(input.outOfScope, 2_000)}`);
  const agents = Array.isArray(input.agents) ? input.agents.map((item) => oneLine(item, 100)).filter(Boolean).slice(0, 64) : [];
  lines.push(agents.length ? `/only ${agents.join(',')}` : '/only clear');
  if (input.quick === true) lines.push('/quick');
  lines.push('/run');
  return lines;
}

function oneShotArgs(input, model, scopeHost) {
  const mode = input.mode;
  const args = [mode];
  if (mode === 'run' || mode === 'host' || mode === 'aitest' || mode === 'container') args.push(oneLine(input.target));
  else if (mode === 'mobile') args.push(oneLine(input.repository || input.target));
  else if (mode === 'whitebox' || mode === 'skills') args.push(oneLine(input.repository || input.target));
  else if (mode === 'greybox') args.push(oneLine(input.repository), '--url', oneLine(input.target));
  args.push('--model', `${input.codexCli ? 'openai' : 'litellm'}:${oneLine(model, 400)}`);
  if (input.codexCli) args.push('--subscription');
  if (input.codexCli && input.mcpServers?.length) args.push('--mcp');
  args.push('--vote-n', String(boundedInt(input.votes, 2, 1, 5)));
  if (['run', 'whitebox', 'greybox', 'host'].includes(mode)) {
    args.push('--chain-depth', String(boundedInt(input.chainDepth, 2, 0, 6)));
    args.push('--recon', String(boundedInt(input.recon, 3, 1, 4)));
  }
  if (Number(input.maxAgents) > 0) args.push('--max-agents', String(boundedInt(input.maxAgents, 0, 1, 64)));
  if (input.focus && !['mobile', 'container', 'skills'].includes(mode)) args.push('--focus', oneLine(input.focus, 2_000));
  if (input.quick === true && ['run', 'whitebox', 'greybox'].includes(mode)) args.push('--quick');
  if (scopeHost && mode === 'run') {
    args.push('--in-scope', scopeHost, '--environment', oneLine(input.environment || 'production', 40), '--policy', oneLine(input.policy || 'web', 40));
  } else if (scopeHost && ['host', 'aitest'].includes(mode)) {
    args.push('--session-in-scope', scopeHost, '--session-environment', oneLine(input.environment || 'production', 40), '--session-policy', oneLine(input.policy || 'web', 40));
  }
  if (input.engagementId) args.push('--engagement', oneLine(input.engagementId, 120));
  args.push('--verbose');
  return args;
}

export class NeuroSploitManager extends EventEmitter {
  constructor({ root, spawnImpl = nodeSpawn, onTerminal = null } = {}) {
    super();
    this.root = root;
    this.spawnImpl = spawnImpl;
    this.onTerminal = onTerminal;
    this.paths = runtimePaths(root);
    this.jobs = new Map();
    this.ready = this.restore();
  }

  async restore() {
    await fs.mkdir(this.paths.jobs, { recursive: true, mode: 0o700 });
    const entries = await fs.readdir(this.paths.jobs, { withFileTypes: true }).catch(() => []);
    for (const entry of entries) {
      if (!entry.isDirectory()) continue;
      try {
        const parsed = JSON.parse(await fs.readFile(path.join(this.paths.jobs, entry.name, 'job.json'), 'utf8'));
        parsed.feed = Array.isArray(parsed.feed) ? parsed.feed.slice(-MAX_FEED) : [];
        parsed.findings = Array.isArray(parsed.findings) ? parsed.findings : [];
        parsed.input = parsed.launch && typeof parsed.launch === 'object' ? parsed.launch : null;
        parsed.child = null;
        parsed.repl = REPL_MODES.has(parsed.mode);
        if (!parsed.done && ACTIVE.has(parsed.phase)) {
          parsed.phase = 'interrupted';
          parsed.interrupted = true;
          parsed.resumable = parsed.repl;
          parsed.updatedAt = new Date().toISOString();
        }
        this.jobs.set(parsed.id, parsed);
      } catch { /* ignore malformed runtime snapshots */ }
    }
  }

  binaryReady() {
    try { fsSync.accessSync(this.paths.binary, fsSync.constants.X_OK); return true; } catch { return false; }
  }

  async status() {
    await this.ready;
    return {
      installed: fsSync.existsSync(this.paths.engine),
      binaryReady: this.binaryReady(),
      version: '4.4.3',
      modes: [...MODES],
      jobs: [...this.jobs.values()].map((job) => publicJob(job)),
    };
  }

  job(id) { return this.jobs.get(String(id || '').trim()) || null; }

  owns(job, principal) {
    const owner = String(principal?.sub || '').trim();
    return Boolean(job && owner && (job.owner === owner || principal?.role === 'admin'));
  }

  jobDir(id) { return path.join(this.paths.jobs, id); }

  runDir(job) {
    if (!job?.runId || !/^ns-[A-Za-z0-9._-]+$/.test(job.runId)) return null;
    const candidate = path.resolve(this.jobDir(job.id), 'project', 'runs', job.runId);
    const root = path.resolve(this.jobDir(job.id), 'project', 'runs');
    return candidate.startsWith(`${root}${path.sep}`) ? candidate : null;
  }

  async persist(job) {
    const value = {
      ...publicJob(job, { includeFeed: true }),
      // Secret-free launch shape used only to recover an interrupted REPL.
      launch: job.input || null,
    };
    await writeJson(path.join(this.jobDir(job.id), 'job.json'), value);
  }

  push(job, event) {
    const safe = redactAutoValue({ ...event, at: event.at || new Date().toISOString() });
    job.feed.push(safe);
    if (job.feed.length > MAX_FEED) job.feed.splice(0, job.feed.length - MAX_FEED);
    job.updatedAt = new Date().toISOString();
    this.emit(`job:${job.id}`, safe);
    clearTimeout(job.persistTimer);
    job.persistTimer = setTimeout(() => { void this.persist(job); }, event.type === 'finding' ? 0 : 750);
    job.persistTimer.unref?.();
  }

  async start(input, { owner, profile, artexToken, artexBaseUrl, scopeHost }) {
    await this.ready;
    if (!this.binaryReady()) throw new Error('binário NeuroSploit ausente; execute npm run neurosploit:build');
    if (!MODES.has(input.mode)) throw new Error('modo NeuroSploit inválido');
    const id = randomUUID();
    const now = new Date().toISOString();
    const projectDir = path.join(this.jobDir(id), 'project');
    await fs.mkdir(projectDir, { recursive: true, mode: 0o700 });
    const mcpServers = await validateCodexMcpSelection({ root: this.root, selected: input.mcpServers });
    if (mcpServers.length && input.codexCli !== true) {
      throw new Error('MCPs pessoais e gerenciados exigem execução pelo Codex CLI');
    }
    if (input.codexCli === true && String(profile.format || '') !== 'chatgpt-plan') {
      throw new Error('execução Codex CLI exige um perfil Codex/ChatGPT Plan');
    }
    const managedMcpPath = path.join(projectDir, 'mcp.servers.json');
    const managedMcpServers = codexManagedMcpServers(this.root, mcpServers);
    await writeJson(managedMcpPath, { mcpServers: managedMcpServers });
    const personalMcpNames = await discoverCodexMcpNames();
    const autoContext = input?.autoContext && typeof input.autoContext === 'object'
      ? input.autoContext
      : null;
    const autoContextPath = autoContext ? path.join(projectDir, 'auto-context.json') : '';
    if (autoContextPath) await writeJson(autoContextPath, autoContext);
    const contextInstruction = autoContextPath
      ? `Continue o plano Auto do GHOSTRECON. Leia ${autoContextPath} antes de agir; reutilize as coletas concluídas e valide somente lacunas ainda abertas.`
      : '';
    const runtimeInput = {
      ...input,
      focus: [contextInstruction, input.focus].filter(Boolean).join(' '),
    };
    const { autoContext: _autoContext, ...launchInput } = runtimeInput;
    const job = {
      id,
      owner,
      mode: input.mode,
      target: oneLine(input.target),
      repository: oneLine(input.repository),
      engagementId: oneLine(input.engagementId, 120),
      authorizationReference: oneLine(input.authorizationReference, 240),
      autoSessionId: oneLine(input.autoSessionId, 140) || null,
      autoPlanHash: oneLine(input.autoPlanHash, 80) || null,
      profileId: Number(profile.id),
      profileName: oneLine(profile.name, 160),
      model: oneLine(profile.model, 400),
      codexCli: input.codexCli === true,
      mcpServers,
      phase: 'starting',
      done: false,
      interrupted: false,
      resumable: REPL_MODES.has(input.mode),
      repl: REPL_MODES.has(input.mode),
      exitCode: null,
      runId: null,
      reportReady: false,
      findings: [],
      feed: [],
      agents: 0,
      agentsDone: 0,
      startedAt: now,
      updatedAt: now,
      input: redactAutoValue({ ...launchInput, profileId: Number(profile.id) }),
      child: null,
    };
    this.jobs.set(id, job);
    await this.persist(job);
    const args = job.repl
      ? [
          ...(scopeHost ? ['--session-in-scope', scopeHost] : []),
          '--session-environment', oneLine(input.environment || 'production', 40),
          '--session-policy', oneLine(input.policy || 'web', 40),
          ...(job.engagementId ? ['--engagement', job.engagementId] : []),
        ]
      : oneShotArgs(runtimeInput, profile.model, scopeHost);
    const bridge = `${String(artexBaseUrl).replace(/\/+$/, '')}/api/internal/llm/profiles/${Number(profile.id)}/v1`;
    const env = {
      ...process.env,
      NEUROSPLOIT_BASE: this.paths.engine,
      NEUROSPLOIT_RUN_ROOT: projectDir,
      NEUROSPLOIT_CACHE_SCOPE: id,
      NEUROSPLOIT_CACHE: 'on',
      ...(input.codexCli === true ? {} : { LITELLM_BASE_URL: bridge, LITELLM_API_KEY: artexToken }),
      NEUROSPLOIT_MCP_SERVERS_FILE: managedMcpPath,
      NEUROSPLOIT_CODEX_PERSONAL_MCPS: personalMcpNames.join(','),
      NEUROSPLOIT_CODEX_MCP_ALLOWLIST: mcpServers.join(','),
      NEUROSPLOIT_MCP_PLAYWRIGHT: mcpServers.includes('playwright') ? '1' : '0',
      GHOSTRECON_NEUROSPLOIT_JOB: id,
    };
    this.launch(job, args, env, job.repl ? replScript(runtimeInput, profile.model) : []);
    return publicJob(job, { includeFeed: true });
  }

  launch(job, args, env, script = []) {
    const child = this.spawnImpl(this.paths.binary, args, {
      cwd: path.join(this.jobDir(job.id), 'project'),
      env,
      detached: process.platform !== 'win32',
      stdio: ['pipe', 'pipe', 'pipe'],
      windowsHide: true,
    });
    job.child = child;
    let buffer = '';
    const onData = (chunk) => {
      buffer += chunk.toString('utf8');
      let index;
      while ((index = buffer.indexOf('\n')) >= 0) {
        const line = buffer.slice(0, index);
        buffer = buffer.slice(index + 1);
        ingestLine(this, job, line);
      }
      if (buffer.length > MAX_LINE * 4) {
        ingestLine(this, job, buffer.slice(0, MAX_LINE));
        buffer = '';
      }
    };
    child.stdout?.on('data', onData);
    child.stderr?.on('data', onData);
    child.on('error', (error) => {
      this.push(job, { type: 'error', message: cleanLine(error?.message || error) });
      this.finish(job, -1, 'failed');
    });
    child.on('close', (code, signal) => {
      if (buffer.trim()) ingestLine(this, job, buffer);
      job.child = null;
      if (!job.done) this.finish(job, Number.isInteger(code) ? code : -1, signal ? 'cancelled' : (code === 0 ? 'completed' : 'failed'));
      else void this.persist(job);
    });
    for (const line of script) child.stdin?.write(`${line}\n`);
  }

  async finish(job, exitCode, phase) {
    if (job.done) return;
    job.done = true;
    job.phase = phase;
    job.exitCode = exitCode;
    job.finishedAt = new Date().toISOString();
    job.updatedAt = job.finishedAt;
    await this.hydrateFindings(job);
    this.push(job, { type: 'done', exitCode, phase });
    await this.persist(job);
    if (typeof this.onTerminal === 'function') {
      try {
        job.cortex = await this.onTerminal(publicJob(job, { includeFeed: false }), this.runDir(job));
      } catch (error) {
        job.cortex = { ok: false, error: cleanLine(error?.message || error) };
      }
      await this.persist(job);
    }
    this.emit(`job-terminal:${job.id}`, publicJob(job, { includeFeed: true }));
  }

  async hydrateFindings(job) {
    const dir = this.runDir(job);
    if (!dir) return;
    try {
      const rows = JSON.parse(await fs.readFile(path.join(dir, 'findings.json'), 'utf8'));
      if (Array.isArray(rows)) job.findings = rows.map(publicFinding).filter(Boolean);
      job.reportReady = ['report.html', 'report.md', 'report.json', 'report.pdf'].some((name) => fsSync.existsSync(path.join(dir, name)));
    } catch { /* live findings remain available */ }
  }

  async snapshot(id, { includeFeed = true } = {}) {
    await this.ready;
    const job = this.job(id);
    return job ? publicJob(job, { includeFeed }) : null;
  }

  async waitForTerminal(id, { signal = null, timeoutMs = 2 * 60 * 60_000, onEvent = null } = {}) {
    await this.ready;
    const job = this.job(id);
    if (!job) throw new Error('engagement NeuroSploit não encontrado');
    if (job.done) return publicJob(job, { includeFeed: true });
    return new Promise((resolve, reject) => {
      const eventName = `job:${job.id}`;
      const terminalName = `job-terminal:${job.id}`;
      let timer = null;
      const cleanup = () => {
        this.off(eventName, handleEvent);
        this.off(terminalName, handleTerminal);
        signal?.removeEventListener?.('abort', handleAbort);
        if (timer) clearTimeout(timer);
      };
      const handleEvent = (event) => {
        try { onEvent?.(event); } catch { /* observer errors never stop the engine */ }
      };
      const handleTerminal = (snapshot) => {
        cleanup();
        resolve(snapshot);
      };
      const handleAbort = () => {
        cleanup();
        this.kill(job.child?.pid, 'SIGTERM');
        const error = signal?.reason instanceof Error ? signal.reason : new Error('NeuroSploit Auto cancelado');
        error.name = 'AbortError';
        reject(error);
      };
      this.on(eventName, handleEvent);
      this.once(terminalName, handleTerminal);
      if (signal?.aborted) {
        handleAbort();
        return;
      }
      signal?.addEventListener?.('abort', handleAbort, { once: true });
      timer = setTimeout(() => {
        cleanup();
        this.kill(job.child?.pid, 'SIGTERM');
        reject(new Error('timeout aguardando o NeuroSploit no Modo Auto'));
      }, Math.max(1_000, Number(timeoutMs) || 2 * 60 * 60_000));
      timer.unref?.();
    });
  }

  async control(id, action) {
    await this.ready;
    const job = this.job(id);
    if (!job) throw new Error('engagement NeuroSploit não encontrado');
    if (!job.child || job.child.exitCode !== null) throw new Error('processo NeuroSploit não está ativo');
    if (action === 'pause' || action === 'continue') {
      if (!job.repl || !job.child.stdin?.writable) throw new Error('pause/continue exige modo interativo');
      job.child.stdin.write(action === 'pause' ? '/pause\n' : '/continue\n');
      job.phase = action === 'pause' ? 'pausing' : 'resuming';
    } else if (action === 'stop') {
      if (job.repl && job.child.stdin?.writable) {
        job.child.stdin.write('/stop\n1\n');
        job.phase = 'stopping';
        const pid = job.child.pid;
        setTimeout(() => this.kill(pid, 'SIGTERM'), 45_000).unref?.();
      } else {
        this.kill(job.child.pid, 'SIGINT');
        job.phase = 'stopping';
      }
    } else throw new Error('ação NeuroSploit inválida');
    this.push(job, { type: 'control', action });
    await this.persist(job);
    return publicJob(job, { includeFeed: true });
  }

  async resume(id, { profile, artexToken, artexBaseUrl, scopeHost }) {
    await this.ready;
    const job = this.job(id);
    if (!job) throw new Error('engagement NeuroSploit não encontrado');
    if (!job.interrupted || !job.resumable || !job.repl || !job.input) {
      throw new Error('este engagement NeuroSploit não possui checkpoint retomável');
    }
    if (Number(profile?.id) !== Number(job.profileId)) throw new Error('o perfil LLM original do engagement não está disponível');
    const projectDir = path.join(this.jobDir(job.id), 'project');
    const args = [
      ...(scopeHost ? ['--session-in-scope', scopeHost] : []),
      '--session-environment', oneLine(job.input.environment || 'production', 40),
      '--session-policy', oneLine(job.input.policy || 'web', 40),
      ...(job.engagementId ? ['--engagement', job.engagementId] : []),
    ];
    const bridge = `${String(artexBaseUrl).replace(/\/+$/, '')}/api/internal/llm/profiles/${Number(profile.id)}/v1`;
    const mcpServers = normalizeMcpSelection(job.input.mcpServers);
    const personalMcpNames = await discoverCodexMcpNames();
    const env = {
      ...process.env,
      NEUROSPLOIT_BASE: this.paths.engine,
      NEUROSPLOIT_RUN_ROOT: projectDir,
      NEUROSPLOIT_CACHE_SCOPE: job.id,
      NEUROSPLOIT_CACHE: 'on',
      NEUROSPLOIT_AUTO_RESUME: '1',
      ...(job.codexCli ? {} : { LITELLM_BASE_URL: bridge, LITELLM_API_KEY: artexToken }),
      NEUROSPLOIT_MCP_SERVERS_FILE: path.join(projectDir, 'mcp.servers.json'),
      NEUROSPLOIT_CODEX_PERSONAL_MCPS: personalMcpNames.join(','),
      NEUROSPLOIT_CODEX_MCP_ALLOWLIST: mcpServers.join(','),
      NEUROSPLOIT_MCP_PLAYWRIGHT: mcpServers.includes('playwright') ? '1' : '0',
      GHOSTRECON_NEUROSPLOIT_JOB: job.id,
    };
    job.done = false;
    job.interrupted = false;
    job.phase = 'resuming';
    job.exitCode = null;
    job.finishedAt = null;
    this.push(job, { type: 'control', action: 'resume' });
    this.launch(job, args, env, []);
    await this.persist(job);
    return publicJob(job, { includeFeed: true });
  }

  kill(pid, signal) {
    if (!Number.isInteger(pid) || pid <= 0) return;
    try { process.kill(process.platform === 'win32' ? pid : -pid, signal); } catch { /* already gone */ }
  }

  async artifact(id, relative) {
    const job = this.job(id);
    const root = this.runDir(job);
    if (!root) return null;
    const safe = oneLine(relative, 500).replace(/\\/g, '/');
    if (!safe || safe.startsWith('/') || safe.split('/').includes('..')) return null;
    const full = path.resolve(root, safe);
    if (full !== root && !full.startsWith(`${root}${path.sep}`)) return null;
    const stat = await fs.stat(full).catch(() => null);
    return stat?.isFile() ? { full, size: stat.size, name: path.basename(full) } : null;
  }
}

let shared = null;

export function getNeuroSploitManager(options = {}) {
  if (!shared || shared.root !== options.root) shared = new NeuroSploitManager(options);
  else if (options.onTerminal) shared.onTerminal = options.onTerminal;
  return shared;
}

export function resetNeuroSploitManagerForTests() { shared = null; }

export const NEUROSPLOIT_MODES = Object.freeze([...MODES]);
