#!/usr/bin/env node
/**
 * Stack completo GHOSTRECON — `npm start`
 * Sobe: motor Vigolium, GhostIA/Artex, HackBot, GhostTrace, GhostMap, GhostDesk, HexStrike, API Node.
 * Desliga um serviço: GHOSTRECON_STACK_<NOME>=0 (ver .env.example).
 */
import fs from 'node:fs';
import path from 'node:path';
import { spawn, spawnSync } from 'node:child_process';
import { randomBytes } from 'node:crypto';
import { fileURLToPath } from 'node:url';
import { getVigoliumCapabilities } from '../bridge/vigolium-capabilities.mjs';
import { ensureCveWebDb } from './ensure-cve-web-db.mjs';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const ROOT = path.resolve(__dirname, '..');

// Garante .env no processo pai (stack) — a API também carrega em server/load-env.js
await import('../server/load-env.js');
const API_PORT = Number(process.env.PORT || 3847);
const API_URL = process.env.GHOSTRECON_API_URL || `http://127.0.0.1:${API_PORT}`;

const GHOST_DIR = path.join(ROOT, 'ghost-local-v5', 'ghost-local');
const GHOST_START_SCRIPT = path.join(GHOST_DIR, 'start.sh');
const GHOST_UI_DIR = path.join(GHOST_DIR, 'frontend');
const GHOST_UI_PACKAGE = path.join(GHOST_UI_DIR, 'package.json');
const GHOST_UI_LOCK = path.join(GHOST_UI_DIR, 'package-lock.json');
const GHOST_UI_ENTRY = path.join(GHOST_UI_DIR, 'dist', 'index.html');
const GHOST_PORT = Number(process.env.GHOST_PORT || process.env.PORT_GHOST || 8000);
const GHOST_HEALTH_URL = process.env.GHOST_HEALTH_URL || `http://127.0.0.1:${GHOST_PORT}/health`;
const GHOST_LOG_FILE = path.join(GHOST_DIR, 'ghost.log');

const ARTEX_DIR = path.join(ROOT, 'IAs', 'artex');
const ARTEX_BIN = path.join(ARTEX_DIR, process.platform === 'win32' ? 'artex.exe' : 'artex');
const ARTEX_START_SCRIPT = path.join(ARTEX_DIR, 'start.sh');
const ARTEX_COMPOSE_FILE = path.join(ARTEX_DIR, 'docker-compose.ghostrecon.yml');
const ARTEX_RUNTIME_DIR = path.join(ROOT, '.runtime', 'artex');
const ARTEX_ADMIN_PASSWORD_FILE = path.join(ARTEX_RUNTIME_DIR, 'admin-password');
const ARTEX_POSTGRES_ENV_FILE = path.join(ARTEX_RUNTIME_DIR, 'postgres.env');
const ARTEX_LOG_FILE = path.join(ARTEX_DIR, 'artex.log');
const ARTEX_PORT = Number(process.env.ARTEX_PORT || 8787);
const ARTEX_PROXY_PORT = Number(process.env.ARTEX_PROXY_PORT || 8788);
const ARTEX_POSTGRES_PORT = Number(process.env.ARTEX_POSTGRES_PORT || 5433);
const ARTEX_BASE_URL = String(process.env.ARTEX_BASE_URL || `http://127.0.0.1:${ARTEX_PORT}`).replace(/\/+$/, '');
const ARTEX_HEALTH_URL = `${ARTEX_BASE_URL}/api/health`;

const HACKBOT_DIR = path.join(ROOT, 'IAs', 'hackbot');
const HACKBOT_ADAPTER = path.join(HACKBOT_DIR, 'ghostrecon_api.py');
const HACKBOT_VENV_PYTHON = path.join(HACKBOT_DIR, '.venv', process.platform === 'win32' ? 'Scripts/python.exe' : 'bin/python');
const HACKBOT_RUNTIME_DIR = path.join(ROOT, '.runtime', 'hackbot');
const HACKBOT_SERVICE_TOKEN_FILE = path.join(HACKBOT_RUNTIME_DIR, 'service-token');
const HACKBOT_PID_FILE = path.join(HACKBOT_RUNTIME_DIR, 'pid');
const HACKBOT_BINDINGS_FILE = path.join(HACKBOT_RUNTIME_DIR, 'model-bindings.json');
const HACKBOT_DATA_DIR = path.join(HACKBOT_RUNTIME_DIR, 'data');
const HACKBOT_LOG_FILE = path.join(HACKBOT_RUNTIME_DIR, 'hackbot.log');
const HACKBOT_PORT = Number(process.env.GHOSTRECON_HACKBOT_PORT || 8791);
const HACKBOT_BASE_URL = String(process.env.GHOSTRECON_HACKBOT_URL || `http://127.0.0.1:${HACKBOT_PORT}`).replace(/\/+$/, '');
const HACKBOT_HEALTH_URL = `${HACKBOT_BASE_URL}/health`;

const NEUROSPLOIT_DIR = path.join(ROOT, 'engines', 'neurosploit');
const NEUROSPLOIT_RUST_DIR = path.join(NEUROSPLOIT_DIR, 'neurosploit-rs');
const NEUROSPLOIT_BIN = path.join(NEUROSPLOIT_RUST_DIR, 'target', 'release', process.platform === 'win32' ? 'neurosploit.exe' : 'neurosploit');

const GHOSTTRACE_START_SCRIPT = path.join(ROOT, 'scripts', 'start-anotacao.sh');
const GHOSTTRACE_PORT = Number(process.env.GHOSTTRACE_PORT || 3010);
const GHOSTTRACE_HEALTH_URL =
  process.env.GHOSTTRACE_HEALTH_URL || `http://127.0.0.1:${GHOSTTRACE_PORT}/anotacao`;
const GHOSTTRACE_LOG_FILE = path.join(ROOT, 'GhostTrace', 'ghosttrace-dev.log');

const GHOSTMAP_START_SCRIPT = path.join(ROOT, 'scripts', 'start-ghostmap.sh');
const GHOSTMAP_PORT = Number(process.env.GHOSTMAP_PORT || 3020);
const GHOSTMAP_HEALTH_URL =
  process.env.GHOSTMAP_HEALTH_URL || `http://127.0.0.1:${GHOSTMAP_PORT}/ghostmap`;
const GHOSTMAP_LOG_FILE = path.join(ROOT, 'ghostmap', 'frontend', 'ghostmap.log');

const GHOSTDESK_START_SCRIPT = path.join(ROOT, 'scripts', 'start-ghostdesk.sh');
const GHOSTDESK_PORT = Number(process.env.GHOSTDESK_PORT || 5173);
const GHOSTDESK_HEALTH_URL =
  process.env.GHOSTDESK_HEALTH_URL || `http://127.0.0.1:${GHOSTDESK_PORT}/`;
const GHOSTDESK_LOG_FILE = path.join(ROOT, 'GhostDesk', 'frontend', 'ghostdesk.log');

const HEXSTRIKE_DIR = path.join(ROOT, 'IAs', 'hexstrike-ai');
const HEXSTRIKE_SERVER = path.join(HEXSTRIKE_DIR, 'hexstrike_server.py');
const HEXSTRIKE_VENV_PYTHON = path.join(HEXSTRIKE_DIR, 'hexstrike-env', 'bin', 'python3');
const HEXSTRIKE_PORT = Number(process.env.GHOSTRECON_HEXSTRIKE_PORT || process.env.HEXSTRIKE_PORT || 8888);
const HEXSTRIKE_BASE_URL = String(
  process.env.GHOSTRECON_HEXSTRIKE_URL || process.env.GHOST_HEXSTRIKE_URL || `http://127.0.0.1:${HEXSTRIKE_PORT}`,
).trim().replace(/\/+$/, '');
const HEXSTRIKE_HEALTH_URL = `${HEXSTRIKE_BASE_URL}/health`;
const HEXSTRIKE_LOG_FILE = path.join(HEXSTRIKE_DIR, 'hexstrike-server.log');

const VIGOLIUM_INSTALL_SCRIPT = path.join(ROOT, 'scripts', 'install-vigolium-engine.sh');
const VIGOLIUM_ENGINE_PATH = path.join(ROOT, 'engines', 'vigolium');
const SERVER_ENTRY = path.join(ROOT, 'server', 'index.js');

const stackStatus = [];
const trackedPids = [];
const PID_FILE = path.join(ROOT, '.runtime', 'stack-pids.json');

function trackPidValue(name, pidValue, detail = '') {
  const pid = Number(pidValue);
  if (!Number.isInteger(pid) || pid <= 0) return;
  if (trackedPids.some((entry) => entry.pid === pid)) return;
  trackedPids.push({ name, pid, detail, startedAt: new Date().toISOString() });
  try {
    fs.mkdirSync(path.dirname(PID_FILE), { recursive: true });
    fs.writeFileSync(PID_FILE, `${JSON.stringify({
      updatedAt: new Date().toISOString(),
      processes: trackedPids,
    }, null, 2)}\n`, { mode: 0o600 });
  } catch {
    // PID file é best-effort
  }
}

function trackPid(name, child, detail = '') {
  trackPidValue(name, child?.pid, detail);
}

function log(msg) {
  process.stdout.write(`[STACK] ${msg}\n`);
}

function warn(msg) {
  process.stderr.write(`[STACK][WARN] ${msg}\n`);
}

/** @param {'VIGOLIUM'|'GHOST'|'HACKBOT'|'NEUROSPLOIT'|'GHOSTTRACE'|'GHOSTMAP'|'GHOSTDESK'|'HEXSTRIKE'|'API'|'CVE'} name */
function stackEnabled(name, defaultOn = true) {
  const key = `GHOSTRECON_STACK_${name}`;
  const v = String(process.env[key] ?? '').trim().toLowerCase();
  if (v === '0' || v === 'false' || v === 'no') return false;
  if (v === '1' || v === 'true' || v === 'yes') return true;
  return defaultOn;
}

function noteService(name, state, detail = '') {
  stackStatus.push({ name, state, detail });
}

async function commandExists(cmd) {
  const finder = process.platform === 'win32' ? 'where' : 'which';
  return new Promise((resolve) => {
    const child = spawn(finder, [cmd], { stdio: 'ignore' });
    child.on('error', () => resolve(false));
    child.on('close', (code) => resolve(code === 0));
  });
}

async function healthOk(url) {
  try {
    const res = await fetch(url, { signal: AbortSignal.timeout(1200) });
    return res.ok;
  } catch {
    return false;
  }
}

async function waitForHealth(url, attempts = 25) {
  for (let i = 0; i < attempts; i++) {
    if (await healthOk(url)) return true;
    await new Promise((resolve) => setTimeout(resolve, 1000));
  }
  return false;
}

async function portInUse(port) {
  if (process.platform === 'win32') return false;
  return new Promise((resolve) => {
    const child = spawn('ss', ['-tln'], { stdio: ['ignore', 'pipe', 'ignore'] });
    let out = '';
    child.stdout?.on('data', (chunk) => {
      out += chunk;
    });
    child.on('error', () => resolve(false));
    child.on('close', () => resolve(new RegExp(`:${port} `).test(out)));
  });
}

function runBashScript(scriptPath, { cwd = ROOT, env = process.env, stdio = 'inherit' } = {}) {
  return new Promise((resolve) => {
    const child = spawn('bash', [scriptPath], { cwd, env, stdio, windowsHide: true });
    child.on('error', () => resolve(1));
    child.on('close', (code) => resolve(code ?? 1));
  });
}

function startDetachedBash(scriptPath, logFile, env = process.env) {
  fs.mkdirSync(path.dirname(logFile), { recursive: true });
  const outFd = fs.openSync(logFile, 'a');
  const errFd = fs.openSync(logFile, 'a');
  const child = spawn('bash', [scriptPath], {
    cwd: ROOT,
    detached: true,
    env,
    stdio: ['ignore', outFd, errFd],
    windowsHide: true,
  });
  trackPid(path.basename(scriptPath, path.extname(scriptPath)), child, scriptPath);
  child.unref();
  return child;
}

function resolveHexstrikePython() {
  if (fs.existsSync(HEXSTRIKE_VENV_PYTHON)) {
    try {
      fs.accessSync(HEXSTRIKE_VENV_PYTHON, fs.constants.X_OK);
      return HEXSTRIKE_VENV_PYTHON;
    } catch {
      // fall through
    }
  }
  return null;
}

function startDetachedPython(pythonPath, scriptPath, logFile, { cwd = ROOT, args = [], env = process.env } = {}) {
  fs.mkdirSync(path.dirname(logFile), { recursive: true });
  const outFd = fs.openSync(logFile, 'a');
  const errFd = fs.openSync(logFile, 'a');
  const child = spawn(pythonPath, [scriptPath, ...args], {
    cwd,
    detached: true,
    env,
    stdio: ['ignore', outFd, errFd],
    windowsHide: true,
  });
  trackPid(path.basename(scriptPath, path.extname(scriptPath)), child, scriptPath);
  child.unref();
  return child;
}

async function ensureVigoliumEngine() {
  if (!stackEnabled('VIGOLIUM')) {
    noteService('Vigolium', 'skip', 'GHOSTRECON_STACK_VIGOLIUM=0');
    return;
  }

  let cap = await getVigoliumCapabilities({ ghostRoot: ROOT });
  if (cap.installed) {
    log(`Motor Vigolium: ${cap.version || 'OK'} (${cap.binary})`);
    noteService('Vigolium', 'ok', cap.version || cap.binary);
    if (!process.env.GHOSTRECON_VIGOLIUM_BIN && cap.binary) {
      process.env.GHOSTRECON_VIGOLIUM_BIN = cap.binary;
    }
    return;
  }

  if (!fs.existsSync(VIGOLIUM_INSTALL_SCRIPT)) {
    warn('Motor Vigolium: install script ausente; DAST Go indisponível até npm run engine:install');
    noteService('Vigolium', 'warn', 'binário ausente');
    return;
  }
  if (!(await commandExists('bash'))) {
    warn('bash não encontrado; não foi possível instalar engines/vigolium');
    noteService('Vigolium', 'warn', 'sem bash');
    return;
  }

  log('Motor Vigolium: a instalar em engines/vigolium...');
  const code = await runBashScript(VIGOLIUM_INSTALL_SCRIPT);
  cap = await getVigoliumCapabilities({ ghostRoot: ROOT });
  if (cap.installed) {
    log(`Motor Vigolium instalado: ${cap.version || cap.binary}`);
    noteService('Vigolium', 'ok', `instalado ${cap.version || ''}`.trim());
    if (!process.env.GHOSTRECON_VIGOLIUM_BIN) process.env.GHOSTRECON_VIGOLIUM_BIN = cap.binary;
  } else if (code !== 0) {
    warn(`Instalação Vigolium falhou (exit ${code}); corre: npm run engine:install`);
    noteService('Vigolium', 'warn', `install exit ${code}`);
  } else {
    warn('Vigolium não encontrado no PATH após install; npm run engine:install ou curl install.sh');
    noteService('Vigolium', 'warn', 'não encontrado');
  }
}

async function startGhostIfNeeded() {
  if (!stackEnabled('GHOST')) {
    noteService('GHOST IA', 'skip', 'GHOSTRECON_STACK_GHOST=0');
    return;
  }
  if (!fs.existsSync(GHOST_UI_ENTRY) && fs.existsSync(GHOST_UI_PACKAGE)) {
    if (!(await commandExists(process.platform === 'win32' ? 'npm.cmd' : 'npm'))) {
      warn('npm não encontrado; a interface React do GHOST local não será compilada.');
    } else {
      const npmCommand = process.platform === 'win32' ? 'npm.cmd' : 'npm';
      const uiBuildEnv = {
        ...process.env,
        NODE_ENV: 'development',
        npm_config_omit: '',
        npm_config_production: 'false',
      };
      const ghostUiDepsReady = () => fs.existsSync(
        path.join(GHOST_UI_DIR, 'node_modules', 'vite', 'package.json'),
      );
      if (!ghostUiDepsReady()) {
        const installArgs = fs.existsSync(GHOST_UI_LOCK) ? ['ci'] : ['install'];
        log(`Dependências da UI GHOST em falta — a correr npm ${installArgs[0]}...`);
        const installResult = spawnSync(npmCommand, installArgs, {
          cwd: GHOST_UI_DIR,
          env: uiBuildEnv,
          stdio: 'inherit',
          windowsHide: true,
        });
        if (installResult.status !== 0) {
          warn(`Falha ao instalar a UI GHOST (exit ${installResult.status ?? 'desconhecido'}).`);
        }
      }
      if (ghostUiDepsReady()) {
        log('A compilar interface React do GHOST local...');
        const buildResult = spawnSync(npmCommand, ['run', 'build'], {
          cwd: GHOST_UI_DIR,
          env: uiBuildEnv,
          stdio: 'inherit',
          windowsHide: true,
        });
        if (buildResult.status !== 0 || !fs.existsSync(GHOST_UI_ENTRY)) {
          warn(`Build da UI GHOST indisponível (exit ${buildResult.status ?? 'desconhecido'}); /gui/ poderá responder 503.`);
        }
      }
    }
  }
  if (await healthOk(GHOST_HEALTH_URL) || (await portInUse(GHOST_PORT))) {
    log(`GHOST já está online em ${GHOST_HEALTH_URL}`);
    noteService('GHOST IA', 'ok', GHOST_HEALTH_URL);
    return;
  }
  if (!fs.existsSync(GHOST_START_SCRIPT)) {
    warn(`script do GHOST não encontrado em ${GHOST_START_SCRIPT}`);
    noteService('GHOST IA', 'warn', 'script ausente');
    return;
  }
  if (!(await commandExists('bash'))) {
    warn('bash não encontrado; GHOST local não será iniciado.');
    noteService('GHOST IA', 'warn', 'sem bash');
    return;
  }

  fs.mkdirSync(path.dirname(GHOST_LOG_FILE), { recursive: true });
  const outFd = fs.openSync(GHOST_LOG_FILE, 'a');
  const errFd = fs.openSync(GHOST_LOG_FILE, 'a');
  log(`A iniciar GHOST IA local em ${GHOST_HEALTH_URL}...`);
  const child = spawn('bash', [GHOST_START_SCRIPT], {
    cwd: GHOST_DIR,
    detached: true,
    env: {
      ...process.env,
      GHOST_START_HEXSTRIKE: process.env.GHOST_START_HEXSTRIKE || '0',
      PORT: String(GHOST_PORT),
      HOST: process.env.GHOST_HOST || process.env.HOST_GHOST || '127.0.0.1',
    },
    stdio: ['ignore', outFd, errFd],
    windowsHide: true,
  });
  child.unref();

  if (await waitForHealth(GHOST_HEALTH_URL)) {
    log(`GHOST online em ${GHOST_HEALTH_URL}`);
    noteService('GHOST IA', 'ok', GHOST_HEALTH_URL);
  } else {
    warn(`GHOST não respondeu; verifica ${GHOST_LOG_FILE}`);
    noteService('GHOST IA', 'warn', 'timeout');
  }
}

function readOrCreateRuntimeSecret(file, bytes = 32) {
  fs.mkdirSync(path.dirname(file), { recursive: true, mode: 0o700 });
  try {
    const value = fs.readFileSync(file, 'utf8').trim();
    if (value.length >= 24) return value;
  } catch {
    // first boot
  }
  const value = randomBytes(bytes).toString('base64url');
  fs.writeFileSync(file, `${value}\n`, { mode: 0o600 });
  return value;
}

function ensureArtexPostgresEnv() {
  const passwordFile = path.join(ARTEX_RUNTIME_DIR, 'postgres-password');
  const password = readOrCreateRuntimeSecret(passwordFile, 36);
  fs.mkdirSync(ARTEX_RUNTIME_DIR, { recursive: true, mode: 0o700 });
  const content = [
    'ARTEX_POSTGRES_USER=artex',
    `ARTEX_POSTGRES_PASSWORD=${password}`,
    'ARTEX_POSTGRES_DB=artex',
    `ARTEX_POSTGRES_PORT=${ARTEX_POSTGRES_PORT}`,
    '',
  ].join('\n');
  fs.writeFileSync(ARTEX_POSTGRES_ENV_FILE, content, { mode: 0o600 });
  return `postgres://artex:${password}@127.0.0.1:${ARTEX_POSTGRES_PORT}/artex?sslmode=disable`;
}

function artexSourcesNewerThanBinary() {
  if (!fs.existsSync(ARTEX_BIN)) return true;
  const binaryMtime = fs.statSync(ARTEX_BIN).mtimeMs;
  const pending = [ARTEX_DIR];
  while (pending.length) {
    const dir = pending.pop();
    for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
      if (entry.name === 'web' || entry.name === 'data' || entry.name === '.git') continue;
      const full = path.join(dir, entry.name);
      if (entry.isDirectory()) pending.push(full);
      else if ((entry.name.endsWith('.go') || entry.name === 'go.mod' || entry.name === 'go.sum')
        && fs.statSync(full).mtimeMs > binaryMtime) return true;
    }
  }
  return false;
}

async function startArtexIfNeeded() {
  if (!stackEnabled('ARTEX')) {
    noteService('GhostIA/Artex', 'skip', 'GHOSTRECON_STACK_ARTEX=0');
    return;
  }
  if (!fs.existsSync(ARTEX_DIR)) {
    warn(`backend Artex não encontrado em ${ARTEX_DIR}`);
    noteService('GhostIA/Artex', 'warn', 'backend ausente');
    return;
  }
  if (await healthOk(ARTEX_HEALTH_URL)) {
    log(`GhostIA/Artex já está online em ${ARTEX_BASE_URL}`);
    process.env.ARTEX_BASE_URL = ARTEX_BASE_URL;
    noteService('GhostIA/Artex', 'ok', ARTEX_BASE_URL);
    return;
  }
  if (await portInUse(ARTEX_PORT)) {
    warn(`porta ${ARTEX_PORT} ocupada por um serviço que não respondeu como Artex; GhostIA não será conectada.`);
    noteService('GhostIA/Artex', 'warn', `porta ${ARTEX_PORT} em conflito`);
    return;
  }

  const adminPassword = readOrCreateRuntimeSecret(ARTEX_ADMIN_PASSWORD_FILE, 36);
  let pgDsn = String(process.env.ARTEX_PG_DSN || '').trim();
  if (!pgDsn) {
    pgDsn = ensureArtexPostgresEnv();
    if (!(await commandExists('docker'))) {
      warn('Docker não encontrado; configure ARTEX_PG_DSN ou instale Docker para iniciar o PostgreSQL do Artex.');
      noteService('GhostIA/Artex', 'warn', 'PostgreSQL indisponível');
      return;
    }
    const compose = spawnSync('docker', [
      'compose', '-f', ARTEX_COMPOSE_FILE, '--env-file', ARTEX_POSTGRES_ENV_FILE,
      'up', '-d', 'postgres',
    ], { cwd: ARTEX_DIR, stdio: 'inherit', windowsHide: true });
    if (compose.status !== 0) {
      warn(`PostgreSQL Artex não iniciou via Docker Compose (exit ${compose.status ?? '?'}).`);
      noteService('GhostIA/Artex', 'warn', 'docker compose falhou');
      return;
    }
    for (let i = 0; i < 30 && !(await portInUse(ARTEX_POSTGRES_PORT)); i++) {
      await new Promise((resolve) => setTimeout(resolve, 1_000));
    }
  }

  if (artexSourcesNewerThanBinary()) {
    if (!(await commandExists('go'))) {
      warn('Go não encontrado; não foi possível compilar o backend Artex.');
      noteService('GhostIA/Artex', 'warn', 'Go ausente');
      return;
    }
    log('A compilar backend Artex sem frontend embutido...');
    const build = spawnSync('go', ['build', '-o', ARTEX_BIN, './cmd/artex'], {
      cwd: ARTEX_DIR,
      env: { ...process.env },
      stdio: 'inherit',
      windowsHide: true,
    });
    if (build.status !== 0) {
      warn(`Build Artex falhou (exit ${build.status ?? '?'}).`);
      noteService('GhostIA/Artex', 'warn', 'build falhou');
      return;
    }
  }
  if (!fs.existsSync(ARTEX_START_SCRIPT)) {
    warn(`supervisor Artex ausente em ${ARTEX_START_SCRIPT}`);
    noteService('GhostIA/Artex', 'warn', 'start.sh ausente');
    return;
  }

  fs.mkdirSync(path.dirname(ARTEX_LOG_FILE), { recursive: true });
  const outFd = fs.openSync(ARTEX_LOG_FILE, 'a');
  const errFd = fs.openSync(ARTEX_LOG_FILE, 'a');
  log(`A iniciar GhostIA/Artex em ${ARTEX_BASE_URL}...`);
  const child = spawn('bash', [ARTEX_START_SCRIPT,
    '-addr', `127.0.0.1:${ARTEX_PORT}`,
    '-proxy', `127.0.0.1:${ARTEX_PROXY_PORT}`,
    '-data', path.join(ARTEX_RUNTIME_DIR, 'data'),
  ], {
    cwd: ARTEX_DIR,
    detached: true,
    env: {
      ...process.env,
      ARTEX_PG_DSN: pgDsn,
      ARTEX_ADMIN_PASSWORD: adminPassword,
      ARTEX_CHATGPT_AUTH_FILE: path.join(ARTEX_DIR, 'chatgpt-plan-auth.json'),
      ARTEX_CHATGPT_REDIRECT_URI: process.env.ARTEX_CHATGPT_REDIRECT_URI || `${ARTEX_BASE_URL}/api/auth/chatgpt-plan/callback`,
      ARTEX_SKILL_DIR: path.join(ARTEX_DIR, 'skills'),
      ARTEX_LANG: process.env.ARTEX_LANG || 'en',
    },
    stdio: ['ignore', outFd, errFd],
    windowsHide: true,
  });
  trackPid('artex', child, ARTEX_BASE_URL);
  child.unref();
  process.env.ARTEX_BASE_URL = ARTEX_BASE_URL;
  process.env.ARTEX_ADMIN_PASSWORD = adminPassword;

  if (await waitForHealth(ARTEX_HEALTH_URL, 45)) {
    log(`GhostIA/Artex online em ${ARTEX_BASE_URL}`);
    noteService('GhostIA/Artex', 'ok', ARTEX_BASE_URL);
  } else {
    warn(`GhostIA/Artex não respondeu; verifica ${ARTEX_LOG_FILE}`);
    noteService('GhostIA/Artex', 'warn', 'timeout');
  }
}

async function startHackbotIfNeeded() {
  if (!stackEnabled('HACKBOT')) {
    noteService('HackBot', 'skip', 'GHOSTRECON_STACK_HACKBOT=0');
    return;
  }
  if (!fs.existsSync(HACKBOT_ADAPTER)) {
    warn(`adaptador HackBot não encontrado em ${HACKBOT_ADAPTER}`);
    noteService('HackBot', 'warn', 'backend ausente');
    return;
  }

  const serviceToken = readOrCreateRuntimeSecret(HACKBOT_SERVICE_TOKEN_FILE, 36);
  process.env.GHOSTRECON_HACKBOT_SERVICE_TOKEN = serviceToken;
  process.env.GHOSTRECON_HACKBOT_URL = HACKBOT_BASE_URL;
  process.env.HACKBOT_MODEL_BINDINGS_FILE = HACKBOT_BINDINGS_FILE;
  process.env.HACKBOT_DATA_DIR = HACKBOT_DATA_DIR;

  if (await healthOk(HACKBOT_HEALTH_URL)) {
    log(`HackBot já está online em ${HACKBOT_BASE_URL}`);
    try {
      const existingPid = Number(fs.readFileSync(HACKBOT_PID_FILE, 'utf8').trim());
      if (Number.isInteger(existingPid) && existingPid > 0) {
        process.kill(existingPid, 0);
        trackPidValue('hackbot', existingPid, HACKBOT_BASE_URL);
      }
    } catch {
      warn('HackBot online sem PID gerenciado; reinicie-o para incorporá-lo ao stack:stop.');
    }
    noteService('HackBot', 'ok', HACKBOT_BASE_URL);
    return;
  }
  if (await portInUse(HACKBOT_PORT)) {
    warn(`porta ${HACKBOT_PORT} ocupada por outro serviço; HackBot não será conectado.`);
    noteService('HackBot', 'warn', `porta ${HACKBOT_PORT} em conflito`);
    return;
  }

  let pythonName = '';
  if (fs.existsSync(HACKBOT_VENV_PYTHON)) {
    try {
      fs.accessSync(HACKBOT_VENV_PYTHON, fs.constants.X_OK);
      pythonName = HACKBOT_VENV_PYTHON;
    } catch {
      pythonName = '';
    }
  }
  if (!pythonName) {
    pythonName = (await commandExists('python3')) ? 'python3' : ((await commandExists('python')) ? 'python' : '');
  }
  if (!pythonName) {
    warn('Python 3 não encontrado; HackBot não será iniciado.');
    noteService('HackBot', 'warn', 'Python ausente');
    return;
  }
  const dependencyProbe = spawnSync(pythonName, ['-c', 'import fastapi, uvicorn'], {
    cwd: HACKBOT_DIR,
    stdio: 'ignore',
    windowsHide: true,
  });
  if (dependencyProbe.status !== 0) {
    warn('FastAPI/Uvicorn ausentes; o adaptador HackBot não será iniciado.');
    noteService('HackBot', 'warn', 'dependências HTTP ausentes');
    return;
  }

  fs.mkdirSync(HACKBOT_RUNTIME_DIR, { recursive: true, mode: 0o700 });
  log(`A iniciar HackBot em ${HACKBOT_BASE_URL}...`);
  const child = startDetachedPython(pythonName, HACKBOT_ADAPTER, HACKBOT_LOG_FILE, {
    cwd: HACKBOT_DIR,
    args: ['--host', '127.0.0.1', '--port', String(HACKBOT_PORT)],
    env: {
      ...process.env,
      GHOSTRECON_HACKBOT_SERVICE_TOKEN: serviceToken,
      GHOSTRECON_HACKBOT_URL: HACKBOT_BASE_URL,
      GHOSTRECON_ROOT: ROOT,
      HACKBOT_MODEL_BINDINGS_FILE: HACKBOT_BINDINGS_FILE,
      HACKBOT_DATA_DIR,
      GHOSTRECON_HACKBOT_ALLOWED_ROOTS: [
        path.join(ROOT, 'reports'),
        path.join(ROOT, 'logs'),
        HACKBOT_RUNTIME_DIR,
        path.join(HACKBOT_DIR, 'samples'),
      ].join(path.delimiter),
    },
  });
  if (Number.isInteger(child?.pid) && child.pid > 0) {
    fs.writeFileSync(HACKBOT_PID_FILE, `${child.pid}\n`, { mode: 0o600 });
  }

  if (await waitForHealth(HACKBOT_HEALTH_URL, 20)) {
    log(`HackBot online em ${HACKBOT_BASE_URL}`);
    noteService('HackBot', 'ok', HACKBOT_BASE_URL);
  } else {
    warn(`HackBot não respondeu; verifica ${HACKBOT_LOG_FILE}`);
    noteService('HackBot', 'warn', 'timeout');
  }
}

function neurosploitSourcesNewerThanBinary() {
  if (!fs.existsSync(NEUROSPLOIT_BIN)) return true;
  const binaryMtime = fs.statSync(NEUROSPLOIT_BIN).mtimeMs;
  const pending = [NEUROSPLOIT_RUST_DIR];
  while (pending.length) {
    const dir = pending.pop();
    for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
      if (entry.name === 'target' || entry.name === '.git') continue;
      const full = path.join(dir, entry.name);
      if (entry.isDirectory()) pending.push(full);
      else if ((entry.name.endsWith('.rs') || entry.name === 'Cargo.toml' || entry.name === 'Cargo.lock')
        && fs.statSync(full).mtimeMs > binaryMtime) return true;
    }
  }
  return false;
}

async function ensureNeuroSploitEngine() {
  if (!stackEnabled('NEUROSPLOIT')) {
    noteService('NeuroSploit', 'skip', 'GHOSTRECON_STACK_NEUROSPLOIT=0');
    return;
  }
  if (!fs.existsSync(path.join(NEUROSPLOIT_RUST_DIR, 'Cargo.toml'))) {
    warn(`backend NeuroSploit não encontrado em ${NEUROSPLOIT_DIR}`);
    noteService('NeuroSploit', 'warn', 'backend ausente');
    return;
  }
  if (neurosploitSourcesNewerThanBinary()) {
    if (!(await commandExists('cargo'))) {
      warn('Rust/Cargo não encontrado; o NeuroSploit não pôde ser compilado.');
      noteService('NeuroSploit', 'warn', 'Cargo ausente');
      return;
    }
    log('A compilar motor NeuroSploit (Cargo offline, sem baixar dependências)...');
    const build = spawnSync('cargo', ['build', '--release', '--locked', '--offline'], {
      cwd: NEUROSPLOIT_RUST_DIR,
      env: { ...process.env },
      stdio: 'inherit',
      windowsHide: true,
    });
    if (build.status !== 0) {
      warn('Build offline do NeuroSploit falhou; execute `npm run neurosploit:build` para permitir dependências ausentes.');
      noteService('NeuroSploit', 'warn', 'build offline falhou');
      return;
    }
  }
  noteService('NeuroSploit', 'ok', 'engine local · perfis GhostIA/Artex');
}

async function startGhosttraceIfNeeded() {
  if (!stackEnabled('GHOSTTRACE')) {
    noteService('GhostTrace', 'skip', 'GHOSTRECON_STACK_GHOSTTRACE=0');
    return;
  }
  if (!fs.existsSync(GHOSTTRACE_START_SCRIPT)) {
    warn(`GhostTrace não encontrado em ${GHOSTTRACE_START_SCRIPT}`);
    noteService('GhostTrace', 'warn', 'script ausente');
    return;
  }
  if (await portInUse(GHOSTTRACE_PORT)) {
    log(`GhostTrace já está na porta ${GHOSTTRACE_PORT}`);
    noteService('GhostTrace', 'ok', `:${GHOSTTRACE_PORT}`);
    return;
  }
  if (!(await commandExists('bash'))) {
    warn('bash não encontrado; GhostTrace não será iniciado.');
    noteService('GhostTrace', 'warn', 'sem bash');
    return;
  }

  log(`A iniciar GhostTrace (anotações) na porta ${GHOSTTRACE_PORT}...`);
  startDetachedBash(GHOSTTRACE_START_SCRIPT, GHOSTTRACE_LOG_FILE, {
    ...process.env,
    GHOSTTRACE_PORT: String(GHOSTTRACE_PORT),
  });

  if (await waitForHealth(GHOSTTRACE_HEALTH_URL, 40)) {
    log(`GhostTrace online em ${GHOSTTRACE_HEALTH_URL}`);
    noteService('GhostTrace', 'ok', GHOSTTRACE_HEALTH_URL);
  } else if (await portInUse(GHOSTTRACE_PORT)) {
    log(`GhostTrace a escutar na porta ${GHOSTTRACE_PORT} (health check pendente)`);
    noteService('GhostTrace', 'ok', `:${GHOSTTRACE_PORT}`);
  } else {
    warn(`GhostTrace não respondeu; verifica ${GHOSTTRACE_LOG_FILE}`);
    noteService('GhostTrace', 'warn', 'timeout');
  }
}

async function startGhostmapIfNeeded() {
  if (!stackEnabled('GHOSTMAP')) {
    noteService('GhostMap', 'skip', 'GHOSTRECON_STACK_GHOSTMAP=0');
    return;
  }
  if (!fs.existsSync(GHOSTMAP_START_SCRIPT)) {
    warn(`script do GhostMap não encontrado em ${GHOSTMAP_START_SCRIPT}`);
    noteService('GhostMap', 'warn', 'script ausente');
    return;
  }
  if (await portInUse(GHOSTMAP_PORT)) {
    log(`GhostMap já está na porta ${GHOSTMAP_PORT}`);
    noteService('GhostMap', 'ok', `:${GHOSTMAP_PORT}`);
    return;
  }
  if (!(await commandExists('bash'))) {
    warn('bash não encontrado; GhostMap não será iniciado.');
    noteService('GhostMap', 'warn', 'sem bash');
    return;
  }

  log(`A iniciar GhostMap na porta ${GHOSTMAP_PORT}...`);
  startDetachedBash(GHOSTMAP_START_SCRIPT, GHOSTMAP_LOG_FILE);

  if (await waitForHealth(GHOSTMAP_HEALTH_URL, 45)) {
    log(`GhostMap online em ${GHOSTMAP_HEALTH_URL}`);
    noteService('GhostMap', 'ok', GHOSTMAP_HEALTH_URL);
  } else {
    warn(`GhostMap não respondeu; verifica ${GHOSTMAP_LOG_FILE}`);
    noteService('GhostMap', 'warn', 'timeout');
  }
}

async function startGhostdeskIfNeeded() {
  if (!stackEnabled('GHOSTDESK')) {
    noteService('GhostDesk', 'skip', 'GHOSTRECON_STACK_GHOSTDESK=0');
    return;
  }
  if (!fs.existsSync(GHOSTDESK_START_SCRIPT)) {
    warn(`script do GhostDesk não encontrado em ${GHOSTDESK_START_SCRIPT}`);
    noteService('GhostDesk', 'warn', 'script ausente');
    return;
  }
  if (await portInUse(GHOSTDESK_PORT)) {
    log(`GhostDesk já está na porta ${GHOSTDESK_PORT}`);
    noteService('GhostDesk', 'ok', `:${GHOSTDESK_PORT}`);
    return;
  }
  if (!(await commandExists('bash'))) {
    warn('bash não encontrado; GhostDesk não será iniciado.');
    noteService('GhostDesk', 'warn', 'sem bash');
    return;
  }

  log(`A iniciar GhostDesk na porta ${GHOSTDESK_PORT}...`);
  startDetachedBash(GHOSTDESK_START_SCRIPT, GHOSTDESK_LOG_FILE);

  if (await waitForHealth(GHOSTDESK_HEALTH_URL, 30)) {
    log(`GhostDesk online em ${GHOSTDESK_HEALTH_URL}`);
    noteService('GhostDesk', 'ok', GHOSTDESK_HEALTH_URL);
  } else {
    warn(`GhostDesk não respondeu; verifica ${GHOSTDESK_LOG_FILE}`);
    noteService('GhostDesk', 'warn', 'timeout');
  }
}

async function startHexstrikeIfNeeded() {
  if (!stackEnabled('HEXSTRIKE')) {
    noteService('HexStrike', 'skip', 'GHOSTRECON_STACK_HEXSTRIKE=0');
    return;
  }
  if (!fs.existsSync(HEXSTRIKE_SERVER)) {
    warn(`HexStrike não encontrado em ${HEXSTRIKE_SERVER}`);
    noteService('HexStrike', 'warn', 'server ausente');
    return;
  }
  if (await healthOk(HEXSTRIKE_HEALTH_URL) || (await portInUse(HEXSTRIKE_PORT))) {
    log(`HexStrike já está online em ${HEXSTRIKE_BASE_URL}`);
    noteService('HexStrike', 'ok', HEXSTRIKE_BASE_URL);
    if (!process.env.GHOSTRECON_HEXSTRIKE_URL) {
      process.env.GHOSTRECON_HEXSTRIKE_URL = HEXSTRIKE_BASE_URL;
    }
    return;
  }

  const pythonPath = resolveHexstrikePython();
  if (!pythonPath) {
    warn('HexStrike venv ausente; corre ./install.sh (ou --profile minimal -y) para criar IAs/hexstrike-ai/hexstrike-env');
    noteService('HexStrike', 'warn', 'venv ausente');
    return;
  }

  log(`A iniciar HexStrike AI em ${HEXSTRIKE_BASE_URL}...`);
  startDetachedPython(pythonPath, HEXSTRIKE_SERVER, HEXSTRIKE_LOG_FILE, {
    cwd: HEXSTRIKE_DIR,
    args: ['--port', String(HEXSTRIKE_PORT)],
    env: {
      ...process.env,
      GHOSTRECON_HEXSTRIKE_URL: HEXSTRIKE_BASE_URL,
    },
  });
  process.env.GHOSTRECON_HEXSTRIKE_URL = HEXSTRIKE_BASE_URL;

  if (await waitForHealth(HEXSTRIKE_HEALTH_URL, 90)) {
    log(`HexStrike online em ${HEXSTRIKE_BASE_URL}`);
    noteService('HexStrike', 'ok', HEXSTRIKE_BASE_URL);
  } else if (await portInUse(HEXSTRIKE_PORT)) {
    log(`HexStrike a escutar na porta ${HEXSTRIKE_PORT} (health check pendente)`);
    noteService('HexStrike', 'ok', `:${HEXSTRIKE_PORT}`);
  } else {
    warn(`HexStrike não respondeu; verifica ${HEXSTRIKE_LOG_FILE}`);
    noteService('HexStrike', 'warn', 'timeout');
  }
}

function printStackSummary() {
  log('── Stack GHOSTRECON ──');
  for (const row of stackStatus) {
    log(`  ${row.name.padEnd(12)} ${row.state.padEnd(5)} ${row.detail || ''}`.trimEnd());
  }
  log(`  ${'API'.padEnd(12)} start ${API_URL}`);
  log(`  ${'UI'.padEnd(12)}       ${API_URL}/`);
  if (stackEnabled('GHOSTTRACE')) {
    log(`  ${'Anotações'.padEnd(12)}   ${API_URL}/anotacao`);
  }
  if (stackEnabled('GHOSTMAP')) {
    log(`  ${'GhostMap'.padEnd(12)}   ${API_URL}/ghostmap/ghostrecon`);
  }
  if (stackEnabled('HEXSTRIKE')) {
    log(`  ${'HexStrike'.padEnd(12)}   ${HEXSTRIKE_BASE_URL}`);
  }
  if (stackEnabled('ARTEX')) {
    log(`  ${'GhostIA'.padEnd(12)}   ${ARTEX_BASE_URL}`);
  }
  if (stackEnabled('HACKBOT')) {
    log(`  ${'HackBot'.padEnd(12)}   ${HACKBOT_BASE_URL}`);
  }
  log('──────────────────────');
}

/**
 * Último passo do start (depois dos sidecars, antes da API): desativa IPv6 via sysctl.
 * Corre só estes três comandos com sudo para o prompt de senha não bloquear o resto da stack.
 * Desligar: GHOSTRECON_STACK_DISABLE_IPV6=0
 */
function applyDisableIpv6() {
  if (String(process.env.GHOSTRECON_STACK_DISABLE_IPV6 ?? '1').trim() === '0') {
    noteService('IPv6', 'skip', 'GHOSTRECON_STACK_DISABLE_IPV6=0');
    return;
  }

  const settings = [
    'net.ipv6.conf.all.disable_ipv6=1',
    'net.ipv6.conf.default.disable_ipv6=1',
    'net.ipv6.conf.lo.disable_ipv6=1',
  ];

  log('Último passo: desativar IPv6 (sudo). Digite a senha se pedida...');
  for (const setting of settings) {
    const result = spawnSync('sudo', ['sysctl', '-w', setting], {
      cwd: ROOT,
      stdio: 'inherit',
      windowsHide: true,
    });
    if (result.error) {
      warn(`IPv6: ${result.error.message || result.error}`);
      noteService('IPv6', 'warn', result.error.message || 'spawn falhou');
      return;
    }
    if (result.status !== 0) {
      warn(`IPv6: sudo sysctl -w ${setting} falhou (exit ${result.status ?? '?'})`);
      noteService('IPv6', 'warn', setting);
      return;
    }
  }
  noteService('IPv6', 'ok', 'disabled');
  log('IPv6 desativado.');
}

function startApi() {
  noteService('API', 'start', API_URL);
  printStackSummary();
  log('A iniciar API GHOSTRECON (Node) — Ctrl+C para parar...');
  const childEnv = { ...process.env };
  if (fs.existsSync(VIGOLIUM_ENGINE_PATH) && !childEnv.GHOSTRECON_VIGOLIUM_BIN) {
    childEnv.GHOSTRECON_VIGOLIUM_BIN = VIGOLIUM_ENGINE_PATH;
  }
  const child = spawn(process.execPath, [SERVER_ENTRY], {
    cwd: ROOT,
    env: childEnv,
    stdio: 'inherit',
    windowsHide: true,
  });
  trackPid('api', child, API_URL);
  child.on('exit', (code, signal) => {
    if (signal) {
      process.kill(process.pid, signal);
      return;
    }
    process.exit(typeof code === 'number' ? code : 1);
  });
}

async function ensureCveDataset() {
  if (!stackEnabled('CVE', true)) {
    noteService('CVE web DB', 'skip', 'GHOSTRECON_STACK_CVE=0');
    return;
  }
  try {
    const result = await ensureCveWebDb();
    if (result.status === 'skip') {
      noteService('CVE web DB', 'skip', result.detail);
    } else if (result.status === 'warn') {
      noteService('CVE web DB', 'warn', result.detail);
    } else {
      noteService('CVE web DB', 'ok', result.detail);
    }
  } catch (error) {
    warn(`CVE web DB: ${error?.message || error}`);
    noteService('CVE web DB', 'warn', error?.message || 'erro');
  }
}

await ensureCveDataset();
await ensureVigoliumEngine();
// A GhostIA atual é o backend Artex. O GHOST Python anterior permanece apenas
// como compatibilidade opt-in durante a migração.
if (stackEnabled('LEGACY_GHOST', false)) await startGhostIfNeeded();
await startArtexIfNeeded();
await startHackbotIfNeeded();
await ensureNeuroSploitEngine();
await startGhosttraceIfNeeded();
await startGhostmapIfNeeded();
await startGhostdeskIfNeeded();
await startHexstrikeIfNeeded();
applyDisableIpv6();
startApi();
