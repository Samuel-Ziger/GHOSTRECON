#!/usr/bin/env node
/**
 * Stack completo GHOSTRECON — `npm start`
 * Sobe: motor Vigolium, GHOST IA, GhostTrace, GhostMap, GhostDesk, API Node.
 * Desliga um serviço: GHOSTRECON_STACK_<NOME>=0 (ver .env.example).
 */
import fs from 'node:fs';
import path from 'node:path';
import { spawn } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { getVigoliumCapabilities } from '../bridge/vigolium-capabilities.mjs';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const ROOT = path.resolve(__dirname, '..');

// Garante .env no processo pai (stack) — a API também carrega em server/load-env.js
await import('../server/load-env.js');
const API_PORT = Number(process.env.PORT || 3847);
const API_URL = process.env.GHOSTRECON_API_URL || `http://127.0.0.1:${API_PORT}`;

const GHOST_DIR = path.join(ROOT, 'ghost-local-v5', 'ghost-local');
const GHOST_START_SCRIPT = path.join(GHOST_DIR, 'start.sh');
const GHOST_PORT = Number(process.env.GHOST_PORT || process.env.PORT_GHOST || 8000);
const GHOST_HEALTH_URL = process.env.GHOST_HEALTH_URL || `http://127.0.0.1:${GHOST_PORT}/health`;
const GHOST_LOG_FILE = path.join(GHOST_DIR, 'ghost.log');

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

const VIGOLIUM_INSTALL_SCRIPT = path.join(ROOT, 'scripts', 'install-vigolium-engine.sh');
const VIGOLIUM_ENGINE_PATH = path.join(ROOT, 'engines', 'vigolium');
const SERVER_ENTRY = path.join(ROOT, 'server', 'index.js');

const stackStatus = [];

function log(msg) {
  process.stdout.write(`[STACK] ${msg}\n`);
}

function warn(msg) {
  process.stderr.write(`[STACK][WARN] ${msg}\n`);
}

/** @param {'VIGOLIUM'|'GHOST'|'GHOSTTRACE'|'GHOSTMAP'|'GHOSTDESK'|'API'} name */
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
  log('──────────────────────');
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
  child.on('exit', (code, signal) => {
    if (signal) {
      process.kill(process.pid, signal);
      return;
    }
    process.exit(typeof code === 'number' ? code : 1);
  });
}

await ensureVigoliumEngine();
await startGhostIfNeeded();
await startGhosttraceIfNeeded();
await startGhostmapIfNeeded();
await startGhostdeskIfNeeded();
startApi();
