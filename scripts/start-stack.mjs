#!/usr/bin/env node
import fs from 'node:fs';
import path from 'node:path';
import { spawn } from 'node:child_process';
import { fileURLToPath } from 'node:url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const ROOT = path.resolve(__dirname, '..');
const GHOST_DIR = path.join(ROOT, 'ghost-local-v5', 'ghost-local');
const GHOST_START_SCRIPT = path.join(GHOST_DIR, 'start.sh');
const GHOST_PORT = Number(process.env.GHOST_PORT || process.env.PORT_GHOST || 8000);
const GHOST_HEALTH_URL = process.env.GHOST_HEALTH_URL || `http://127.0.0.1:${GHOST_PORT}/health`;
const GHOST_LOG_FILE = path.join(GHOST_DIR, 'ghost.log');
const SERVER_ENTRY = path.join(ROOT, 'server', 'index.js');

function log(msg) {
  process.stdout.write(`[STACK] ${msg}\n`);
}

function warn(msg) {
  process.stderr.write(`[STACK][WARN] ${msg}\n`);
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

async function startGhostIfNeeded() {
  if (await healthOk(GHOST_HEALTH_URL)) {
    log(`GHOST já está online em ${GHOST_HEALTH_URL}`);
    return;
  }
  if (!fs.existsSync(GHOST_START_SCRIPT)) {
    warn(`script do GHOST não encontrado em ${GHOST_START_SCRIPT}`);
    return;
  }
  if (!(await commandExists('bash'))) {
    warn('bash não encontrado; GHOST local não será iniciado automaticamente. A API Node continuará.');
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
  } else {
    warn(`GHOST não respondeu no tempo esperado; verifica ${GHOST_LOG_FILE}`);
  }
}

function startApi() {
  log('A iniciar API GHOSTRECON (Node)...');
  const child = spawn(process.execPath, [SERVER_ENTRY], {
    cwd: ROOT,
    env: process.env,
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

await startGhostIfNeeded();
startApi();
