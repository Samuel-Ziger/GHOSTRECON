#!/usr/bin/env node
/**
 * Cursor/stdio launcher for HexStrike AI MCP.
 *
 * Ensures the local HexStrike API (:8888) is reachable, then runs hexstrike_mcp.py.
 * Stderr from the Python MCP client is redirected to a log file so Cursor does not
 * treat colored INFO logs as connection errors during tool discovery.
 */
import { spawn } from 'node:child_process';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const ROOT = path.resolve(__dirname, '..');
const HEX_DIR = path.join(ROOT, 'IAs', 'hexstrike-ai');
const PYTHON = path.join(HEX_DIR, 'hexstrike-env', 'bin', 'python3');
const SERVER_PY = path.join(HEX_DIR, 'hexstrike_server.py');
const MCP_PY = path.join(HEX_DIR, 'hexstrike_mcp.py');
const PORT = Number(process.env.GHOSTRECON_HEXSTRIKE_PORT || process.env.HEXSTRIKE_PORT || 8888);
const BASE_URL = String(
  process.env.GHOSTRECON_HEXSTRIKE_URL
    || process.env.HEXSTRIKE_URL
    || `http://127.0.0.1:${PORT}`,
).replace(/\/$/, '');
const HEALTH_URL = `${BASE_URL}/health`;
const SERVER_LOG = path.join(HEX_DIR, 'hexstrike-server.log');
const MCP_LOG = path.join(HEX_DIR, 'hexstrike-mcp-client.log');
const WAIT_MS = Number(process.env.HEXSTRIKE_MCP_WAIT_MS || 45000);

function logLine(message) {
  try {
    fs.appendFileSync(MCP_LOG, `[launcher] ${new Date().toISOString()} ${message}\n`);
  } catch {
    // ignore log write failures
  }
}

function fail(message) {
  logLine(`ERROR ${message}`);
  process.stderr.write(`[hexstrike-mcp-launcher] ${message}\n`);
  process.exit(1);
}

function assertReady() {
  for (const p of [PYTHON, SERVER_PY, MCP_PY]) {
    if (!fs.existsSync(p)) fail(`arquivo ausente: ${p}`);
  }
  try {
    fs.accessSync(PYTHON, fs.constants.X_OK);
  } catch {
    fail(`python do venv sem permissão de execução: ${PYTHON}`);
  }
}

async function healthOk(timeoutMs = 2500) {
  const ac = new AbortController();
  const t = setTimeout(() => ac.abort(), timeoutMs);
  try {
    const res = await fetch(HEALTH_URL, { signal: ac.signal });
    return res.ok;
  } catch {
    return false;
  } finally {
    clearTimeout(t);
  }
}

function startServerDetached() {
  fs.mkdirSync(HEX_DIR, { recursive: true });
  const out = fs.openSync(SERVER_LOG, 'a');
  const child = spawn(PYTHON, [SERVER_PY, '--port', String(PORT)], {
    cwd: HEX_DIR,
    detached: true,
    stdio: ['ignore', out, out],
    env: {
      ...process.env,
      GHOSTRECON_HEXSTRIKE_URL: BASE_URL,
      PYTHONUNBUFFERED: '1',
    },
  });
  child.unref();
  logLine(`started hexstrike_server.py pid=${child.pid} url=${BASE_URL}`);
}

async function ensureServer() {
  if (await healthOk()) {
    logLine(`hexstrike api already healthy at ${HEALTH_URL}`);
    return;
  }
  logLine(`hexstrike api offline; starting ${SERVER_PY}`);
  startServerDetached();
  const deadline = Date.now() + WAIT_MS;
  while (Date.now() < deadline) {
    if (await healthOk()) {
      logLine(`hexstrike api healthy at ${HEALTH_URL}`);
      return;
    }
    await new Promise((r) => setTimeout(r, 1000));
  }
  fail(`HexStrike API não respondeu em ${HEALTH_URL} após ${WAIT_MS}ms (veja ${SERVER_LOG})`);
}

function runMcp() {
  const logFd = fs.openSync(MCP_LOG, 'a');
  logLine(`exec mcp client --server ${BASE_URL}`);
  const child = spawn(PYTHON, [MCP_PY, '--server', BASE_URL], {
    cwd: HEX_DIR,
    env: {
      ...process.env,
      GHOSTRECON_HEXSTRIKE_URL: BASE_URL,
      PYTHONUNBUFFERED: '1',
    },
    // Keep MCP JSON-RPC on stdout; park noisy colored logs in a file.
    stdio: ['inherit', 'inherit', logFd],
  });

  const forward = (signal) => {
    try {
      child.kill(signal);
    } catch {
      // ignore
    }
  };
  process.on('SIGINT', () => forward('SIGINT'));
  process.on('SIGTERM', () => forward('SIGTERM'));

  child.on('error', (err) => fail(err.message));
  child.on('exit', (code, signal) => {
    if (signal) process.exit(1);
    process.exit(code ?? 1);
  });
}

assertReady();
await ensureServer();
runMcp();
