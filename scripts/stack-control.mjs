#!/usr/bin/env node
/**
 * Controle auxiliar da stack: status / stop a partir de .runtime/stack-pids.json.
 * Uso: node scripts/stack-control.mjs status|stop
 */
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const ROOT = path.resolve(__dirname, '..');
const PID_FILE = path.join(ROOT, '.runtime', 'stack-pids.json');

function readPidFile() {
  try {
    return JSON.parse(fs.readFileSync(PID_FILE, 'utf8'));
  } catch {
    return null;
  }
}

function isAlive(pid) {
  if (!Number.isInteger(pid) || pid <= 0) return false;
  try {
    process.kill(pid, 0);
    return true;
  } catch {
    return false;
  }
}

function cmdStatus() {
  const data = readPidFile();
  if (!data?.processes?.length) {
    process.stdout.write('stack: nenhum PID file (.runtime/stack-pids.json)\n');
    return 1;
  }
  process.stdout.write(`stack: atualizado ${data.updatedAt || '?'}\n`);
  for (const row of data.processes) {
    const alive = isAlive(row.pid);
    process.stdout.write(
      `  ${String(row.name || '?').padEnd(14)} pid=${row.pid} ${alive ? 'alive' : 'dead'}`
      + `${row.detail ? ` ${row.detail}` : ''}\n`,
    );
  }
  return 0;
}

function cmdStop() {
  const data = readPidFile();
  if (!data?.processes?.length) {
    process.stderr.write('stack: nada para parar (PID file ausente)\n');
    return 1;
  }
  let stopped = 0;
  for (const row of [...data.processes].reverse()) {
    if (!isAlive(row.pid)) continue;
    try {
      process.kill(row.pid, 'SIGTERM');
      stopped += 1;
      process.stdout.write(`stack: SIGTERM ${row.name} pid=${row.pid}\n`);
    } catch (error) {
      process.stderr.write(`stack: falha ao parar ${row.name}: ${error.message}\n`);
    }
  }
  try {
    fs.rmSync(PID_FILE, { force: true });
  } catch {
    // ignore
  }
  process.stdout.write(`stack: sinal enviado a ${stopped} processo(s)\n`);
  return 0;
}

const cmd = String(process.argv[2] || 'status').trim().toLowerCase();
if (cmd === 'status') process.exit(cmdStatus());
if (cmd === 'stop') process.exit(cmdStop());
process.stderr.write('uso: node scripts/stack-control.mjs status|stop\n');
process.exit(2);
