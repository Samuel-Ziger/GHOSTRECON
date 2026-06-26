#!/usr/bin/env node
import '../load-env.js';
import {
  closeGhostCommandGate,
  ghostCommandConfig,
  loadGhostCommandGate,
  openGhostCommandGate,
} from '../modules/ghostcommand.mjs';

const cmd = String(process.argv[2] || 'status').trim().toLowerCase();
const config = ghostCommandConfig();

try {
  if (cmd === 'open') {
    const gate = await openGhostCommandGate({ reason: process.argv[3] || 'manual', by: 'vps-cli' }, config.stateDir);
    process.stdout.write(`${JSON.stringify({ ok: true, gate }, null, 2)}\n`);
  } else if (cmd === 'close') {
    const gate = await closeGhostCommandGate({ reason: process.argv[3] || 'manual', by: 'vps-cli' }, config.stateDir);
    process.stdout.write(`${JSON.stringify({ ok: true, gate }, null, 2)}\n`);
  } else if (cmd === 'status') {
    const gate = await loadGhostCommandGate(config.stateDir);
    process.stdout.write(`${JSON.stringify({ ok: true, gate }, null, 2)}\n`);
  } else {
    process.stderr.write('uso: node server/scripts/ghostcommand-gate.mjs open|close|status [reason]\n');
    process.exit(2);
  }
} catch (e) {
  process.stderr.write(`ghostcommand-gate: ${e?.message || e}\n`);
  process.exit(1);
}
