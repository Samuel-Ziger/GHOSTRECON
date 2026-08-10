import test from 'node:test';
import assert from 'node:assert/strict';
import {
  parseWifiTargets,
  parseWifiToolLine,
  detectAlfaFromLsusb,
  parseIwInterfaces,
  runWifiPentest,
  probeWifiEnvironment,
} from '../modules/kali-wifi.mjs';

test('parseWifiTargets separa BSSID e SSID', () => {
  const t = parseWifiTargets('AA:BB:CC:DD:EE:FF\nLabAP\n#ignore\n');
  assert.deepEqual(t.bssids, ['aa:bb:cc:dd:ee:ff']);
  assert.deepEqual(t.ssids, ['LabAP']);
});

test('detectAlfaFromLsusb reconhece 0e8d:7612', () => {
  const d = detectAlfaFromLsusb(
    'Bus 001 Device 004: ID 0e8d:7612 MediaTek Inc. Wireless\nBus 001 Device 001: ID 1d6b:0002',
  );
  assert.equal(d.found, true);
  assert.equal(d.matches[0].byId, true);
});

test('parseIwInterfaces extrai wlan', () => {
  const ifaces = parseIwInterfaces(`
phy#0
	Interface wlan0
		ifindex 3
		wdev 0x1
		addr 00:c0:ca:a1:b2:c3
		type managed
`);
  assert.equal(ifaces.length, 1);
  assert.equal(ifaces[0].name, 'wlan0');
  assert.equal(ifaces[0].type, 'managed');
});

test('parseWifiToolLine: handshake e crack', () => {
  const h = parseWifiToolLine('[+] Handshake captured for aa:bb:cc:dd:ee:ff');
  assert.equal(h.type, 'wifi_handshake');
  const c = parseWifiToolLine('[+] KEY FOUND! PSK: secretlab');
  assert.equal(c.type, 'wifi_crack');
  assert.match(c.meta, /secretlab/);
});

function mockRunner(handlers) {
  return async (cmd, args = [], opts = {}) => {
    const normalizedCmd = cmd === 'where' ? 'which' : cmd;
    const key = `${normalizedCmd} ${args.join(' ')}`.trim();
    for (const [prefix, fn] of handlers) {
      if (key === prefix || key.startsWith(prefix) || normalizedCmd === prefix || cmd === prefix) {
        const out = typeof fn === 'function' ? await fn(normalizedCmd, args, opts) : fn;
        return {
          code: 0,
          stdout: out.stdout || '',
          stderr: out.stderr || '',
          timedOut: false,
        };
      }
    }
    return { code: 1, stdout: '', stderr: `missing mock for ${cmd} ${args.join(' ')}`, timedOut: false };
  };
}

test('runWifiPentest sem confirm: só readiness', async () => {
  const events = [];
  const runProcessImpl = mockRunner([
    ['which', async (_c, args) => ({ stdout: `/usr/bin/${args[0]}\n` })],
    ['lsusb', { stdout: 'Bus 001 Device 004: ID 0e8d:7612 MediaTek AWUS036ACM\n' }],
    ['iw', { stdout: 'Interface wlan0\n\ttype managed\n' }],
  ]);

  const r = await runWifiPentest({
    targetsText: 'aa:bb:cc:dd:ee:ff',
    labConfirm: false,
    emit: (e) => events.push(e),
    runProcessImpl,
    getKaliCapabilitiesImpl: async () => ({ kali: true, message: 'ok', tools: {} }),
  });

  assert.equal(r.reason, 'readiness_only');
  assert.ok(r.findings.some((f) => /ALFA/.test(f.value)));
  assert.equal(events.some((e) => e.type === 'log' && /wifite/.test(e.message || '')), false);
});

test('runWifiPentest sem alvos: readiness', async () => {
  const runProcessImpl = mockRunner([
    ['which', async (_c, args) => ({ stdout: `/usr/bin/${args[0]}\n` })],
    ['lsusb', { stdout: 'ID 0e8d:7612\n' }],
    ['iw', { stdout: 'Interface wlan0\n\ttype managed\n' }],
  ]);
  const r = await runWifiPentest({
    targetsText: '',
    labConfirm: true,
    runProcessImpl,
    getKaliCapabilitiesImpl: async () => ({ kali: true, message: 'ok', tools: {} }),
  });
  assert.equal(r.reason, 'readiness_only');
});

test('runWifiPentest com alvos+confirm chama wifite', async () => {
  const called = [];
  const runProcessImpl = mockRunner([
    ['which', async (_c, args) => ({ stdout: `/usr/bin/${args[0]}\n` })],
    ['lsusb', { stdout: 'ID 0e8d:7612 AWUS036ACM\n' }],
    ['iw', { stdout: 'Interface wlan0\n\ttype managed\n' }],
    ['airmon-ng', async (_c, args) => {
      called.push(['airmon-ng', ...args]);
      if (args[0] === 'start') return { stdout: 'monitor mode enabled on wlan0mon\n' };
      return { stdout: 'stopped\n' };
    }],
    ['wifite', async (_c, args, opts) => {
      called.push(['wifite', ...args]);
      if (typeof opts.onStdout === 'function') {
        opts.onStdout(Buffer.from('[+] Handshake captured for aa:bb:cc:dd:ee:ff\n'));
      }
      return { stdout: '', stderr: '' };
    }],
  ]);

  const findings = [];
  const r = await runWifiPentest({
    targetsText: 'aa:bb:cc:dd:ee:ff',
    labConfirm: true,
    emit: (e) => {
      if (e.type === 'finding') findings.push(e.finding);
    },
    runProcessImpl,
    getKaliCapabilitiesImpl: async () => ({ kali: true, message: 'ok', tools: {} }),
  });

  assert.equal(r.ok, true);
  assert.ok(called.some((c) => c[0] === 'wifite'));
  assert.ok(findings.some((f) => f.type === 'wifi_handshake'));
});

test('probeWifiEnvironment degrada sem Kali tools', async () => {
  const runProcessImpl = mockRunner([
    ['which', async () => ({ stdout: '' })],
  ]);
  const p = await probeWifiEnvironment({ runProcessImpl });
  assert.equal(p.adapter.found, false);
  assert.equal(p.readyForAttack, false);
});

test('runWifiPentest not_kali skip', async () => {
  const r = await runWifiPentest({
    labConfirm: true,
    targetsText: 'aa:bb:cc:dd:ee:ff',
    runProcessImpl: async () => {
      throw new Error('não deve spawnar');
    },
    getKaliCapabilitiesImpl: async () => ({ kali: false, message: 'não é Kali' }),
  });
  assert.equal(r.reason, 'not_kali');
});
