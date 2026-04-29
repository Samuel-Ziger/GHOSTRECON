/**
 * Tor STRICT — testes do anti-leak central.
 *
 * Foco em comportamento puro (sem I/O para Tor real):
 *  - isStrict / shouldWrap / wrapCommand
 *  - sanitizeOutboundHeaders
 *  - telemetryFor / snapshotTelemetry
 *  - strictPrereqs estrutura (não conseguimos garantir resultados sem rede,
 *    mas validamos o formato)
 */
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';

// Setup env ANTES do import
process.env.GHOSTRECON_TOR_STRICT = '1';
process.env.GHOSTRECON_PROXYCHAINS_BIN = '/bin/false';     // wrapCommand → refuse
process.env.GHOSTRECON_PROXYCHAINS_CONF = ''; // que a init reescreva no .runtime
const TMP = fs.mkdtempSync(path.join(os.tmpdir(), 'gr-tor-strict-'));

const {
  isStrict, initTorStrict, shouldWrap, wrapCommand,
  sanitizeOutboundHeaders, telemetryFor, snapshotTelemetry,
  clearTelemetry, strictPrereqs,
} = await import('../modules/tor-strict.js');

initTorStrict({ proxychainsBin: '/usr/bin/this-binary-does-not-exist-9999' });

// ─── isStrict ───────────────────────────────────────────────────────────────
test('isStrict respeita GHOSTRECON_TOR_STRICT=1', () => {
  assert.equal(isStrict(), true);
});

// ─── shouldWrap ─────────────────────────────────────────────────────────────
test('shouldWrap inclui defaults: nmap, sqlmap, curl, dig', () => {
  for (const c of ['nmap', 'sqlmap', 'curl', 'dig', 'host', 'wget', 'ffuf', 'nuclei']) {
    assert.equal(shouldWrap(c), true, `esperado wrap para ${c}`);
  }
});

test('shouldWrap ignora comandos não-listados (e.g. python3, node)', () => {
  for (const c of ['python3', 'node', 'bash', 'ls']) {
    assert.equal(shouldWrap(c), false);
  }
});

// ─── wrapCommand ────────────────────────────────────────────────────────────
test('wrapCommand recusa quando proxychains4 não existe', () => {
  const r = wrapCommand('nmap', ['-sV', 'x']);
  assert.equal(r.refuse, true);
  assert.match(r.reason, /proxychains4/i);
});

test('wrapCommand devolve { cmd, args } sem alterações para comandos não-wrap', () => {
  const r = wrapCommand('python3', ['-c', 'print(1)']);
  assert.equal(r.cmd, 'python3');
  assert.deepEqual(r.args, ['-c', 'print(1)']);
});

// ─── sanitizeOutboundHeaders ────────────────────────────────────────────────
test('sanitizeOutboundHeaders strip Referer/Origin/X-Forwarded-* e força UA Tor', () => {
  const out = sanitizeOutboundHeaders({
    Referer: 'https://internal.local/admin',
    Origin: 'https://internal.local',
    'X-Forwarded-For': '10.0.0.7',
    'X-Real-IP': '10.0.0.7',
    'X-Custom-Header': 'keep',
  });
  assert.equal(out.Referer, undefined);
  assert.equal(out.Origin, undefined);
  assert.equal(out['X-Forwarded-For'], undefined);
  assert.equal(out['X-Real-IP'], undefined);
  assert.equal(out['X-Custom-Header'], 'keep');
  assert.match(out['User-Agent'], /Firefox\/115/);
  assert.equal(out['Accept-Language'], 'en-US,en;q=0.5');
  assert.equal(out['DNT'], '1');
});

test('sanitizeOutboundHeaders remove sec-ch-ua* (ainda do Chrome)', () => {
  const out = sanitizeOutboundHeaders({
    'sec-ch-ua': '"Chromium";v="122"',
    'sec-ch-ua-mobile': '?0',
    'sec-ch-ua-platform': '"Windows"',
  });
  assert.equal(out['sec-ch-ua'], undefined);
  assert.equal(out['sec-ch-ua-mobile'], undefined);
  assert.equal(out['sec-ch-ua-platform'], undefined);
});

test('sanitizeOutboundHeaders preserva Cookie quando domain bate target', () => {
  const out = sanitizeOutboundHeaders(
    { Cookie: 'sid=abc; domain=example.com' },
    { targetHost: 'app.example.com' },
  );
  assert.equal(out.Cookie, 'sid=abc; domain=example.com');
});

test('sanitizeOutboundHeaders strip Cookie quando domain não bate', () => {
  const out = sanitizeOutboundHeaders(
    { Cookie: 'sid=abc; domain=other-tracker.net' },
    { targetHost: 'app.example.com' },
  );
  assert.equal(out.Cookie, undefined);
});

// ─── Telemetry ──────────────────────────────────────────────────────────────
test('telemetryFor / snapshotTelemetry contagem básica', () => {
  const runId = 'test-run-1';
  clearTelemetry(runId);
  const t = telemetryFor(runId);
  t.requests = 5;
  t.requestsViaTor = 4;
  t.exitIps.add('185.220.101.5');
  t.exitIps.add('185.220.101.7');
  t.proxyKindCounts.socks = 4;
  t.proxyKindCounts.direct = 1;
  const snap = snapshotTelemetry(runId);
  assert.equal(snap.requests, 5);
  assert.equal(snap.requestsViaTor, 4);
  assert.equal(snap.torRatio, 0.8);
  assert.equal(snap.exitIps.length, 2);
  assert.equal(snap.proxyKindCounts.socks, 4);
});

test('snapshotTelemetry devolve null para runId desconhecido', () => {
  assert.equal(snapshotTelemetry('does-not-exist'), null);
});

// ─── strictPrereqs estrutura ────────────────────────────────────────────────
test('strictPrereqs devolve checks array com nomes esperados', () => {
  const p = strictPrereqs();
  assert.equal(typeof p.ok, 'boolean');
  assert.ok(Array.isArray(p.checks));
  const names = p.checks.map((c) => c.name);
  assert.ok(names.includes('proxychains4'));
  assert.ok(names.includes('tor.socks'));
  assert.ok(names.includes('tor.dns'));
  assert.ok(names.includes('tor.control'));
  assert.ok(names.includes('proxychains.conf'));
  assert.ok(names.includes('node.dns.locked'));
  assert.ok(names.includes('proxy_pool.socks'));
});
