import test from 'node:test';
import assert from 'node:assert/strict';
import {
  buildProxychainsCommand,
  normalizeProxychainsInvocation,
} from '../modules/kali-scan.js';

test('proxychains força Nmap TCP connect', () => {
  const result = normalizeProxychainsInvocation('nmap', ['-sV', '-Pn', 'example.test']);
  assert.ok(result.args.includes('-sT'));
  assert.ok(result.args.includes('-sV'));
});

test('proxychains recusa modos raw, agressivo e UDP do Nmap', () => {
  for (const flag of ['-sS', '-sU', '-sSU', '-sSVC', '-O', '-A', '--traceroute']) {
    assert.throws(
      () => normalizeProxychainsInvocation('nmap', [flag, 'example.test']),
      (error) => error.code === 'PROXYCHAINS_NMAP_MODE_UNSUPPORTED',
      flag,
    );
  }
});

test('proxychains reconhece caminho absoluto do Nmap e não deixa scan raw compacto passar', () => {
  assert.throws(
    () => normalizeProxychainsInvocation('/usr/bin/nmap', ['-sSU', 'example.test']),
    (error) => error.code === 'PROXYCHAINS_NMAP_MODE_UNSUPPORTED',
  );
  const safe = normalizeProxychainsInvocation('/usr/bin/nmap', ['-sV', 'example.test']);
  assert.ok(safe.args.includes('-sT'));
});

test('buildProxychainsCommand envolve TCP base sem shell', () => {
  const previous = process.env.GHOSTRECON_PROXYCHAINS;
  const previousStrict = process.env.GHOSTRECON_TOR_STRICT;
  process.env.GHOSTRECON_PROXYCHAINS = '1';
  delete process.env.GHOSTRECON_TOR_STRICT;
  try {
    const wrapped = buildProxychainsCommand('nmap', ['-sV', 'example.test'], { useProxychains: true });
    assert.match(wrapped.cmd, /proxychains/);
    assert.ok(wrapped.args.includes('nmap'));
    assert.ok(wrapped.args.includes('-sT'));
  } finally {
    if (previous == null) delete process.env.GHOSTRECON_PROXYCHAINS;
    else process.env.GHOSTRECON_PROXYCHAINS = previous;
    if (previousStrict == null) delete process.env.GHOSTRECON_TOR_STRICT;
    else process.env.GHOSTRECON_TOR_STRICT = previousStrict;
  }
});
