import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import { parseArgs, parseDuration, kvListToObject } from '../modules/cli/args.mjs';
import {
  formatPlanSpecificApproval,
  requestPlanSpecificApproval,
} from '../modules/cli/commands/run.mjs';

test('parseArgs: string flag with --key value', () => {
  const { opts } = parseArgs(['--target', 'example.com'], [
    { name: 'target', type: 'string', required: true },
  ]);
  assert.equal(opts.target, 'example.com');
});

test('parseArgs: string flag with --key=value', () => {
  const { opts } = parseArgs(['--target=api.example.com'], [
    { name: 'target', type: 'string', required: true },
  ]);
  assert.equal(opts.target, 'api.example.com');
});

test('parseArgs: csv split', () => {
  const { opts } = parseArgs(['--modules', 'a,b,c,,d'], [
    { name: 'modules', type: 'csv' },
  ]);
  assert.deepEqual(opts.modules, ['a', 'b', 'c', 'd']);
});

test('parseArgs: repeat accumulates', () => {
  const { opts } = parseArgs(['--header', 'A=1', '--header', 'B=2'], [
    { name: 'header', type: 'repeat' },
  ]);
  assert.deepEqual(opts.header, ['A=1', 'B=2']);
});

test('parseArgs: bool turns on flag', () => {
  const { opts } = parseArgs(['--kali'], [
    { name: 'kali', type: 'bool', default: false },
  ]);
  assert.equal(opts.kali, true);
});

test('parseArgs: default respected when omitted', () => {
  const { opts } = parseArgs([], [
    { name: 'profile', type: 'string', default: 'standard' },
  ]);
  assert.equal(opts.profile, 'standard');
});

test('parseArgs: required missing throws', () => {
  assert.throws(() =>
    parseArgs([], [{ name: 'target', type: 'string', required: true }]),
  );
});

test('parseArgs: unknown argv captured', () => {
  const { unknown } = parseArgs(['--zzz', '42'], []);
  assert.deepEqual(unknown, ['--zzz']);
});

test('CLI auto: exige --target e valida approval-mode', async () => {
  const { autoCommand } = await import('../modules/cli/commands/auto.mjs');
  assert.equal(await autoCommand([]), 2);
  assert.equal(await autoCommand(['--target', 'example.com', '--approval-mode', 'nope']), 2);
});

test('parseArgs: int validation', () => {
  const { opts } = parseArgs(['--timeout', '120'], [
    { name: 'timeout', type: 'int', default: 60 },
  ]);
  assert.equal(opts.timeout, 120);
  assert.throws(() =>
    parseArgs(['--timeout', 'abc'], [{ name: 'timeout', type: 'int' }]),
  );
});

test('parseDuration: various units', () => {
  assert.equal(parseDuration('6h'), 6 * 3600_000);
  assert.equal(parseDuration('30m'), 30 * 60_000);
  assert.equal(parseDuration('45s'), 45_000);
  assert.equal(parseDuration('2d'), 2 * 86_400_000);
  assert.equal(parseDuration('500ms'), 500);
  assert.throws(() => parseDuration('abc'));
});

test('parseDuration: raw number accepted', () => {
  assert.equal(parseDuration('1234'), 1234);
});

test('kvListToObject: parse K=V pairs', () => {
  const obj = kvListToObject(['X-API-Key=abc', 'Auth=Bearer xyz']);
  assert.deepEqual(obj, { 'X-API-Key': 'abc', Auth: 'Bearer xyz' });
});

test('kvListToObject: ignora entries inválidas', () => {
  const obj = kvListToObject(['no-equals', '=nokey', 'K=']);
  assert.deepEqual(obj, { K: '' });
});

test('CLI RUN não herda confirmação global e usa aprovação vinculada ao plano', async () => {
  const source = await fs.readFile(
    new URL('../modules/cli/commands/run.mjs', import.meta.url),
    'utf8',
  );
  assert.doesNotMatch(source, /GHOSTRECON_CONFIRM_ACTIVE/);
  assert.match(source, /\/api\/recon\/preflight/);
  assert.match(source, /\/api\/recon\/approval/);
  assert.doesNotMatch(source, /delete preflightBody\.auth/);
  assert.doesNotMatch(source, /delete preflightBody\.vigoliumAuth/);
  assert.match(source, /requestPlanSpecificApproval\(preflight\.plan\)/);
  assert.match(source, /includeManualImplicit:\s*true/);
  assert.match(source, /includeManualIntrusive:\s*Boolean\(opts\[['"]confirm-active['"]\]\)/);
  assert.match(source, /kaliMode:\s*Boolean\(opts\.kali\)/);
  assert.match(source, /body\.manualApproval/);
});

test('CLI RUN falha fechado sem TTY e não consulta confirmação', async () => {
  let asked = false;
  const result = await requestPlanSpecificApproval({
    hash: 'a'.repeat(64),
  }, {
    input: { isTTY: false },
    output: { isTTY: false, write() {} },
    ask: async () => {
      asked = true;
      return 'a'.repeat(12);
    },
  });
  assert.equal(result.approved, false);
  assert.match(result.reason, /terminal interativo/);
  assert.equal(asked, false);
});

test('CLI RUN exige prefixo do hash e exibe somente resumo seguro', async () => {
  const hash = 'b'.repeat(64);
  const chunks = [];
  const output = {
    isTTY: true,
    write(chunk) {
      chunks.push(String(chunk));
    },
  };
  const result = await requestPlanSpecificApproval({
    target: 'lab.example.test',
    hash,
    intrusiveModules: ['vigolium_dast'],
    engines: {
      frameseven: { enabled: false },
      vigolium: { enabled: true, agent: 'audit' },
    },
    auth: { cookie: 'secret-cookie' },
    unexpectedSecret: 'secret-token',
  }, {
    input: { isTTY: true },
    output,
    ask: async (prompt) => {
      assert.match(prompt, /bbbbbbbbbbbb/);
      return 'bbbbbbbbbbbb';
    },
  });
  const rendered = chunks.join('');
  assert.equal(result.approved, true);
  assert.match(rendered, /lab\.example\.test/);
  assert.match(rendered, /vigolium_dast/);
  assert.doesNotMatch(rendered, /secret-cookie|secret-token/);
  assert.doesNotMatch(
    formatPlanSpecificApproval({
      hash,
      auth: { cookie: 'secret-cookie' },
      unexpectedSecret: 'secret-token',
    }),
    /secret-cookie|secret-token/,
  );
});
