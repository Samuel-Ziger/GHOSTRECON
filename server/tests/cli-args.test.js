import test from 'node:test';
import assert from 'node:assert/strict';
import { parseArgs, parseDuration, kvListToObject } from '../modules/cli/args.mjs';

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
