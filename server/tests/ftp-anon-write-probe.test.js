import test from 'node:test';
import assert from 'node:assert/strict';
import { EventEmitter } from 'node:events';

import { probeFtpAnonymousWritable } from '../modules/ftp-anon-write-probe.js';

const FIXTURE_ADDRESS = '192.0.2.21';

class FakeSocket extends EventEmitter {
  constructor({ onWrite = null, onEnd = null, completeWrites = true } = {}) {
    super();
    this.onWrite = onWrite;
    this.onEnd = onEnd;
    this.completeWrites = completeWrites;
    this.writes = [];
    this.destroyed = false;
    this.ended = false;
    this.timeoutHandler = null;
  }

  setEncoding() {}
  setTimeout(_timeoutMs, handler) {
    if (typeof handler === 'function') this.timeoutHandler = handler;
  }

  write(value, callback) {
    const text = Buffer.isBuffer(value) ? value.toString('utf8') : String(value);
    this.writes.push(text);
    this.onWrite?.(text);
    if (this.completeWrites && typeof callback === 'function') queueMicrotask(() => callback(null));
    return true;
  }

  end() {
    this.ended = true;
    this.onEnd?.();
  }

  destroy() {
    this.destroyed = true;
  }
}

function scriptedFtp({
  deleteCode = 250,
  sizeCode = 550,
  transferCode = 226,
  coalesceTransferReplies = false,
  onDataWrite = null,
  completeDataWrites = true,
  pasvTuple = '203,0,113,99,7,208',
} = {}) {
  let control = null;
  let data = null;
  const reply = (line) => queueMicrotask(() => control.emit('data', `${line}\r\n`));
  const connectImpl = (options) => {
    if (options.channel === 'data') {
      data = new FakeSocket({
        onWrite: onDataWrite,
        completeWrites: completeDataWrites,
        onEnd: () => {
          if (!coalesceTransferReplies) reply(`${transferCode} Transfer complete`);
        },
      });
      data.remoteAddress = options.host;
      queueMicrotask(() => data.emit('connect'));
      return data;
    }
    control = new FakeSocket({
      onWrite(command) {
        if (command === 'USER anonymous\r\n') reply('331 Password required');
        else if (command === 'PASS anonymous@ghostrecon.local\r\n') reply('230 Login successful');
        else if (command === 'TYPE I\r\n') reply('200 Type set');
        else if (command === 'PASV\r\n') reply(`227 Entering Passive Mode (${pasvTuple})`);
        else if (command.startsWith('STOR ')) {
          if (coalesceTransferReplies) {
            queueMicrotask(() => control.emit(
              'data',
              `150 Opening data connection\r\n${transferCode} Transfer complete\r\n`,
            ));
          } else reply('150 Opening data connection');
        }
        else if (command.startsWith('DELE ')) reply(`${deleteCode} ${deleteCode === 250 ? 'Deleted' : 'Delete denied'}`);
        else if (command.startsWith('SIZE ')) reply(`${sizeCode} ${sizeCode === 550 ? 'Not found' : 'Still present'}`);
      },
    });
    control.remoteAddress = options.host;
    queueMicrotask(() => {
      control.emit('connect');
      queueMicrotask(() => control.emit('data', '220 Synthetic FTP\r\n'));
    });
    return control;
  };
  return {
    connectImpl,
    get control() { return control; },
    get data() { return data; },
  };
}

test('write probe confirma STOR e remoção DELE sem seguir host PASV', async () => {
  const ftp = scriptedFtp();
  const connectedHosts = [];
  const result = await probeFtpAnonymousWritable({
    host: 'ftp.lab.test',
    enabled: true,
    labAcknowledged: true,
    labTargets: ['ftp.lab.test'],
    hostAllowed: (host) => host === 'ftp.lab.test',
    observedAddress: FIXTURE_ADDRESS,
    addressAllowed: (address) => address === FIXTURE_ADDRESS,
    connectImpl: (options) => {
      connectedHosts.push(options.host);
      return ftp.connectImpl(options);
    },
    randomBytesImpl: () => Buffer.from('01020304', 'hex'),
    now: () => 123,
  });

  assert.equal(result.writable, true);
  assert.equal(result.cleanupVerified, true);
  assert.equal(result.detail, 'stor_ok_dele_and_absence_verified');
  assert.equal(result.probeFile, '.ghr_w_123_01020304.txt');
  assert.deepEqual(connectedHosts, [FIXTURE_ADDRESS, FIXTURE_ADDRESS]);
  assert.ok(ftp.control.writes.includes('QUIT\r\n'));
});

test('write probe reporta resíduo quando DELE não é confirmado', async () => {
  const ftp = scriptedFtp({ deleteCode: 550 });
  const result = await probeFtpAnonymousWritable({
    host: 'ftp.lab.test',
    enabled: true,
    labAcknowledged: true,
    labTargets: ['ftp.lab.test'],
    hostAllowed: () => true,
    observedAddress: FIXTURE_ADDRESS,
    addressAllowed: (address) => address === FIXTURE_ADDRESS,
    connectImpl: ftp.connectImpl,
  });

  assert.equal(result.writable, true);
  assert.equal(result.cleanupVerified, false);
  assert.equal(result.cleanupCode, 550);
  assert.match(result.detail, /cleanup_unverified_dele_550/);
});

test('write probe preserva replies coalescidos sem perder o 226', async () => {
  const ftp = scriptedFtp({ coalesceTransferReplies: true });
  const result = await probeFtpAnonymousWritable({
    host: 'ftp.lab.test',
    enabled: true,
    labAcknowledged: true,
    labTargets: ['ftp.lab.test'],
    hostAllowed: () => true,
    observedAddress: FIXTURE_ADDRESS,
    addressAllowed: (address) => address === FIXTURE_ADDRESS,
    connectImpl: ftp.connectImpl,
  });
  assert.equal(result.writable, true);
  assert.equal(result.transferConfirmed, true);
  assert.equal(result.cleanupVerified, true);
});

test('falha depois do STOR tenta cleanup e não inventa transferência confirmada', async () => {
  const ftp = scriptedFtp({ transferCode: 451 });
  const result = await probeFtpAnonymousWritable({
    host: 'ftp.lab.test',
    enabled: true,
    labAcknowledged: true,
    labTargets: ['ftp.lab.test'],
    hostAllowed: () => true,
    observedAddress: FIXTURE_ADDRESS,
    addressAllowed: (address) => address === FIXTURE_ADDRESS,
    connectImpl: ftp.connectImpl,
  });
  assert.equal(result.writable, false);
  assert.equal(result.remoteWritePossible, true);
  assert.equal(result.payloadSent, true);
  assert.equal(result.transferConfirmed, false);
  assert.equal(result.cleanupVerified, true);
  assert.equal(result.detail, 'stor_incomplete_but_cleanup_verified');
  assert.ok(ftp.control.writes.some((command) => command.startsWith('DELE ')));
  assert.ok(ftp.control.writes.some((command) => command.startsWith('SIZE ')));
});

test('timeout de controle após STOR preliminar tenta cleanup antes de finalizar', async () => {
  let ftp;
  ftp = scriptedFtp({
    completeDataWrites: false,
    onDataWrite: () => queueMicrotask(() => ftp.control.timeoutHandler?.()),
  });
  const result = await probeFtpAnonymousWritable({
    host: 'ftp.lab.test',
    enabled: true,
    labAcknowledged: true,
    labTargets: ['ftp.lab.test'],
    hostAllowed: () => true,
    observedAddress: FIXTURE_ADDRESS,
    addressAllowed: (address) => address === FIXTURE_ADDRESS,
    connectImpl: ftp.connectImpl,
  });
  assert.equal(result.remoteWritePossible, true);
  assert.equal(result.transferConfirmed, false);
  assert.equal(result.cleanupVerified, true);
  assert.equal(result.detail, 'stor_incomplete_but_cleanup_verified');
  assert.match(result.error, /^timeout:transfer$/);
  assert.ok(ftp.control.writes.some((command) => command.startsWith('DELE ')));
  assert.ok(ftp.control.writes.some((command) => command.startsWith('SIZE ')));
});

test('cancelamento após reply preliminar informa possível resíduo e fecha sockets', async () => {
  const controller = new AbortController();
  const ftp = scriptedFtp({ onDataWrite: () => controller.abort(new Error('operator_cancelled')) });
  let caught = null;
  try {
    await probeFtpAnonymousWritable({
      host: 'ftp.lab.test',
      enabled: true,
      labAcknowledged: true,
      labTargets: ['ftp.lab.test'],
      hostAllowed: () => true,
      observedAddress: FIXTURE_ADDRESS,
      addressAllowed: (address) => address === FIXTURE_ADDRESS,
      connectImpl: ftp.connectImpl,
      signal: controller.signal,
    });
  } catch (error) {
    caught = error;
  }
  assert.equal(caught?.name, 'AbortError');
  assert.equal(caught?.remoteWritePossible, true);
  assert.equal(caught?.cleanupVerified, false);
  assert.match(caught?.probeFile || '', /^\.ghr_w_/);
  assert.equal(ftp.control.destroyed, true);
  assert.equal(ftp.data.destroyed, true);
});

test('write probe desabilitado ou fora de escopo não abre socket', async () => {
  let connections = 0;
  const connectImpl = () => {
    connections += 1;
    return new FakeSocket();
  };
  assert.equal((await probeFtpAnonymousWritable({
    host: 'ftp.lab.test',
    enabled: false,
    connectImpl,
  })).detail, 'probe_disabled');
  assert.equal((await probeFtpAnonymousWritable({
    host: 'outside.test',
    enabled: true,
    labAcknowledged: true,
    labTargets: ['outside.test'],
    hostAllowed: () => false,
    connectImpl,
  })).detail, 'target_out_of_scope');
  assert.equal(connections, 0);
});

test('write probe recusa porta inválida antes de abrir socket', async () => {
  let connections = 0;
  const result = await probeFtpAnonymousWritable({
    host: 'ftp.lab.test',
    port: -1,
    enabled: true,
    labAcknowledged: true,
    labTargets: ['ftp.lab.test'],
    connectImpl: () => {
      connections += 1;
      return new FakeSocket();
    },
  });
  assert.equal(result.detail, 'invalid_port');
  assert.equal(connections, 0);
});

test('write probe exige o IP observado pelo Nmap antes de abrir controle/dados', async () => {
  let connections = 0;
  const result = await probeFtpAnonymousWritable({
    host: 'ftp.lab.test',
    enabled: true,
    labAcknowledged: true,
    labTargets: ['ftp.lab.test'],
    hostAllowed: () => true,
    connectImpl: () => {
      connections += 1;
      return new FakeSocket();
    },
  });
  assert.equal(result.detail, 'observed_address_required');
  assert.equal(connections, 0);
});

test('cancelamento do write probe fecha sockets e rejeita', async () => {
  const controller = new AbortController();
  const control = new FakeSocket();
  const pending = probeFtpAnonymousWritable({
    host: 'ftp.lab.test',
    enabled: true,
    labAcknowledged: true,
    labTargets: ['ftp.lab.test'],
    signal: controller.signal,
    observedAddress: FIXTURE_ADDRESS,
    addressAllowed: (address) => address === FIXTURE_ADDRESS,
    connectImpl: () => control,
  });
  controller.abort(new Error('operator_cancelled'));
  await assert.rejects(pending, /operator_cancelled/);
  assert.equal(control.destroyed, true);
});

test('write probe exige confirmação e allowlist de laboratório antes do socket', async () => {
  let connections = 0;
  const connectImpl = () => {
    connections += 1;
    return new FakeSocket();
  };
  assert.equal((await probeFtpAnonymousWritable({
    host: 'ftp.lab.test',
    enabled: true,
    labAcknowledged: false,
    labTargets: ['ftp.lab.test'],
    connectImpl,
  })).detail, 'controlled_lab_ack_required');
  assert.equal((await probeFtpAnonymousWritable({
    host: 'ftp.bounty.test',
    enabled: true,
    labAcknowledged: true,
    labTargets: ['ftp.lab.test'],
    connectImpl,
  })).detail, 'controlled_lab_target_not_allowlisted');
  assert.equal(connections, 0);
});

test('write probe recusa porta PASV privilegiada para impedir bounce de escrita', async () => {
  const ftp = scriptedFtp({ pasvTuple: '203,0,113,99,0,80' });
  const result = await probeFtpAnonymousWritable({
    host: 'ftp.lab.test',
    enabled: true,
    labAcknowledged: true,
    labTargets: ['ftp.lab.test'],
    hostAllowed: () => true,
    observedAddress: FIXTURE_ADDRESS,
    addressAllowed: (address) => address === FIXTURE_ADDRESS,
    connectImpl: ftp.connectImpl,
  });
  assert.equal(result.writable, false);
  assert.equal(result.error, 'pasv_port_refused');
  assert.equal(ftp.data, null);
});
