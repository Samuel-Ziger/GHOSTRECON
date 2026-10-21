import test from 'node:test';
import assert from 'node:assert/strict';
import { EventEmitter } from 'node:events';

import {
  ftpAnonymousLoginFinding,
  isFtpServiceRow,
  probeFtpAnonymousLogin,
} from '../modules/ftp-anonymous-login.mjs';

const fixtureLookup = async () => [{ address: '192.0.2.21', family: 4 }];

class FakeFtpSocket extends EventEmitter {
  constructor(replyForWrite = () => null, {
    closeOnEnd = true,
    closeOnDestroy = true,
    remoteAddress = '192.0.2.21',
  } = {}) {
    super();
    this.replyForWrite = replyForWrite;
    this.closeOnEnd = closeOnEnd;
    this.closeOnDestroy = closeOnDestroy;
    this.remoteAddress = remoteAddress;
    this.writes = [];
    this.ended = false;
    this.destroyed = false;
  }

  setEncoding() {}
  setTimeout() {}

  write(value) {
    this.writes.push(String(value));
    const reply = this.replyForWrite(String(value));
    if (reply) queueMicrotask(() => this.emit('data', reply));
    return true;
  }

  end(value = '', callback = null) {
    if (value) this.writes.push(String(value));
    this.ended = true;
    if (typeof callback === 'function') queueMicrotask(callback);
    if (this.closeOnEnd) queueMicrotask(() => this.emit('close'));
  }

  destroy() {
    this.destroyed = true;
    if (this.closeOnDestroy) queueMicrotask(() => this.emit('close'));
  }
}

test('detecta FTP por porta, nome ou produto', () => {
  assert.equal(isFtpServiceRow({ proto: 'tcp', port: '21' }), true);
  assert.equal(isFtpServiceRow({ proto: 'tcp', port: '2121', name: 'ftp-alt' }), true);
  assert.equal(isFtpServiceRow({ proto: 'udp', port: '21', name: 'ftp' }), false);
  assert.equal(isFtpServiceRow({ proto: 'tcp', port: '22', name: 'sftp' }), false);
  assert.equal(isFtpServiceRow({ proto: 'tcp', port: '20', name: 'ftp-data' }), false);
  assert.equal(isFtpServiceRow({ proto: 'tcp', port: '990', name: 'ftps', product: 'vsftpd' }), false);
  assert.equal(isFtpServiceRow({ proto: 'tcp', port: '2121', name: 'ftp', tunnel: 'ssl' }), false);
});

test('confirma anonymous, tenta senha vazia e e-mail, envia QUIT e fecha', async () => {
  const socket = new FakeFtpSocket((write) => {
    if (write === 'USER anonymous\r\n') return '331 Password required\r\n';
    if (write === 'PASS \r\n') return '530 Login incorrect\r\n';
    if (write === 'PASS anonymous@ghostrecon.local\r\n') return '230 Login successful\r\n';
    return null;
  });
  const resultPromise = probeFtpAnonymousLogin({
    host: 'ftp.lab.test',
    port: 21,
    hostAllowed: (host) => host === 'ftp.lab.test',
    lookupImpl: fixtureLookup,
    connectImpl: () => socket,
  });
  setImmediate(() => socket.emit('data', '220 Synthetic FTP\r\n'));

  const result = await resultPromise;
  assert.equal(result.ok, true);
  assert.equal(result.passUsed, 'anonymous@ghostrecon.local');
  assert.deepEqual(socket.writes, [
    'USER anonymous\r\n',
    'PASS \r\n',
    'USER anonymous\r\n',
    'PASS anonymous@ghostrecon.local\r\n',
    'QUIT\r\n',
  ]);
  assert.equal(socket.ended, true);

  const finding = ftpAnonymousLoginFinding(result);
  assert.equal(finding.type, 'ftp_anonymous_login');
  assert.equal(finding.prio, 'low');
  assert.match(finding.value, /FTP anonymous login observado/);
  assert.equal(finding.meta.connection, 'quit_sent_close_attested');
  assert.equal(finding.meta.cleanupConfirmed, true);
  assert.match(finding.provenance.how, /Nmap/);
  for (const event of ['connect', 'data', 'timeout', 'error', 'close']) {
    assert.equal(socket.listenerCount(event), 0, event);
  }
});

test('resposta FTP multiline não trata código interno como resposta terminal', async () => {
  const socket = new FakeFtpSocket((write) => {
    if (write === 'USER anonymous\r\n') {
      return '331-Details follow\r\n230 texto interno, não é sucesso\r\n331 Password required\r\n';
    }
    if (write === 'PASS \r\n') return '230 Login successful\r\n';
    return null;
  });
  const pending = probeFtpAnonymousLogin({
    host: 'ftp.lab.test',
    lookupImpl: fixtureLookup,
    connectImpl: () => socket,
  });
  setImmediate(() => socket.emit('data', '220 Synthetic FTP\r\n'));
  const result = await pending;
  assert.equal(result.ok, true);
  assert.equal(result.passUsed, '');
  assert.deepEqual(socket.writes, ['USER anonymous\r\n', 'PASS \r\n', 'QUIT\r\n']);
});

test('sucesso força destroy limitado quando o peer não fecha após QUIT', async () => {
  const socket = new FakeFtpSocket((write) => (
    write === 'USER anonymous\r\n' ? '230 Login successful\r\n' : null
  ), { closeOnEnd: false, closeOnDestroy: false });
  const pending = probeFtpAnonymousLogin({
    host: 'ftp.lab.test',
    closeGraceMs: 10,
    lookupImpl: fixtureLookup,
    connectImpl: () => socket,
  });
  setImmediate(() => socket.emit('data', '220 Synthetic FTP\r\n'));
  const result = await pending;
  assert.equal(result.ok, true);
  assert.equal(result.connectionClose, 'quit_sent_force_destroyed');
  assert.equal(result.closeAttested, false);
  assert.equal(result.cleanupConfirmed, true);
  assert.equal(result.forcedDestroy, true);
  assert.equal(result.terminationConfirmed, true);
  assert.equal(result.quitFlushed, true);
  assert.equal(socket.destroyed, true);
  for (const event of ['connect', 'data', 'timeout', 'error', 'close']) {
    assert.equal(socket.listenerCount(event), 0, event);
  }
  const writesAtSettlement = [...socket.writes];
  socket.emit('data', '331 Password required\r\n');
  assert.deepEqual(socket.writes, writesAtSettlement);
});

test('falha fechado se nem close nem destroy local puderem ser confirmados', async () => {
  const socket = new FakeFtpSocket((write) => (
    write === 'USER anonymous\r\n' ? '230 Login successful\r\n' : null
  ), { closeOnEnd: false, closeOnDestroy: false });
  socket.destroy = () => {};
  const pending = probeFtpAnonymousLogin({
    host: 'ftp.lab.test',
    closeGraceMs: 10,
    lookupImpl: fixtureLookup,
    connectImpl: () => socket,
  });
  setImmediate(() => socket.emit('data', '220 Synthetic FTP\r\n'));
  const result = await pending;
  assert.equal(result.ok, false);
  assert.equal(result.loginConfirmed, true);
  assert.equal(result.error, 'FTP_SOCKET_UNTERMINATED');
  assert.equal(result.terminationConfirmed, false);
});

test('limita resposta FTP antes de parsear conteúdo ilimitado', async () => {
  const socket = new FakeFtpSocket();
  const pending = probeFtpAnonymousLogin({
    host: 'ftp.lab.test',
    timeoutMs: 1_000,
    lookupImpl: fixtureLookup,
    connectImpl: () => socket,
  });
  setImmediate(() => socket.emit('data', 'x'.repeat(70 * 1024)));
  const result = await pending;
  assert.equal(result.ok, false);
  assert.equal(result.error, 'response_too_large');
  assert.equal(socket.destroyed, true);
});

test('limite de resposta é cumulativo mesmo com muitas linhas curtas', async () => {
  const socket = new FakeFtpSocket();
  const pending = probeFtpAnonymousLogin({
    host: 'ftp.lab.test',
    timeoutMs: 1_000,
    lookupImpl: fixtureLookup,
    connectImpl: () => socket,
  });
  setImmediate(() => {
    for (let i = 0; i < 1_200; i += 1) socket.emit('data', `200 ${'x'.repeat(60)}\r\n`);
  });
  const result = await pending;
  assert.equal(result.ok, false);
  assert.equal(result.error, 'response_too_large');
  assert.equal(socket.destroyed, true);
});

test('flood depois do login preserva a evidência, mas marca resultado parcial e encerra', async () => {
  let socket;
  socket = new FakeFtpSocket((write) => {
    if (write === 'USER anonymous\r\n') {
      setImmediate(() => socket.emit('data', 'x'.repeat(70 * 1024)));
      return '230 Login successful\r\n';
    }
    return null;
  }, { closeOnEnd: false, closeOnDestroy: false });
  const pending = probeFtpAnonymousLogin({
    host: 'ftp.lab.test',
    closeGraceMs: 1_000,
    lookupImpl: fixtureLookup,
    connectImpl: () => socket,
  });
  setImmediate(() => socket.emit('data', '220 Synthetic FTP\r\n'));
  const result = await pending;
  assert.equal(result.ok, true);
  assert.equal(result.operationalPartial, true);
  assert.equal(result.warning, 'response_too_large_after_login');
  assert.equal(result.cleanupConfirmed, true);
  assert.equal(result.forcedDestroy, true);
  assert.equal(socket.destroyed, true);
});

test('nega alvo fora de escopo antes de abrir socket', async () => {
  let connected = false;
  const result = await probeFtpAnonymousLogin({
    host: 'outside.test',
    hostAllowed: () => false,
    lookupImpl: fixtureLookup,
    connectImpl: () => {
      connected = true;
      return new FakeFtpSocket();
    },
  });
  assert.equal(result.ok, false);
  assert.equal(result.error, 'target_out_of_scope');
  assert.equal(connected, false);
});

test('pina DNS e recusa endereço resolvido fora do escopo antes do socket', async () => {
  let connected = false;
  const result = await probeFtpAnonymousLogin({
    host: 'ftp.lab.test',
    lookupImpl: fixtureLookup,
    addressAllowed: () => false,
    connectImpl: () => {
      connected = true;
      return new FakeFtpSocket();
    },
  });
  assert.equal(result.ok, false);
  assert.equal(result.error, 'resolved_address_out_of_scope');
  assert.equal(connected, false);
});

test('usa o endereço observado pelo Nmap e recusa peer diferente', async () => {
  let connectOptions = null;
  const socket = new FakeFtpSocket(() => null, { remoteAddress: '198.51.100.9' });
  const pending = probeFtpAnonymousLogin({
    host: 'ftp.lab.test',
    observedAddress: '192.0.2.21',
    addressAllowed: (address) => address === '192.0.2.21',
    connectImpl: (options) => {
      connectOptions = options;
      return socket;
    },
  });
  setImmediate(() => socket.emit('connect'));
  const result = await pending;
  assert.equal(connectOptions.host, '192.0.2.21');
  assert.equal(result.ok, false);
  assert.equal(result.error, 'peer_address_mismatch');
  assert.equal(socket.destroyed, true);
});

test('retorna negativo quando todas as credenciais anonymous são recusadas', async () => {
  const socket = new FakeFtpSocket((write) => {
    if (write === 'USER anonymous\r\n') return '331 Password required\r\n';
    if (write.startsWith('PASS ')) return '530 Login incorrect\r\n';
    return null;
  });
  const pending = probeFtpAnonymousLogin({
    host: 'ftp.lab.test',
    lookupImpl: fixtureLookup,
    connectImpl: () => socket,
  });
  setImmediate(() => socket.emit('data', '220 Synthetic FTP\r\n'));
  const result = await pending;
  assert.equal(result.ok, false);
  assert.equal(result.passReply, '530 Login incorrect');
  assert.equal(socket.destroyed, true);
});

test('timeout encerra o socket sem produzir falso positivo', async () => {
  const socket = new FakeFtpSocket();
  const pending = probeFtpAnonymousLogin({
    host: 'ftp.lab.test',
    timeoutMs: 25,
    lookupImpl: fixtureLookup,
    connectImpl: () => socket,
  });
  setImmediate(() => socket.emit('timeout'));
  const result = await pending;
  assert.equal(result.ok, false);
  assert.match(result.error, /timeout 25ms/);
  assert.equal(socket.destroyed, true);
});

test('falha fechado sem socket direto quando OPSEC exige proxy', async () => {
  let connected = false;
  const result = await probeFtpAnonymousLogin({
    host: 'ftp.lab.test',
    allowDirectNetwork: false,
    lookupImpl: fixtureLookup,
    connectImpl: () => {
      connected = true;
      return new FakeFtpSocket();
    },
  });
  assert.equal(result.error, 'direct_network_blocked');
  assert.equal(connected, false);
});

test('cancelamento destrói o socket e rejeita imediatamente', async () => {
  const controller = new AbortController();
  const socket = new FakeFtpSocket();
  const pending = probeFtpAnonymousLogin({
    host: 'ftp.lab.test',
    signal: controller.signal,
    lookupImpl: fixtureLookup,
    connectImpl: () => socket,
  });
  controller.abort(new Error('operator_cancelled'));
  await assert.rejects(pending, /operator_cancelled/);
  assert.equal(socket.destroyed, true);
});

test('cancelamento preserva a razão e o código de timeout sem mutá-los', async () => {
  const controller = new AbortController();
  const socket = new FakeFtpSocket();
  const reason = Object.assign(new Error('phase deadline'), { code: 'PIPELINE_PHASE_TIMEOUT' });
  const pending = probeFtpAnonymousLogin({
    host: 'ftp.lab.test',
    signal: controller.signal,
    lookupImpl: fixtureLookup,
    connectImpl: () => socket,
  });
  controller.abort(reason);
  await assert.rejects(pending, (error) => (
    error !== reason
    && error.name === 'AbortError'
    && error.code === 'PIPELINE_PHASE_TIMEOUT'
    && error.cause === reason
  ));
  assert.equal(reason.name, 'Error');
  assert.equal(reason.code, 'PIPELINE_PHASE_TIMEOUT');
});
