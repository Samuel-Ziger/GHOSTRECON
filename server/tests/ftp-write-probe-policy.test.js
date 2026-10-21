import test from 'node:test';
import assert from 'node:assert/strict';

import {
  ftpWriteProbeEnabled,
  resolveFtpWriteProbePolicy,
} from '../modules/ftp-anon-write-probe.js';

test('FTP write probe fica desligado por padrão e com valor vazio/inválido', () => {
  const previous = process.env.GHOSTRECON_FTP_WRITE_PROBE;
  try {
    delete process.env.GHOSTRECON_FTP_WRITE_PROBE;
    assert.equal(ftpWriteProbeEnabled(), false);
    process.env.GHOSTRECON_FTP_WRITE_PROBE = '';
    assert.equal(ftpWriteProbeEnabled(), false);
    process.env.GHOSTRECON_FTP_WRITE_PROBE = 'maybe';
    assert.equal(ftpWriteProbeEnabled(), false);
  } finally {
    if (previous == null) delete process.env.GHOSTRECON_FTP_WRITE_PROBE;
    else process.env.GHOSTRECON_FTP_WRITE_PROBE = previous;
  }
});

test('FTP write probe exige opt-in, ack e allowlist exata de laboratório', () => {
  const enabled = {
    GHOSTRECON_FTP_WRITE_PROBE: '1',
    GHOSTRECON_FTP_WRITE_PROBE_LAB_ACK: '1',
    GHOSTRECON_FTP_WRITE_PROBE_LAB_TARGETS: 'ftp.lab.test,127.0.0.1',
  };
  assert.equal(ftpWriteProbeEnabled(enabled), true);
  assert.equal(ftpWriteProbeEnabled({ ...enabled, GHOSTRECON_FTP_WRITE_PROBE_LAB_ACK: '0' }), false);
  assert.equal(ftpWriteProbeEnabled({ ...enabled, GHOSTRECON_FTP_WRITE_PROBE_LAB_TARGETS: '' }), false);
  assert.equal(ftpWriteProbeEnabled({ ...enabled, GHOSTRECON_FTP_WRITE_PROBE_LAB_TARGETS: '*' }), false);
  assert.deepEqual(resolveFtpWriteProbePolicy(enabled).labTargets, ['127.0.0.1', 'ftp.lab.test']);
});
