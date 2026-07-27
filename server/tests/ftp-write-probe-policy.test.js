import test from 'node:test';
import assert from 'node:assert/strict';

import { ftpWriteProbeEnabled } from '../modules/ftp-anon-write-probe.js';

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

test('FTP write probe exige opt-in booleano explícito', () => {
  const previous = process.env.GHOSTRECON_FTP_WRITE_PROBE;
  try {
    for (const value of ['1', 'true', 'yes', 'on', 'TRUE']) {
      process.env.GHOSTRECON_FTP_WRITE_PROBE = value;
      assert.equal(ftpWriteProbeEnabled(), true, value);
    }
    for (const value of ['0', 'false', 'no', 'off']) {
      process.env.GHOSTRECON_FTP_WRITE_PROBE = value;
      assert.equal(ftpWriteProbeEnabled(), false, value);
    }
  } finally {
    if (previous == null) delete process.env.GHOSTRECON_FTP_WRITE_PROBE;
    else process.env.GHOSTRECON_FTP_WRITE_PROBE = previous;
  }
});
