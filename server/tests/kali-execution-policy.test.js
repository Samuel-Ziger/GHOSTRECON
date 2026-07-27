import test from 'node:test';
import assert from 'node:assert/strict';

import {
  resolveKaliExecutionPolicy,
  shouldRunKaliTcpBase,
} from '../modules/kali-scan.js';

test('RUN manual preserva nmap TCP base quando entra no modo Kali', () => {
  assert.equal(
    shouldRunKaliTcpBase({ autoModeExecution: false, modules: [] }),
    true,
  );
});

test('Auto não transforma kaliMode em autorização implícita para nmap TCP', () => {
  assert.equal(
    shouldRunKaliTcpBase({
      autoModeExecution: true,
      modules: ['kali_nuclei', 'kali_ffuf'],
    }),
    false,
  );
});

test('Auto libera nmap TCP somente para capacidades que dependem dele', () => {
  for (const capability of [
    'kali_nmap_aggressive',
    'kali_nmap_udp',
    'nmap_cve_match',
    'nmap_backport_review',
    'mysql_3306_intel',
    'nmap_service_followups',
  ]) {
    assert.equal(
      shouldRunKaliTcpBase({
        autoModeExecution: true,
        modules: [capability],
      }),
      true,
      capability,
    );
  }
});

test('kaliMode sozinho não autoriza ferramentas/follow-ups implícitos no Auto', () => {
  assert.deepEqual(
    resolveKaliExecutionPolicy({
      autoModeExecution: true,
      modules: ['kali_nuclei'],
    }),
    {
      runNmapBase: false,
      runWhois: false,
      runWpscan: false,
      runDalfox: false,
      runXssVibes: false,
      allowNmapServiceFollowups: false,
      allowFtpWriteProbe: false,
    },
  );
});

test('Auto libera cada ferramenta Kali apenas pelo ID explícito', () => {
  assert.deepEqual(
    resolveKaliExecutionPolicy({
      autoModeExecution: true,
      modules: [
        'kali_whois',
        'kali_wpscan',
        'kali_dalfox',
        'kali_xss_vibes',
        'nmap_service_followups',
        'ftp_write_probe',
      ],
    }),
    {
      runNmapBase: true,
      runWhois: true,
      runWpscan: true,
      runDalfox: true,
      runXssVibes: true,
      allowNmapServiceFollowups: true,
      allowFtpWriteProbe: false,
    },
  );
});

test('ftp_write_probe permanece proibido no Auto mesmo se escapar ao catálogo', () => {
  assert.deepEqual(
    resolveKaliExecutionPolicy({
      autoModeExecution: true,
      modules: ['ftp_write_probe'],
    }),
    {
      runNmapBase: false,
      runWhois: false,
      runWpscan: false,
      runDalfox: false,
      runXssVibes: false,
      allowNmapServiceFollowups: false,
      allowFtpWriteProbe: false,
    },
  );
});

test('ftp_write_probe no RUN manual ainda exige ID explícito além do gate de ambiente', () => {
  assert.equal(
    resolveKaliExecutionPolicy({
      autoModeExecution: false,
      modules: [],
    }).allowFtpWriteProbe,
    false,
  );
  assert.deepEqual(
    resolveKaliExecutionPolicy({
      autoModeExecution: false,
      modules: ['ftp_write_probe'],
    }),
    {
      runNmapBase: true,
      runWhois: true,
      runWpscan: true,
      runDalfox: true,
      runXssVibes: true,
      allowNmapServiceFollowups: true,
      allowFtpWriteProbe: true,
    },
  );
});
