import test from 'node:test';
import assert from 'node:assert/strict';

import {
  classifyFtpAnonymousAuditOutcome,
  classifyFtpWriteProbeOutcome,
  resolveKaliExecutionPolicy,
  runKaliAggressiveScan,
  shouldRunKaliTcpBase,
} from '../modules/kali-scan.js';

test('RUN manual não injeta nmap TCP sem módulo explícito', () => {
  assert.equal(
    shouldRunKaliTcpBase({ autoModeExecution: false, modules: [] }),
    false,
  );
});

test('FTP write expõe cleanup incerto como falha terminal, não sucesso', () => {
  assert.deepEqual(
    classifyFtpWriteProbeOutcome(
      { attempted: 1, writeConfirmed: 1, cleanupUnconfirmed: 1 },
      { nmapState: 'done', ftpAuditSummary: { servicesDetected: 1, confirmed: 1 } },
    ),
    { status: 'failed', reason: 'remote_cleanup_unconfirmed', partial: true },
  );
  assert.deepEqual(
    classifyFtpWriteProbeOutcome(
      { attempted: 1, writeConfirmed: 1 },
      { nmapState: 'done', ftpAuditSummary: { servicesDetected: 1, confirmed: 1 } },
    ),
    { status: 'done', reason: 'write_and_cleanup_confirmed', partial: false },
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

test('política Nmap/proxy incompatível ainda emite outcomes FTP terminais', async () => {
  const events = [];
  await assert.rejects(
    runKaliAggressiveScan({
      domain: 'ftp.lab.test',
      subdomainsAlive: [],
      cap: { tools: { nmap: true } },
      log: () => {},
      addFinding: () => {},
      wordpressTargets: [],
      paramUrls: [],
      runNmapBase: true,
      runNmapAggressive: true,
      useProxychains: true,
      allowFtpAnonymousAudit: true,
      allowFtpWriteProbe: true,
      emit: (event) => events.push(event),
    }),
    (error) => error?.code === 'PROXYCHAINS_NMAP_AGGRESSIVE_UNSUPPORTED',
  );

  for (const moduleId of ['ftp_anonymous_audit', 'ftp_write_probe']) {
    const outcomes = events.filter((event) => (
      event.type === 'module_outcome' && event.moduleId === moduleId
    ));
    assert.equal(outcomes.length, 1);
    assert.equal(outcomes[0].status, 'failed');
    assert.equal(outcomes[0].reason, 'proxychains_nmap_aggressive_incompatible');
    assert.ok(events.some((event) => (
      event.type === 'pipe' && event.name === moduleId && event.state === 'failed'
    )));
  }
});

test('Auto libera nmap TCP somente para capacidades que dependem dele', () => {
  for (const capability of [
    'kali_nmap',
    'ftp_anonymous_audit',
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
      allowNmapServiceFollowups: false,
      allowFtpAnonymousAudit: false,
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
      allowNmapServiceFollowups: true,
      allowFtpAnonymousAudit: false,
      allowFtpWriteProbe: false,
    },
  );
});

test('nmap_service_followups não injeta login FTP sem a capability dedicada', () => {
  const policy = resolveKaliExecutionPolicy({
    autoModeExecution: false,
    modules: ['nmap_service_followups'],
  });
  assert.equal(policy.allowNmapServiceFollowups, true);
  assert.equal(policy.allowFtpAnonymousAudit, false);
  assert.equal(policy.allowFtpWriteProbe, false);
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
      allowNmapServiceFollowups: false,
      allowFtpAnonymousAudit: false,
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
      runWhois: false,
      runWpscan: false,
      runDalfox: false,
      allowNmapServiceFollowups: false,
      allowFtpAnonymousAudit: true,
      allowFtpWriteProbe: true,
    },
  );
});

test('FTP bug bounty limita o plano a login anônimo sem write nem outros follow-ups', () => {
  assert.deepEqual(
    resolveKaliExecutionPolicy({
      autoModeExecution: false,
      modules: ['ftp_anonymous_audit'],
    }),
    {
      runNmapBase: true,
      runWhois: false,
      runWpscan: false,
      runDalfox: false,
      allowNmapServiceFollowups: false,
      allowFtpAnonymousAudit: true,
      allowFtpWriteProbe: false,
    },
  );
});

test('FTP anonymous expõe outcomes distintos para ausência, negativo, timeout e sucesso parcial', () => {
  assert.deepEqual(
    classifyFtpAnonymousAuditOutcome({}, { nmapState: 'done' }),
    { status: 'done', reason: 'no_ftp_control_service', partial: false },
  );
  assert.deepEqual(
    classifyFtpAnonymousAuditOutcome({ servicesDetected: 1, denied: 1 }, { nmapState: 'done' }),
    { status: 'done', reason: 'anonymous_login_not_accepted', partial: false },
  );
  assert.deepEqual(
    classifyFtpAnonymousAuditOutcome({ servicesDetected: 1, timeouts: 1 }, { nmapState: 'done' }),
    { status: 'timeout', reason: 'ftp_login_timeout', partial: false },
  );
  assert.deepEqual(
    classifyFtpAnonymousAuditOutcome(
      { servicesDetected: 2, confirmed: 1, failed: 1 },
      { nmapState: 'done' },
    ),
    { status: 'done', reason: 'anonymous_login_confirmed', partial: true },
  );
  assert.deepEqual(
    classifyFtpAnonymousAuditOutcome(
      { hostsTruncated: 3 },
      { nmapState: 'done' },
    ),
    { status: 'done', reason: 'no_ftp_control_service_in_scanned_sample', partial: true },
  );
  assert.deepEqual(
    classifyFtpAnonymousAuditOutcome(
      { servicesDetected: 1, confirmed: 1, cleanupUnconfirmed: 1 },
      { nmapState: 'done' },
    ),
    { status: 'done', reason: 'anonymous_login_confirmed', partial: true },
  );
  assert.deepEqual(
    classifyFtpAnonymousAuditOutcome(
      { servicesDetected: 2, timeouts: 1, failed: 1 },
      { nmapState: 'done' },
    ),
    { status: 'timeout', reason: 'ftp_login_incomplete_mixed', partial: true },
  );
  assert.deepEqual(
    classifyFtpAnonymousAuditOutcome({}, { nmapState: 'cancelled' }),
    { status: 'cancelled', reason: 'operation_cancelled', partial: false },
  );
});

test('FTP encerra Nmap antes do pós-processamento e emite outcome rico', async () => {
  const events = [];
  const findings = [];
  await runKaliAggressiveScan({
    domain: 'example.test',
    subdomainsAlive: [],
    cap: { tools: { nmap: true } },
    log: () => {},
    addFinding: (finding) => findings.push(finding),
    wordpressTargets: [],
    paramUrls: [],
    runNmapBase: true,
    allowFtpAnonymousAudit: true,
    emit: (event) => events.push(event),
    hostAllowed: () => true,
    ftpAddressAllowed: (_host, address) => address === '192.0.2.21',
    nmapRunner: async () => [{
      host: 'example.test',
      address: '192.0.2.21',
      port: '21',
      proto: 'tcp',
      name: 'ftp',
      tunnel: '',
    }],
    ftpAnonymousLoginImpl: async ({ observedAddress }) => ({
      ok: true,
      host: 'example.test',
      port: 21,
      networkAddress: observedAddress,
      passUsed: '',
      cleanupConfirmed: true,
      connectionClose: 'quit_sent_close_attested',
      closeAttested: true,
      terminationConfirmed: true,
      quitSent: true,
    }),
  });

  const nmapDone = events.findIndex((event) => event.type === 'pipe' && event.name === 'nmap' && event.state === 'done');
  const ftpOutcome = events.findIndex((event) => event.type === 'module_outcome' && event.moduleId === 'ftp_anonymous_audit');
  assert.ok(nmapDone >= 0 && ftpOutcome > nmapDone);
  assert.equal(events[ftpOutcome].status, 'done');
  assert.equal(events[ftpOutcome].attempted, 1);
  assert.equal(events[ftpOutcome].resultCount, 1);
  assert.equal(events[ftpOutcome].hostsScanned, 1);
  assert.equal(findings.some((finding) => finding.type === 'ftp_anonymous_login'), true);
});

test('FTP write laboratorial emite lifecycle próprio somente após cleanup atestado', async () => {
  const events = [];
  await runKaliAggressiveScan({
    domain: 'ftp.lab.test',
    subdomainsAlive: [],
    cap: { tools: { nmap: true } },
    log: () => {},
    addFinding: () => {},
    wordpressTargets: [],
    paramUrls: [],
    runNmapBase: true,
    allowFtpAnonymousAudit: true,
    allowFtpWriteProbe: true,
    emit: (event) => events.push(event),
    hostAllowed: () => true,
    ftpAddressAllowed: (_host, address) => address === '192.0.2.21',
    nmapRunner: async () => [{
      host: 'ftp.lab.test', address: '192.0.2.21', port: '21', proto: 'tcp', name: 'ftp', tunnel: '',
    }],
    ftpAnonymousLoginImpl: async ({ observedAddress }) => ({
      ok: true,
      host: 'ftp.lab.test',
      port: 21,
      networkAddress: observedAddress,
      passUsed: '',
      cleanupConfirmed: true,
      connectionClose: 'quit_sent_close_attested',
      closeAttested: true,
      terminationConfirmed: true,
      quitSent: true,
    }),
    ftpWritableProbeImpl: async ({ observedAddress }) => ({
      writable: true,
      probeFile: '.fixture.txt',
      remoteWritePossible: true,
      payloadSent: true,
      transferConfirmed: true,
      cleanupVerified: observedAddress === '192.0.2.21',
      detail: 'stor_ok_dele_and_absence_verified',
    }),
  });

  const outcomes = events.filter((event) => (
    event.type === 'module_outcome' && event.moduleId === 'ftp_write_probe'
  ));
  assert.equal(outcomes.length, 1);
  assert.equal(outcomes[0].status, 'done');
  assert.equal(outcomes[0].reason, 'write_and_cleanup_confirmed');
  assert.equal(outcomes[0].attempted, 1);
  assert.equal(outcomes[0].resultCount, 1);
  assert.equal(outcomes[0].cleanupUnconfirmedCount, 0);
  assert.ok(events.some((event) => (
    event.type === 'pipe' && event.name === 'ftp_write_probe' && event.state === 'done'
  )));
});

test('FTP write não inicia quando o login anterior não atesta encerramento', async () => {
  const events = [];
  let writeCalls = 0;
  await runKaliAggressiveScan({
    domain: 'ftp.lab.test',
    subdomainsAlive: [],
    cap: { tools: { nmap: true } },
    log: () => {},
    addFinding: () => {},
    wordpressTargets: [],
    paramUrls: [],
    runNmapBase: true,
    allowFtpAnonymousAudit: true,
    allowFtpWriteProbe: true,
    emit: (event) => events.push(event),
    hostAllowed: () => true,
    ftpAddressAllowed: () => true,
    nmapRunner: async () => [{
      host: 'ftp.lab.test', address: '192.0.2.21', port: '21', proto: 'tcp', name: 'ftp', tunnel: '',
    }],
    ftpAnonymousLoginImpl: async () => ({
      ok: true,
      host: 'ftp.lab.test',
      port: 21,
      passUsed: '',
      cleanupConfirmed: false,
      terminationConfirmed: false,
      quitSent: true,
    }),
    ftpWritableProbeImpl: async () => {
      writeCalls += 1;
      return { writable: true, cleanupVerified: true };
    },
  });

  assert.equal(writeCalls, 0);
  const safeOutcome = events.find((event) => (
    event.type === 'module_outcome' && event.moduleId === 'ftp_anonymous_audit'
  ));
  assert.equal(safeOutcome.status, 'done');
  assert.equal(safeOutcome.partial, true);
  assert.equal(safeOutcome.cleanupUnconfirmedCount, 1);
  const writeOutcome = events.find((event) => (
    event.type === 'module_outcome' && event.moduleId === 'ftp_write_probe'
  ));
  assert.equal(writeOutcome.status, 'skipped');
  assert.equal(writeOutcome.reason, 'write_gate_or_prerequisite_blocked');
  assert.equal(writeOutcome.attempted, 0);
  assert.equal(writeOutcome.skipCount, 1);
  assert.ok(writeOutcome.reasonDetails.includes('login_session_cleanup_unconfirmed'));
});

test('FTP write bloqueia a sequência e emite evidência quando cleanup fica incerto', async () => {
  const events = [];
  const findings = [];
  let writeCalls = 0;
  await runKaliAggressiveScan({
    domain: 'ftp.lab.test',
    subdomainsAlive: [],
    cap: { tools: { nmap: true } },
    log: () => {},
    addFinding: (finding) => findings.push(finding),
    wordpressTargets: [],
    paramUrls: [],
    runNmapBase: true,
    allowFtpAnonymousAudit: true,
    allowFtpWriteProbe: true,
    emit: (event) => events.push(event),
    hostAllowed: () => true,
    ftpAddressAllowed: () => true,
    nmapRunner: async () => [
      { host: 'ftp.lab.test', address: '192.0.2.21', port: '21', proto: 'tcp', name: 'ftp', tunnel: '' },
      { host: 'ftp2.lab.test', address: '192.0.2.22', port: '21', proto: 'tcp', name: 'ftp', tunnel: '' },
    ],
    ftpAnonymousLoginImpl: async ({ host }) => ({
      ok: true,
      host,
      port: 21,
      passUsed: '',
      cleanupConfirmed: true,
      terminationConfirmed: true,
      quitSent: true,
    }),
    ftpWritableProbeImpl: async () => {
      writeCalls += 1;
      return {
        writable: false,
        probeFile: '.fixture-residue.txt',
        remoteWritePossible: true,
        payloadSent: true,
        transferConfirmed: false,
        cleanupVerified: false,
        detail: 'stor_incomplete_cleanup_unverified',
      };
    },
  });

  assert.equal(writeCalls, 1);
  assert.ok(findings.some((finding) => finding.type === 'ftp_write_probe_cleanup_unconfirmed'));
  const outcome = events.find((event) => (
    event.type === 'module_outcome' && event.moduleId === 'ftp_write_probe'
  ));
  assert.equal(outcome.status, 'failed');
  assert.equal(outcome.reason, 'remote_cleanup_unconfirmed');
  assert.equal(outcome.cleanupUnconfirmedCount, 1);
  assert.equal(outcome.attempted, 1);
  assert.equal(outcome.skipCount, 1);
});

test('cancelamento após STOR preliminar propaga abort e marca cleanup remoto como falha', async () => {
  const events = [];
  const findings = [];
  const error = Object.assign(new Error('operator cancelled after STOR'), {
    name: 'AbortError',
    code: 'PROCESS_ABORTED',
    remoteWritePossible: true,
    probeFile: '.fixture-cancelled.txt',
    payloadSent: false,
    transferConfirmed: false,
    cleanupVerified: false,
  });

  await assert.rejects(
    runKaliAggressiveScan({
      domain: 'ftp.lab.test',
      subdomainsAlive: [],
      cap: { tools: { nmap: true } },
      log: () => {},
      addFinding: (finding) => findings.push(finding),
      wordpressTargets: [],
      paramUrls: [],
      runNmapBase: true,
      allowFtpAnonymousAudit: true,
      allowFtpWriteProbe: true,
      emit: (event) => events.push(event),
      hostAllowed: () => true,
      ftpAddressAllowed: () => true,
      nmapRunner: async () => [{
        host: 'ftp.lab.test', address: '192.0.2.21', port: '21', proto: 'tcp', name: 'ftp', tunnel: '',
      }],
      ftpAnonymousLoginImpl: async () => ({
        ok: true,
        host: 'ftp.lab.test',
        port: 21,
        passUsed: '',
        cleanupConfirmed: true,
        terminationConfirmed: true,
        quitSent: true,
      }),
      ftpWritableProbeImpl: async () => { throw error; },
    }),
    (thrown) => thrown === error,
  );

  assert.ok(findings.some((finding) => (
    finding.type === 'ftp_write_probe_cleanup_unconfirmed'
    && finding.meta?.probeFile === '.fixture-cancelled.txt'
  )));
  const outcomes = events.filter((event) => (
    event.type === 'module_outcome' && event.moduleId === 'ftp_write_probe'
  ));
  assert.equal(outcomes.length, 1);
  assert.equal(outcomes[0].status, 'failed');
  assert.equal(outcomes[0].reason, 'operation_cancelled_remote_cleanup_unconfirmed');
  assert.equal(outcomes[0].cleanupUnconfirmedCount, 1);
  assert.equal(outcomes[0].partial, true);
  assert.equal(events.filter((event) => (
    event.type === 'pipe'
    && event.name === 'ftp_write_probe'
    && ['done', 'failed', 'timeout', 'cancelled', 'skip'].includes(event.state)
  )).length, 1);
});

test('cancelamento durante FTP preserva Nmap done e termina FTP como cancelled', async () => {
  const events = [];
  const error = Object.assign(new Error('phase deadline'), {
    name: 'AbortError',
    code: 'PIPELINE_PHASE_TIMEOUT',
  });
  await assert.rejects(
    runKaliAggressiveScan({
      domain: 'example.test',
      subdomainsAlive: [],
      cap: { tools: { nmap: true } },
      log: () => {},
      addFinding: () => {},
      wordpressTargets: [],
      paramUrls: [],
      runNmapBase: true,
      allowFtpAnonymousAudit: true,
      emit: (event) => events.push(event),
      hostAllowed: () => true,
      ftpAddressAllowed: () => true,
      nmapRunner: async () => [{
        host: 'example.test', address: '192.0.2.21', port: '21', proto: 'tcp', name: 'ftp', tunnel: '',
      }],
      ftpAnonymousLoginImpl: async () => { throw error; },
    }),
    (thrown) => thrown === error,
  );
  assert.ok(events.some((event) => event.type === 'pipe' && event.name === 'nmap' && event.state === 'done'));
  assert.ok(events.some((event) => (
    event.type === 'module_outcome'
    && event.moduleId === 'ftp_anonymous_audit'
    && event.status === 'cancelled'
  )));
  assert.ok(events.some((event) => (
    event.type === 'pipe'
    && event.name === 'ftp_anonymous_audit'
    && event.state === 'cancelled'
  )));
});
