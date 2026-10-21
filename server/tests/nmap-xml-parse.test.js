import test from 'node:test';
import assert from 'node:assert/strict';
import {
  classifyNmapProcessResult,
  normalizeNmapConfiguredArgs,
  normalizeNmapUdpPortsSpec,
  parseNmapXml,
} from '../modules/kali-scan.js';

const minimalHost = (body) =>
  `<?xml version="1.0"?><nmaprun><host><status state="up"/>
<address addr="98.80.212.94" addrtype="ipv4"/>
<ports>${body}</ports></host></nmaprun>`;

test('parseNmapXml: service com <cpe> (formato típico -sV)', () => {
  const xml = minimalHost(`
<port protocol="tcp" portid="80">
<state state="open" reason="syn-ack" reason_ttl="63"/>
<service name="http" product="nginx" version="1.18.0" method="get" conf="10">
<cpe>cpe:/a:nginx:nginx:1.18.0</cpe>
</service>
</port>
<port protocol="tcp" portid="3306">
<state state="open" reason="syn-ack" reason_ttl="63"/>
<service name="mysql" product="MySQL" version="8.0.35" method="probed" conf="10">
<cpe>cpe:/a:mysql:mysql:8.0.35</cpe>
</service>
</port>`);
  const rows = parseNmapXml(xml);
  assert.equal(rows.length, 2);
  assert.equal(rows[0].host, '98.80.212.94');
  assert.equal(rows[0].address, '98.80.212.94');
  assert.equal(rows[0].port, '80');
  assert.equal(rows[0].name, 'http');
  assert.equal(rows[0].product, 'nginx');
  assert.deepEqual(rows[0].cpes, ['cpe:/a:nginx:nginx:1.18.0']);
  assert.equal(rows[1].port, '3306');
  assert.equal(rows[1].name, 'mysql');
  assert.match(rows[1].searchBlob, /MySQL/);
});

test('parseNmapXml preserva hostname, endereço realmente escaneado e tunnel TLS', () => {
  const xml = `<?xml version="1.0"?><nmaprun><host><status state="up"/>
<address addr="192.0.2.21" addrtype="ipv4"/>
<hostnames><hostname name="ftp.lab.test" type="user"/></hostnames>
<ports><port protocol="tcp" portid="2121"><state state="open"/>
<service name="ftp" product="vsftpd" tunnel="ssl"/></port></ports></host></nmaprun>`;
  const [row] = parseNmapXml(xml);
  assert.equal(row.host, 'ftp.lab.test');
  assert.equal(row.address, '192.0.2.21');
  assert.equal(row.tunnel, 'ssl');
});

test('parseNmapXml: service auto-fechado (formato antigo)', () => {
  const xml = minimalHost(`
<port protocol="tcp" portid="22">
<state state="open" reason="syn-ack" reason_ttl="63"/>
<service name="ssh" product="OpenSSH" version="9.2" extrainfo="protocol 2.0" method="probed" conf="10" />
</port>`);
  const rows = parseNmapXml(xml);
  assert.equal(rows.length, 1);
  assert.equal(rows[0].port, '22');
  assert.equal(rows[0].name, 'ssh');
});

test('parseNmapXml: porta open sem elemento service', () => {
  const xml = minimalHost(`
<port protocol="tcp" portid="9999">
<state state="open" reason="syn-ack" reason_ttl="63"/>
</port>`);
  const rows = parseNmapXml(xml);
  assert.equal(rows.length, 1);
  assert.equal(rows[0].port, '9999');
  assert.equal(rows[0].name, '');
});

test('parseNmapXml: ignora closed e open|filtered', () => {
  const xml = minimalHost(`
<port protocol="tcp" portid="25">
<state state="filtered" reason="no-response" reason_ttl="63"/>
<service name="smtp" method="table" conf="3" />
</port>
<port protocol="udp" portid="161">
<state state="open|filtered" reason="no-response" reason_ttl="63"/>
</port>`);
  assert.equal(parseNmapXml(xml).length, 0);
});

test('Nmap só é aceito como concluído com exit code zero', () => {
  assert.equal(classifyNmapProcessResult({ code: 0 }).status, 'done');
  assert.equal(classifyNmapProcessResult({ code: 2 }).status, 'failed');
  assert.equal(classifyNmapProcessResult({ timedOut: true }).status, 'timeout');
  assert.equal(classifyNmapProcessResult({ aborted: true }).status, 'cancelled');
});

test('args Nmap recusam scripts/alvos ocultos e FTP usa perfil fixo seguro', () => {
  assert.throws(
    () => normalizeNmapConfiguredArgs('--script vuln -sV'),
    (error) => error.code === 'NMAP_ARGS_NOT_ALLOWED',
  );
  assert.throws(
    () => normalizeNmapConfiguredArgs('-sV target-extra.example.test'),
    (error) => error.code === 'NMAP_ARGS_NOT_ALLOWED',
  );
  assert.deepEqual(
    normalizeNmapConfiguredArgs('--script vuln', { forceSafeProfile: true }),
    ['-sV', '-Pn', '-T3', '--host-timeout', '180s'],
  );
  for (const raw of ['-p-', '-T5', '--min-rate 5000', '--top-ports 5000']) {
    assert.throws(
      () => normalizeNmapConfiguredArgs(raw),
      (error) => error.code === 'NMAP_ARGS_NOT_ALLOWED',
      raw,
    );
  }
  assert.deepEqual(
    normalizeNmapConfiguredArgs('-sV -p 21,80,443 -T4'),
    ['-sV', '-p', '21,80,443', '-T4'],
  );
});

test('args Nmap UDP mantêm modo/portas fixos e recusam scripts ou alvo extra', () => {
  assert.deepEqual(
    normalizeNmapConfiguredArgs('', { aggressive: true, udp: true, fixedPorts: true }),
    ['-sU', '-A', '-Pn', '-T4'],
  );
  for (const raw of [
    '--script vuln -sU',
    '-sU target-extra.example.test',
    '-sU -p 53',
    '-sU --top-ports=100',
    '-A -Pn',
    '-sT -Pn',
  ]) {
    assert.throws(
      () => normalizeNmapConfiguredArgs(raw, { aggressive: true, udp: true, fixedPorts: true }),
      (error) => error.code === 'NMAP_ARGS_NOT_ALLOWED',
      raw,
    );
  }
});

test('portas Nmap UDP são validadas, deduplicadas e limitadas', () => {
  assert.equal(normalizeNmapUdpPortsSpec('53,161,53'), '53,161');
  assert.match(normalizeNmapUdpPortsSpec(''), /(?:^|,)53(?:,|$)/);
  for (const raw of ['53,invalid', '0,53', '65536']) {
    assert.throws(
      () => normalizeNmapUdpPortsSpec(raw),
      (error) => error.code === 'NMAP_UDP_PORTS_NOT_ALLOWED',
      raw,
    );
  }
  const tooMany = Array.from({ length: 129 }, (_unused, index) => index + 1).join(',');
  assert.throws(
    () => normalizeNmapUdpPortsSpec(tooMany),
    (error) => error.code === 'NMAP_UDP_PORTS_NOT_ALLOWED',
  );
});
