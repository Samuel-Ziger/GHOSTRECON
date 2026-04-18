import test from 'node:test';
import assert from 'node:assert/strict';
import { parseNmapXml } from '../modules/kali-scan.js';

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
  assert.equal(rows[0].port, '80');
  assert.equal(rows[0].name, 'http');
  assert.equal(rows[0].product, 'nginx');
  assert.equal(rows[1].port, '3306');
  assert.equal(rows[1].name, 'mysql');
  assert.match(rows[1].searchBlob, /MySQL/);
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
