import test from 'node:test';
import assert from 'node:assert/strict';
import { buildMysql3306IntelFindings } from '../modules/mysql-nmap-intel.js';

test('3306/tcp gera inventário estruturado, sem comandos ou vulnerabilidade presumida', () => {
  const rows = [
    {
      host: 'db.example.com',
      port: '3306',
      proto: 'tcp',
      name: 'mysql',
      product: 'MySQL',
      version: '8.0.35',
    },
  ];
  const f = buildMysql3306IntelFindings(rows);
  assert.equal(f.length, 1);
  assert.equal(f[0].type, 'service_inventory');
  assert.match(f[0].value, /db\.example\.com/);
  assert.equal(f[0].prio, 'info');
  assert.equal(f[0].meta.service, 'mysql');
  assert.equal(f[0].meta.version, '8.0.35');
  assert.equal(f[0].meta.evidenceStatus, 'inventory_confirmed_by_nmap_service');
  assert.doesNotMatch(JSON.stringify(f[0]), /sqlmap|nmap -p|mysql -h/);
});

test('dedupe por host', () => {
  const rows = [
    { host: 'x.com', port: '3306', proto: 'tcp', name: 'mysql' },
    { host: 'x.com', port: '3306', proto: 'tcp', name: 'mysql' },
  ];
  assert.equal(buildMysql3306IntelFindings(rows).length, 1);
});

test('ignora 3306 udp e outras portas', () => {
  assert.equal(
    buildMysql3306IntelFindings([{ host: 'a', port: '3306', proto: 'udp', name: 'x' }]).length,
    0,
  );
  assert.equal(buildMysql3306IntelFindings([{ host: 'a', port: '3307', proto: 'tcp', name: 'mysql' }]).length, 0);
});

test('não confunde produto com substring e reaplica escopo ao inventário', () => {
  const rows = [
    { host: 'in.example', port: '3306', proto: 'tcp', name: 'notmysqlproxy' },
    { host: 'out.example', port: '3306', proto: 'tcp', name: 'mysql' },
  ];
  const findings = buildMysql3306IntelFindings(rows, {
    hostAllowed: (host) => host === 'in.example',
  });
  assert.equal(findings.length, 1);
  assert.equal(findings[0].meta.evidenceStatus, 'candidate_by_port');
  assert.equal(findings[0].meta.applicabilityVerified, false);
});
