import test from 'node:test';
import assert from 'node:assert/strict';
import { buildMysql3306IntelFindings } from '../modules/mysql-nmap-intel.js';

test('3306/tcp gera intel com mysql client e nmap scripts', () => {
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
  assert.equal(f[0].type, 'intel');
  assert.match(f[0].value, /db\.example\.com/);
  assert.match(f[0].meta, /mysql -h/);
  assert.match(f[0].meta, /nmap -p3306/);
  assert.match(f[0].meta, /sqlmap -d/);
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
