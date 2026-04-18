import test from 'node:test';
import assert from 'node:assert/strict';
import {
  buildMysqlConfigSurfaceCorrelationFindings,
  collectMysql3306HostsFromFindings,
  pathnameLooksLikeDbOrAppConfig,
} from '../modules/mysql-config-correlation.js';

test('collectMysql3306HostsFromFindings: linha nmap', () => {
  const h = collectMysql3306HostsFromFindings([
    { type: 'nmap', value: 'tcp/3306 10.0.0.5 — mysql MySQL 8.0' },
  ]);
  assert.deepEqual(h, ['10.0.0.5']);
});

test('pathnameLooksLikeDbOrAppConfig', () => {
  assert.equal(pathnameLooksLikeDbOrAppConfig('/config/config.php'), true);
  assert.equal(pathnameLooksLikeDbOrAppConfig('/.env'), true);
  assert.equal(pathnameLooksLikeDbOrAppConfig('/news'), false);
});

test('correlação: 3306 + .env na mesma origem', () => {
  const findings = [
    { type: 'nmap', value: 'tcp/3306 10.0.0.5 — mysql MySQL 8.0' },
    { type: 'endpoint', value: 'http://10.0.0.5/.env', url: 'http://10.0.0.5/.env' },
  ];
  const out = buildMysqlConfigSurfaceCorrelationFindings(findings);
  assert.equal(out.length, 1);
  assert.match(out[0].meta, /mysql_config_surface/);
  assert.equal(out[0].url, 'http://10.0.0.5/.env');
});

test('correlação: host diferente não emite', () => {
  const findings = [
    { type: 'nmap', value: 'tcp/3306 10.0.0.5 — mysql' },
    { type: 'endpoint', value: 'http://10.0.0.99/.env', url: 'http://10.0.0.99/.env' },
  ];
  assert.equal(buildMysqlConfigSurfaceCorrelationFindings(findings).length, 0);
});
