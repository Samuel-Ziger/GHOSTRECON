/**
 * OPSEC — perfis, gates intrusivos, proxy pool, watermark.
 */
import test from 'node:test';
import assert from 'node:assert/strict';
import {
  PROFILES, getProfile, isIntrusive, gateModules,
  createProxyPool, loadProxyPoolFromEnv, buildWatermark, applyWatermarkHeaders,
} from '../modules/opsec.mjs';

test('opsec: perfis conhecidos', () => {
  assert.ok(PROFILES.passive);
  assert.ok(PROFILES.standard);
  assert.ok(PROFILES.aggressive);
  assert.throws(() => getProfile('xyz'), /desconhecido/);
  assert.equal(getProfile('STANDARD').name, 'standard');
});

test('opsec: isIntrusive detecta módulos conhecidos', () => {
  assert.equal(isIntrusive('sqlmap'), true);
  assert.equal(isIntrusive('nuclei-aggressive'), true);
  assert.equal(isIntrusive('crtsh'), false);
  assert.equal(isIntrusive('http'), false);
});

test('opsec: gate bloqueia intrusivo em perfil passive', () => {
  const r = gateModules({ modules: ['crtsh', 'sqlmap'], profile: 'passive' });
  assert.equal(r.ok, false);
  assert.deepEqual(r.blocked, ['sqlmap']);
  assert.equal(r.needsConfirm, false);
});

test('opsec: gate requer confirm em standard (sem flag)', () => {
  const r = gateModules({ modules: ['sqlmap'], profile: 'standard', confirm: false });
  assert.equal(r.ok, false);
  assert.equal(r.needsConfirm, true);
});

test('opsec: gate permite intrusivo em aggressive', () => {
  const r = gateModules({ modules: ['sqlmap'], profile: 'aggressive', confirm: false });
  assert.equal(r.ok, true);
});

test('opsec: gate bloqueia se ROE não assinado mesmo com confirm', () => {
  const r = gateModules({
    modules: ['sqlmap'], profile: 'aggressive', confirm: false,
    engagement: { roeSigned: false },
  });
  assert.equal(r.ok, false);
  assert.equal(r.needsConfirm, true);
});

test('opsec: gate não gera obstáculo sem intrusivos', () => {
  const r = gateModules({ modules: ['crtsh', 'http'], profile: 'passive' });
  assert.equal(r.ok, true);
  assert.deepEqual(r.blocked, []);
});

test('opsec: proxy pool round-robin', () => {
  const pool = createProxyPool(['http://a', 'http://b', 'socks5://c']);
  assert.equal(pool.size, 3);
  assert.equal(pool.next(), 'http://a');
  assert.equal(pool.next(), 'http://b');
  assert.equal(pool.next(), 'socks5://c');
  assert.equal(pool.next(), 'http://a'); // ciclo
});

test('opsec: proxy pool vazio retorna null', () => {
  const pool = createProxyPool([]);
  assert.equal(pool.size, 0);
  assert.equal(pool.next(), null);
});

test('opsec: proxy pool banish remove', () => {
  const pool = createProxyPool(['a', 'b']);
  pool.banish('a');
  assert.equal(pool.size, 1);
  assert.equal(pool.next(), 'b');
});

test('opsec: loadProxyPoolFromEnv parseia CSV', () => {
  const pool = loadProxyPoolFromEnv({ GHOSTRECON_PROXY_POOL: 'http://1,http://2,, socks5://3 ' });
  assert.equal(pool.size, 3);
});

test('opsec: watermark estável (mesmo input → mesmo hash)', () => {
  const a = buildWatermark({ engagementId: 'ENG-1', operator: 'op', key: 'k' });
  const b = buildWatermark({ engagementId: 'ENG-1', operator: 'op', key: 'k' });
  assert.equal(a.value, b.value);
  assert.ok(a.value.startsWith('ENG-1:'));
  assert.ok(a.cookie.startsWith('gr_eng='));
});

test('opsec: watermark diferente para engagements diferentes', () => {
  const a = buildWatermark({ engagementId: 'ENG-1', key: 'k' });
  const b = buildWatermark({ engagementId: 'ENG-2', key: 'k' });
  assert.notEqual(a.value, b.value);
});

test('opsec: applyWatermarkHeaders não sobrescreve headers existentes', () => {
  const h = applyWatermarkHeaders({ 'X-Engagement-Id': 'custom', 'User-Agent': 'mine' }, { engagementId: 'E' });
  assert.equal(h['X-Engagement-Id'], 'custom');
  assert.equal(h['User-Agent'], 'mine');
});

test('opsec: applyWatermarkHeaders sem engagementId não mexe', () => {
  const h = applyWatermarkHeaders({ 'a': 1 }, {});
  assert.deepEqual(h, { 'a': 1 });
});
