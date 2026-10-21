import test from 'node:test';
import assert from 'node:assert/strict';

import {
  auditCookieHeaders,
  loadSystemPublicSuffixList,
  parsePublicSuffixList,
  parseSetCookie,
  publicSuffixInfo,
} from '../modules/cookie-session-audit.mjs';

const PSL_FIXTURE = `
// fixture sintética no formato oficial
com
uk
co.uk
cn
公司.cn
*.ck
!www.ck
github.io
`;

function fixturePsl() {
  return parsePublicSuffixList(PSL_FIXTURE, { source: 'fixture-2026-09' });
}

test('PSL aplica regras exatas, wildcard, exception, privadas e IDN', () => {
  const publicSuffixList = fixturePsl();
  assert.equal(publicSuffixList.ruleCount, 8);
  assert.match(publicSuffixList.versionHash, /^[a-f0-9]{64}$/);

  assert.deepEqual(
    publicSuffixInfo('api.shop.example.co.uk', { publicSuffixList }),
    {
      available: true,
      domain: 'api.shop.example.co.uk',
      publicSuffix: 'co.uk',
      registrableDomain: 'example.co.uk',
      isPublicSuffix: false,
      rule: 'co.uk',
      source: 'fixture-2026-09',
      versionHash: publicSuffixList.versionHash,
    },
  );
  assert.equal(publicSuffixInfo('a.ck', { publicSuffixList }).isPublicSuffix, true);
  assert.equal(publicSuffixInfo('www.ck', { publicSuffixList }).publicSuffix, 'ck');
  assert.equal(publicSuffixInfo('github.io', { publicSuffixList }).isPublicSuffix, true);
  assert.equal(publicSuffixInfo('user.github.io', { publicSuffixList }).registrableDomain, 'user.github.io');

  const idn = publicSuffixInfo('食狮.公司.cn', { publicSuffixList });
  assert.equal(idn.publicSuffix, 'xn--55qx5d.cn');
  assert.equal(idn.registrableDomain, 'xn--85x722f.xn--55qx5d.cn');
});

test('PSL mantém resultado determinístico para corpus amplo de subdomínios', () => {
  const publicSuffixList = fixturePsl();
  for (let i = 0; i < 250; i++) {
    const label = `tenant-${i.toString(36)}`;
    const info = publicSuffixInfo(`api.${label}.example.co.uk`, { publicSuffixList });
    assert.equal(info.publicSuffix, 'co.uk');
    assert.equal(info.registrableDomain, 'example.co.uk');
    assert.equal(info.rule, 'co.uk');
  }
});

test('parser da PSL recusa fonte vazia ou acima do limite', () => {
  assert.throws(() => parsePublicSuffixList('// sem regras\n'), /no_valid_rules/);
  assert.throws(() => parsePublicSuffixList('x'.repeat(2_000_001)), /invalid_or_too_large/);
});

test('loader da PSL usa somente paths fornecidos, limita tamanho e falha fechado', () => {
  const reads = [];
  const loaded = loadSystemPublicSuffixList({
    paths: ['/fixture/psl.dat'],
    statImpl: (path) => ({ isFile: () => path === '/fixture/psl.dat', size: PSL_FIXTURE.length }),
    readFileImpl: (path, encoding) => {
      reads.push([path, encoding]);
      return PSL_FIXTURE;
    },
  });
  assert.equal(loaded.available, true);
  assert.deepEqual(reads, [['/fixture/psl.dat', 'utf8']]);

  const unavailable = loadSystemPublicSuffixList({
    paths: ['/missing'],
    statImpl: () => { throw new Error('ENOENT'); },
    readFileImpl: () => { throw new Error('must_not_read'); },
  });
  assert.equal(unavailable.available, false);
  assert.equal(unavailable.reason, 'system_public_suffix_list_not_found');

  const oversized = loadSystemPublicSuffixList({
    paths: ['/oversized'],
    statImpl: () => ({ isFile: () => true, size: 2_000_001 }),
    readFileImpl: () => { throw new Error('must_not_read'); },
  });
  assert.equal(oversized.available, false);
});

test('cookie Domain em sufixo público é configuração rejeitada, não exposição confirmada', () => {
  const publicSuffixList = fixturePsl();
  const findings = auditCookieHeaders([
    'sessionid=private-value; Domain=.co.uk; Path=/; Secure; HttpOnly; SameSite=Lax',
  ], {
    url: 'https://shop.co.uk/',
    publicSuffixList,
  });
  assert.equal(findings.length, 1);
  assert.match(findings[0].value, /sufixo público/);
  assert.match(findings[0].meta, /browser_acceptance=expected_rejection/);
  assert.match(findings[0].meta, /public_suffix_rule=co\.uk/);
  assert.match(findings[0].meta, /public_suffix_snapshot=[a-f0-9]{64}/);
  assert.doesNotMatch(findings[0].meta, /private-value/);

  const withoutOrigin = auditCookieHeaders([
    'sessionid=private-value; Domain=.co.uk; Path=/; Secure; HttpOnly; SameSite=Lax',
  ], { url: '', publicSuffixList });
  assert.equal(withoutOrigin.length, 1);
  assert.match(withoutOrigin[0].meta, /browser_acceptance=unknown_without_request_host/);
  assert.doesNotMatch(withoutOrigin[0].meta, /browser_acceptance=expected_rejection/);
});

test('cookie sensível com Domain válido registra escopo e proveniência da PSL', () => {
  const publicSuffixList = fixturePsl();
  const findings = auditCookieHeaders([
    'sessionid=opaque; Domain=.example.co.uk; Path=/; Secure; HttpOnly; SameSite=Strict',
  ], {
    url: 'https://app.example.co.uk/',
    publicSuffixList,
  });
  assert.equal(findings.length, 1);
  assert.match(findings[0].value, /escopo de domínio e subdomínios/);
  assert.match(findings[0].meta, /public_suffix_check=performed/);
  assert.match(findings[0].meta, /registrable_domain=example\.co\.uk/);
});

test('prefixos, Partitioned e atributos duplicados seguem semântica conservadora', () => {
  const publicSuffixList = fixturePsl();
  const valid = auditCookieHeaders([
    '__Host-session=opaque; Secure; HttpOnly; SameSite=Lax; Path=/',
  ], { url: 'https://app.example.com/', publicSuffixList });
  assert.deepEqual(valid, []);

  const invalidPrefix = auditCookieHeaders([
    '__Host-session=opaque; Domain=app.example.com; Secure; HttpOnly; SameSite=Lax; Path=/',
  ], { url: 'https://app.example.com/', publicSuffixList });
  assert.equal(invalidPrefix.length, 1);
  assert.match(invalidPrefix[0].value, /prefixo/);
  assert.match(invalidPrefix[0].meta, /expected_rejection/);

  const invalidPartitioned = auditCookieHeaders([
    'cart=opaque; Partitioned; SameSite=None; Path=/',
  ], { url: 'https://shop.example.com/', publicSuffixList });
  assert.equal(invalidPartitioned.length, 1);
  assert.match(invalidPartitioned[0].value, /Partitioned sem Secure/);

  const parsed = parseSetCookie('sid=opaque; SameSite=None; SameSite=Lax; Secure');
  assert.equal(parsed.sameSite, 'lax');
  assert.equal(parsed.secure, true);
});

test('nomes de sessão conhecidos usam tokens exatos sem substring genérica', () => {
  const publicSuffixList = fixturePsl();
  for (const name of ['PHPSESSID', 'JSESSIONID', 'ASPSESSIONIDABC123']) {
    const findings = auditCookieHeaders([`${name}=opaque; Path=/`], {
      url: 'https://app.example.com/',
      publicSuffixList,
    });
    assert.ok(findings.some((finding) => /HttpOnly/.test(finding.value)), name);
  }
  const unrelated = auditCookieHeaders(['accessibility=on; Path=/'], {
    url: 'https://app.example.com/',
    publicSuffixList,
  });
  assert.equal(unrelated.some((finding) => /HttpOnly|SameSite/.test(finding.value)), false);
});

test('PSL indisponível não inventa classificação de sufixo público', () => {
  const unavailable = loadSystemPublicSuffixList({
    paths: [],
    statImpl: () => { throw new Error('must_not_stat'); },
    readFileImpl: () => { throw new Error('must_not_read'); },
  });
  const findings = auditCookieHeaders([
    'sessionid=opaque; Domain=.example.test; Secure; HttpOnly; SameSite=Lax; Path=/',
  ], {
    url: 'https://app.example.test/',
    publicSuffixList: unavailable,
  });
  assert.equal(findings.length, 1);
  assert.match(findings[0].meta, /public_suffix_check=unavailable/);
  assert.doesNotMatch(findings[0].value, /sufixo público/);
});
