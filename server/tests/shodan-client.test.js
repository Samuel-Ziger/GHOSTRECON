import test from 'node:test';
import assert from 'node:assert/strict';
import {
  runShodanMembershipRecon,
  shodanFeatureFlags,
  shodanHostSummary,
} from '../modules/shodan-client.mjs';

const SECRET_KEY = 'shodan-secret-key-do-not-leak';

function mockFetchRouter(handlers) {
  return async (url) => {
    const u = new URL(String(url));
    const path = u.pathname;
    for (const [prefix, fn] of handlers) {
      const base = String(prefix);
      const hit =
        path === base
        || path.startsWith(base.endsWith('/') ? base : `${base}/`)
        || (base.endsWith('/') && path.startsWith(base.slice(0, -1) + '/') && path.length > base.length - 1);
      if (!hit) continue;
      // Evitar que /shodan/host/ engula count/search se vier primeiro
      if (base === '/shodan/host' || base === '/shodan/host/') {
        if (path === '/shodan/host/count' || path.startsWith('/shodan/host/search')) continue;
      }
      const body = await fn(u);
      if (body && typeof body.status === 'number') {
        return {
          ok: body.status >= 200 && body.status < 300,
          status: body.status,
          text: async () => (typeof body.body === 'string' ? body.body : JSON.stringify(body.body ?? {})),
        };
      }
      return {
        ok: true,
        status: 200,
        text: async () => JSON.stringify(body),
      };
    }
    return { ok: false, status: 404, text: async () => '{"error":"not found"}' };
  };
}

test('shodanFeatureFlags: defaults e desligar search/dns', () => {
  assert.deepEqual(shodanFeatureFlags({}), {
    enableDnsDomain: true,
    enableSearch: true,
    maxQueryCredits: 4,
  });
  assert.equal(shodanFeatureFlags({ GHOSTRECON_SHODAN_SEARCH: '0' }).enableSearch, false);
  assert.equal(shodanFeatureFlags({ GHOSTRECON_SHODAN_DNS_DOMAIN: 'off' }).enableDnsDomain, false);
  assert.equal(shodanFeatureFlags({ GHOSTRECON_SHODAN_MAX_QUERY_CREDITS: '2' }).maxQueryCredits, 2);
});

test('sem API key: degrada sem throw', async () => {
  const r = await runShodanMembershipRecon({
    domain: 'example.test',
    apiKey: '',
    fetchImpl: async () => {
      throw new Error('não deve chamar rede');
    },
  });
  assert.equal(r.ok, false);
  assert.match(r.note, /SHODAN_API_KEY/);
  assert.equal(r.findings.length, 0);
});

test('orçamento: SSL search omitido quando créditos=2 (DNS + hostname)', async () => {
  const seen = [];
  const fetchImpl = mockFetchRouter([
    ['/api-info', async () => ({ plan: 'membership', query_credits: 100 })],
    ['/dns/domain', async (u) => {
      seen.push('dns');
      assert.match(u.pathname, /example\.test$/);
      return {
        domain: 'example.test',
        subdomains: ['www'],
        data: [{ subdomain: 'www', type: 'A', value: '192.0.2.10' }],
      };
    }],
    ['/shodan/host/count', async () => ({ total: 3, facets: { port: [{ value: 443, count: 2 }] } })],
    ['/shodan/host/search', async (u) => {
      const q = u.searchParams.get('query') || '';
      seen.push(`search:${q}`);
      return {
        total: 1,
        matches: [{ ip_str: '192.0.2.10', port: 443, product: 'nginx', hostnames: ['www.example.test'] }],
      };
    }],
    ['/shodan/host/', async (u) => {
      seen.push(`host:${u.pathname}`);
      return {
        ip_str: '192.0.2.10',
        org: 'Fixture Org',
        asn: 'AS64500',
        country_name: 'Testland',
        ports: [443],
        hostnames: ['www.example.test'],
        vulns: [],
        tags: ['cdn'],
        data: [{ product: 'nginx', port: 443, http: { title: 'Fixture' } }],
      };
    }],
  ]);

  const r = await runShodanMembershipRecon({
    domain: 'example.test',
    hosts: ['www.example.test'],
    apiKey: SECRET_KEY,
    hostInScope: () => true,
    fetchImpl,
    collectIpv4Impl: async () => ['192.0.2.10'],
    enableDnsDomain: true,
    enableSearch: true,
    maxQueryCredits: 2,
    limits: {
      shodanResolveMaxHosts: 14,
      shodanMaxIps: 12,
      shodanSearchMaxMatches: 40,
      shodanDomainMaxSubdomains: 200,
    },
  });

  assert.equal(r.ok, true);
  assert.equal(r.creditsUsed, 2);
  assert.ok(seen.includes('dns'));
  assert.ok(seen.some((x) => x.startsWith('search:hostname:')));
  assert.equal(seen.some((x) => x.includes('ssl.cert')), false);
  assert.ok(r.logs.some((l) => /ssl.*omitido|orçamento/i.test(l.message)));
  assert.ok(r.findings.some((f) => /Shodan host 192\.0\.2\.10/.test(f.value)));
  assert.ok(r.findings.some((f) => /count hostname/.test(f.value)));
});

test('escopo: IP fora da allowlist não vira finding', async () => {
  const fetchImpl = mockFetchRouter([
    ['/api-info', async () => ({ plan: 'membership', query_credits: 50 })],
    ['/dns/domain', async () => ({
      subdomains: [],
      data: [
        { subdomain: '', type: 'A', value: '192.0.2.10' },
        { subdomain: '', type: 'A', value: '198.51.100.20' },
      ],
    })],
    ['/shodan/host/count', async () => ({ total: 0, facets: {} })],
    ['/shodan/host/search', async () => ({
      total: 2,
      matches: [
        { ip_str: '192.0.2.10', port: 80, hostnames: [] },
        { ip_str: '198.51.100.20', port: 80, hostnames: [] },
      ],
    })],
    ['/shodan/host/', async (u) => {
      const ip = u.pathname.split('/').pop();
      return { ip_str: ip, org: 'x', ports: [80], hostnames: [], vulns: [], data: [] };
    }],
  ]);

  const r = await runShodanMembershipRecon({
    domain: 'lab.acme.test',
    apiKey: SECRET_KEY,
    hostInScope: (h) => h === '192.0.2.10' || String(h).endsWith('lab.acme.test'),
    fetchImpl,
    collectIpv4Impl: async () => ['192.0.2.10', '198.51.100.20'],
    enableDnsDomain: true,
    enableSearch: true,
    maxQueryCredits: 4,
    limits: {
      shodanResolveMaxHosts: 14,
      shodanMaxIps: 12,
      shodanSearchMaxMatches: 40,
      shodanDomainMaxSubdomains: 200,
    },
  });

  assert.equal(r.ok, true);
  assert.ok(r.outOfScopeIps.includes('198.51.100.20'));
  assert.equal(r.findings.some((f) => /198\.51\.100\.20/.test(f.value) || /198\.51\.100\.20/.test(f.meta)), false);
  assert.ok(r.findings.some((f) => /192\.0\.2\.10/.test(f.value)));
});

test('chave nunca aparece em note/meta/logs', async () => {
  const fetchImpl = async (url) => {
    assert.ok(String(url).includes(SECRET_KEY));
    return {
      ok: false,
      status: 401,
      text: async () => JSON.stringify({ error: `bad key ${SECRET_KEY}` }),
    };
  };

  const host = await shodanHostSummary('192.0.2.1', SECRET_KEY, { fetchImpl });
  assert.equal(host.ok, false);
  assert.equal(host.note.includes(SECRET_KEY), false);

  const r = await runShodanMembershipRecon({
    domain: 'example.test',
    apiKey: SECRET_KEY,
    fetchImpl: mockFetchRouter([
      ['/api-info', async () => ({ status: 401, body: { error: SECRET_KEY } })],
      ['/dns/domain', async () => ({ status: 401, body: { error: SECRET_KEY } })],
      ['/shodan/host/count', async () => ({ status: 401, body: { error: SECRET_KEY } })],
    ]),
    collectIpv4Impl: async () => [],
    enableDnsDomain: true,
    enableSearch: false,
    maxQueryCredits: 1,
  });

  const blob = JSON.stringify(r);
  assert.equal(blob.includes(SECRET_KEY), false);
  for (const log of r.logs) {
    assert.equal(log.message.includes(SECRET_KEY), false);
  }
});

test('host summary enriquecido extrai produtos e asn', async () => {
  const fetchImpl = mockFetchRouter([
    ['/shodan/host/', async () => ({
      ip_str: '203.0.113.5',
      org: 'Example',
      asn: 'AS64501',
      country_code: 'PT',
      ports: [443, 22],
      hostnames: ['a.example.test'],
      tags: ['vpn'],
      vulns: ['CVE-2024-0001'],
      data: [
        { product: 'OpenSSH', port: 22 },
        { product: 'nginx', port: 443, http: { title: 'Welcome' } },
      ],
    })],
  ]);
  const h = await shodanHostSummary('203.0.113.5', SECRET_KEY, { fetchImpl });
  assert.equal(h.ok, true);
  assert.equal(h.asn, 'AS64501');
  assert.ok(h.products.includes('nginx'));
  assert.ok(h.vulns.includes('CVE-2024-0001'));
  assert.ok(h.titles.includes('Welcome'));
});
