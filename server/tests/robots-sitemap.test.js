import { gzipSync } from 'node:zlib';
import test from 'node:test';
import assert from 'node:assert/strict';

import {
  canonicalizeSitemapUrl,
  crawlRobotsAndSitemapsForOrigin,
  parseSitemapDocument,
} from '../modules/robots-sitemap.js';

function response(body = '', { status = 200, headers = {} } = {}) {
  return new Response(body, { status, headers });
}

function routeFetch(routes, calls = []) {
  return async (rawUrl) => {
    const url = String(rawUrl);
    calls.push(url);
    const handler = routes.get(url);
    if (!handler) return response('', { status: 404 });
    return typeof handler === 'function' ? handler(url) : handler;
  };
}

test('parser Sitemap valida XML, namespaces, atributos, entidades e CDATA', () => {
  const parsed = parseSitemapDocument(`<?xml version="1.0" encoding="UTF-8"?>
    <sm:urlset xmlns:sm="http://www.sitemaps.org/schemas/sitemap/0.9" note="1 > 0">
      <sm:url><sm:loc>https://example.test/a?x=1&amp;y=2</sm:loc></sm:url>
      <sm:url><sm:loc><![CDATA[https://example.test/b?x=1&y=2]]></sm:loc></sm:url>
      <sm:url><image:image xmlns:image="urn:image"><image:loc>https://cdn.example.test/ignored</image:loc></image:image></sm:url>
    </sm:urlset>`, 1);

  assert.equal(parsed.kind, 'pages');
  assert.equal(parsed.locCount, 2);
  assert.equal(parsed.truncated, true);
  assert.deepEqual(parsed.urls, ['https://example.test/a?x=1&y=2']);

  const invalidDocuments = [
    '<!DOCTYPE urlset [<!ENTITY x SYSTEM "file:///etc/passwd">]><urlset/>',
    '<urlset><url><loc>https://example.test/&unknown;</loc></url></urlset>',
    '<urlset xmlns=http://example.test/>',
    '<urlset><url></urlset>',
    '<urlset/><urlset/>',
    '<?xml version="1.0" encoding="ISO-8859-1"?><urlset/>',
    '<urlset><!-- invalid -- comment --></urlset>',
    '<s:urlset><s:url><s:loc>https://example.test/a</s:loc></s:url></s:urlset>',
    '<s:urlset xmlns:s="urn:not-sitemap"><s:url/></s:urlset>',
  ];
  for (const document of invalidDocuments) {
    assert.throws(() => parseSitemapDocument(document), Error, document);
  }
});

test('parser preserva resultado determinístico em variações estruturais limitadas', () => {
  for (let index = 0; index < 80; index += 1) {
    const prefix = index % 2 === 0 ? 's:' : '';
    const namespace = prefix ? ' xmlns:s="http://www.sitemaps.org/schemas/sitemap/0.9"' : '';
    const gap = index % 3 === 0 ? '\n  ' : '';
    const source = `<${prefix}urlset${namespace}>${gap}<${prefix}url><${prefix}loc>https://example.test/p/${index}&#x3F;a=1&amp;b=2</${prefix}loc></${prefix}url>${gap}</${prefix}urlset>`;
    const parsed = parseSitemapDocument(source);
    assert.deepEqual(parsed.urls, [`https://example.test/p/${index}?a=1&b=2`]);
    assert.equal(parsed.locCount, 1);
    assert.equal(parsed.truncated, false);
  }
});

test('parser não confunde loc de namespace de extensão com URL do protocolo', () => {
  const parsed = parseSitemapDocument(`
    <urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9" xmlns:x="urn:extension">
      <url><x:loc>https://evil.test/extension-only</x:loc></url>
      <url><loc>https://example.test/real</loc></url>
    </urlset>
  `);
  assert.deepEqual(parsed.urls, ['https://example.test/real']);
  assert.equal(parsed.locCount, 1);
});

test('canonicaliza somente URLs HTTP(S) absolutas, sem credenciais ou fragmentos', () => {
  assert.equal(
    canonicalizeSitemapUrl('HTTPS://EXAMPLE.TEST:443/a/../b#section'),
    'https://example.test/b',
  );
  assert.equal(canonicalizeSitemapUrl('https://user:secret@example.test/a'), null);
  assert.equal(canonicalizeSitemapUrl('/relative.xml'), null);
  assert.equal(canonicalizeSitemapUrl('ftp://example.test/sitemap.xml'), null);
  assert.equal(canonicalizeSitemapUrl(`https://example.test/${'x'.repeat(4_100)}`), null);
});

test('crawler percorre índices aninhados, gzip e ciclos com dedupe e proveniência', async () => {
  const calls = [];
  const routes = new Map([
    ['https://example.test/robots.txt', () => response(`
      Sitemap: HTTPS://EXAMPLE.TEST:443/root.xml#fragment
      Sitemap: https://evil.test/out.xml
      Sitemap: ftp://example.test/not-http.xml
      Disallow: /admin/private
    `)],
    ['https://example.test/sitemap.xml', () => response('', { status: 404 })],
    ['https://example.test/root.xml', () => response(`
      <sitemapindex xmlns="http://www.sitemaps.org/schemas/sitemap/0.9" note="1 > 0">
        <sitemap><loc>https://example.test/level-one.xml</loc></sitemap>
        <sitemap><loc>https://example.test/level-one.xml#duplicate</loc></sitemap>
      </sitemapindex>
    `)],
    ['https://example.test/level-one.xml', () => response(`
      <sitemapindex>
        <sitemap><loc>https://example.test/level-two.xml.gz</loc></sitemap>
        <sitemap><loc>https://example.test/root.xml#cycle</loc></sitemap>
      </sitemapindex>
    `)],
    ['https://example.test/level-two.xml.gz', () => response(gzipSync(`
      <urlset>
        <url><loc>https://EXAMPLE.TEST:443/a#one</loc></url>
        <url><loc>https://example.test/a#two</loc></url>
        <url><loc>https://example.test/b?x=1&amp;y=2</loc></url>
        <url><loc>https://cdn.example.test/c</loc></url>
        <url><loc>https://evil.test/no</loc></url>
      </urlset>
    `), { headers: { 'content-type': 'application/gzip' } })],
  ]);

  const result = await crawlRobotsAndSitemapsForOrigin(
    'https://example.test/start',
    'example.test',
    [],
    null,
    {
      fetchImpl: routeFetch(routes, calls),
      maxSitemapFiles: 8,
      maxDepth: 4,
      urlAllowed: (url) => {
        const hostname = new URL(url).hostname;
        return hostname === 'example.test' || hostname.endsWith('.example.test');
      },
    },
  );

  assert.equal(result.status, 'done');
  assert.equal(result.robotsOk, true);
  assert.deepEqual(result.disallowHints, ['/admin/private']);
  assert.deepEqual(result.pageUrls, [
    'https://example.test/a',
    'https://example.test/b?x=1&y=2',
    'https://cdn.example.test/c',
  ]);
  assert.equal(calls.filter((url) => url === 'https://example.test/root.xml').length, 1);
  assert.equal(calls.some((url) => new URL(url).hostname === 'evil.test'), false);
  assert.equal(calls.some((url) => url.startsWith('ftp:')), false);
  assert.equal(result.metrics.duplicateUrls >= 2, true);
  assert.equal(result.metrics.outOfScopeUrls >= 2, true);
  assert.equal(result.metrics.invalidUrls >= 1, true);

  const gzipOutcome = result.outcomes.find((outcome) => outcome.url.endsWith('.xml.gz'));
  assert.equal(gzipOutcome?.state, 'done');
  assert.equal(gzipOutcome?.gzip, true);
  assert.equal(gzipOutcome?.documentKind, 'pages');
  const source = result.pageSources.find((entry) => entry.url === 'https://example.test/a');
  assert.equal(source?.sitemapUrl, 'https://example.test/level-two.xml.gz');
  assert.equal(source?.rootSitemapUrl, 'https://example.test/root.xml');
  assert.equal(source?.depth, 2);
  assert.equal(result.provenance.collector, 'robots_sitemap');
});

test('crawler falha fechado em redirects fora de escopo sem enviar a segunda requisição', async () => {
  const calls = [];
  const routes = new Map([
    ['https://example.test/robots.txt', () => response('', { status: 404 })],
    ['https://example.test/sitemap.xml', () => response('', {
      status: 302,
      headers: { location: 'https://evil.test/sitemap.xml' },
    })],
  ]);
  const result = await crawlRobotsAndSitemapsForOrigin(
    'https://example.test/',
    'example.test',
    [],
    null,
    { fetchImpl: routeFetch(routes, calls) },
  );

  assert.deepEqual(calls, [
    'https://example.test/robots.txt',
    'https://example.test/sitemap.xml',
  ]);
  assert.equal(result.status, 'partial');
  assert.equal(result.outcomes.find((outcome) => outcome.role === 'sitemap')?.state, 'scope_denied');
  assert.deepEqual(result.pageUrls, []);
});

test('401/403 deixam cobertura incompleta em vez de simular negativo limpo', async () => {
  const routes = new Map([
    ['https://example.test/robots.txt', () => response('', { status: 403 })],
    ['https://example.test/sitemap.xml', () => response('', { status: 401 })],
  ]);
  const result = await crawlRobotsAndSitemapsForOrigin(
    'https://example.test/',
    'example.test',
    [],
    null,
    { fetchImpl: routeFetch(routes) },
  );
  assert.equal(result.status, 'failed');
  assert.deepEqual(result.outcomes.map((outcome) => outcome.state), ['denied', 'denied']);
});

test('crawler atesta limites de corpo, descompressão, profundidade e arquivos', async (t) => {
  await t.test('corpo HTTP maior que o limite', async () => {
    const routes = new Map([
      ['https://example.test/robots.txt', () => response('', { status: 404 })],
      ['https://example.test/sitemap.xml', () => response(`<urlset>${' '.repeat(512)}</urlset>`)],
    ]);
    const result = await crawlRobotsAndSitemapsForOrigin(
      'https://example.test/', 'example.test', [], null,
      { fetchImpl: routeFetch(routes), maxBytes: 128 },
    );
    assert.equal(result.status, 'partial');
    assert.equal(result.outcomes.at(-1).state, 'response_too_large');
  });

  await t.test('gzip com saída expandida acima do limite', async () => {
    const compressed = gzipSync(`<urlset>${' '.repeat(2_000)}</urlset>`);
    assert.equal(compressed.length < 128, true);
    const routes = new Map([
      ['https://example.test/robots.txt', () => response('', { status: 404 })],
      ['https://example.test/sitemap.xml', () => response(compressed)],
    ]);
    const result = await crawlRobotsAndSitemapsForOrigin(
      'https://example.test/', 'example.test', [], null,
      { fetchImpl: routeFetch(routes), maxBytes: 128 },
    );
    assert.equal(result.status, 'partial');
    assert.equal(result.outcomes.at(-1).state, 'response_too_large');
  });

  await t.test('profundidade zero não busca filhos do índice', async () => {
    const calls = [];
    const routes = new Map([
      ['https://example.test/robots.txt', () => response('Sitemap: https://example.test/root.xml')],
      ['https://example.test/root.xml', () => response('<sitemapindex><sitemap><loc>https://example.test/child.xml</loc></sitemap></sitemapindex>')],
      ['https://example.test/sitemap.xml', () => response('', { status: 404 })],
      ['https://example.test/child.xml', () => response('<urlset/>')],
    ]);
    const result = await crawlRobotsAndSitemapsForOrigin(
      'https://example.test/', 'example.test', [], null,
      { fetchImpl: routeFetch(routes, calls), maxDepth: 0 },
    );
    assert.equal(calls.includes('https://example.test/child.xml'), false);
    assert.equal(result.metrics.indexesStoppedByDepth, 1);
    assert.equal(result.status, 'partial');
  });

  await t.test('orçamento de arquivos é global e determinístico', async () => {
    const calls = [];
    const routes = new Map([
      ['https://example.test/robots.txt', () => response(`
        Sitemap: https://example.test/one.xml
        Sitemap: https://example.test/two.xml
        Sitemap: https://example.test/three.xml
      `)],
      ['https://example.test/one.xml', () => response('<urlset/>')],
      ['https://example.test/two.xml', () => response('<urlset/>')],
      ['https://example.test/three.xml', () => response('<urlset/>')],
    ]);
    const result = await crawlRobotsAndSitemapsForOrigin(
      'https://example.test/', 'example.test', [], null,
      { fetchImpl: routeFetch(routes, calls), maxSitemapFiles: 2 },
    );
    assert.deepEqual(calls, [
      'https://example.test/robots.txt',
      'https://example.test/one.xml',
      'https://example.test/two.xml',
    ]);
    assert.equal(result.metrics.filesSkippedByLimit, 2);
    assert.equal(result.status, 'partial');
  });
});

test('crawler propaga cancelamento anterior sem realizar rede', async () => {
  const controller = new AbortController();
  controller.abort(new Error('operator_cancelled'));
  let calls = 0;
  await assert.rejects(
    crawlRobotsAndSitemapsForOrigin(
      'https://example.test/',
      'example.test',
      [],
      null,
      {
        signal: controller.signal,
        fetchImpl: async () => { calls += 1; throw new Error('unexpected network'); },
      },
    ),
    /operator_cancelled/,
  );
  assert.equal(calls, 0);
});

test('timeout local encerra a origem como falha atestada sem rejeitar toda a fase', async () => {
  let calls = 0;
  const result = await crawlRobotsAndSitemapsForOrigin(
    'https://example.test/',
    'example.test',
    [],
    null,
    {
      timeoutMs: 10,
      fetchImpl: async (_url, { signal }) => {
        calls += 1;
        return new Promise((resolve, reject) => {
          const fallback = setTimeout(() => reject(new Error('timeout signal was not propagated')), 250);
          signal.addEventListener('abort', () => {
            clearTimeout(fallback);
            reject(signal.reason);
          }, { once: true });
        });
      },
    },
  );

  assert.equal(calls, 1);
  assert.equal(result.status, 'failed');
  assert.match(result.error, /timeout seguro/);
  assert.equal(result.outcomes[0]?.state, 'timeout');
});
