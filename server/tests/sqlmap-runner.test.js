import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import {
  buildSqlmapArgs,
  buildSqlmapCurlAuthConfig,
  buildSqlmapPreflightCurlArgs,
  classifySqlmapPreflight,
  createSqlmapAuthTransport,
  formatSqlmapCommandForLog,
  runSqlmapModule,
  sniffSqlmapHints,
} from '../modules/sqlmap-runner.js';

test('sniffSqlmapHints: MySQL na mensagem', () => {
  const h = sniffSqlmapHints("You have an error in your SQL syntax near ''1'''");
  assert.equal(h.dbms, 'MySQL');
});

test('sniffSqlmapHints: PostgreSQL', () => {
  const h = sniffSqlmapHints('ERROR: syntax error at or near "LIMIT"');
  assert.equal(h.dbms, 'PostgreSQL');
});

test('sniffSqlmapHints: Unknown database', () => {
  const h = sniffSqlmapHints("Unknown database 'acme_prod' in information");
  assert.equal(h.dbms, 'MySQL');
  assert.equal(h.database, 'acme_prod');
});

test('sqlmap mantém Cookie e Authorization fora de argv e logs', async (t) => {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), 'ghostrecon-sqlmap-auth-test-'));
  t.after(() => fs.rm(root, { recursive: true, force: true }));
  const secret = 'Bearer sqlmap-secret-token';
  const cookie = 'sid=sqlmap-secret-cookie';
  const auth = { cookie, headers: { Authorization: secret } };
  const transport = await createSqlmapAuthTransport({
    targetUrl: 'https://example.test/items?id=1',
    auth,
    tempRoot: root,
  });
  t.after(() => transport.cleanup());

  const args = buildSqlmapArgs(
    'https://example.test/items?id=1',
    'id',
    {},
    false,
    transport,
  );
  const joined = args.join(' ');
  assert.equal(joined.includes(secret), false);
  assert.equal(joined.includes(cookie), false);
  assert.equal(args.includes('--cookie'), false);
  assert.equal(args.includes('--header'), false);
  assert.match(formatSqlmapCommandForLog(args), /<restricted-request-file>/);
  assert.doesNotMatch(formatSqlmapCommandForLog(args), /sqlmap-secret/);

  const stat = await fs.stat(transport.requestFile);
  assert.equal(stat.mode & 0o777, 0o600);
  const request = await fs.readFile(transport.requestFile, 'utf8');
  assert.match(request, /Authorization: Bearer sqlmap-secret-token/);
  assert.match(request, /Cookie: sid=sqlmap-secret-cookie/);

  await transport.cleanup();
  await assert.rejects(fs.access(transport.requestFile));
});

test('pré-flight curl usa arquivo 0600 em vez de segredo inline', () => {
  const secret = 'Bearer preflight-secret';
  const config = buildSqlmapCurlAuthConfig({
    cookie: 'sid=preflight-cookie',
    headers: { Authorization: secret },
  });
  assert.match(config, /Authorization: Bearer preflight-secret/);
  const args = buildSqlmapPreflightCurlArgs({
    url: 'https://example.test/?id=1',
    authConfigFile: '/tmp/restricted-auth.curlrc',
    headerFile: '/tmp/headers',
    bodyFile: '/tmp/body',
  });
  assert.equal(args.join(' ').includes(secret), false);
  assert.equal(args.join(' ').includes('preflight-cookie'), false);
  assert.deepEqual(args.slice(args.indexOf('--config'), args.indexOf('--config') + 2), [
    '--config',
    '/tmp/restricted-auth.curlrc',
  ]);
});

test('sqlmap propaga cancelamento sem executar subprocesso ou rede', async () => {
  const controller = new AbortController();
  controller.abort(new Error('operator_cancelled'));
  await assert.rejects(
    runSqlmapModule({
      findings: [],
      auth: null,
      log() {},
      signal: controller.signal,
    }),
    /operator_cancelled|cancelado/i,
  );
});

test('preflight aceita diferencial booleano repetível e remove reflexão do payload', () => {
  const row = (body, code = 200) => ({ ok: true, body, code });
  const result = classifySqlmapPreflight({
    baselineA: row('results for T-Shirt: all products'),
    baselineB: row('results for T-Shirt: all products'),
    quote: row('generic page'),
    booleanTrue: row("results for T-Shirt' AND '1'='1: all products"),
    booleanFalseA: row("results for T-Shirt' AND '1'='2: empty"),
    booleanFalseB: row("results for T-Shirt' AND '1'='2: empty"),
    baseValue: 'T-Shirt',
    trueValue: "T-Shirt' AND '1'='1",
    falseValue: "T-Shirt' AND '1'='2",
  });
  assert.equal(result.interesting, true);
  assert.equal(result.kind, 'stable_boolean_differential');
});

test('preflight recusa 500 genérico, WAF e resposta instável', () => {
  const row = (body, code = 200) => ({ ok: true, body, code });
  const generic500 = classifySqlmapPreflight({
    baselineA: row('normal'), baselineB: row('normal'), quote: row('server error', 500),
    booleanTrue: row('normal'), booleanFalseA: row('normal'), booleanFalseB: row('normal'),
  });
  const waf = classifySqlmapPreflight({
    baselineA: row('normal'), baselineB: row('normal'), quote: row('blocked', 403),
    booleanTrue: row('blocked', 403), booleanFalseA: row('blocked', 403), booleanFalseB: row('blocked', 403),
  });
  const unstable = classifySqlmapPreflight({
    baselineA: row('dynamic-a'), baselineB: row('dynamic-b'), quote: row('normal'),
    booleanTrue: row('dynamic-a'), booleanFalseA: row('empty'), booleanFalseB: row('empty'),
  });
  assert.equal(generic500.interesting, false);
  assert.equal(waf.interesting, false);
  assert.equal(unstable.interesting, false);
});
