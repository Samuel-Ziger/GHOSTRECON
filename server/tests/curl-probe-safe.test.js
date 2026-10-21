import test from 'node:test';
import assert from 'node:assert/strict';

import { CURL_PROBE_METHODS, runCurlProbeModule } from '../modules/curl-probe.mjs';

function response({ status = 200, body = 'ok', headers = {}, method = 'GET', url = 'https://target.test/' } = {}) {
  return {
    ok: true,
    status,
    body,
    bodyHash: `hash:${body}`,
    bodySize: Buffer.byteLength(body),
    headers,
    metrics: { http_code: String(status), url_effective: url },
    curlTemplate: `curl -X ${method} "${url}"`,
  };
}

test('curl_probe nunca envia método mutável nem payload SQLi', async () => {
  const calls = [];
  await runCurlProbeModule({
    target: 'target.test',
    persist: false,
    execCurlImpl: async (opts) => {
      calls.push(opts);
      return response({ method: opts.method, url: opts.url });
    },
  });
  assert.deepEqual(CURL_PROBE_METHODS, ['GET', 'HEAD', 'OPTIONS']);
  assert.ok(calls.length > 0);
  assert.ok(calls.every((call) => ['GET', 'HEAD', 'OPTIONS'].includes(call.method)));
  assert.ok(calls.every((call) => call.body == null));
  assert.ok(calls.every((call) => !/OR\s+'?1'?='?1|UNION|ORDER BY/i.test(JSON.stringify(call))));
});

test('curl_probe bloqueia URL fora de escopo antes do executor', async () => {
  let calls = 0;
  const result = await runCurlProbeModule({
    target: 'target.test',
    findings: [{ type: 'endpoint', value: 'https://outside.test/private' }],
    urlAllowed: (url) => new URL(url).hostname === 'target.test',
    persist: false,
    execCurlImpl: async (opts) => {
      calls += 1;
      return response({ method: opts.method, url: opts.url });
    },
  });
  assert.equal(calls, 4);
  assert.deepEqual(result, []);
});

test('curl_probe trata Allow como inventário e não testa os métodos anunciados', async () => {
  const calls = [];
  const findings = await runCurlProbeModule({
    target: 'target.test',
    persist: false,
    execCurlImpl: async (opts) => {
      calls.push(opts);
      return response({
        method: opts.method,
        url: opts.url,
        headers: opts.method === 'OPTIONS' ? { allow: 'GET, POST, PUT, DELETE' } : {},
      });
    },
  });
  const inventory = findings.find((finding) => finding.type === 'http_method_advertised');
  assert.ok(inventory);
  assert.equal(inventory.verification.classification, 'inventory');
  assert.equal(inventory.prio, 'low');
  assert.ok(calls.every((call) => !['POST', 'PUT', 'PATCH', 'DELETE'].includes(call.method)));
});

test('curl_probe não chama resposta pública de auth bypass', async () => {
  const findings = await runCurlProbeModule({
    target: 'target.test',
    auth: { headers: { Authorization: 'Bearer fixture' } },
    persist: false,
    execCurlImpl: async (opts) => response({ method: opts.method, url: opts.url, body: 'public page' }),
  });
  assert.equal(findings.some((finding) => finding.type === 'curl_auth_bypass'), false);
  const inventory = findings.find((finding) => finding.type === 'auth_surface_equivalent');
  assert.ok(inventory);
  assert.equal(inventory.prio, 'info');
});

test('curl_probe classifica CORS refletido como candidato, não confirmação', async () => {
  const findings = await runCurlProbeModule({
    target: 'target.test',
    persist: false,
    execCurlImpl: async (opts) => response({
      method: opts.method,
      url: opts.url,
      headers: opts.extraHeaders?.Origin
        ? {
            'access-control-allow-origin': opts.extraHeaders.Origin,
            'access-control-allow-credentials': 'true',
          }
        : {},
    }),
  });
  const cors = findings.find((finding) => finding.type === 'cors_policy_candidate');
  assert.ok(cors);
  assert.equal(cors.verification.classification, 'candidate');
  assert.equal(cors.prio, 'med');
});

test('curl_probe redige valores de query em finding e reprodução', async () => {
  const secret = 'super-secret-query-value';
  const findings = await runCurlProbeModule({
    target: `https://target.test/search?q=${secret}`,
    persist: false,
    urlAllowed: () => true,
    execCurlImpl: async (opts) => response({
      method: opts.method,
      url: opts.url,
      headers: opts.extraHeaders?.Origin
        ? {
            'access-control-allow-origin': opts.extraHeaders.Origin,
            'access-control-allow-credentials': 'true',
          }
        : {},
    }),
  });
  assert.ok(findings.length > 0);
  assert.doesNotMatch(JSON.stringify(findings), new RegExp(secret));
});

test('curl_probe falha explicitamente quando o executor não produz resposta', async () => {
  await assert.rejects(runCurlProbeModule({
    target: 'target.test',
    persist: false,
    execCurlImpl: async () => ({
      ok: false,
      status: 0,
      body: '',
      bodyHash: '',
      bodySize: 0,
      headers: {},
      metrics: {},
    }),
  }), /nenhuma requisição produziu resposta utilizável/);
});

test('curl_probe recusa credencial embutida na URL antes do executor', async () => {
  let calls = 0;
  const findings = await runCurlProbeModule({
    target: 'https://user:password@target.test/private',
    persist: false,
    urlAllowed: () => true,
    execCurlImpl: async () => {
      calls += 1;
      return response();
    },
  });
  assert.equal(calls, 0);
  assert.deepEqual(findings, []);
});
