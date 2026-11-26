import test from 'node:test';
import assert from 'node:assert/strict';

import { listModuleManifests, getRegistryEntry } from '../modules/module-registry.mjs';
import { moduleRunners } from '../modules/module-registry-runners.mjs';

test('todo manifest registrado possui runner executável', () => {
  const phaseManaged = new Set(['risk_explainer', 'vigolium_dast', 'vigolium_audit', 'vigolium_swarm']);
  for (const manifest of listModuleManifests()) {
    if (phaseManaged.has(manifest.id)) continue;
    assert.equal(typeof getRegistryEntry(manifest.id)?.run, 'function', manifest.id);
  }
});

test('adapters passivos alimentam cloud, runtime e voucher pelo estado do pipeline', async () => {
  const source = `
    <script>
      function generateGiftCode() {
        const table={v:"3",u:"1",l:"2",n:"a",c:"9",a:"7",r:"5",t:"a"};
        const seed="vulncart"; let out="";
        for (let c of seed) out += table[c];
        out += "994e"; return "GIFT-" + out;
      }
      const giftCard = generateGiftCode();
      const statusApi = "https://orders-fixture.lambda-url.us-east-1.on.aws/status";
    </script>`;
  const state = {
    probeResults: [{ r: { ok: true, url: 'https://lab.invalid/', status: 200, htmlSample: source } }],
    _jsAuditBodies: [{ url: 'https://lab.invalid/app.js', body: source }],
    originByHost: new Map([['lab.invalid', { origin: 'https://lab.invalid' }]]),
    fetchImpl: async (url) => {
      const pathname = new URL(url).pathname;
      if (pathname === '/debug') {
        return new Response(JSON.stringify({
          aws_account_id: '123456789012',
          function_arn: 'arn:aws:lambda:us-east-1:123456789012:function:orders',
          environment_variables: { AWS_SESSION_TOKEN: 'fixture-secret-never-public' },
        }), { status: 200, headers: { 'content-type': 'application/json' } });
      }
      return new Response(JSON.stringify({ error: 'not found' }), { status: 404, headers: { 'content-type': 'application/json' } });
    },
    urlInScope: (url) => new URL(url).origin === 'https://lab.invalid',
    signal: null,
  };

  const cloud = await moduleRunners.cloud_debug_env_audit(state);
  const runtime = await moduleRunners.runtime_endpoint_pivot(state);
  const voucher = await moduleRunners.deterministic_voucher_audit(state);
  assert.equal(cloud.findings.length, 1);
  assert.equal(runtime.findings.length, 1);
  assert.equal(voucher.findings.some((row) => row.score >= 70), true);
  assert.doesNotMatch(JSON.stringify({ cloud, runtime, voucher }), /fixture-secret-never-public|GIFT-312a975a994e/);
  assert.equal(state.runtimeEndpointCandidates[0].automaticallyFollowed, false);
});

test('adapters ativos e auditor de artefato falham fechados sem configuração explícita', async () => {
  const state = {};
  const jwt = await moduleRunners.jwt_claim_authz_diff(state);
  const authz = await moduleRunners.authz_object_matrix_v2(state);
  const artifact = await moduleRunners.artifact_safety_audit(state);
  assert.equal(jwt.status, 'skipped');
  assert.equal(authz.status, 'skipped');
  assert.equal(artifact.status, 'skipped');
});
