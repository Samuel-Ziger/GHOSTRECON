import test from 'node:test';
import assert from 'node:assert/strict';
import { runPanelExposureAudit } from '../modules/panel-exposure-audit.mjs';

test('runPanelExposureAudit detecta painel comum com GET unico', async () => {
  const calls = [];
  const fetchImpl = async (url) => {
    calls.push(url);
    if (String(url).endsWith('/grafana')) {
      return new Response('<html><title>Grafana</title><script src="/grafana/public/build/app.js"></script>', {
        status: 200,
        headers: { 'content-type': 'text/html' },
      });
    }
    return new Response('not found', { status: 404 });
  };
  const findings = await runPanelExposureAudit({
    origins: ['https://example.test/'],
    modules: [],
    fetchImpl,
  });
  assert.ok(calls.length > 0);
  assert.equal(findings.length, 1);
  assert.equal(findings[0].type, 'panel');
  assert.match(findings[0].meta, /grafana/);
});
