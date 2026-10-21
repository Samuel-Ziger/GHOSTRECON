import test from 'node:test';
import assert from 'node:assert/strict';

import {
  parseWafw00fOutput,
  wafw00fFingerprint,
} from '../modules/waf-fingerprint.js';
import {
  auditDomClobberingHtml,
  auditDomClobberingJs,
  correlateDomClobberingChains,
  runDomClobberingAudit,
} from '../modules/dom-clobbering-audit.mjs';
import {
  looksLikePanelSoft404,
  runPanelExposureAudit,
} from '../modules/panel-exposure-audit.mjs';
import {
  extractFirebaseConfig,
  extractFirestoreCollectionCandidates,
  runFirebaseAudit,
} from '../modules/firebase-audit.mjs';
import {
  filterDirsearchDiscoveryResults,
  infoDisclosureFindingFromRow,
  parseFfufDiscoveryJson,
  validateInfoDisclosureJson,
} from '../modules/kali-scan.js';
import { buildMysql3306IntelFindings } from '../modules/mysql-nmap-intel.js';
import {
  cancelShannonWorkflow,
  extractShannonFindings,
  extractTemporalWorkflowId,
} from '../modules/shannon-runner.js';
import { runWebshellHeuristicProbe } from '../modules/webshell-probe.js';
import { buildVigoliumAgentArgs } from '../../bridge/agent-bridge.mjs';

test('wafw00f usa parser determinístico e executor injetado', async () => {
  assert.deepEqual(
    parseWafw00fOutput('[+] https://example.test is behind Cloudflare (Cloudflare Inc.).'),
    { waf: 'Cloudflare (Cloudflare Inc.)', detected: ['Cloudflare (Cloudflare Inc.)'], state: 'detected' },
  );
  const calls = [];
  const result = await wafw00fFingerprint('example.test', {
    capability: { available: true, version: 'wafw00f 2.3.1' },
    signal: new AbortController().signal,
    executor: async (cmd, args, opts) => {
      calls.push({ cmd, args, opts });
      return { code: 0, stdout: 'example.test is behind Example WAF.', stderr: '' };
    },
  });
  assert.equal(result.state, 'detected');
  assert.equal(result.waf, 'Example WAF');
  assert.equal(calls.length, 1);
  assert.ok(calls[0].opts.signal);
  assert.equal((await wafw00fFingerprint('-invalid', { capability: { available: true } })).state, 'failed');
  assert.equal((await wafw00fFingerprint('example.test', {
    capability: { available: false, error: 'missing' },
  })).state, 'unavailable');
});

test('wafw00f distingue negativo reconhecido, formato desconhecido e execução incompleta', async () => {
  assert.equal(parseWafw00fOutput('No WAF detected by the generic detection').state, 'not_detected');
  assert.equal(parseWafw00fOutput('').state, 'inconclusive');
  assert.equal(parseWafw00fOutput('unexpected parser version').state, 'inconclusive');
  for (const [proc, expected] of [
    [{ code: 2, stdout: 'example.test is behind Example WAF.' }, 'failed'],
    [{ code: 0, timedOut: true, stdout: 'No WAF detected' }, 'timeout'],
  ]) {
    const result = await wafw00fFingerprint('example.test', {
      capability: { available: true }, executor: async () => proc,
    });
    assert.equal(result.state, expected);
  }
  const controller = new AbortController();
  controller.abort(new Error('cancel waf fixture'));
  await assert.rejects(wafw00fFingerprint('example.test', {
    signal: controller.signal,
    executor: async () => assert.fail('não deve executar'),
  }), /cancel waf fixture/);
});

test('DOM clobbering exige vínculo documental e permanece candidato estático', () => {
  const inventory = auditDomClobberingHtml('<form id="location"></form>');
  assert.equal(inventory[0].prio, 'info');
  const findings = correlateDomClobberingChains(
    '<a id="redirectTarget"></a><script src="/app.js"></script>',
    'const cfg = window.redirectTarget; link.href = cfg.url;',
    { htmlUrl: 'https://example.test/', jsUrl: 'https://example.test/app.js' },
  );
  assert.equal(findings.length, 1);
  assert.equal(findings[0].prio, 'low');
  assert.match(findings[0].meta, /evidence_status=candidate/);
  assert.equal(correlateDomClobberingChains('<a id="safe"></a>', 'console.log(window.safe)').length, 0);
  assert.equal(correlateDomClobberingChains(
    '<a id="safe"></a>',
    'const cfg = window.safe; fetch("/health");',
  ).length, 0);
  assert.ok(auditDomClobberingJs('const x = window[key];').every((finding) => finding.prio === 'info'));
  const unrelated = runDomClobberingAudit({
    htmlBodies: [{ url: 'https://a.example.test/', body: '<a id="cfg"></a>' }],
    jsBodies: [{ url: 'https://b.example.test/app.js', body: 'link.href = window.cfg.url;' }],
  });
  assert.equal(unrelated.findings.some((finding) => /evidence_status=candidate/.test(finding.meta)), false);
});

test('panel exposure elimina catch-all/soft-404 e exige assinatura no conteúdo', async () => {
  assert.equal(looksLikePanelSoft404(
    { status: 200, title: 'SPA', body: '<html><title>SPA</title><main>app</main></html>' },
    { status: 200, title: 'SPA', body: '<html><title>SPA</title><main>app</main></html>' },
  ), true);

  const previous = process.env.GHOSTRECON_PANEL_MAX_PATHS;
  process.env.GHOSTRECON_PANEL_MAX_PATHS = '1';
  try {
    const catchAll = await runPanelExposureAudit({
      origins: ['https://example.test'],
      baselinePathFactory: () => '/ghostrecon-panel-baseline-fixture',
      fetchImpl: async () => new Response('<html><title>SPA</title><main>app</main></html>', {
        status: 200,
        headers: { 'content-type': 'text/html' },
      }),
    });
    assert.deepEqual(catchAll, []);

    const real = await runPanelExposureAudit({
      origins: ['https://example.test'],
      baselinePathFactory: () => '/ghostrecon-panel-baseline-fixture',
      fetchImpl: async (url) => new Response(
        String(url).includes('baseline')
          ? '<html><title>Not found</title></html>'
          : '<html><title>Grafana</title><div class="grafana-app"></div></html>',
        { status: 200, headers: { 'content-type': 'text/html' } },
      ),
    });
    assert.equal(real.length, 1);
    assert.match(real[0].meta, /grafana/);
    assert.equal(real[0].prio, 'info');
    assert.match(real[0].meta, /evidence_status=inventory/);
    assert.equal(real[0].owasp, undefined);

    const baselineFailure = await runPanelExposureAudit({
      origins: ['https://example.test'],
      fetchImpl: async () => { throw new Error('offline'); },
    });
    assert.deepEqual(baselineFailure, []);
  } finally {
    if (previous == null) delete process.env.GHOSTRECON_PANEL_MAX_PATHS;
    else process.env.GHOSTRECON_PANEL_MAX_PATHS = previous;
  }
});

test('Firebase deriva collections do cliente e nunca habilita write pelo audit read-only', async () => {
  const bundle = `
    const firebaseConfig = { apiKey: "AIza${'A'.repeat(35)}", projectId: "demo-project" };
    const orders = collection(db, "orders");
  `;
  assert.deepEqual(extractFirestoreCollectionCandidates(bundle), ['orders']);
  assert.deepEqual(extractFirebaseConfig(bundle).firestoreCollections, ['orders']);
  const calls = [];
  const result = await runFirebaseAudit(
    { ...extractFirebaseConfig(bundle), bundleText: bundle },
    {
      writeProbes: true,
      requestImpl: async (url, options = {}) => {
        calls.push({ url, method: options.method || 'GET' });
        if (url.includes('/documents/orders?')) {
          return { status: 200, body: '{"documents":[{"name":"orders/1"}]}', headers: {}, error: null };
        }
        return { status: 403, body: '{}', headers: {}, error: null };
      },
    },
  );
  assert.ok(result.findings.some((finding) => finding.type === 'firebase_firestore_public_read'));
  assert.equal(calls.some((call) => /\/documents\/users\?/.test(call.url)), false);
  assert.equal(calls.some((call) => ['POST', 'PUT', 'PATCH', 'DELETE'].includes(call.method)), false);
  assert.equal(result.summary.results.writeProbes, 'refused_read_only_module');
  assert.ok(result.findings.every((finding) => ['info', 'low', 'med', 'high', 'critical'].includes(finding.prio)));
});

test('InfoHunter exige schema limitado e marca erro diferencial como provável', () => {
  const json = { achados: [{ modulo: 'errors', severidade: 'HIGH', titulo: 'Stack trace', url: 'https://example.test/?x=%27', evidencia: 'induced_new_signature=true' }] };
  assert.equal(validateInfoDisclosureJson(json), true);
  assert.equal(validateInfoDisclosureJson({ achados: [{ modulo: 1 }] }), false);
  const finding = infoDisclosureFindingFromRow(json.achados[0]);
  assert.match(finding.meta, /evidence_status=probable/);
});

test('ffuf/dirsearch preservam evidência HTTP, filtram status e impedem origem externa', () => {
  const ffuf = parseFfufDiscoveryJson(JSON.stringify({ results: [
    { url: 'https://example.test/admin', status: 403, length: 123, words: 7, lines: 3 },
    { url: 'https://evil.test/out', status: 200, length: 10 },
    { url: 'https://example.test/error', status: 500, length: 10 },
  ] }), { baseUrl: 'https://example.test/' });
  assert.deepEqual(ffuf.map((row) => row.status), [403]);
  assert.equal(ffuf[0].words, 7);

  const dirsearch = filterDirsearchDiscoveryResults([
    { url: 'https://example.test/login', status: 401, length: 10 },
    { url: 'https://evil.test/login', status: 200, length: 10 },
    { url: 'https://example.test/fail', status: 500, length: 10 },
  ], { baseUrl: 'https://example.test/' });
  assert.deepEqual(dirsearch.map((row) => row.status), [401]);
});

test('mysql 3306 é inventário estruturado e nunca prova vulnerabilidade', () => {
  const [finding] = buildMysql3306IntelFindings([{
    host: 'db.example.test', port: '3306', proto: 'tcp', name: 'mysql', product: 'MariaDB', version: '10.11',
  }]);
  assert.equal(finding.type, 'service_inventory');
  assert.equal(finding.prio, 'info');
  assert.equal(finding.meta.evidenceStatus, 'inventory_confirmed_by_nmap_service');
  assert.doesNotMatch(JSON.stringify(finding), /sqlmap|empty-password|-u root/);
});

test('Shannon extrai candidatos e distingue pedido de cancelamento de término', async () => {
  const findings = extractShannonFindings(`
## [HIGH] SQL injection em consulta
Severity: HIGH
File: src/db.js
Entrada concatenada na consulta.
  `, { repoFullName: 'acme/app', workspaceId: 'ws-1', reportPath: '/tmp/report.md' });
  assert.equal(findings.length, 1);
  assert.equal(findings[0].type, 'shannon_whitebox');
  assert.equal(findings[0].meta.evidenceStatus, 'candidate_ai_report');
  assert.equal(extractTemporalWorkflowId('http://localhost:8233/namespaces/default/workflows/wf-123'), 'wf-123');
  const cancelled = await cancelShannonWorkflow({
    workflowId: 'wf-123',
    processRunner: async (cmd, args) => ({ code: cmd === 'temporal' && args.includes('wf-123') ? 0 : 1 }),
  });
  assert.equal(cancelled.requested, true);
  assert.equal(cancelled.confirmed, false);
});

test('webshell usa fetch injetado, escopo e signal pai', async () => {
  const controller = new AbortController();
  const calls = [];
  const findings = await runWebshellHeuristicProbe({
    origins: ['https://example.test/'],
    maxOrigins: 1,
    signal: controller.signal,
    urlAllowed: (url) => new URL(url).hostname === 'example.test',
    fetchImpl: async (url, init) => {
      calls.push({ url, signal: init.signal });
      return new Response('uid=33(www-data) gid=33(www-data) groups=33(www-data)\n', {
        status: 200,
        headers: { 'content-type': 'text/plain' },
      });
    },
  });
  assert.equal(findings.length, 3);
  assert.ok(calls.every((call) => call.signal));
  assert.ok(findings.every((finding) => /evidence_status=candidate/.test(finding.meta)));
  assert.ok(calls.every((call) => new URL(call.url).search === ''));

  const aborted = new AbortController();
  aborted.abort(new Error('cancel fixture'));
  await assert.rejects(
    runWebshellHeuristicProbe({ origins: ['https://example.test/'], signal: aborted.signal }),
    /cancel fixture/,
  );
});

test('Vigolium swarm falha fechado e autopilot permanece plan-only', () => {
  const swarm = buildVigoliumAgentArgs({
    domain: 'example.test',
    vigoliumModules: ['headers', 'xss_reflection'],
    vigoliumAgentTimeoutMs: 120_000,
  }, 'swarm');
  assert.equal(swarm.skipped, true);
  assert.deepEqual(swarm.args, []);
  assert.equal(buildVigoliumAgentArgs({
    domain: 'example.test',
    vigoliumAuthFiles: ['one.json', 'two.json'],
  }, 'swarm', { privateDbPath: '/tmp/private.sqlite' }).skipped, true);

  const autopilot = buildVigoliumAgentArgs({
    domain: 'example.test',
    vigoliumAgentTimeoutMs: 120_000,
  }, 'autopilot');
  assert.ok(autopilot.args.includes('--dry-run'));
  assert.ok(autopilot.args.includes('--no-prescan'));
  assert.ok(autopilot.args.includes('--no-post-halt-verify'));
});
