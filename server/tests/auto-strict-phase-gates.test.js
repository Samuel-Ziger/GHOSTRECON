import assert from 'node:assert/strict';
import test from 'node:test';

import {
  autoCapabilityClass,
  autoCapabilityPhase,
} from '../auto-agent/pipeline-capabilities.mjs';
import {
  createPipelineState,
  pipelineCapabilityAllowed,
} from '../pipeline/pipeline-state.mjs';
import { MANUAL_IMPLICIT_CAPABILITIES } from '../modules/opsec.mjs';
import { runAssetDiscoveryPhase } from '../pipeline/phases/asset-discovery.mjs';
import {
  runProbePhase,
  shouldRunWafFingerprint,
} from '../pipeline/phases/probe.mjs';
import { runValidationPhase } from '../pipeline/phases/validation.mjs';

function autoState(modules = []) {
  const events = [];
  const state = createPipelineState({
    domain: 'example.invalid',
    exactMatch: false,
    modules,
    emit(event) {
      events.push(event);
    },
    profile: 'quick',
    autoModeExecution: true,
  });
  return { events, state };
}

test('catálogo classifica ações implícitas como capacidades ativas ou intrusivas', () => {
  const expected = new Map([
    ['http_probe', ['active', 'probe']],
    ['evidence_verification', ['intrusive', 'validation']],
    ['active_param_discovery', ['intrusive', 'validation']],
    ['asset_discovery', ['active', 'asset_discovery']],
    ['high_recheck', ['active', 'finalize']],
    ['browser_xss_verify', ['intrusive', 'finalize']],
  ]);

  for (const [id, [riskClass, phase]] of expected) {
    assert.equal(autoCapabilityClass(id), riskClass, id);
    assert.equal(autoCapabilityPhase(id), phase, id);
  }

  for (const id of [
    'security_headers',
    'robots_sitemap',
    'wellknown_security_txt',
    'wellknown_openid',
    'header_intel',
    'js_intel',
    'client_surface_audit',
    'graphql_recon',
  ]) {
    assert.equal(autoCapabilityClass(id), 'active', id);
  }

  for (const id of ['subdomains', 'rdap', 'dns_enrichment', 'wayback', 'common_crawl']) {
    assert.equal(autoCapabilityClass(id), 'passive', id);
  }
});

test('gate manual exige plano efetivo para implícitas intrusivas e normaliza IDs no Auto', () => {
  for (const id of ['http_probe', 'asset_discovery', 'high_recheck']) {
    assert.equal(
      pipelineCapabilityAllowed({ autoModeExecution: false, modules: [] }, id),
      true,
      id,
    );
  }
  for (const id of ['evidence_verification', 'active_param_discovery', 'browser_xss_verify']) {
    assert.equal(
      pipelineCapabilityAllowed({ autoModeExecution: false, modules: [] }, id),
      false,
      id,
    );
  }
  const manualCapabilityIds = new Set(MANUAL_IMPLICIT_CAPABILITIES);
  assert.equal(
    pipelineCapabilityAllowed(
      { autoModeExecution: false, manualCapabilityIds },
      'evidence_verification',
    ),
    true,
  );
  assert.equal(
    pipelineCapabilityAllowed({ autoModeExecution: false, modules: [] }, 'future_implicit_probe'),
    false,
  );

  const { state } = autoState(['http-probe', 'high_recheck']);
  assert.equal(pipelineCapabilityAllowed(state, 'http_probe'), true);
  assert.equal(state.allowsPipelineCapability('high-recheck'), true);
  assert.equal(pipelineCapabilityAllowed(state, 'evidence_verification'), false);
});

test('WAF implícito continua no RUN manual, mas exige seleção explícita no Auto', () => {
  assert.equal(shouldRunWafFingerprint({
    autoModeExecution: false,
    modules: [],
    runtimeProfile: { name: 'standard' },
  }), true);

  const autoWithoutWaf = autoState(['http_probe']).state;
  assert.equal(shouldRunWafFingerprint(autoWithoutWaf), false);

  const autoWithWaf = autoState(['http_probe', 'wafw00f']).state;
  assert.equal(shouldRunWafFingerprint(autoWithWaf), true);
});

test('probe Auto sem http_probe não faz request implícito nem ativa WAF por perfil', async (t) => {
  const originalFetch = globalThis.fetch;
  let fetchCalls = 0;
  globalThis.fetch = async () => {
    fetchCalls += 1;
    throw new Error('network must remain disabled in this fixture');
  };
  t.after(() => {
    globalThis.fetch = originalFetch;
  });

  const { events, state } = autoState([]);
  await runProbePhase(state);

  assert.equal(fetchCalls, 0);
  assert.deepEqual(state.probeResults, []);
  assert.equal(state.originByHost instanceof Map, true);
  assert.ok(events.some((event) => event.type === 'pipe' && event.name === 'alive' && event.state === 'skip'));
  assert.ok(events.some((event) => event.type === 'pipe' && event.name === 'wafw00f' && event.state === 'skip'));
});

test('validation Auto não executa verify nem arjun/x8 sem capacidades explícitas', async (t) => {
  const originalFetch = globalThis.fetch;
  let fetchCalls = 0;
  globalThis.fetch = async () => {
    fetchCalls += 1;
    throw new Error('network must remain disabled in this fixture');
  };
  t.after(() => {
    globalThis.fetch = originalFetch;
  });

  const { events, state } = autoState([]);
  state.findings.push({
    type: 'endpoint',
    prio: 'high',
    value: 'https://example.invalid/account',
    url: 'https://example.invalid/account',
  });
  await runValidationPhase(state);

  assert.equal(fetchCalls, 0);
  assert.ok(events.some((event) => event.type === 'pipe' && event.name === 'verify' && event.state === 'skip'));
  assert.ok(events.some(
    (event) =>
      event.type === 'pipe'
      && event.name === 'active_param_discovery'
      && event.state === 'skip',
  ));
});

test('asset discovery/takeover implícito é omitido no Auto sem capacidade', async (t) => {
  const originalFetch = globalThis.fetch;
  let fetchCalls = 0;
  globalThis.fetch = async () => {
    fetchCalls += 1;
    throw new Error('network must remain disabled in this fixture');
  };
  t.after(() => {
    globalThis.fetch = originalFetch;
  });

  const { events, state } = autoState([]);
  state.subdomainsAlive.push('dangling.example.invalid');
  state.findings.push({
    type: 'subdomain',
    prio: 'low',
    value: 'dangling.example.invalid',
  });
  await runAssetDiscoveryPhase(state);

  assert.equal(fetchCalls, 0);
  assert.ok(events.some((event) => event.type === 'pipe' && event.name === 'assets' && event.state === 'skip'));
});
