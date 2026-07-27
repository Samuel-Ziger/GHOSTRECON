import { describe, it } from 'node:test';
import assert from 'node:assert';
import {
  normalizeOutOfScopeToken,
  parseOutOfScopeClientInput,
  mergeOutOfScopeLists,
  createEngagementScopePolicy,
  hostInReconScope,
  urlInReconScope,
} from '../modules/scope.js';
import { createPipelineState } from '../pipeline/pipeline-state.mjs';
import { filterDiscoveredHostsInScope } from '../pipeline/phases/discovery.mjs';
import { discoverAssetHints } from '../modules/asset-discovery.js';

describe('scope / fora de escopo', () => {
  it('normaliza URL para hostname', () => {
    assert.strictEqual(normalizeOutOfScopeToken('https://cdn.a.com/x'), 'cdn.a.com');
    assert.strictEqual(normalizeOutOfScopeToken('http://b.com:8080/'), 'b.com');
  });

  it('preserva e aplica CIDR IPv4 recebido em outOfScope', () => {
    assert.equal(normalizeOutOfScopeToken('192.0.2.128/25'), '192.0.2.128/25');
    assert.deepEqual(
      parseOutOfScopeClientInput('192.0.2.128/25'),
      ['192.0.2.128/25'],
    );
    assert.equal(
      hostInReconScope('192.0.2.200', '192.0.2.200', ['192.0.2.128/25']),
      false,
    );
  });

  it('mantém wildcard *.', () => {
    assert.strictEqual(normalizeOutOfScopeToken('*.x.y.com'), '*.x.y.com');
  });

  it('parse textarea multilinha e vírgulas', () => {
    const r = parseOutOfScopeClientInput('a.com\nhttps://b.com/c, *.staging.z.com');
    assert.deepStrictEqual(r, ['a.com', 'b.com', '*.staging.z.com']);
  });

  it('merge deduplica', () => {
    assert.deepStrictEqual(mergeOutOfScopeLists(['a.com'], ['a.com', 'b.com']), ['a.com', 'b.com']);
  });

  it('hostInReconScope exclui lista UI', () => {
    assert.strictEqual(hostInReconScope('ok.target.com', 'target.com', ['bad.target.com']), true);
    assert.strictEqual(hostInReconScope('bad.target.com', 'target.com', ['bad.target.com']), false);
  });

  it('engagement exato autoriza somente o hostname exato, não subdomínios descobertos', () => {
    const policy = createEngagementScopePolicy({
      rootDomain: 'lab.acme.test',
      engagement: {
        id: 'ENG-EXACT',
        scopeDomains: ['lab.acme.test'],
        scopeIps: [],
        exclusions: [],
      },
      engagementId: 'ENG-EXACT',
      authorizationBinding: 'binding-exact',
    });
    assert.equal(
      hostInReconScope('lab.acme.test', 'lab.acme.test', [], policy),
      true,
    );
    assert.equal(
      hostInReconScope('api.lab.acme.test', 'lab.acme.test', [], policy),
      false,
    );
    assert.equal(
      urlInReconScope('https://api.lab.acme.test/v1', 'lab.acme.test', [], policy),
      false,
    );
  });

  it('wildcard formal autoriza descendentes do alvo, mas exclusão ganha precedência', () => {
    const policy = createEngagementScopePolicy({
      rootDomain: 'lab.acme.test',
      engagement: {
        id: 'ENG-WILDCARD',
        scopeDomains: ['*.acme.test'],
        scopeIps: [],
        exclusions: ['blocked.lab.acme.test'],
      },
      engagementId: 'ENG-WILDCARD',
      authorizationBinding: 'binding-wildcard',
    });
    assert.equal(
      hostInReconScope('api.lab.acme.test', 'lab.acme.test', [], policy),
      true,
    );
    assert.equal(
      hostInReconScope('blocked.lab.acme.test', 'lab.acme.test', [], policy),
      false,
    );
    assert.equal(
      hostInReconScope('child.blocked.lab.acme.test', 'lab.acme.test', [], policy),
      false,
    );
  });

  it('allowlist IPv4 aceita CIDR e aplica exclusão CIDR antes da permissão', () => {
    const policy = createEngagementScopePolicy({
      rootDomain: '192.0.2.10',
      engagement: {
        id: 'ENG-IP',
        scopeDomains: [],
        scopeIps: ['192.0.2.0/24'],
        exclusions: ['192.0.2.128/25'],
      },
      engagementId: 'ENG-IP',
      authorizationBinding: 'binding-ip',
    });
    assert.equal(hostInReconScope('192.0.2.10', '192.0.2.10', [], policy), true);
    assert.equal(hostInReconScope('192.0.2.200', '192.0.2.10', [], policy), false);
    assert.deepEqual(policy.exclusions, ['192.0.2.128/25']);
  });

  it('IP derivado de domínio exige allowlist IP formal explícita', () => {
    const deniedPolicy = createEngagementScopePolicy({
      rootDomain: 'lab.acme.test',
      engagement: {
        id: 'ENG-DOMAIN-ONLY',
        scopeDomains: ['lab.acme.test'],
        scopeIps: [],
        exclusions: [],
      },
      engagementId: 'ENG-DOMAIN-ONLY',
      authorizationBinding: 'binding-domain-only',
    });
    assert.equal(
      hostInReconScope('192.0.2.10', 'lab.acme.test', [], deniedPolicy),
      false,
    );

    const allowedPolicy = createEngagementScopePolicy({
      rootDomain: 'lab.acme.test',
      engagement: {
        id: 'ENG-DOMAIN-IP',
        scopeDomains: ['lab.acme.test'],
        scopeIps: ['192.0.2.0/27'],
        exclusions: ['192.0.2.16/28'],
      },
      engagementId: 'ENG-DOMAIN-IP',
      authorizationBinding: 'binding-domain-ip',
    });
    assert.equal(
      hostInReconScope('192.0.2.10', 'lab.acme.test', [], allowedPolicy),
      true,
    );
    assert.equal(
      hostInReconScope('192.0.2.20', 'lab.acme.test', [], allowedPolicy),
      false,
    );
    assert.equal(
      hostInReconScope('192.0.2.40', 'lab.acme.test', [], allowedPolicy),
      false,
    );
  });

  it('pipeline preserva a policy formal para cada gate de host e URL', () => {
    const policy = createEngagementScopePolicy({
      rootDomain: 'lab.acme.test',
      engagement: {
        id: 'ENG-PIPE',
        scopeDomains: ['*.acme.test'],
        scopeIps: [],
        exclusions: ['blocked.lab.acme.test'],
      },
      engagementId: 'ENG-PIPE',
      authorizationBinding: 'binding-pipeline',
    });
    const state = createPipelineState({
      domain: 'lab.acme.test',
      exactMatch: false,
      modules: [],
      emit: () => {},
      engagementId: 'ENG-PIPE',
      scopePolicy: policy,
    });
    assert.equal(state.hostInScope('api.lab.acme.test'), true);
    assert.equal(state.urlInScope('https://api.lab.acme.test/v1'), true);
    assert.equal(state.hostInScope('blocked.lab.acme.test'), false);
    assert.equal(state.urlInScope('https://evil.example/v1'), false);
    assert.ok(Object.isFrozen(state.scopePolicy));
    assert.deepEqual(
      filterDiscoveredHostsInScope([
        'api.lab.acme.test',
        'blocked.lab.acme.test',
        'other.example',
      ], state),
      ['api.lab.acme.test'],
    );
  });

  it('asset discovery não consulta RDAP para IP derivado fora da allowlist', async () => {
    const queriedIps = [];
    const findings = await discoverAssetHints(
      'lab.acme.test',
      [],
      [],
      {
        ipAllowed: (ip) => ip === '192.0.2.10',
        resolveNsImpl: async () => [],
        collectUniqueIpv4Impl: async () => ['192.0.2.10', '198.51.100.20'],
        fetchIpRdapImpl: async (ip) => {
          queriedIps.push(ip);
          return { ip, asn: 'fixture' };
        },
      },
    );
    assert.deepEqual(queriedIps, ['192.0.2.10']);
    assert.equal(findings.some((finding) => /198\.51\.100\.20/.test(finding.value)), false);
  });
});
