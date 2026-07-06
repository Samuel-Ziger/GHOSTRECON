import test from 'node:test';
import assert from 'node:assert/strict';

import {
  extractHexstrikeProfile,
  normalizeHexstrikeAnalysis,
  normalizeHexstrikeToolPlan,
  runHexstrikeOrchestrator,
} from '../modules/hexstrike-orchestrator.mjs';
import { getRegistryEntry, listModuleManifests } from '../modules/module-registry.mjs';
import { normalizeModuleId } from '../modules/module-ids.mjs';

function responseJson(body, { ok = true, status = 200 } = {}) {
  return {
    ok,
    status,
    headers: { get: () => 'application/json' },
    async json() { return body; },
  };
}

test('normaliza target_profile do HexStrike em finding de inteligencia', () => {
  const data = {
    success: true,
    target_profile: {
      target: 'https://app.example.test',
      target_type: 'web_application',
      technologies: ['react', 'nginx'],
      open_ports: [80, 443],
      subdomains: ['api.example.test'],
      endpoints: ['/api/v1/users'],
      attack_surface_score: 7.5,
      risk_level: 'high',
      confidence_score: 0.8,
    },
  };

  assert.equal(extractHexstrikeProfile(data), data.target_profile);
  const findings = normalizeHexstrikeAnalysis(data, { target: 'https://app.example.test' });
  assert.equal(findings.length, 1);
  assert.equal(findings[0].type, 'hexstrike_intel');
  assert.equal(findings[0].prio, 'high');
  assert.match(findings[0].meta, /technologies=react,nginx/);
  assert.match(findings[0].meta, /ports=80,443/);
  assert.equal(findings[0].verification.evidence.targetType, 'web_application');
});

test('normaliza plano de ferramentas sem executar comandos', () => {
  const findings = normalizeHexstrikeToolPlan({
    target: 'example.test',
    objective: 'comprehensive',
    selected_tools: ['nuclei', 'httpx', 'katana'],
  });

  assert.equal(findings.length, 1);
  assert.equal(findings[0].type, 'hexstrike_tool_plan');
  assert.match(findings[0].meta, /tools=nuclei,httpx,katana/);
  assert.deepEqual(findings[0].verification.evidence.selectedTools, ['nuclei', 'httpx', 'katana']);
});

test('runner chama apenas endpoints de inteligencia e retorna findings', async () => {
  const calls = [];
  const fetchImpl = async (url, init) => {
    calls.push({ url, init });
    if (String(url).endsWith('/api/intelligence/analyze-target')) {
      return responseJson({
        success: true,
        target_profile: {
          target: 'example.test',
          target_type: 'api_endpoint',
          technologies: ['unknown'],
          risk_level: 'medium',
          confidence_score: 0.6,
        },
      });
    }
    if (String(url).endsWith('/api/intelligence/select-tools')) {
      return responseJson({
        success: true,
        target: 'example.test',
        objective: 'quick',
        selected_tools: ['httpx'],
      });
    }
    throw new Error(`unexpected url ${url}`);
  };

  const result = await runHexstrikeOrchestrator({
    target: 'example.test',
    objective: 'quick',
    fetchImpl,
  });

  assert.equal(calls.length, 2);
  assert.ok(calls.every((c) => c.init.method === 'POST'));
  assert.ok(calls.every((c) => String(c.url).includes('/api/intelligence/')));
  assert.equal(result.findings.length, 2);
  assert.equal(result.logLevel, 'success');
});

test('runner trata HexStrike offline como aviso sem quebrar pipeline', async () => {
  const result = await runHexstrikeOrchestrator({
    target: 'example.test',
    fetchImpl: async () => {
      throw new Error('ECONNREFUSED');
    },
  });

  assert.deepEqual(result.findings, []);
  assert.equal(result.logLevel, 'warn');
  assert.match(result.logOk, /indisponivel/);
});

test('hexstrike_orchestrator aparece no registry com alias legado', () => {
  assert.equal(normalizeModuleId('hexstrike-orchestrator'), 'hexstrike_orchestrator');
  assert.ok(listModuleManifests().some((m) => m.id === 'hexstrike_orchestrator'));
  const entry = getRegistryEntry('hexstrike-orchestrator');
  assert.equal(entry.manifest.id, 'hexstrike_orchestrator');
  assert.equal(typeof entry.run, 'function');
});
