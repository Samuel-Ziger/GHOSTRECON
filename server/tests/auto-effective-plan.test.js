import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';
import { createHash } from 'node:crypto';

import {
  buildEffectiveAutoPlan,
  effectivePlanApprovalDetails,
  phaseTimeoutsFromModuleLimits,
} from '../auto-agent/effective-plan.mjs';
import {
  AUTO_PROHIBITED_CAPABILITY_IDS,
  autoCapabilityClass,
  autoCapabilityPhase,
} from '../auto-agent/pipeline-capabilities.mjs';
import {
  AUTO_DEEP_PASSIVE_MODULES,
  buildAutoToolCatalog,
  classifyAutoModule,
} from '../auto-agent/tool-catalog.mjs';
import { computeForgeArtifactIntegrity } from '../auto-agent/forge/artifact-integrity.mjs';
import { createForgeSandboxOperationAttestation } from '../auto-agent/forge/sandbox-policy.mjs';
import { isIntrusive } from '../modules/opsec.mjs';

const FRAMESEVEN_RECON_TOOLS_V1 = 'recon,cve';
const FRAMESEVEN_OFFENSIVE_TOOLS_V1 = [
  'recon',
  'access',
  'redirect',
  'misconfig',
  'cve',
  'crawler',
  'content',
  'subdomain',
  'ports',
  'nmap',
  'bannergrab',
].join(',');

function catalogOf(rows) {
  const needsHttpProbe = rows.some((row) => (
    (['active', 'intrusive'].includes(row.class)
      || row.manifest?.intrusive === true
      || isIntrusive(row.id))
      && !String(row.id || '').startsWith('frameseven_')
      && !String(row.id || '').startsWith('vigolium_')
  ));
  const effectiveRows = needsHttpProbe && !rows.some((row) => row.id === 'http_probe')
    ? [...rows, { id: 'http_probe', class: 'active' }]
    : rows;
  return {
    modules: effectiveRows.map((row) => ({
      available: true,
      manifest: {},
      source: 'test',
      ...row,
    })),
    engines: {
      frameseven: {
        available: true,
        identity: {
          algorithm: 'sha256',
          sha256: 'f'.repeat(64),
          size: 7,
        },
      },
      vigolium: {
        available: true,
        identity: {
          algorithm: 'sha256',
          sha256: 'e'.repeat(64),
          size: 8,
        },
      },
    },
  };
}

test('catálogo Auto é opt-in para HexStrike, Vigolium e FrameSeven', async () => {
  const catalog = await buildAutoToolCatalog();
  const ids = new Set(catalog.modules.map((item) => item.id));

  assert.equal(ids.has('hexstrike_orchestrator'), false);
  assert.equal([...ids].some((id) => id.startsWith('vigolium_')), false);
  assert.equal([...ids].some((id) => id.startsWith('frameseven_')), false);
  for (const id of AUTO_PROHIBITED_CAPABILITY_IDS) assert.equal(ids.has(id), false, id);
});

test('catálogo escolhe a classificação mais conservadora entre manifest e legado', () => {
  assert.equal(classifyAutoModule('security_headers', { class: 'passive' }), 'active');
  assert.equal(classifyAutoModule('secret_validation', { class: 'passive' }), 'intrusive');
  assert.equal(classifyAutoModule('identity_rotation', { class: 'passive' }), 'destructive');
  assert.equal(classifyAutoModule('ftp_write_probe', { class: 'passive' }), 'destructive');
});

test('ferramentas Kali implícitas viram capacidades explícitas e FTP write não entra no Auto', async () => {
  const catalog = await buildAutoToolCatalog({ includeIntrusive: true });
  const byId = new Map(catalog.modules.map((item) => [item.id, item]));

  assert.equal(byId.get('kali_whois')?.class, 'active');
  for (const id of [
    'kali_wpscan',
    'kali_dalfox',
    'kali_xss_vibes',
    'nmap_service_followups',
  ]) {
    assert.equal(byId.get(id)?.class, 'intrusive', id);
    assert.equal(byId.get(id)?.manifest?.requiresKali, true, id);
    assert.equal(autoCapabilityPhase(id), 'aggressive', id);
  }
  assert.equal(byId.get('kali_whois')?.manifest?.requiresKali, true);
  assert.equal(autoCapabilityPhase('kali_whois'), 'aggressive');
  assert.equal(autoCapabilityClass('ftp_write_probe'), 'destructive');
  assert.equal(catalog.modules.some((item) => item.id === 'ftp_write_probe'), false);
});

test('catálogo não deixa manifest HexStrike burlar toggle e representa indisponibilidade real', async () => {
  const disabled = await buildAutoToolCatalog({
    includeHexstrike: false,
    hexstrikeCapabilities: { installed: true, reachable: true },
  });
  assert.equal(disabled.modules.some((item) => item.id === 'hexstrike_orchestrator'), false);

  const offline = await buildAutoToolCatalog({
    includeHexstrike: true,
    hexstrikeCapabilities: { installed: true, reachable: false },
  });
  const rows = offline.modules.filter((item) => item.id === 'hexstrike_orchestrator');
  assert.equal(rows.length, 1);
  assert.equal(rows[0].source, 'hexstrike');
  assert.equal(rows[0].available, false);
  assert.match(rows[0].unavailableReason, /not reachable/i);

  const online = await buildAutoToolCatalog({
    includeHexstrike: true,
    hexstrikeCapabilities: { installed: true, reachable: true },
  });
  assert.equal(online.modules.find((item) => item.id === 'hexstrike_orchestrator')?.available, true);
});

test('catálogo FrameSeven expõe auth somente com ambos os toggles', async (t) => {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), 'ghostrecon-auto-catalog-'));
  t.after(() => fs.rm(root, { recursive: true, force: true }));
  const binary = path.join(root, 'FrameSeven', 'bin', 'frameseven', 'cli', 'v1');
  await fs.mkdir(path.dirname(binary), { recursive: true });
  await fs.writeFile(binary, 'fixture');
  await fs.chmod(binary, 0o755);

  const noAuth = await buildAutoToolCatalog({
    ghostRoot: root,
    includeFrameSeven: true,
    frameSevenAuth: false,
    includeIntrusive: true,
  });
  const firstIdentity = noAuth.engines.frameseven.identity;
  assert.match(firstIdentity?.sha256 || '', /^[a-f0-9]{64}$/);
  assert.equal(firstIdentity?.size, 7);
  assert.equal(noAuth.modules.find((item) => item.id === 'frameseven_recon')?.available, true);
  assert.equal(noAuth.modules.some((item) => item.id === 'frameseven_active'), true);
  assert.equal(noAuth.modules.some((item) => item.id === 'frameseven_authenticated'), false);

  const auth = await buildAutoToolCatalog({
    ghostRoot: root,
    includeFrameSeven: true,
    frameSevenAuth: true,
    includeIntrusive: true,
  });
  assert.equal(auth.modules.find((item) => item.id === 'frameseven_authenticated')?.available, true);

  const engineOff = await buildAutoToolCatalog({
    ghostRoot: root,
    includeFrameSeven: false,
    frameSevenAuth: true,
    includeIntrusive: true,
  });
  assert.equal(engineOff.modules.some((item) => item.id.startsWith('frameseven_')), false);

  await fs.writeFile(binary, 'fixture-v2');
  const changed = await buildAutoToolCatalog({
    ghostRoot: root,
    includeFrameSeven: true,
    frameSevenAuth: false,
    includeIntrusive: true,
  });
  assert.notEqual(changed.engines.frameseven.identity.sha256, firstIdentity.sha256);
});

test('catálogo Forge filtra por alvo e expõe identidade selada do runtime', async (t) => {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), 'ghostrecon-auto-forge-catalog-'));
  t.after(() => fs.rm(root, { recursive: true, force: true }));

  async function writeActiveForge(forgeId, target, id, source) {
    const dir = path.join(root, 'dynamic', 'by-model', 'codex', 'active', forgeId);
    const manifest = {
      id,
      name: id,
      category: 'surface',
      class: 'passive',
      intrusive: false,
      requiresAuth: false,
      requiresKali: false,
      timeoutMs: 5_000,
      concurrency: 1,
      outputs: ['finding'],
    };
    const manifestText = JSON.stringify(manifest);
    const moduleSha256 = createHash('sha256').update(source).digest('hex');
    const manifestSha256 = createHash('sha256').update(manifestText).digest('hex');
    await fs.mkdir(dir, { recursive: true });
    await Promise.all([
      fs.writeFile(path.join(dir, 'module.mjs'), source),
      fs.writeFile(path.join(dir, 'manifest.json'), manifestText),
      fs.writeFile(path.join(dir, 'module.test.js'), 'import "./module.mjs";\n'),
      fs.writeFile(path.join(dir, 'forge-request.json'), JSON.stringify({
        proposedId: id,
        gap: 'fixture local',
      })),
    ]);
    const artifactIntegrity = await computeForgeArtifactIntegrity(dir);
    await Promise.all([
      fs.writeFile(path.join(dir, 'provenance.json'), JSON.stringify({
        forgeId,
        state: 'active',
        target,
        runtimeIntegrity: {
          algorithm: 'sha256',
          artifactSha256: artifactIntegrity.artifactSha256,
          moduleSha256,
          manifestSha256,
        },
      })),
      fs.writeFile(path.join(dir, 'verdict.json'), JSON.stringify({
        validation: { ok: true, artifactIntegrity },
        tests: {
          ok: true,
          artifactIntegrity,
          isolation: createForgeSandboxOperationAttestation({
            operation: 'test',
            operationId: `${forgeId}-operation`,
            challenge: `${forgeId}-challenge`,
            runner: 'test-fixture',
          }),
        },
        aiReview: {
          approved: true,
          authorExcluded: true,
          quorumMet: true,
          minimumQuorum: 2,
          independentVotes: 2,
          artifactIntegrity,
        },
        policy: { pipelineEnabled: true },
      })),
    ]);
    return {
      artifactSha256: artifactIntegrity.artifactSha256,
      moduleSha256,
      manifestSha256,
    };
  }

  const expected = await writeActiveForge(
    'forge-target-a',
    'alpha.example',
    'forge_alpha',
    'export async function run() { return { findings: [] }; }\n',
  );
  await writeActiveForge(
    'forge-target-b',
    'beta.example',
    'forge_beta',
    'export async function run() { return { findings: [] }; }\n',
  );

  const catalog = await buildAutoToolCatalog({
    ghostRoot: root,
    target: 'https://alpha.example/path',
  });
  const dynamic = catalog.modules.filter((item) => item.source === 'ai-forge');
  assert.deepEqual(dynamic.map((item) => item.id), ['forge_alpha']);
  assert.equal(dynamic[0].forgeId, 'forge-target-a');
  assert.deepEqual(dynamic[0].runtimeIntegrity, {
    algorithm: 'sha256',
    ...expected,
  });

  const sandboxUnavailable = await buildAutoToolCatalog({
    ghostRoot: root,
    target: 'alpha.example',
    forgeRuntimeAvailable: false,
  });
  const unavailableForge = sandboxUnavailable.modules.find((item) => item.id === 'forge_alpha');
  assert.equal(unavailableForge.available, false);
  assert.match(unavailableForge.unavailableReason, /sandbox/i);
  assert.equal(sandboxUnavailable.engines.forge.available, false);
});

test('catálogo respeita toggles deep/Vigolium e omite capacidades proibidas até no nível intrusivo', async () => {
  const shallow = await buildAutoToolCatalog({
    includeDeepPassive: false,
    includeIntrusive: true,
    includeVigolium: false,
  });
  const shallowIds = new Set(shallow.modules.map((item) => item.id));
  for (const id of AUTO_DEEP_PASSIVE_MODULES) assert.equal(shallowIds.has(id), false, id);
  for (const id of AUTO_PROHIBITED_CAPABILITY_IDS) assert.equal(shallowIds.has(id), false, id);

  const missingVigolium = await buildAutoToolCatalog({
    includeVigolium: true,
    includeIntrusive: true,
    vigoliumCapabilities: { installed: false, binary: null },
  });
  assert.equal(missingVigolium.modules.find((item) => item.id === 'vigolium_audit')?.available, false);
  assert.match(
    missingVigolium.modules.find((item) => item.id === 'vigolium_audit')?.unavailableReason,
    /binary not found/i,
  );

  const withVigolium = await buildAutoToolCatalog({
    includeDeepPassive: true,
    includeIntrusive: true,
    includeVigolium: true,
    vigoliumCapabilities: { installed: true, binary: '/fixture/vigolium' },
  });
  const byId = new Map(withVigolium.modules.map((item) => [item.id, item]));
  assert.equal(byId.get('vigolium_audit')?.class, 'intrusive');
  assert.equal(byId.get('vigolium_dast')?.class, 'intrusive');
  assert.equal(byId.get('vigolium_swarm')?.class, 'intrusive');
  assert.equal(byId.get('api_contract_diff')?.class, 'active');
  assert.equal(byId.get('websocket_recon')?.class, 'deep_passive');
  assert.equal(byId.get('cors_audit')?.class, 'active');
  assert.equal(autoCapabilityClass('cred_spray'), 'destructive');
  assert.equal(autoCapabilityClass('api_contract_diff'), 'active');
  assert.equal(autoCapabilityClass('websocket_recon'), 'deep_passive');
  assert.equal(isIntrusive('kali-nmap-aggressive'), true);
  assert.equal(isIntrusive('frameseven_authenticated'), true);
});

test('catálogo vincula Vigolium ao conteúdo do executável selecionado', async (t) => {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), 'ghostrecon-auto-vigolium-catalog-'));
  t.after(() => fs.rm(root, { recursive: true, force: true }));
  const binary = path.join(root, 'vigolium-fixture');
  await fs.writeFile(binary, 'vigolium-v1');
  await fs.chmod(binary, 0o755);

  const first = await buildAutoToolCatalog({
    ghostRoot: root,
    includeVigolium: true,
    includeIntrusive: true,
    vigoliumCapabilities: { installed: true, binary },
  });
  await fs.writeFile(binary, 'vigolium-v2');
  const second = await buildAutoToolCatalog({
    ghostRoot: root,
    includeVigolium: true,
    includeIntrusive: true,
    vigoliumCapabilities: { installed: true, binary },
  });
  assert.match(first.engines.vigolium.identity?.sha256 || '', /^[a-f0-9]{64}$/);
  assert.notEqual(
    first.engines.vigolium.identity.sha256,
    second.engines.vigolium.identity.sha256,
  );
});

test('telemetria relaciona capacidades às fases reais do pipeline', () => {
  assert.equal(autoCapabilityPhase('subdomains'), 'discovery');
  assert.equal(autoCapabilityPhase('api-contract-diff'), 'probe');
  assert.equal(autoCapabilityPhase('cors_audit'), 'probe');
  assert.equal(autoCapabilityPhase('websocket_recon'), 'content_discovery');
  assert.equal(autoCapabilityPhase('sqlmap'), 'validation');
  assert.equal(autoCapabilityPhase('kali_nuclei'), 'aggressive');
  assert.equal(autoCapabilityPhase('vigolium_dast'), 'go_engine');
  assert.equal(autoCapabilityPhase('vigolium_audit'), 'go_agent');
  assert.equal(autoCapabilityPhase('risk_explainer'), 'finalize');
  assert.equal(autoCapabilityPhase('forge_test', { source: 'ai-forge' }), 'dynamic_modules');
  assert.equal(autoCapabilityPhase('unknown'), null);
});

test('observation aceita apenas plano passivo e não injeta FrameSeven por padrão', () => {
  const catalog = catalogOf([
    { id: 'subdomains', class: 'passive' },
    { id: 'cors_audit', class: 'active' },
    { id: 'sqlmap', class: 'intrusive', manifest: { intrusive: true } },
    { id: 'frameseven_recon', class: 'active' },
  ]);
  const passive = buildEffectiveAutoPlan({
    plan: { target: 'example.test', action: 'run_modules', modules: ['subdomains'] },
    catalog,
    autonomyLevel: 'observation',
    frameSevenAvailable: true,
  });

  assert.deepEqual(passive.selectedModules, ['subdomains']);
  assert.equal(passive.engines.frameseven.enabled, false);
  assert.equal(passive.requiresHumanApproval, false);
  assert.throws(() => buildEffectiveAutoPlan({
    plan: { target: 'example.test', action: 'run_modules', modules: ['cors_audit'] },
    catalog,
    autonomyLevel: 'observation',
  }), /não permite: cors_audit/);
  assert.throws(() => buildEffectiveAutoPlan({
    plan: { target: 'example.test', action: 'run_modules', modules: ['sqlmap'] },
    catalog,
    autonomyLevel: 'observation',
  }), /não permite: sqlmap/);
  assert.throws(() => buildEffectiveAutoPlan({
    plan: { target: 'example.test', action: 'run_modules', modules: ['sqlmap'] },
    catalog: catalogOf([{ id: 'sqlmap', class: 'passive' }]),
    autonomyLevel: 'observation',
  }), /não permite: sqlmap/);
  assert.throws(() => buildEffectiveAutoPlan({
    plan: { action: 'execute_modules', modules: ['subdomains'] },
    catalog,
    autonomyLevel: 'observation',
  }), /Ação AUTO inválida/);
  assert.throws(() => buildEffectiveAutoPlan({
    plan: { action: 'run_modules', modules: ['subdomains'] },
    catalog,
    autonomyLevel: 'unknown',
  }), /Autonomia AUTO desconhecida/);
});

test('assisted congela e hashia exatamente o plano ativo aprovado', () => {
  const catalog = catalogOf([{ id: 'cors_audit', class: 'active' }]);
  const input = {
    plan: {
      target: 'example.test',
      action: 'run_modules',
      mode: 'deep',
      modules: ['cors-audit', 'cors_audit'],
    },
    catalog,
    body: {
      opsecProfile: 'aggressive',
      engagementId: 'ENG-PLAN',
      engagementAuthorizationBinding: 'a'.repeat(64),
    },
    autonomyLevel: 'assisted',
  };
  const first = buildEffectiveAutoPlan(input);
  const second = buildEffectiveAutoPlan(input);

  assert.deepEqual(first.selectedModules, ['cors_audit', 'http_probe']);
  assert.deepEqual(first.pipelineModules, ['cors_audit', 'http_probe']);
  assert.equal(first.profile, 'standard');
  assert.equal(first.opsecProfile, 'standard');
  assert.equal(first.requiresHumanApproval, true);
  assert.equal(first.execution.confirmActive, true);
  assert.equal(first.execution.engagementAuthorizationBinding, 'a'.repeat(64));
  assert.deepEqual(first.moduleLimits, [
    {
      id: 'cors_audit',
      source: 'test',
      class: 'active',
      phase: 'probe',
      timeoutMs: 90_000,
      concurrency: 1,
    },
    {
      id: 'http_probe',
      source: 'test',
      class: 'active',
      phase: 'probe',
      timeoutMs: 90_000,
      concurrency: 1,
    },
  ]);
  assert.deepEqual(first.execution.phaseTimeoutsMs, { probe: 180_000 });
  assert.equal(first.hash, second.hash);
  assert.notEqual(
    first.hash,
    buildEffectiveAutoPlan({
      ...input,
      body: {
        ...input.body,
        engagementAuthorizationBinding: 'b'.repeat(64),
      },
    }).hash,
  );
  assert.equal(Object.isFrozen(first), true);
  assert.equal(Object.isFrozen(first.engines), true);
});

test('authorized/opsec exige aprovação, expande Vigolium e identifica Kali/intrusivos', () => {
  const catalog = catalogOf([
    { id: 'subdomains', class: 'passive' },
    {
      id: 'sqlmap',
      class: 'intrusive',
      requiresKali: true,
      manifest: { intrusive: true, requiresKali: true },
    },
    { id: 'vigolium_dast', class: 'intrusive', manifest: { intrusive: true } },
  ]);
  const plan = buildEffectiveAutoPlan({
    plan: {
      target: 'lab.example.test',
      action: 'run_modules',
      modules: ['subdomains', 'sqlmap', 'vigolium_dast'],
    },
    catalog,
    body: { includeVigolium: true, opsecProfile: 'aggressive' },
    autonomyLevel: 'authorized_opsec',
  });

  assert.deepEqual(plan.pipelineModules, ['subdomains', 'sqlmap', 'vigolium_dast', 'http_probe']);
  assert.deepEqual(plan.intrusiveModules, ['sqlmap', 'vigolium_dast']);
  assert.equal(plan.engines.vigolium.enabled, true);
  assert.equal(plan.engines.vigolium.identity.sha256, 'e'.repeat(64));
  assert.equal(plan.engines.vigolium.engine, 'both');
  assert.deepEqual(plan.engines.vigolium.input, {
    mode: 'authorized_target',
    file: null,
    type: null,
    allowEnvironment: false,
  });
  assert.equal(plan.execution.kaliMode, true);
  assert.equal(plan.opsecProfile, 'aggressive');
  assert.equal(plan.requiresHumanApproval, true);

  const approval = effectivePlanApprovalDetails(plan);
  assert.equal(approval.intrusive, true);
  assert.equal(approval.requiredScope, 'recon.intrusive');
  assert.equal(approval.planHash, plan.hash);
  assert.equal(approval.limits.modules.find((item) => item.id === 'sqlmap')?.phase, 'validation');
  assert.match(approval.limits.enforcement, /deadlines? por fase/);
});

test('plano Auto recusa arquivo Vigolium -T que poderia ampliar o escopo', () => {
  const catalog = catalogOf([
    { id: 'vigolium_dast', class: 'intrusive', manifest: { intrusive: true } },
  ]);
  assert.throws(() => buildEffectiveAutoPlan({
    plan: {
      target: 'lab.example.test',
      action: 'run_modules',
      modules: ['vigolium_dast'],
    },
    catalog,
    body: {
      includeVigolium: true,
      vigoliumInputFile: '/tmp/spec-com-servidor-externo.yaml',
      vigoliumInputType: 'openapi',
    },
    autonomyLevel: 'authorized',
  }), /Vigolium -T.*plano Auto/i);
});

test('timeouts do catálogo viram deadlines de fase determinísticos e limitados', () => {
  assert.deepEqual(phaseTimeoutsFromModuleLimits([
    { phase: 'probe', timeoutMs: 1_000 },
    { phase: 'probe', timeoutMs: 2_000 },
    { phase: 'validation', timeoutMs: 5_000 },
    { phase: 'frameseven', timeoutMs: 99_000 },
  ]), {
    probe: 3_000,
    validation: 5_000,
  });
  assert.deepEqual(phaseTimeoutsFromModuleLimits([
    { phase: 'validation', timeoutMs: 3_600_000 },
    { phase: 'validation', timeoutMs: 3_600_000 },
  ]), {
    validation: 3_600_000,
  });
});

test('timeout FrameSeven aprovado fica congelado no engine e participa do hash do plano', () => {
  const build = (timeoutMs) => buildEffectiveAutoPlan({
    plan: {
      target: 'example.test',
      action: 'run_modules',
      modules: ['frameseven_recon'],
    },
    catalog: catalogOf([{
      id: 'frameseven_recon',
      class: 'active',
      manifest: { timeoutMs },
    }]),
    body: { includeFrameSeven: true },
    autonomyLevel: 'assisted',
    frameSevenAvailable: true,
  });

  const first = build(123_456);
  const same = build(123_456);
  const changed = build(234_567);
  assert.equal(first.engines.frameseven.runTimeoutMs, 123_456);
  assert.equal(first.moduleLimits.find((item) => item.id === 'frameseven_recon')?.timeoutMs, 123_456);
  assert.equal(first.hash, same.hash);
  assert.notEqual(first.hash, changed.hash);
});

test('identidade FrameSeven aprovada fica congelada no plano e troca altera o hash', () => {
  const build = (sha256, includeIdentity = true) => {
    const catalog = catalogOf([{ id: 'frameseven_recon', class: 'active' }]);
    if (includeIdentity) catalog.engines.frameseven.identity.sha256 = sha256;
    else catalog.engines.frameseven.identity = null;
    return buildEffectiveAutoPlan({
      plan: {
        target: 'example.test',
        action: 'run_modules',
        modules: ['frameseven_recon'],
      },
      catalog,
      body: { includeFrameSeven: true },
      autonomyLevel: 'assisted',
      frameSevenAvailable: true,
    });
  };
  const first = build('a'.repeat(64));
  const changed = build('b'.repeat(64));
  assert.equal(first.engines.frameseven.identity.sha256, 'a'.repeat(64));
  assert.notEqual(first.hash, changed.hash);
  assert.throws(
    () => build('a'.repeat(64), false),
    /identidade executável selada/i,
  );
});

test('authorized exige popup também para plano somente ativo', () => {
  const catalog = catalogOf([{ id: 'cors_audit', class: 'active' }]);
  const plan = buildEffectiveAutoPlan({
    plan: { target: 'lab.example.test', action: 'run_modules', modules: ['cors_audit'] },
    catalog,
    autonomyLevel: 'authorized',
  });
  const approval = effectivePlanApprovalDetails(plan);

  assert.equal(plan.requiresHumanApproval, true);
  assert.equal(approval.intrusive, false);
  assert.equal(approval.requiredScope, null);
  assert.equal(approval.kind, 'execution_plan');
});

test('plano efetivo aplica opt-in independente para cada motor externo', () => {
  const catalog = catalogOf([
    { id: 'frameseven_recon', class: 'active' },
    {
      id: 'frameseven_authenticated',
      class: 'intrusive',
      manifest: { intrusive: true, requiresAuth: true },
    },
    { id: 'vigolium_audit', class: 'active' },
    { id: 'hexstrike_orchestrator', class: 'hexstrike_intel' },
  ]);

  assert.throws(() => buildEffectiveAutoPlan({
    plan: { action: 'run_modules', modules: ['frameseven_recon'] },
    catalog,
    autonomyLevel: 'assisted',
  }), /FrameSeven exige opt-in/);
  assert.throws(() => buildEffectiveAutoPlan({
    plan: { action: 'run_modules', modules: ['frameseven_authenticated'] },
    catalog,
    body: { includeFrameSeven: true, frameSevenAuth: false },
    autonomyLevel: 'authorized',
    frameSevenAvailable: true,
  }), /frameSevenAuth=true/);
  assert.throws(() => buildEffectiveAutoPlan({
    plan: { action: 'run_modules', modules: ['vigolium_audit'] },
    catalog,
    autonomyLevel: 'assisted',
  }), /includeVigolium=true/);
  assert.throws(() => buildEffectiveAutoPlan({
    plan: { action: 'run_modules', modules: ['hexstrike_orchestrator'] },
    catalog,
    autonomyLevel: 'observation',
  }), /includeHexstrike=true/);
});

test('FrameSeven usa perfis explícitos, ofensivo aprovado e modos mutuamente exclusivos', () => {
  const catalog = catalogOf([
    { id: 'frameseven_recon', class: 'active' },
    { id: 'frameseven_active', class: 'intrusive', manifest: { intrusive: true } },
    {
      id: 'frameseven_authenticated',
      class: 'intrusive',
      manifest: { intrusive: true, requiresAuth: true },
    },
  ]);
  const active = buildEffectiveAutoPlan({
    plan: { action: 'run_modules', modules: ['frameseven_recon', 'frameseven_active'] },
    catalog,
    body: { includeFrameSeven: true, frameSevenAuth: false },
    autonomyLevel: 'authorized',
    frameSevenAvailable: true,
  });

  assert.equal(active.requiresFormalAuthorization, true);
  assert.ok(active.activeModules.includes('frameseven_recon') || active.intrusiveModules.length > 0);
  assert.equal(active.engines.frameseven.enabled, true);
  assert.equal(active.engines.frameseven.authBrowser, false);
  assert.equal(active.engines.frameseven.profile, 'offensive_v1');
  assert.equal(active.engines.frameseven.offensive, true);
  assert.equal(active.engines.frameseven.tools, FRAMESEVEN_OFFENSIVE_TOOLS_V1);
  assert.deepEqual(active.engines.frameseven.moduleIds, ['frameseven_active']);
  assert.deepEqual(active.selectedModules, ['frameseven_active']);
  for (const forbidden of [
    'all',
    'sqli',
    'sqlmap',
    'ratelimit',
    'ssrf',
    'lfi',
    'xss',
    'xxe',
    'cmdi',
    'ssti',
    'authtest',
  ]) {
    assert.equal(active.engines.frameseven.tools.split(',').includes(forbidden), false, forbidden);
  }

  const authenticated = buildEffectiveAutoPlan({
    plan: {
      action: 'run_modules',
      modules: ['frameseven_recon', 'frameseven_active', 'frameseven_authenticated'],
    },
    catalog,
    body: { includeFrameSeven: true, frameSevenAuth: true },
    autonomyLevel: 'authorized',
    frameSevenAvailable: true,
    forceFrameSevenRecon: true,
  });
  assert.deepEqual(authenticated.selectedModules, ['frameseven_authenticated']);
  assert.deepEqual(authenticated.engines.frameseven.moduleIds, ['frameseven_authenticated']);
  assert.equal(authenticated.engines.frameseven.authBrowser, true);
  assert.equal(authenticated.engines.frameseven.profile, 'offensive_v1');
  assert.equal(authenticated.engines.frameseven.offensive, true);
  assert.equal(authenticated.engines.frameseven.tools, FRAMESEVEN_OFFENSIVE_TOOLS_V1);

  const recon = buildEffectiveAutoPlan({
    plan: { action: 'run_modules', modules: ['frameseven_recon'] },
    catalog,
    body: { includeFrameSeven: true, frameSevenAuth: false },
    autonomyLevel: 'assisted',
    frameSevenAvailable: true,
  });
  assert.deepEqual(recon.selectedModules, ['frameseven_recon']);
  assert.equal(recon.engines.frameseven.profile, 'recon_v1');
  assert.equal(recon.engines.frameseven.offensive, false);
  assert.equal(recon.engines.frameseven.tools, FRAMESEVEN_RECON_TOOLS_V1);
});

test('agentes Vigolium mutuamente exclusivos não podem constar no mesmo plano exato', () => {
  const catalog = catalogOf([
    { id: 'vigolium_audit', class: 'active' },
    { id: 'vigolium_swarm', class: 'intrusive', manifest: { intrusive: true } },
  ]);
  assert.throws(() => buildEffectiveAutoPlan({
    plan: { action: 'run_modules', modules: ['vigolium_audit', 'vigolium_swarm'] },
    catalog,
    body: { includeVigolium: true },
    autonomyLevel: 'authorized',
  }), /mutuamente exclusivos/);
});

test('finish e abstain não executam módulos nem injetam FrameSeven autenticado', () => {
  const catalog = catalogOf([
    { id: 'frameseven_recon', class: 'active' },
    {
      id: 'frameseven_authenticated',
      class: 'intrusive',
      manifest: { intrusive: true, requiresAuth: true },
    },
  ]);

  for (const action of ['finish', 'abstain']) {
    const plan = buildEffectiveAutoPlan({
      plan: { action, modules: ['frameseven_authenticated'] },
      catalog,
      body: { includeFrameSeven: true, frameSevenAuth: true },
      autonomyLevel: 'authorized',
      frameSevenAvailable: true,
      forceFrameSevenRecon: true,
    });

    assert.deepEqual(plan.selectedModules, [], action);
    assert.deepEqual(plan.pipelineModules, [], action);
    assert.equal(plan.engines.frameseven.enabled, false, action);
    assert.equal(plan.engines.frameseven.authBrowser, false, action);
    assert.equal(plan.requiresHumanApproval, false, action);
  }
});
