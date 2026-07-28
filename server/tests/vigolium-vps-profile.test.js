import test from 'node:test';
import assert from 'node:assert/strict';
import {
  appendVigoliumVpsScanFlags,
  buildVigoliumOutputBase,
  shouldUseVigoliumVpsProfile,
  vigoliumArtifactPaths,
  vigoliumReportPublicUrl,
} from '../../bridge/vigolium-vps-profile.mjs';
import { buildVigoliumScanArgs } from '../../bridge/vigolium-runner.mjs';
import { resolveVigoliumStrategy, shouldWriteVigoliumHtmlReport } from '../../bridge/vigolium-config.mjs';

test('VPS profile ativo quando vigolium_dast está nos módulos', () => {
  assert.equal(shouldUseVigoliumVpsProfile({ modules: ['vigolium_dast'] }), true);
  assert.equal(shouldUseVigoliumVpsProfile({ modules: ['rdap'], vigoliumVpsProfile: false }), false);
  assert.equal(shouldUseVigoliumVpsProfile({ modules: ['vigolium_dast'], vigoliumVpsProfile: false }), false);
});

test('decisão VPS explícita true/false prevalece sobre ambiente injetado', () => {
  assert.equal(
    shouldUseVigoliumVpsProfile(
      { modules: ['rdap'], vigoliumVpsProfile: true },
      { GHOSTRECON_VIGOLIUM_VPS_PROFILE: '0' },
    ),
    true,
  );
  assert.equal(
    shouldUseVigoliumVpsProfile(
      { modules: ['vigolium_dast'], vigoliumVpsProfile: false },
      { GHOSTRECON_VIGOLIUM_VPS_PROFILE: '1' },
    ),
    false,
  );
});

test('buildVigoliumScanArgs perfil VPS inclui -S, strict e skip external-harvest', () => {
  const built = buildVigoliumScanArgs(
    { domain: 'example.com', modules: ['vigolium_dast'], vigoliumStrategy: 'deep' },
    { outBase: '/tmp/out-base' },
  );
  assert.equal(built.vpsProfile, true);
  assert.ok(built.args.includes('-S'));
  assert.ok(built.args.includes('--scope-origin'));
  assert.ok(built.args.includes('strict'));
  assert.ok(built.args.includes('--skip'));
  assert.ok(built.args.includes('external-harvest'));
  assert.ok(built.args.includes('html,sqlite,jsonl'));
  assert.ok(built.args.includes('/tmp/out-base'));
});

test('resolveVigoliumStrategy default deep com vigolium_dast (VPS)', () => {
  assert.equal(resolveVigoliumStrategy({ modules: ['vigolium_dast'] }), 'deep');
  assert.equal(resolveVigoliumStrategy({}), 'lite');
});

test('shouldWriteVigoliumHtmlReport default on no perfil VPS', () => {
  assert.equal(shouldWriteVigoliumHtmlReport({ modules: ['vigolium_dast'] }), true);
  assert.equal(shouldWriteVigoliumHtmlReport({ modules: ['rdap'] }), false);
});

test('vigoliumArtifactPaths e report public URL', () => {
  const paths = vigoliumArtifactPaths('/reports/alvo-ts');
  assert.equal(paths.html, '/reports/alvo-ts.html');
  assert.equal(paths.sqlite, '/reports/alvo-ts.sqlite');
  const base = buildVigoliumOutputBase('/root', 'https://alvo.com');
  assert.match(base.replace(/\\/g, '/'), /vigolium-reports\/alvo\.com-/);
  const prevPort = process.env.PORT;
  process.env.PORT = '3847';
  assert.match(vigoliumReportPublicUrl('/root/.runtime/vigolium-reports/x.html'), /\/api\/vigolium\/reports\/x\.html/);
  if (prevPort === undefined) delete process.env.PORT;
  else process.env.PORT = prevPort;
});

test('appendVigoliumVpsScanFlags não duplica flags', () => {
  const args = ['scan', '-t', 'https://x.test', '-S', '--scope-origin', 'strict', '--skip', 'external-harvest'];
  const next = appendVigoliumVpsScanFlags(args, { modules: ['vigolium_dast'] });
  assert.equal(next.filter((a) => a === '-S').length, 1);
});
