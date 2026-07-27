import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs/promises';

test('perfil e presets nunca concedem consentimento ativo automaticamente', async () => {
  const html = await fs.readFile(new URL('../../public/index.html', import.meta.url), 'utf8');

  assert.doesNotMatch(html, /setInputChecked\(\s*['"]confirmActiveToggle['"]\s*,\s*true\s*\)/);
  assert.doesNotMatch(html, /confirmActiveToggle[\s\S]{0,120}\.checked\s*=\s*true/);
  assert.match(html, /marque «Confirmar ativo» manualmente/);
});

test('body do Auto não transporta auth e RUN manual usa preflight + popup + aprovação vinculada', async () => {
  const html = await fs.readFile(new URL('../../public/index.html', import.meta.url), 'utf8');
  const route = await fs.readFile(new URL('../routes/recon-stream.mjs', import.meta.url), 'utf8');
  const autoBodyStart = html.indexOf(
    'const body = {',
    html.indexOf('AUTO motores opcionais:'),
  );
  const autoBodyEnd = html.indexOf('\n    };', autoBodyStart);

  assert.notEqual(autoBodyStart, -1);
  assert.notEqual(autoBodyEnd, -1);
  const autoBody = html.slice(autoBodyStart, autoBodyEnd);
  assert.doesNotMatch(autoBody, /\bauth\s*:/);
  assert.match(route, /const confirmActive = Boolean\(req\.body\?\.confirmActive\);/);
  assert.doesNotMatch(route, /confirmActive[\s\S]{0,100}opsecProfile\s*===\s*['"]deep['"]/);
  assert.match(html, /\/api\/recon\/preflight/);
  assert.match(html, /\/api\/recon\/approval/);
  assert.match(html, /Hash do plano:/);
  assert.match(html, /delete preflightBody\.auth/);
  assert.match(route, /manualApprovalStore\.consume/);
  assert.match(route, /planHash:\s*manualReconPlan\.hash/);
});

test('UI diferencia lifecycle parcial e timeout de motores Auto', async () => {
  const html = await fs.readFile(new URL('../../public/index.html', import.meta.url), 'utf8');
  assert.match(html, /ev\.type === 'engine_partial'/);
  assert.match(html, /ev\.type === 'engine_timeout'/);
});
