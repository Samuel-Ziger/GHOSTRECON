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
  assert.match(html, /Identidades seladas:/);
  assert.match(html, /frameSeven\.identity\?\.sha256/);
  assert.match(html, /vigolium\.identity\?\.sha256/);
  assert.match(html, /getPipelineAuthConfig/);
  assert.doesNotMatch(html, /delete preflightBody\.(?:auth|vigoliumAuth)/);
  assert.match(html, /Autenticação pipeline:/);
  assert.match(html, /Autenticação Vigolium:/);
  assert.match(route, /buildManualReconPrivateContext/);
  assert.match(route, /manualApprovalStore\.consume/);
  assert.match(route, /planHash:\s*manualReconPlan\.hash/);
});

test('UI diferencia lifecycle parcial e timeout de motores Auto', async () => {
  const html = await fs.readFile(new URL('../../public/index.html', import.meta.url), 'utf8');
  assert.match(html, /ev\.type === 'engine_partial'/);
  assert.match(html, /ev\.type === 'engine_timeout'/);
});

test('UI Auto continua em error recuperável e distingue AUTO PARCIAL de COMPLETO', async () => {
  const html = await fs.readFile(new URL('../../public/index.html', import.meta.url), 'utf8');
  assert.match(html, /AUTO PARCIAL/);
  assert.match(html, /outcome\.status === 'partial'/);
  assert.match(html, /ev\.recoverable === true/);
  assert.match(html, /stream Auto continua/);
  assert.match(
    html,
    /\['completed',\s*'partial',\s*'cancelled',\s*'interrupted',\s*'failed',\s*'timed_out',\s*'stalled',\s*'budget_exceeded'\]/,
  );
  const errorHandler = html.indexOf("if (ev.type === 'error')");
  assert.notEqual(errorHandler, -1);
  const errorBlock = html.slice(errorHandler, errorHandler + 450);
  assert.match(errorBlock, /recoverable === true/);
  assert.match(errorBlock, /continue;/);
  assert.match(errorBlock, /break outer;/);
  assert.ok(
    errorBlock.indexOf('recoverable === true') < errorBlock.indexOf('break outer;'),
    'erro recuperável deve ser tratado antes do break fatal',
  );
});

test('UI Auto mapeia outcomes para estados de statusText (não só regex de rótulo)', async () => {
  const html = await fs.readFile(new URL('../../public/index.html', import.meta.url), 'utf8');
  assert.match(html, /function autoUiTerminalStatusText\(outcome\)/);
  assert.match(html, /getElementById\('statusText'\)\.textContent = autoUiTerminalStatusText\(outcome\)/);
  const start = html.indexOf('function autoUiTerminalStatusText(outcome)');
  assert.notEqual(start, -1);
  const end = html.indexOf('\nfunction markAutoAwaitingTerminal', start);
  assert.notEqual(end, -1);
  const fnSource = html.slice(start, end);
  // eslint-disable-next-line no-new-func
  const autoUiTerminalStatusText = new Function(`${fnSource}; return autoUiTerminalStatusText;`)();
  assert.equal(autoUiTerminalStatusText('completed'), 'AUTO COMPLETO');
  assert.equal(autoUiTerminalStatusText('partial'), 'AUTO PARCIAL');
  assert.equal(autoUiTerminalStatusText('cancelled'), 'AUTO CANCELADO');
  assert.equal(autoUiTerminalStatusText('interrupted'), 'AUTO CANCELADO');
  assert.equal(autoUiTerminalStatusText('cancel_requested_unconfirmed'), 'AUTO CANCELADO');
  assert.equal(autoUiTerminalStatusText('failed'), 'ERRO');
  assert.equal(autoUiTerminalStatusText('timed_out'), 'ERRO');
  assert.equal(autoUiTerminalStatusText('stalled'), 'ERRO');
  assert.equal(autoUiTerminalStatusText('budget_exceeded'), 'ERRO');
});

test('UI Auto aguarda terminal confirmado e mantém cancel disponível', async () => {
  const html = await fs.readFile(new URL('../../public/index.html', import.meta.url), 'utf8');
  assert.match(html, /async function waitForAutoSessionTerminal/);
  assert.match(html, /function markAutoAwaitingTerminal/);
  assert.match(html, /\/api\/recon\/auto\/sessions\/\$\{encodeURIComponent\(id\)\}/);
  assert.match(html, /cancel_requested_unconfirmed/);
  assert.match(html, /markAutoAwaitingTerminal/);
  assert.match(html, /AUTO AGUARDANDO TERMINAL/);
  // Cancel permanece acionável enquanto aguarda confirmação do servidor.
  assert.match(html, /if \(cancelBtn\) cancelBtn\.disabled = false/);
});
