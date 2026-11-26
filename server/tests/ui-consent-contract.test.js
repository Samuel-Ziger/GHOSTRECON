import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs/promises';

test('RUN manual mantém engagement opcional e aprovação do plano, sem toggles OPSEC/bounty', async () => {
  const html = await fs.readFile(new URL('../../frontend/templates/index.html', import.meta.url), 'utf8');
  const runForm = await fs.readFile(new URL('../../frontend/src/features/run-form/model.ts', import.meta.url), 'utf8');
  const manualRecon = await fs.readFile(new URL('../../frontend/src/features/manual-recon/service.ts', import.meta.url), 'utf8');
  const api = await fs.readFile(new URL('../modules/api-extensions.js', import.meta.url), 'utf8');

  assert.doesNotMatch(html, /id="confirmActiveToggle"/);
  assert.doesNotMatch(html, /id="opsecProfileSelect"/);
  assert.doesNotMatch(html, /id="bountyContextJsonInput"/);
  assert.match(html, /id="autoOpsecProfileSelect"/);
  assert.match(html, /id="autoBountyContextJsonInput"/);
  assert.match(runForm, /opsecProfile: 'standard'/);
  assert.match(html, /id="manualAuthorizationToggle"/);
  assert.match(manualRecon, /\/api\/engagements\/manual-authorization/);
  assert.doesNotMatch(html, /setInputChecked\(\s*['"]manualAuthorizationToggle['"]\s*,\s*true\s*\)/);
  assert.doesNotMatch(html, /id="manualAuthorizationToggle"[^>]*\bchecked\b/);
  assert.match(api, /app\.post\('\/api\/engagements\/manual-authorization', requireScope\('engagement\.write'\)/);

  assert.match(html, /engagement opcional/i);
  assert.doesNotMatch(html, /const authorizeNow = window\.confirm\(/);

  const autoApproval = manualRecon.indexOf('approved: true');
  const confirmed = manualRecon.indexOf('confirmActive: true', autoApproval);
  assert.notEqual(autoApproval, -1);
  assert.ok(confirmed > autoApproval, 'a seleção manual deve aprovar o plano exato antes do stream');
  assert.doesNotMatch(manualRecon, /Plano manual recusado pelo operador/);
  assert.doesNotMatch(html, /return window\.confirm\(`Vigolium guardrail:/);
});

test('body do Auto não transporta auth e RUN manual usa preflight + aprovação automática vinculada', async () => {
  const html = await fs.readFile(new URL('../../frontend/templates/index.html', import.meta.url), 'utf8');
  const manualRecon = await fs.readFile(new URL('../../frontend/src/features/manual-recon/service.ts', import.meta.url), 'utf8');
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
  assert.match(manualRecon, /\/api\/recon\/preflight/);
  assert.match(manualRecon, /\/api\/recon\/approval/);
  assert.match(manualRecon, /Hash do plano:/);
  assert.match(manualRecon, /Identidades seladas:/);
  assert.match(manualRecon, /frameSeven\.identity\?\.sha256/);
  assert.match(manualRecon, /vigolium\.identity\?\.sha256/);
  assert.match(html, /getPipelineAuthConfig/);
  assert.doesNotMatch(manualRecon, /delete preflightBody\.(?:auth|vigoliumAuth)/);
  assert.match(manualRecon, /Autenticação pipeline:/);
  assert.match(manualRecon, /Autenticação Vigolium:/);
  assert.match(route, /buildManualReconPrivateContext/);
  assert.match(route, /manualApprovalStore\.consume/);
  assert.match(route, /planHash:\s*manualReconPlan\.hash/);
});

test('UI diferencia lifecycle parcial e timeout de motores Auto', async () => {
  const html = await fs.readFile(new URL('../../frontend/templates/index.html', import.meta.url), 'utf8');
  assert.match(html, /ev\.type === 'engine_partial'/);
  assert.match(html, /ev\.type === 'engine_timeout'/);
});

test('UI separa FTP de bug bounty sem escrita do write probe de laboratório', async () => {
  const html = await fs.readFile(new URL('../../frontend/templates/index.html', import.meta.url), 'utf8');
  const vigolium = await fs.readFile(new URL('../../frontend/src/features/vigolium/service.ts', import.meta.url), 'utf8');
  assert.match(html, /value="ftp_anonymous_audit"/);
  assert.match(html, /FTP anonymous audit \(sem escrita\)/);
  assert.match(html, /FTP anonymous audit \(sem escrita\)<\/span>\s*<span class="tag tag-high">INTRUSIVE<\/span>/);
  assert.match(html, /Não lista, baixa, envia, altera ou exclui arquivos/);
  assert.match(html, /Follow-ups de serviço \(SMB \/ RPC \/ versões\)/);
  assert.match(html, /FTP não é executado por esta caixa/);
  assert.match(html, /value="ftp_write_probe"/);
  const fullExclude = vigolium.slice(
    vigolium.indexOf('export const FULL_MODULES_EXCLUDE'),
    vigolium.indexOf('export const VIGOLIUM_PROFILE_STORAGE_KEY'),
  );
  assert.match(fullExclude, /ftp_write_probe/);
  assert.doesNotMatch(fullExclude, /ftp_anonymous_audit/);
});

test('UI descreve Supabase como leitura e não promete reutilizar token ou executar writes', async () => {
  const html = await fs.readFile(new URL('../../frontend/templates/index.html', import.meta.url), 'utf8');
  assert.match(html, /Supabase audit \(somente leitura\)/);
  assert.match(html, /Tokens do cliente nunca são reutilizados/);
  assert.match(html, /sb_publishable_/);
  assert.match(html, /sb_secret_/);
  assert.match(html, /falham antes da rede/);
  assert.doesNotMatch(html, /Supabase audit \(auto token \/ RLS \/ payment\)/);
  assert.doesNotMatch(html, /Token autenticado: bundle → signup anônimo/);
});

test('UI Auto continua em error recuperável e distingue AUTO PARCIAL de COMPLETO', async () => {
  const html = await fs.readFile(new URL('../../frontend/templates/index.html', import.meta.url), 'utf8');
  const autoForge = await fs.readFile(new URL('../../frontend/src/features/auto-forge/service.ts', import.meta.url), 'utf8');
  assert.match(autoForge, /AUTO PARCIAL/);
  assert.match(html, /outcome\.status === 'partial'/);
  assert.match(html, /ev\.recoverable === true/);
  assert.match(html, /stream Auto continua/);
  assert.match(
    autoForge,
    /'completed',[\s\S]*'partial',[\s\S]*'failed',[\s\S]*'cancelled',[\s\S]*'interrupted',[\s\S]*'timed_out',[\s\S]*'stalled',[\s\S]*'budget_exceeded'/,
  );
  const errorHandler = html.indexOf("if (ev.type === 'error')");
  assert.notEqual(errorHandler, -1);
  const errorBlock = html.slice(errorHandler, errorHandler + 450);
  assert.match(errorBlock, /recoverable === true/);
  assert.match(errorBlock, /return undefined;/);
  assert.match(errorBlock, /return \{ failed: true, stop: true \};/);
  assert.ok(
    errorBlock.indexOf('return undefined;') < errorBlock.indexOf('return { failed: true, stop: true };'),
    'erro recuperável deve ser tratado antes do retorno fatal',
  );
});

test('UI Auto mapeia outcomes para estados de statusText (não só regex de rótulo)', async () => {
  const html = await fs.readFile(new URL('../../frontend/templates/index.html', import.meta.url), 'utf8');
  const autoForge = await fs.readFile(new URL('../../frontend/src/features/auto-forge/service.ts', import.meta.url), 'utf8');
  assert.match(autoForge, /export function autoUiTerminalStatusText\(outcome: unknown\): string/);
  assert.match(html, /getElementById\('statusText'\)\.textContent = window\.__ghostreconNativeServices\.autoForge\.autoUiTerminalStatusText\(outcome\)/);
  assert.match(autoForge, /outcome === 'completed'\) return 'AUTO COMPLETO'/);
  assert.match(autoForge, /outcome === 'partial'\) return 'AUTO PARCIAL'/);
  assert.match(autoForge, /\['cancelled', 'interrupted', 'cancel_requested_unconfirmed'\]/);
  assert.match(autoForge, /return 'AUTO CANCELADO'/);
  assert.match(autoForge, /return 'ERRO'/);
});

test('UI Auto aguarda terminal confirmado e mantém cancel disponível', async () => {
  const html = await fs.readFile(new URL('../../frontend/templates/index.html', import.meta.url), 'utf8');
  const autoForge = await fs.readFile(new URL('../../frontend/src/features/auto-forge/service.ts', import.meta.url), 'utf8');
  assert.match(autoForge, /async function waitForTerminal/);
  assert.match(html, /function markAutoAwaitingTerminal/);
  assert.match(autoForge, /\/api\/recon\/auto\/sessions\/\$\{encodeURIComponent\(id\)\}/);
  assert.match(html, /cancel_requested_unconfirmed/);
  assert.match(html, /markAutoAwaitingTerminal/);
  assert.match(html, /AUTO AGUARDANDO TERMINAL/);
  // Cancel permanece acionável enquanto aguarda confirmação do servidor.
  assert.match(html, /if \(cancelBtn\) cancelBtn\.disabled = false/);
});
