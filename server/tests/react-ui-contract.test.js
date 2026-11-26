import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs/promises';

const ROOT = new URL('../../', import.meta.url);
const PUBLIC_PAGES = [
  'index.html',
  'como-usar.html',
  'cortex.html',
  'mitre-map.html',
  'post-exploitation.html',
  'reporte.html',
  'tor-validator.html',
  'vigolium-workbench.html',
  'wifi-pentest.html',
  'ghostia.html',
  'hackbot.html',
];

async function read(relativePath) {
  return fs.readFile(new URL(relativePath, ROOT), 'utf8');
}

test('todas as páginas operacionais usam o host React local', async () => {
  for (const page of PUBLIC_PAGES) {
    const shell = await read(`public/${page}`);
    assert.match(shell, /id="root"/);
    assert.match(shell, /\.\/assets\/ghostrecon-ui\.css/);
    assert.match(shell, /\.\/assets\/ghostrecon-ui\.js/);
    assert.doesNotMatch(shell, /async function startRecon/);
  }
});

test('registro React cobre todas as URLs e templates compatíveis', async () => {
  const registry = await read('frontend/src/page-registry.ts');
  for (const page of PUBLIC_PAGES) {
    assert.match(registry, new RegExp(page.replaceAll('.', '\\.')));
    const template = await read(`frontend/templates/${page}`);
    assert.match(template, /<!DOCTYPE html>|<!doctype html>/i);
    assert.ok(template.length > 500, `${page} deve preservar o documento original`);
  }
});

test('cockpit React preserva contratos críticos do monólito', async () => {
  const cockpit = await read('frontend/templates/index.html');
  const inventory = JSON.parse(await read('frontend/contracts/ui-inventory.json'));
  const apiClient = await read('frontend/src/services/api-client.ts');
  const manualRecon = await read('frontend/src/features/manual-recon/service.ts');
  const autoForge = await read('frontend/src/features/auto-forge/service.ts');
  const infraHistory = await read('frontend/src/features/infra-history/service.ts');
  const vigolium = await read('frontend/src/features/vigolium/service.ts');
  const exportsIntegrations = await read('frontend/src/features/exports-integrations/service.ts');
  const contractSource = `${cockpit}\n${apiClient}\n${manualRecon}\n${autoForge}\n${infraHistory}\n${vigolium}\n${exportsIntegrations}`;
  const requiredContracts = [
    '/api/recon/stream',
    '/api/recon/auto/stream',
    '/api/recon/preflight',
    '/api/recon/approval',
    '/api/csrf-token',
    '/api/setup/auto-auth',
    '/api/auto-rag/status',
    '/api/tunnel/status',
    '/api/ai/lmstudio-check',
    '/api/vigolium/modules',
    '/api/capabilities',
    'ghostrecon_api_base',
    'ghostrecon_auth_json',
    'ghostrecon.auto.lastSessionId',
    'ghostrecon_mitre_live_session_id',
    'ghostrecon-history',
    'consumeReconStreamFromResponse',
    'cancelAutoModeRecon',
    'exportPlatformBundle',
  ];
  for (const contract of requiredContracts) assert.ok(contractSource.includes(contract), contract);

  assert.equal(
    (cockpit.match(/\b(?:async\s+)?function\s+[A-Za-z_$][\w$]*/g) || []).length,
    inventory.pages['index.html'].functionDeclarationCount,
    'inventário deve acompanhar a extração progressiva do controller',
  );
  assert.ok((cockpit.match(/class="mod"/g) || []).length >= 80);
  assert.equal((cockpit.match(/\bfetch\s*\(/g) || []).length, 4, 'só exemplos XSS devem manter fetch');
  assert.doesNotMatch(cockpit, /fetch\(apiUrl\(/, 'controller não deve manter transporte real');
  assert.ok((contractSource.match(/fetch(?:Impl)?\s*\(/g) || []).length >= 15);
});

test('runtime React monta todas as árvores antes dos scripts e mantém file:// sem CDN', async () => {
  const runtime = await read('frontend/src/LegacyDocument.tsx');
  const auxiliary = await read('frontend/src/features/pages/AuxiliaryPage.tsx');
  const config = await read('frontend/vite.config.ts');
  const packageJson = JSON.parse(await read('package.json'));

  assert.match(runtime, /new DOMParser\(\)/);
  assert.doesNotMatch(runtime, /dangerouslySetInnerHTML/);
  assert.doesNotMatch(auxiliary, /dangerouslySetInnerHTML/);
  assert.match(auxiliary, /domChildrenToReact\(parsed\.body\)/);
  assert.match(auxiliary, /useEffect\(\(\) => \{[\s\S]*executeScripts\(snapshot\.scripts, page\.id\)/);
  assert.match(auxiliary, /ghostreconReactTree/);
  assert.match(runtime, /document\.dispatchEvent\(new Event\('DOMContentLoaded'/);
  assert.match(runtime, /nativeDomContentLoadedSeen/);
  assert.match(auxiliary, /ghostreconLegacyReady/);
  assert.match(config, /formats:\s*\['iife'\]/);
  assert.match(config, /ghostrecon-ui\.js/);
  assert.equal(packageJson.dependencies.react, '18.3.1');
  assert.equal(packageJson.dependencies['react-dom'], '18.3.1');
});

test('oito páginas auxiliares têm componentes e árvores React registradas', async () => {
  const app = await read('frontend/src/App.tsx');
  const auxiliary = await read('frontend/src/features/pages/AuxiliaryPage.tsx');
  const cortex = await read('frontend/src/features/pages/cortex/CortexPage.tsx');

  assert.match(app, /AUXILIARY_PAGE_COMPONENTS/);
  assert.match(app, /<PageComponent page=\{page\}/);
  assert.doesNotMatch(app, /LegacyDocument/);
  for (const component of ['GuidePage', 'MitreMapRedirectPage']) {
    assert.match(auxiliary, new RegExp(`function ${component}`));
  }
  assert.match(auxiliary, /import \{ CortexPage \} from '.\/cortex\/CortexPage'/);
  assert.match(auxiliary, /import \{ PostExploitationPage \} from '.\/post-exploitation\/PostExploitationPage'/);
  assert.match(auxiliary, /import \{ ReportPage \} from '.\/report\/ReportPage'/);
  assert.match(auxiliary, /import \{ TorValidatorPage \} from '.\/tor-validator\/TorValidatorPage'/);
  assert.match(auxiliary, /import \{ VigoliumWorkbenchPage \} from '.\/vigolium-workbench\/VigoliumWorkbenchPage'/);
  assert.match(auxiliary, /import \{ WifiPentestPage \} from '.\/wifi-pentest\/WifiPentestPage'/);
  assert.match(cortex, /export function CortexPage/);
  assert.doesNotMatch(cortex, /executeScripts/);
});

test('inventário versionado cobre funções, DOM, módulos e integrações do cockpit', async () => {
  const inventory = JSON.parse(await read('frontend/contracts/ui-inventory.json'));
  const cockpit = inventory.pages['index.html'];

  assert.equal(inventory.schemaVersion, 1);
  assert.equal(inventory.pageCount, 11);
  assert.equal(cockpit.domIdCount, 226);
  assert.equal(cockpit.moduleCount, 88);
  assert.equal(
    cockpit.fetchCallCount,
    (await read('frontend/templates/index.html')).match(/fetch\s*\(/g)?.length || 0,
  );
  assert.equal(
    cockpit.addEventListenerCount,
    (await read('frontend/templates/index.html')).match(/\.addEventListener\s*\(/g)?.length || 0,
  );
  assert.equal(cockpit.inlineHandlers.onclick, 83);
  assert.ok(cockpit.functions.includes('startRecon'));
  assert.ok(cockpit.functions.includes('startAutoModeRecon'));
  assert.ok(cockpit.functions.includes('consumeReconStreamFromResponse'));
  assert.ok(!cockpit.functions.includes('exportPlatformBundle'));
});

test('página de pós-exploração mantém inicialização tardia e handlers globais', async () => {
  const postExploitation = await read('frontend/templates/post-exploitation.html');
  assert.match(postExploitation, /addEventListener\('DOMContentLoaded'/);
  assert.match(postExploitation, /window\.copyCmd = copyCmd/);
  assert.match(postExploitation, /window\.runSearchsploit = runSearchsploit/);
});

test('cockpit usa árvore React nativa sem dangerouslySetInnerHTML', async () => {
  const app = await read('frontend/src/App.tsx');
  const cockpit = await read('frontend/src/features/cockpit/CockpitPage.tsx');
  const findings = await read('frontend/src/features/execution/FindingsView.tsx');
  const renderer = await read('frontend/src/runtime/react-dom-tree.tsx');
  const shell = await read('frontend/src/shell.css');

  assert.match(app, /page\.id === 'cockpit'/);
  assert.match(app, /<CockpitPage page=\{page\}/);
  assert.doesNotMatch(cockpit, /dangerouslySetInnerHTML/);
  assert.match(cockpit, /CockpitHeader/);
  assert.match(cockpit, /CockpitWorkspace/);
  assert.match(cockpit, /ghostreconNativeCockpit/);
  assert.match(renderer, /createElement\(tagName/);
  assert.match(renderer, /defaultChecked/);
  assert.match(renderer, /defaultValue/);
  assert.match(findings, /useLayoutEffect/);
  assert.match(findings, /ResizeObserver/);
  assert.match(findings, /FINDINGS_STACK_BREAKPOINT = 1020/);
  assert.match(shell, /\.findings-panel[\s\S]{0,240}justify-self: end/);
  assert.match(shell, /var\(--findings-panel-width, minmax\(320px, 1\.22fr\)\)/);
});

test('overlays e cheatsheets do cockpit usam estado e eventos React nativos', async () => {
  const cockpit = await read('frontend/templates/index.html');
  const page = await read('frontend/src/features/cockpit/CockpitPage.tsx');
  const help = await read('frontend/src/features/help/CockpitHelpOverlays.tsx');

  assert.match(page, /<CockpitHelpOverlays source=\{page\.source\}/);
  assert.match(help, /COCKPIT_HELP_OVERLAY_IDS/);
  assert.match(help, /useState<CockpitHelpOverlayId/);
  assert.match(help, /document\.addEventListener\('keydown', keydown\)/);
  assert.match(help, /finishAiConsent/);
  assert.match(help, /copyRow/);
  assert.equal((cockpit.match(/data-ghostrecon-help-action=/g) || []).length, 220);
  assert.doesNotMatch(cockpit, /function openSidebarHelpModal/);
  assert.doesNotMatch(cockpit, /function openFindingsHelpModal/);
  assert.doesNotMatch(cockpit, /function openModulesHelpModal/);
  assert.doesNotMatch(cockpit, /function openSqlmapHelpModal/);
  assert.doesNotMatch(cockpit, /function openPromptInjHelpModal/);
  assert.doesNotMatch(cockpit, /function openXssHelpModal/);
  assert.doesNotMatch(cockpit, /function aiReportsConsentFinish/);
  assert.doesNotMatch(cockpit, /onclick="copy(?:SqlmapCmd|PromptInj|ShellStabilize|Xss)Row/);
});

test('controller do cockpit delega domínios extraídos aos serviços TypeScript', async () => {
  const cockpit = await read('frontend/templates/index.html');
  const page = await read('frontend/src/features/cockpit/CockpitPage.tsx');
  const bridge = await read('frontend/src/features/cockpit/native-services.ts');
  const infraHistory = await read('frontend/src/features/infra-history/service.ts');
  const exportsIntegrations = await read('frontend/src/features/exports-integrations/service.ts');
  const executionStore = await read('frontend/src/features/execution/store.tsx');
  const findingsView = await read('frontend/src/features/execution/FindingsView.tsx');
  const pipelineView = await read('frontend/src/features/execution/PipelineView.tsx');

  assert.match(page, /installNativeCockpitServices\(window\)/);
  assert.match(bridge, /createNativeCockpitServices/);
  assert.match(bridge, /new NdjsonDecoder/);
  assert.match(bridge, /pipelineReducer/);
  assert.match(bridge, /selectFindings/);
  for (const domain of [
    'api',
    'autoForge',
    'infraHistory',
    'manualRecon',
    'pipeline',
    'runForm',
    'vigolium',
  ]) {
    assert.match(cockpit, new RegExp(`__ghostreconNativeServices\\?\\.${domain}`));
  }
  assert.doesNotMatch(cockpit, /__ghostreconNativeServices\.artex/);
  assert.match(bridge, /ndjson: Object\.freeze/);
  assert.match(bridge, /findings: Object\.freeze/);
  assert.match(findingsView, /__ghostreconNativeServices\?\.findings/);
  assert.match(cockpit, /runForm\?\.consumeStream/);
  assert.match(cockpit, /nativePipeline\.reduce/);
  assert.match(page, /<ExecutionStoreProvider store=\{executionStore\}>/);
  assert.match(page, /<PipelineBar key=\{key\}/);
  assert.match(page, /<FindingsPanel key=\{key\}/);
  assert.match(executionStore, /executionSelectors/);
  assert.match(executionStore, /useSyncExternalStore/);
  assert.match(pipelineView, /PIPELINE_PHASES/);
  assert.match(findingsView, /finding-manual-val-badge/);
  assert.match(findingsView, /finding-owasp/);
  assert.match(findingsView, /finding-mitre/);
  assert.match(findingsView, /finding-provenance/);
  assert.doesNotMatch(cockpit, /function renderFinding/);
  assert.doesNotMatch(cockpit, /findingsList'\)\.innerHTML/);
  assert.doesNotMatch(cockpit, /getElementById\(`pipe-\$\{id\}`\)/);
  assert.doesNotMatch(cockpit, /function prepareManualReconApproval/);
  assert.doesNotMatch(cockpit, /function createTemporaryManualEngagement/);
  assert.doesNotMatch(cockpit, /function autoApiHeaders/);
  assert.doesNotMatch(cockpit, /function postAutoApiJson/);
  assert.doesNotMatch(cockpit, /function waitForAutoSessionTerminal/);
  assert.doesNotMatch(cockpit, /function autoUiTerminalStatusText/);
  assert.match(bridge, /createAutoForgeService/);
  assert.doesNotMatch(bridge, /createArtexService/);
  assert.match(bridge, /createInfraHistoryService/);
  assert.match(bridge, /createVigoliumService/);
  assert.match(bridge, /installExportsIntegrations/);
  assert.match(exportsIntegrations, /buildPlatformExport/);
  assert.match(exportsIntegrations, /openGhostmapAndReporteOnReconStartSync/);
  assert.match(infraHistory, /manualValidationFingerprints/);
  assert.doesNotMatch(cockpit, /function exportPlatformBundle/);
  assert.doesNotMatch(cockpit, /function openMitreMapPage/);
  assert.doesNotMatch(cockpit, /fetch\(apiUrl\(`\/api\/vigolium\/modules/);
  assert.doesNotMatch(cockpit, /fetch\(apiUrl\('\/api\/capabilities'\)/);
});
