import { chromium } from 'playwright';

const baseUrl = String(process.env.GHOSTRECON_UI_BASE_URL || 'http://127.0.0.1:3847').replace(/\/$/, '');
const pages = [
  {
    path: '/',
    page: 'cockpit',
    selector: '#domainInput',
    setup: async (browserPage) => {
      await browserPage.route('**/api/csrf-token', (route) => route.fulfill({
        contentType: 'application/json',
        body: JSON.stringify({ token: 'smoke-csrf' }),
      }));
      await browserPage.route('**/api/engagements/manual-authorization', (route) => route.fulfill({
        contentType: 'application/json',
        body: JSON.stringify({ ok: true, engagement: { id: 'MANUAL-smoke' } }),
      }));
      await browserPage.route('**/api/recon/preflight', (route) => route.fulfill({
        contentType: 'application/json',
        body: JSON.stringify({
          ok: true,
          requiresApproval: true,
          approval: { approvalId: 'smoke-approval' },
          plan: { target: 'example.test', hash: 'smoke-hash', intrusiveModules: [] },
        }),
      }));
      await browserPage.route('**/api/recon/approval', (route) => route.fulfill({
        contentType: 'application/json',
        body: JSON.stringify({ ok: true }),
      }));
      await browserPage.route('**/api/recon/stream', (route) => route.fulfill({
        contentType: 'application/x-ndjson',
        body: '{"type":"done","target":"example.test","runId":1,"storage":"smoke"}\n',
      }));
      await browserPage.route('**/api/recon/auto/sessions?resumable=1', (route) => route.fulfill({
        contentType: 'application/json',
        body: JSON.stringify({ ok: true, sessions: [] }),
      }));
      await browserPage.route('**/api/recon/auto/stream', (route) => route.fulfill({
        contentType: 'application/x-ndjson',
        body: [
          JSON.stringify({ type: 'auto_session', phase: 'started', sessionId: 'AUTO-smoke', mode: 'balanced' }),
          JSON.stringify({ type: 'progress', pct: 100 }),
          JSON.stringify({ type: 'auto_session', phase: 'completed', sessionId: 'AUTO-smoke' }),
          JSON.stringify({ type: 'done' }),
          '',
        ].join('\n'),
      }));
      await browserPage.route('**/api/artex/status', (route) => route.fulfill({
        contentType: 'application/json',
        body: JSON.stringify({
          ok: true,
          online: true,
          profiles: [],
          conversations: [],
          chatgptPlan: { connected: false },
          ghostreconMcp: { enabled: true },
          canManage: true,
        }),
      }));
      await browserPage.route('**/api/neurosploit/status', (route) => route.fulfill({
        contentType: 'application/json',
        body: JSON.stringify({
          ok: true,
          installed: true,
          binaryReady: true,
          version: 'smoke',
          jobs: [],
          profiles: [{
            id: 7,
            name: 'Codex smoke',
            model: 'gpt-smoke',
            format: 'chatgpt-plan',
            ready: true,
            credentialSource: 'codex-plan',
          }],
        }),
      }));
      await browserPage.route('**/api/auto-forge', (route) => route.fulfill({
        contentType: 'application/json',
        body: JSON.stringify({ ok: true, items: [] }),
      }));
    },
    verify: async (browserPage) => {
      const globals = await browserPage.evaluate(() => [
        typeof startRecon,
        typeof startAutoModeRecon,
        typeof consumeReconStreamFromResponse,
        typeof exportJSON,
      ]);
      if (globals.some((type) => type !== 'function')) throw new Error(`globals inválidos: ${globals.join(',')}`);
      const nativeCockpit = await browserPage.evaluate(
        () => document.body.dataset.ghostreconNativeCockpit,
      );
      if (nativeCockpit !== '1') throw new Error('cockpit não montado pela árvore React nativa');
      const parity = await browserPage.evaluate(() => ({
        batchHidden: getComputedStyle(document.querySelector('#batchWrap')).display === 'none',
        delay: document.querySelector('#dorkDelayMs')?.value,
        ids: document.querySelectorAll('[id]').length,
        modules: document.querySelectorAll('input.mod').length,
        profile: document.querySelector('#reconProfileSelect')?.value,
      }));
      if (parity.ids < 225 || parity.modules !== 88 || parity.delay !== '1200'
        || parity.profile !== 'standard' || !parity.batchHidden) {
        throw new Error(`paridade DOM inválida: ${JSON.stringify(parity)}`);
      }
      const vigoliumRuntime = await browserPage.evaluate(() => {
        const baseline = window.__ghostreconNativeServices?.calls?.vigolium || 0;
        applySmartFastPreset();
        saveVigoliumRunProfile();
        const profile = window.__ghostreconNativeServices?.vigolium?.loadProfile?.();
        clearVigoliumRunProfile();
        const selected = [...document.querySelectorAll('input.mod:checked')].map((input) => input.value);
        return {
          calls: window.__ghostreconNativeServices?.calls?.vigolium || 0,
          baseline,
          profile,
          selected,
        };
      });
      if (vigoliumRuntime.calls < vigoliumRuntime.baseline + 4
        || vigoliumRuntime.profile?.strategy !== 'lite'
        || !vigoliumRuntime.selected.includes('subdomains')
        || vigoliumRuntime.selected.includes('vigolium_dast')) {
        throw new Error(`Vigolium nativo incompleto: ${JSON.stringify(vigoliumRuntime)}`);
      }
      await browserPage.locator('#batchModeToggle').evaluate((element) => {
        element.checked = true;
        element.dispatchEvent(new Event('change', { bubbles: true }));
      });
      if (await browserPage.locator('#batchWrap').evaluate((element) => getComputedStyle(element).display) === 'none') {
        throw new Error('toggle React da fila não atualizou o painel');
      }
      await browserPage.locator('.findings-search-chip[data-q="login"]').click();
      if (await browserPage.locator('#findingsSearchInput').inputValue() !== 'login') {
        throw new Error('busca/chip de findings perdeu o listener');
      }
      const nativeRuntime = await browserPage.evaluate(async () => {
        const services = window.__ghostreconNativeServices;
        const streamOk = await consumeReconStreamFromResponse(
          new Response([
            '{"type":"progress","pct":17}',
            '{"type":"pipe","name":"vigolium_engine","state":"active"}',
            '{"type":"pipe_detail","name":"vigolium_engine","current":1,"total":3}',
            '',
          ].join('\n'), { headers: { 'Content-Type': 'application/x-ndjson' } }),
          0,
          null,
        );
        const state = services?.pipeline?.getState?.();
        const result = {
          calls: { ...services?.calls },
          currentNode: state?.currentNode,
          detail: state?.nodes?.vigolium_dast?.detail,
          marker: document.body.dataset.ghostreconNativeServices,
          progress: state?.progress,
          streamOk,
          version: services?.version,
        };
        resetPipelineVisual();
        setProgress(0);
        return result;
      });
      if (nativeRuntime.marker !== '1' || nativeRuntime.version !== 1 || !nativeRuntime.streamOk
        || nativeRuntime.calls.infraHistory < 1 || nativeRuntime.calls.runForm < 1
        || nativeRuntime.calls.findings < 1 || nativeRuntime.calls.pipeline < 1
        || nativeRuntime.currentNode !== 'vigolium_dast' || nativeRuntime.detail !== '1/3'
        || nativeRuntime.progress !== 17) {
        throw new Error(`ponte nativa incompleta: ${JSON.stringify(nativeRuntime)}`);
      }
      await browserPage.locator('#batchModeToggle').evaluate((element) => {
        element.checked = false;
        element.dispatchEvent(new Event('change', { bubbles: true }));
      });
      await browserPage.locator('#domainInput').fill('example.test');
      await browserPage.locator('#manualAuthorizationToggle').evaluate((element) => {
        element.checked = true;
        element.dispatchEvent(new Event('change', { bubbles: true }));
      });
      await browserPage.locator('#runBtn').click();
      await browserPage.waitForFunction(
        () => window.__ghostreconNativeServices?.calls?.manualRecon >= 1
          && !document.querySelector('#runBtn')?.classList.contains('running'),
        undefined,
        { timeout: 10_000 },
      );
      const manualRuntime = await browserPage.evaluate(() => ({
        calls: window.__ghostreconNativeServices?.calls?.manualRecon,
        status: document.querySelector('#statusText')?.textContent,
      }));
      if (manualRuntime.calls < 1 || manualRuntime.status !== 'RECON COMPLETO') {
        throw new Error(`RUN manual nativo incompleto: ${JSON.stringify(manualRuntime)}`);
      }
      const findingsBefore = await browserPage.locator('.findings-panel').boundingBox();
      if (!findingsBefore) throw new Error('painel Findings sem geometria');
      await browserPage.getByRole('button', { name: 'Aumentar painel de findings' }).click();
      await browserPage.waitForFunction(
        (beforeWidth) => document.querySelector('.findings-panel')?.getBoundingClientRect().width > beforeWidth + 20,
        findingsBefore.width,
      );
      const findingsAfter = await browserPage.locator('.findings-panel').boundingBox();
      if (!findingsAfter
        || Math.abs((findingsAfter.x + findingsAfter.width) - (findingsBefore.x + findingsBefore.width)) > 1
        || findingsAfter.width <= findingsBefore.width) {
        throw new Error(`borda direita de Findings deslocou: ${JSON.stringify({ findingsBefore, findingsAfter })}`);
      }
      await browserPage.getByRole('button', { name: 'Restaurar tamanho do painel de findings' }).click();
      await browserPage.getByRole('button', { name: 'Ajuda: painel esquerdo' }).click();
      if (await browserPage.locator('#sidebarHelpOverlay').evaluate((element) => getComputedStyle(element).display) === 'none') {
        throw new Error('handler React do modal de ajuda não abriu o overlay');
      }
      await browserPage.evaluate(() => closeSidebarHelpModal());
      await browserPage.locator('#autoRunBtn').click();
      const display = await browserPage.locator('#autoModeModal').evaluate((element) => getComputedStyle(element).display);
      if (display === 'none') throw new Error('modal Auto não abriu');
      await browserPage.waitForFunction(
        () => document.querySelector('#neurosploitProfileSelect')?.value === '7',
      );
      await browserPage.locator('#autoEngagementIdInput').fill('ENG-smoke');
      const beforeAutoCalls = await browserPage.evaluate(
        () => window.__ghostreconNativeServices?.calls?.autoForge || 0,
      );
      await browserPage.locator('#autoTargetInput').fill('example.test');
      await browserPage.locator('#autoStartBtn').click();
      await browserPage.waitForFunction(
        (baseline) => window.__ghostreconNativeServices?.calls?.autoForge > baseline
          && document.querySelector('#statusText')?.textContent === 'AUTO COMPLETO',
        beforeAutoCalls,
        { timeout: 10_000 },
      );
      const autoRuntime = await browserPage.evaluate(() => ({
        calls: window.__ghostreconNativeServices?.calls?.autoForge,
        sessionId: localStorage.getItem('ghostrecon.auto.lastSessionId'),
        status: document.querySelector('#statusText')?.textContent,
      }));
      if (autoRuntime.calls <= beforeAutoCalls || autoRuntime.sessionId !== 'AUTO-smoke'
        || autoRuntime.status !== 'AUTO COMPLETO') {
        throw new Error(`AUTO nativo incompleto: ${JSON.stringify(autoRuntime)}`);
      }
    },
  },
  { path: '/como-usar.html', page: 'guide', selector: 'main' },
  {
    path: '/ghostia.html',
    page: 'ghostia',
    selector: '#ghostIaMessageInput',
    setup: async (browserPage) => {
      let created = false;
      let sent = false;
      await browserPage.route('**/api/csrf-token', (route) => route.fulfill({
        contentType: 'application/json', body: JSON.stringify({ token: 'ghostia-smoke-csrf' }),
      }));
      await browserPage.route('**/api/artex/status', (route) => route.fulfill({
        contentType: 'application/json',
        body: JSON.stringify({
          ok: true, online: true, canManage: true,
          chatgptPlan: { connected: false }, ghostreconMcp: { enabled: true },
          profiles: [{ id: 7, name: 'OpenAI smoke', format: 'openai-responses', model: 'fixture-model', is_default: true, api_key_hint: 'test' }],
          conversations: created ? [{ id: 77, title: 'Smoke GhostIA', agent_key: 'ghostia', llm_profile_id: 7, running: sent }] : [],
        }),
      }));
      await browserPage.route('**/api/artex/llm/profiles/7/test', (route) => route.fulfill({
        contentType: 'application/json',
        body: JSON.stringify({ ok: true, result: { ok: true, latency_ms: 14, model: 'fixture-model', reply: 'PROVIDER_OK' } }),
      }));
      const hackbotBindings = Object.fromEntries(['orchestrator', 'researcher', 'analyst', 'document_analyst', 'tutor'].map((name) => [name, {
        model: 'fixture-model', base_url: 'http://127.0.0.1:11434/v1', api_key_env: 'LOCAL_LLM_API_KEY', configured: true,
      }]));
      const hackbotAgents = ['orchestrator', 'researcher', 'analyst', 'document_analyst', 'tutor'].map((name) => ({
        name, label: name === 'orchestrator' ? 'Orquestrador' : name, role: `Função ${name}`, tools: [], binding: hackbotBindings[name],
      }));
      await browserPage.route('**/api/hackbot/status', (route) => route.fulfill({ contentType: 'application/json', body: JSON.stringify({ ok: true, online: true, runtime: { runtime_ready: true, dependencies: {} }, config: { bindings: hackbotBindings }, agents: hackbotAgents }) }));
      await browserPage.route('**/api/hackbot/agents', (route) => route.fulfill({ contentType: 'application/json', body: JSON.stringify({ ok: true, agents: hackbotAgents }) }));
      await browserPage.route('**/api/hackbot/models', (route) => route.fulfill({ contentType: 'application/json', body: JSON.stringify({ ok: true, models: [] }) }));
      await browserPage.route('**/api/hackbot/conversations', (route) => route.fulfill({ contentType: 'application/json', body: JSON.stringify({ ok: true, conversations: [] }) }));
      await browserPage.route('**/api/artex/conversations**', async (route) => {
        const request = route.request();
        const url = new URL(request.url());
        if (url.pathname.endsWith('/messages/1')) {
          await route.fulfill({ contentType: 'application/json', body: JSON.stringify({ ok: true, detail: 'Responda API_OK' }) });
          return;
        }
        if (url.pathname.endsWith('/messages/2')) {
          await route.fulfill({ contentType: 'application/json', body: JSON.stringify({ ok: true, detail: 'API_OK' }) });
          return;
        }
        if (url.pathname.endsWith('/messages') && request.method() === 'GET') {
          sent = false;
          await route.fulfill({
            contentType: 'application/json',
            body: JSON.stringify({
              ok: true, running: false, cursor: sent ? 1 : 2,
              items: [
                { seq: 1, kind: 'user', worker: 'ghostia', summary: 'Responda API_OK' },
                { seq: 2, kind: 'result', worker: 'ghostia', summary: 'API_OK', output_tokens: 3 },
              ],
            }),
          });
          return;
        }
        if (url.pathname.endsWith('/messages') && request.method() === 'POST') {
          sent = true;
          await route.fulfill({ contentType: 'application/json', status: 202, body: JSON.stringify({ ok: true, result: { status: 'accepted' } }) });
          return;
        }
        if (url.pathname.endsWith('/conversations') && request.method() === 'POST') {
          created = true;
          await route.fulfill({ contentType: 'application/json', body: JSON.stringify({ ok: true, conversation: { id: 77, title: 'Smoke GhostIA', llm_profile_id: 7 } }) });
          return;
        }
        await route.fulfill({ contentType: 'application/json', status: 404, body: JSON.stringify({ ok: false, error: 'smoke route ausente' }) });
      });
    },
    verify: async (browserPage) => {
      const marker = await browserPage.evaluate(() => document.body.dataset.ghostreconNativePage);
      if (marker !== 'ghostia') throw new Error(`GhostIA não é React nativa: ${marker}`);
      await browserPage.getByRole('button', { name: 'Multiagentes' }).click();
      await browserPage.waitForSelector('.ghostia-hackbot-host .hackbot-page-shell.is-embedded');
      if (!String(await browserPage.locator('.hackbot-embedded-header').textContent()).includes('Equipe HackBot')) {
        throw new Error('HackBot não apareceu dentro da GhostIA');
      }
      await browserPage.getByRole('button', { name: 'Chat Artex' }).click();
      await browserPage.getByRole('button', { name: 'Testar provider' }).click();
      await browserPage.waitForFunction(() => document.querySelector('.ghostia-page-notice')?.textContent?.includes('PROVIDER_OK'));
      await browserPage.locator('#ghostIaMessageInput').fill('Responda API_OK');
      await browserPage.getByRole('button', { name: 'Enviar' }).click();
      await browserPage.waitForFunction(() => document.querySelector('.ghostia-page-message.is-agent')?.textContent?.includes('API_OK'));
      if (!String(await browserPage.locator('.ghostia-page-message.is-agent').textContent()).includes('API_OK')) {
        throw new Error('resposta da GhostIA não chegou ao transcript React');
      }
    },
  },
  {
    path: '/hackbot.html',
    page: 'hackbot',
    selector: '.hackbot-page-shell',
    setup: async (browserPage) => {
      const sessionId = 'aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee';
      let created = false;
      await browserPage.route('**/api/csrf-token', (route) => route.fulfill({
        contentType: 'application/json', body: JSON.stringify({ token: 'hackbot-smoke-csrf' }),
      }));
      const bindings = Object.fromEntries(['orchestrator', 'researcher', 'analyst', 'document_analyst', 'tutor'].map((name) => [name, {
        model: 'fixture-model', base_url: 'http://127.0.0.1:11434/v1', api_key_env: 'LOCAL_LLM_API_KEY', configured: true,
      }]));
      const agents = [
        { name: 'orchestrator', label: 'Orquestrador', role: 'Planeja e delega', tools: ['plan'] },
        { name: 'researcher', label: 'Pesquisador', role: 'Pesquisa fontes', tools: ['web_search'] },
        { name: 'analyst', label: 'Analista SARIF', role: 'Analisa SARIF', tools: ['load_sarif'] },
        { name: 'document_analyst', label: 'Analista de documentos', role: 'Analisa documentos', tools: ['load_document'] },
        { name: 'tutor', label: 'Tutor', role: 'Explica conceitos', tools: [] },
      ];
      await browserPage.route('**/api/hackbot/status', (route) => route.fulfill({
        contentType: 'application/json',
        body: JSON.stringify({ ok: true, online: true, runtime: { runtime_ready: true, dependencies: {} }, config: { bindings }, agents }),
      }));
      await browserPage.route('**/api/hackbot/agents', (route) => route.fulfill({
        contentType: 'application/json', body: JSON.stringify({ ok: true, agents: agents.map((item) => ({ ...item, binding: bindings[item.name] })) }),
      }));
      await browserPage.route('**/api/hackbot/models', (route) => route.fulfill({
        contentType: 'application/json', body: JSON.stringify({ ok: true, models: [{ id: 'fixture', label: 'Fixture', model: 'fixture-model', base_url: 'http://127.0.0.1:11434/v1', api_key_env: 'LOCAL_LLM_API_KEY' }] }),
      }));
      await browserPage.route('**/api/hackbot/conversations**', async (route) => {
        const request = route.request();
        const url = new URL(request.url());
        if (url.pathname.endsWith('/messages') && request.method() === 'POST') {
          await route.fulfill({
            contentType: 'application/json',
            body: JSON.stringify({
              ok: true,
              session: { id: sessionId, entries: [
                { role: 'user', content: 'Responda HACKBOT_OK', agent: 'orchestrator' },
                { role: 'assistant', content: 'HACKBOT_OK', agent: 'orchestrator', usage: { output_tokens: 3 }, steps: [{ id: '1', agent: 'orchestrator', title: 'plano', status: 'done' }] },
              ] },
            }),
          });
          return;
        }
        if (url.pathname.endsWith('/messages') && request.method() === 'GET') {
          await route.fulfill({ contentType: 'application/json', body: JSON.stringify({ ok: true, session: { id: sessionId, entries: [] }, conversation: { id: sessionId, agent: 'orchestrator' } }) });
          return;
        }
        if (url.pathname.endsWith('/conversations') && request.method() === 'POST') {
          created = true;
          await route.fulfill({ contentType: 'application/json', status: 201, body: JSON.stringify({ ok: true, conversation: { id: sessionId, title: 'Smoke HackBot', agent: 'orchestrator', last_status: 'idle' } }) });
          return;
        }
        if (url.pathname.endsWith('/conversations') && request.method() === 'GET') {
          await route.fulfill({ contentType: 'application/json', body: JSON.stringify({ ok: true, conversations: created ? [{ id: sessionId, title: 'Smoke HackBot', agent: 'orchestrator', last_status: 'idle' }] : [] }) });
          return;
        }
        await route.fulfill({ contentType: 'application/json', status: 404, body: JSON.stringify({ ok: false, error: 'smoke route HackBot ausente' }) });
      });
    },
    verify: async (browserPage) => {
      const marker = await browserPage.evaluate(() => document.body.dataset.ghostreconNativePage);
      if (marker !== 'hackbot') throw new Error(`HackBot não é React nativo: ${marker}`);
      await browserPage.locator('.hackbot-composer textarea').fill('Responda HACKBOT_OK');
      await browserPage.getByRole('button', { name: 'Enviar' }).click();
      await browserPage.waitForFunction(() => document.querySelector('.hackbot-message.is-assistant')?.textContent?.includes('HACKBOT_OK'));
      await browserPage.getByRole('button', { name: 'Agentes' }).click();
      if (await browserPage.locator('.hackbot-agent-grid article').count() !== 5) throw new Error('equipe HackBot incompleta no React');
      await browserPage.getByRole('button', { name: 'Modelos' }).click();
      if (await browserPage.locator('.hackbot-model-list article').count() !== 5) throw new Error('roteamento de modelos incompleto no React');
    },
  },
  {
    path: '/cortex.html',
    page: 'cortex',
    selector: '#cortexMain',
    setup: async (browserPage) => {
      await browserPage.route('**/api/brain/categories', (route) => route.fulfill({
        contentType: 'application/json',
        body: JSON.stringify({ items: [] }),
      }));
    },
    verify: async (browserPage) => {
      const runtime = await browserPage.evaluate(() => ({
        marker: document.body.dataset.ghostreconNativeCortex,
        scripts: document.querySelectorAll('script[data-ghostrecon-react-script="cortex"]').length,
      }));
      if (runtime.marker !== '1' || runtime.scripts !== 0) {
        throw new Error(`Cortex não é React nativo: ${JSON.stringify(runtime)}`);
      }
      await browserPage.locator('#btnFakeBrain').click();
      await browserPage.waitForFunction(
        () => document.querySelectorAll('#railList .nav-item').length === 4,
        undefined,
        { timeout: 5_000 },
      );
      await browserPage.locator('label[for="toggleObsidianGraph"]').click();
      await browserPage.waitForFunction(
        () => Boolean(document.querySelector('#canvasBody .node:not(.node--float)')),
        undefined,
        { timeout: 5_000 },
      );
      await browserPage.locator('#canvasBody .node').first().evaluate((element) => element.click());
      if (await browserPage.locator('#drawer').getAttribute('aria-hidden') !== 'false') {
        throw new Error('drawer React do Cortex não abriu');
      }
      await browserPage.keyboard.press('Escape');
      if (await browserPage.locator('#drawer').getAttribute('aria-hidden') !== 'true') {
        throw new Error('Escape não fechou drawer do Cortex');
      }
    },
  },
  {
    path: '/post-exploitation.html',
    page: 'post-exploitation',
    selector: '#progressFill',
    setup: async (browserPage) => {
      await browserPage.route('**/api/searchsploit?**', (route) => route.fulfill({
        contentType: 'application/json',
        body: JSON.stringify({
          RESULTS_EXPLOIT: [{ Title: 'Apache 2.4 test exploit', Path: 'webapps/99999.py', 'EDB-ID': '99999' }],
        }),
      }));
    },
    verify: async (browserPage) => {
      const state = await browserPage.evaluate(() => ({
        copyCmd: typeof window.copyCmd,
        marker: document.body.dataset.ghostreconNativePage,
        progress: document.querySelector('#progressFill')?.style.width || '',
        runSearchsploit: typeof window.runSearchsploit,
        scripts: document.querySelectorAll('script[data-ghostrecon-react-script="post-exploitation"]').length,
      }));
      if (state.copyCmd !== 'function' || state.runSearchsploit !== 'function' || !state.progress
        || state.marker !== 'post-exploitation' || state.scripts !== 0) {
        throw new Error(`runtime pós-exploração incompleto: ${JSON.stringify(state)}`);
      }
      const status = browserPage.locator('.trail-card-status').first();
      await status.click();
      if (await status.getAttribute('data-status') !== 'in-progress') {
        throw new Error('listener de progresso ausente ou registrado em duplicidade');
      }
      const storedProgress = await browserPage.evaluate(() => localStorage.getItem('ghostrecon_postex_progress'));
      if (!storedProgress?.includes('in-progress')) throw new Error('progresso Post-Ex não foi persistido');
      await browserPage.locator('.trail-card[data-mod="shell"]').click();
      if (!await browserPage.locator('body').evaluate((body) => body.classList.contains('module-view'))) {
        throw new Error('navegação React não abriu o módulo Post-Ex');
      }
      const copyButton = browserPage.locator('#mod-shell .cmd-copy-btn').first();
      await copyButton.click();
      await browserPage.waitForFunction(() => document.querySelector('#mod-shell .cmd-copy-btn')?.textContent?.includes('Copiado'));
      if (!String(await copyButton.textContent()).includes('Copiado')) {
        throw new Error('feedback de clipboard Post-Ex ausente');
      }
      await browserPage.locator('#moduleBackBtn').click();
      await browserPage.locator('.trail-card[data-mod="searchsploit"]').click();
      await browserPage.locator('#ssInput').fill('Apache 2.4');
      await browserPage.locator('#ssInput').press('Enter');
      await browserPage.waitForFunction(() => document.querySelector('#ssResults')?.textContent?.includes('EDB-99999'));
    },
  },
  {
    path: '/reporte.html',
    page: 'report',
    selector: '#reportJsonDockWrap',
    setup: async (browserPage) => {
      await browserPage.addInitScript(() => {
        sessionStorage.setItem('ghostrecon_reporte_payload', JSON.stringify({
          target: 'example.test',
          updatedAt: '2026-11-18T00:00:00.000Z',
          findings: [{
            fingerprint: 'a'.repeat(64),
            type: 'xss',
            prio: 'high',
            value: 'reflected xss',
            url: 'https://example.test/search?q=x',
            owasp: [{ id: 'A03' }],
            mitre: [{ id: 'T1059' }],
          }],
        }));
      });
      await browserPage.route('**/api/capabilities', (route) => route.fulfill({
        contentType: 'application/json', body: JSON.stringify({ ai: { openrouter: true } }),
      }));
      await browserPage.route('**/api/manual-validations/example.test', (route) => route.fulfill({
        contentType: 'application/json', body: JSON.stringify({ items: [] }),
      }));
      await browserPage.route('**/api/csrf-token', (route) => route.fulfill({
        contentType: 'application/json', body: JSON.stringify({ token: 'report-smoke-csrf' }),
      }));
      await browserPage.route('**/api/manual-validations', (route) => route.fulfill({
        contentType: 'application/json', body: JSON.stringify({ ok: true }),
      }));
    },
    verify: async (browserPage) => {
      await browserPage.waitForFunction(() => document.querySelectorAll('#list .row').length === 1);
      const runtime = await browserPage.evaluate(() => ({
        marker: document.body.dataset.ghostreconNativeReport,
        scripts: document.querySelectorAll('script[data-ghostrecon-react-script="report"]').length,
      }));
      if (runtime.marker !== '1' || runtime.scripts !== 0) {
        throw new Error(`Reporte não é React nativo: ${JSON.stringify(runtime)}`);
      }
      await browserPage.locator('#list .val-toggle').click();
      await browserPage.waitForFunction(
        () => document.querySelector('#list .val-toggle')?.getAttribute('aria-pressed') === 'true',
      );
      await browserPage.locator('#brainNo').click();
      if (await browserPage.locator('#btnAi').isDisabled()) {
        throw new Error('validação React não habilitou o relatório IA');
      }
    },
  },
  {
    path: '/tor-validator.html',
    page: 'tor-validator',
    selector: '#tor',
    setup: async (browserPage) => {
      await browserPage.route('**/api/tunnel/validate', (route) => route.fulfill({
        contentType: 'application/json',
        body: JSON.stringify({
          ok: true,
          validated: true,
          status: { active: true, tor: 'active', openvpn: 'inactive' },
          direct: { ok: true, ip: '198.51.100.10', code: 200 },
          tor: { ok: true, isTor: true, ip: '203.0.113.10', code: 200 },
        }),
      }));
    },
    verify: async (browserPage) => {
      await browserPage.waitForFunction(() => document.querySelector('#summary')?.textContent?.includes('VALIDADO'));
      const runtime = await browserPage.evaluate(() => ({
        marker: document.body.dataset.ghostreconNativePage,
        scripts: document.querySelectorAll('script[data-ghostrecon-react-script="tor-validator"]').length,
      }));
      if (runtime.marker !== 'tor-validator' || runtime.scripts !== 0) {
        throw new Error(`Tor Validator não é React nativo: ${JSON.stringify(runtime)}`);
      }
      await browserPage.locator('#autoBtn').click();
      if (await browserPage.locator('#autoBtn').getAttribute('aria-pressed') !== 'true') {
        throw new Error('toggle automático do Tor Validator não atualizou');
      }
    },
  },
  { path: '/vigolium-workbench.html', page: 'vigolium-workbench', selector: '#requestsRows' },
  {
    path: '/wifi-pentest.html',
    page: 'wifi-pentest',
    selector: '#statusBox',
    setup: async (browserPage) => {
      await browserPage.route('**/api/wifi/capabilities', (route) => route.fulfill({
        contentType: 'application/json',
        body: JSON.stringify({ wifi: {
          kali: true, adapter: { found: true }, preferredIface: 'wlan1', message: 'ready',
          tools: { aircrack: true, wifite: true },
        } }),
      }));
      await browserPage.route('**/api/csrf-token', (route) => route.fulfill({
        contentType: 'application/json', body: JSON.stringify({ token: 'wifi-smoke-csrf' }),
      }));
      await browserPage.route('**/api/wifi/stream', (route) => route.fulfill({
        contentType: 'application/x-ndjson',
        body: [
          JSON.stringify({ type: 'start' }),
          JSON.stringify({ type: 'finding', finding: { type: 'wifi', prio: 'high', value: 'LabAP', meta: 'wlan1' } }),
          JSON.stringify({ type: 'done', ok: true, reason: 'smoke', findingCount: 1 }),
          '',
        ].join('\n'),
      }));
    },
    verify: async (browserPage) => {
      await browserPage.waitForFunction(() => document.querySelector('#statusBox')?.textContent?.includes('ALFA MT7612U detetada'));
      const runtime = await browserPage.evaluate(() => ({
        marker: document.body.dataset.ghostreconNativePage,
        scripts: document.querySelectorAll('script[data-ghostrecon-react-script="wifi-pentest"]').length,
      }));
      if (runtime.marker !== 'wifi-pentest' || runtime.scripts !== 0) {
        throw new Error(`Wi-Fi Pentest não é React nativo: ${JSON.stringify(runtime)}`);
      }
      await browserPage.locator('#targets').fill('LabAP');
      await browserPage.locator('#labConfirm').check();
      await browserPage.locator('#btnRun').click();
      await browserPage.waitForFunction(() => document.querySelector('#findingsBox')?.textContent?.includes('LabAP'));
      if (!String(await browserPage.locator('#logBox').textContent()).includes('done: smoke findings=1')) {
        throw new Error('stream NDJSON Wi-Fi não chegou ao log React');
      }
    },
  },
];

const browser = await chromium.launch({ headless: true });
const failures = [];

try {
  for (const item of pages) {
    const page = await browser.newPage();
    const pageErrors = [];
    page.on('pageerror', (error) => pageErrors.push(error.message));
    if (item.setup) await item.setup(page);
    await page.goto(`${baseUrl}${item.path}`, { waitUntil: 'domcontentloaded' });
    await page.waitForFunction(
      (expected) => document.body.dataset.ghostreconReactPage === expected,
      item.page,
      { timeout: 10_000 },
    );
    await page.waitForFunction(
      () => document.body.dataset.ghostreconLegacyReady === '1',
      undefined,
      { timeout: 10_000 },
    );
    if (item.page !== 'cockpit') {
      const reactTree = await page.evaluate(() => document.body.dataset.ghostreconReactTree);
      if (reactTree !== '1') throw new Error(`${item.path}: DOM auxiliar não pertence ao React`);
    }
    await page.locator(item.selector).first().waitFor({ state: 'attached', timeout: 10_000 });
    if (item.verify) await item.verify(page);
    await page.waitForTimeout(500);
    if (pageErrors.length) failures.push(`${item.path}: ${pageErrors.join(' | ')}`);
    console.log(`UI_SMOKE_OK ${item.path} -> ${item.page}`);
    await page.close();
  }
} finally {
  await browser.close();
}

if (failures.length) {
  throw new Error(`Erros de página React:\n${failures.join('\n')}`);
}
