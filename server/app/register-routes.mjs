import { registerInboundWebhooks } from '../modules/inbound-webhooks.js';
import { registerNewApiRoutes } from '../modules/api-extensions.js';
import { registerGhostDeskRoutes } from '../modules/ghostdesk.mjs';
import { registerSetupRoutes } from '../routes/setup.mjs';
import { registerReconStreamRoutes } from '../routes/recon-stream.mjs';
import { registerAutoReconRoutes } from '../routes/auto-recon.mjs';
import { registerProxyTunnelRoutes } from '../routes/proxy-tunnel.mjs';
import { registerMiscRoutes } from '../routes/misc.mjs';
import { registerCapabilitiesRoutes } from '../routes/capabilities.mjs';
import { registerAiRoutes } from '../routes/ai.mjs';
import { registerRunsRoutes } from '../routes/runs.mjs';
import { registerBrainRoutes } from '../routes/brain.mjs';
import { registerHandoffRoutes } from '../routes/handoff.mjs';
import { registerValidationsRoutes } from '../routes/validations.mjs';
import { registerVigoliumRoutes } from '../routes/vigolium.mjs';
import { registerGhostCommandRoutes } from '../routes/ghostcommand.mjs';
import { registerStaticRoutes } from '../routes/static.mjs';

/**
 * Monta todas as rotas HTTP na ordem do monólito original.
 * Rotas API antes de static/proxies; extensões e GhostDesk antes dos proxies.
 */
export function registerAllRoutes(app, deps) {
  const {
    runPipeline,
    ROOT,
    ghostProxy,
    httpHistory,
    issueCsrfToken,
    validateCsrfToken,
    requireCsrf,
    CSRF_TTL_MS,
    allowReconRequest,
    reconHttpHistory,
  } = deps;

  registerSetupRoutes(app, {
    issueCsrfToken,
    validateCsrfToken,
    CSRF_TTL_MS,
    reconHttpHistory,
  });

  registerReconStreamRoutes(app, {
    runPipeline,
    validateCsrfToken,
    allowReconRequest,
    ROOT,
    httpHistory,
  });
  registerAutoReconRoutes(app, {
    runPipeline,
    validateCsrfToken,
    allowReconRequest,
    ROOT,
  });

  registerProxyTunnelRoutes(app, { validateCsrfToken, ghostProxy, ROOT });
  registerMiscRoutes(app);
  registerCapabilitiesRoutes(app, { ROOT });
  registerAiRoutes(app, { validateCsrfToken, ROOT });
  registerRunsRoutes(app);
  registerBrainRoutes(app, { validateCsrfToken });
  registerHandoffRoutes(app, { validateCsrfToken });
  registerValidationsRoutes(app, { validateCsrfToken });
  registerVigoliumRoutes(app, { ROOT });
  registerGhostCommandRoutes(app, { runPipeline });

  registerInboundWebhooks(app);
  registerNewApiRoutes(app, { validateCsrfToken, requireCsrf });
  registerGhostDeskRoutes(app, { validateCsrfToken, requireCsrf });

  registerStaticRoutes(app, { ROOT });
}
