import { getKaliCapabilities } from '../modules/kali-scan.js';
import { aiKeysConfigured } from '../modules/ai-dual-report.js';
import { getShannonCapabilities } from '../modules/shannon-capabilities.js';
import { getPentestGptCapabilities } from '../modules/pentestgpt-capabilities.js';
import { listModuleManifests } from '../modules/module-registry.mjs';

export function registerCapabilitiesRoutes(app, { ROOT }) {
  app.get('/api/capabilities', async (_req, res) => {
    try {
      const cap = await getKaliCapabilities();
      let shannon = null;
      try {
        shannon = await getShannonCapabilities({ ghostRoot: ROOT });
      } catch (e) {
        shannon = { ok: false, home: '', checks: {}, message: e?.message || String(e), prepHints: {} };
      }
      let pentestgpt = null;
      try {
        pentestgpt = await getPentestGptCapabilities({ ghostRoot: ROOT });
      } catch (e) {
        pentestgpt = {
          ok: false,
          home: '',
          checks: {},
          message: e?.message || String(e),
          prepHints: {},
          http: { configured: false, preview: '' },
        };
      }
      res.json({
        ...cap,
        ai: aiKeysConfigured(),
        modules: listModuleManifests(),
        shannon,
        pentestgpt,
      });
    } catch (e) {
      res.status(500).json({
        kali: false,
        message: e.message,
        tools: {},
        ai: aiKeysConfigured(),
        modules: listModuleManifests(),
        shannon: null,
        pentestgpt: null,
      });
    }
  });
}
