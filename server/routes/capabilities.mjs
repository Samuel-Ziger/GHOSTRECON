import { getKaliCapabilities } from '../modules/kali-scan.js';
import { getWifiCapabilities } from '../modules/kali-wifi.mjs';
import { aiKeysConfigured } from '../modules/ai-dual-report.js';
import { getShannonCapabilities } from '../modules/shannon-capabilities.js';
import { getPentestGptCapabilities } from '../modules/pentestgpt-capabilities.js';
import { getHexstrikeCapabilities } from '../modules/hexstrike-capabilities.mjs';
import { listModuleManifests } from '../modules/module-registry.mjs';
import { listExternalToolPacks } from '../modules/external-tools/catalog.mjs';
import { getVigoliumCapabilities } from '../../bridge/vigolium-capabilities.mjs';
import { githubCapabilities } from '../modules/github-token.mjs';
import { buildSupportMatrix } from '../app/support-matrix.mjs';

export function registerCapabilitiesRoutes(app, { ROOT }) {
  app.get('/api/capabilities', async (req, res) => {
    try {
      const cap = await getKaliCapabilities();
      const authenticated = Boolean(req.principal);
      let wifi = null;
      if (authenticated) {
        try {
          wifi = await getWifiCapabilities();
        } catch (e) {
          wifi = {
            ok: false,
            kali: Boolean(cap?.kali),
            message: e?.message || String(e),
            adapter: { found: false, matches: [] },
            tools: {},
            preferredIface: null,
            readyForAttack: false,
          };
        }
      } else {
        wifi = {
          ok: false,
          kali: Boolean(cap?.kali),
          message: 'Inventário WiFi/ALFA requer autenticação',
          adapter: { found: false, matches: [] },
          tools: {},
          preferredIface: null,
          readyForAttack: false,
        };
      }
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
      let hexstrike = null;
      try {
        hexstrike = await getHexstrikeCapabilities({ ghostRoot: ROOT });
      } catch (e) {
        hexstrike = {
          ok: false,
          installed: false,
          reachable: false,
          home: '',
          baseUrl: '',
          checks: {},
          message: e?.message || String(e),
          http: { configured: false, telemetry: false, healthDeepEnabled: false, health: null },
          mcp: { installed: false, commandHint: '' },
          prepHints: {},
        };
      }
      let vigolium = null;
      try {
        vigolium = await getVigoliumCapabilities({ ghostRoot: ROOT });
      } catch (e) {
        vigolium = { ok: false, installed: false, message: e?.message || String(e) };
      }
      const github = githubCapabilities();
      const githubPublic = authenticated
        ? github
        : { configured: Boolean(github?.configured), token_preview: null };
      const support = buildSupportMatrix({ observed: { vigolium, hexstrike } });

      res.json({
        ...cap,
        ai: aiKeysConfigured(),
        github: githubPublic,
        modules: listModuleManifests(),
        externalTools: listExternalToolPacks(),
        shannon,
        pentestgpt,
        hexstrike,
        vigolium,
        wifi,
        support,
      });
    } catch (e) {
      res.status(500).json({
        kali: false,
        message: e.message,
        tools: {},
        ai: aiKeysConfigured(),
        github: { configured: false, token_preview: null },
        modules: listModuleManifests(),
        externalTools: listExternalToolPacks(),
        shannon: null,
        pentestgpt: null,
        hexstrike: null,
        vigolium: null,
        wifi: null,
        support: buildSupportMatrix(),
      });
    }
  });
}
