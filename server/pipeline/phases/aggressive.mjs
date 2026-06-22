import { randomBytes } from 'crypto';
import { sevToPrio, sevToScore } from '../../lib/severity.mjs';
import { fetchCrtShSubdomains } from '../../modules/subdomains.js';
import { resolves } from '../../modules/dns.js';
import { probeHttp, mapPool } from '../../modules/probe.js';
import { extractSuspiciousHtmlComments } from '../../modules/html-surface.js';
import { analyzeSecurityHeaders, summarizeSecurityHeaderGaps } from '../../modules/security-headers.js';
import { analyzeSuspiciousResponseHeaders } from '../../modules/header-intel.js';
import { peekTlsCertificate } from '../../modules/tls-cert.js';
import { crawlRobotsAndSitemapsForOrigin } from '../../modules/robots-sitemap.js';
import {
  parseOutOfScopeEnv,
  hostInReconScope,
  urlInReconScope,
  parseOutOfScopeClientInput,
  mergeOutOfScopeLists,
} from '../../modules/scope.js';
import { fetchCommonCrawlUrls } from '../../modules/commoncrawl.js';
import { fetchRdapSummary } from '../../modules/rdap.js';
import { fetchVirustotalSubdomains } from '../../modules/virustotal.js';
import { fetchWaybackUrls, filterInterestingUrls, extractJsUrls } from '../../modules/wayback.js';
import { extractParamsFromUrls } from '../../modules/params.js';
import { analyzeJsUrl } from '../../modules/js-analyzer.js';
import { scanSecrets } from '../../modules/secrets.js';
import { githubCodeSearch, githubRepoSearch } from '../../modules/github.js';
import { cloneGithubReposForTarget, githubCloneConfig } from '../../modules/github-clone.js';
import { parseGithubManualRepoList } from '../../modules/github-manual-repos.js';
import { buildDorks } from '../../modules/dorks.js';
import { scoreEndpointPath, scoreParamName } from '../../modules/scoring.js';
import { fetchDnsEnrichment } from '../../modules/dns-enrichment.js';
import { fetchWellKnownSecurityTxt, fetchWellKnownOpenIdConfiguration } from '../../modules/wellknown.js';
import { runEvidenceVerification, runMicroExploitVariants } from '../../modules/verify.js';
import { runWebshellHeuristicProbe } from '../../modules/webshell-probe.js';
import { runSqlmapModule } from '../../modules/sqlmap-runner.js';
import { harvestOpenApiFromOrigins, tryGraphqlMinimalProbe } from '../../modules/openapi-harvest.js';
import { discoverAssetHints, detectTakeoverCandidates } from '../../modules/asset-discovery.js';
import { resolveReconProfile } from '../../modules/runtime-profile.js';
import { fetchArchiveToolUrls } from '../../modules/archive-tools.js';
import { wafw00fFingerprint } from '../../modules/waf-fingerprint.js';
import { discoverParamsActive } from '../../modules/param-discovery.js';
import { resolveCnameChain, matchProviderByCname, matchProviderBody } from '../../modules/takeover.js';
import { crawlWithKatana } from '../../modules/js-crawler.js';
import { validateSecretFindings } from '../../modules/secret-validation.js';
import { limits } from '../../config.js';
import { listRuns } from '../../modules/db.js';
import { collectUniqueIpv4, shodanHostSummary } from '../../modules/ip-intel.js';
import { googleCseSearch } from '../../modules/google-cse.js';
import { getKaliCapabilities, runKaliAggressiveScan } from '../../modules/kali-scan.js';
import {
  augmentProcessPathFromCommonDirs,
  prependExtraPathToEnvPath,
  parseExtraPathInput,
} from '../../modules/tool-path.js';
import { enumerateSubdomainsWithSubfinder, enumerateSubdomainsWithAmass } from '../../modules/kali-subdomain-tools.js';
import { withProvenance } from '../../modules/finding-provenance.js';
import { hostLiteralForUrl, targetIsIp } from '../../modules/recon-target.js';
import { secretMaterialFingerprint } from '../../modules/db-common.js';
import { syncValidatedCortexFindingToGhostKb } from '../../modules/ghost-kb-sync.js';
import { gateModules, applyWatermarkHeaders } from '../../modules/opsec.mjs';
import { buildAuthzPlan, runAuthzMatrix, fingerprintBody } from '../../modules/authz-matrix.mjs';
import { bruteforceCloud } from '../../modules/cloud-bruteforce.mjs';
import { monitorCt, classifyNewSubs } from '../../modules/ct-monitor.mjs';
import { buildVerificationPlan } from '../../modules/dom-xss-verify.mjs';
import { probeGraphqlEndpoint } from '../../modules/graphql-recon.mjs';
import { jsBundleToFindings } from '../../modules/js-intel.mjs';
import { analyzeJwt } from '../../modules/jwt-lab.mjs';
import { buildOobPayloads } from '../../modules/oob-collaborator.mjs';
import { detectOriginCandidates, originDiscoveryToFindings, resolveSubsForOrigin } from '../../modules/origin-discovery.mjs';
import { mutatePayload } from '../../modules/payload-mutator.mjs';
import { buildRacePlan } from '../../modules/race-harness.mjs';
import { planSpray } from '../../modules/cred-spray.mjs';
import { fingerprintLovable } from '../../modules/lovable-fingerprint.js';
import { runSupabaseAudit, discoverSupabaseFromTarget } from '../../modules/supabase-audit.mjs';
import { discoverFirebaseFromTarget, runFirebaseAudit, extractFirebaseConfig } from '../../modules/firebase-audit.mjs';
import { auditClientSideAuth, mergeClientAuthFindings } from '../../modules/client-auth-audit.mjs';
import {
  auditClientSurface,
  auditJsSurface,
  auditHtmlSurface,
  auditHeaderSurface,
  mergeClientSurfaceFindings,
  extractSourceMapUrl,
  probeSourceMapDisclosure,
} from '../../modules/client-surface-audit.mjs';
import { auditOidcMetadata } from '../../modules/identity-surface.mjs';
import { runCurlProbeModule } from '../../modules/curl-probe.mjs';
import { runCorsAudit } from '../../modules/cors-audit.mjs';
import { auditCookieSession } from '../../modules/cookie-session-audit.mjs';
import { auditCsrfFlows } from '../../modules/csrf-flow-audit.mjs';
import { runJwtJwksAudit } from '../../modules/jwt-jwks-audit.mjs';
import { runServiceWorkerAudit } from '../../modules/service-worker-audit.mjs';
import { runWebSocketRecon } from '../../modules/websocket-recon.mjs';
import { auditHppParamPollution } from '../../modules/hpp-param-pollution.mjs';
import { runDomClobberingAudit } from '../../modules/dom-clobbering-audit.mjs';
import { runEmailSecurityDeep } from '../../modules/email-security-deep.mjs';
import { rankSecretFindings } from '../../modules/secrets-context-ranker.mjs';
import {
  findPreviousApiContractSnapshots,
  runApiContractDiff,
} from '../../modules/api-contract-diff.mjs';
import {
  quickValidateTor,
  executeNavegationPlaybook,
  getNavegationTunnelStatus,
  validateNavegationTorPath,
  isNavigatorModeActive,
} from '../../modules/navegation.js';
import {
  beginTorStrictScope,
  refuseToRun as torRefuseToRun,
  snapshotTelemetry as torSnapshotTelemetry,
} from '../../modules/tor-strict.js';
import { newnym as torNewnym } from '../../modules/tor-control.js';

import path from 'path';
import { ROOT, firstIpv4FromDnsRecords, sleep } from '../pipeline-shared.mjs';



export async function runAggressivePhase(s) {
  const {
    domain,
    exactMatch,
    modules,
    emit,
    kaliMode,
    auth,
    profile,
    outOfScopeClientRaw,
    projectNameRaw,
    shannonGithubRepos,
    identityCtrl,
    navegation,
    navigatorMode,
    apexHostIsIp,
    bountyCtx,
    runtimeProfile,
    domainStr,
    outOfScopeList,
    findings,
    stats,
    addFinding,
    log,
    pipe,
    skipKaliSubPipe,
    progress,
    subdomainsAlive,
    probedHosts,
    seenEp,
    tlsSanHosts,
    dnsAForHost,
  } = s;

    // ── KALI: nmap / searchsploit / ffuf / nuclei ──
    if (kaliMode) {
      pipe('kali', 'active');
      progress(86);
      const cap = await getKaliCapabilities();
      if (cap.kali) {
        // Só roda wpscan se o passivo já indicou WordPress.
        // Evidência vem de findings do tipo "tech" (geradas no probeHttp).
        const wpHosts = new Set();
        for (const f of findings) {
          if (f?.type !== 'tech') continue;
          const v = String(f.value || '');
          if (!/wordpress/i.test(v)) continue;
          const meta = String(f.meta || '');
          const m = meta.match(/Detectado em\s+(.+)\s*$/i);
          if (m?.[1]) wpHosts.add(m[1]);
        }

        const wordpressTargets = [...wpHosts]
          .slice(0, 10)
          .map((h) => {
            const origin = s.originByHost.get(h)?.origin;
            if (origin) return origin;
            const hl = hostLiteralForUrl(h);
            return [`https://${hl}/`, `http://${hl}/`];
          })
          .flat()
          .filter(Boolean);

        let xssSignals = false;
        let sqliSignals = false;
        const xssParamRe = /[?&](q|query|search|s|keyword|term|message|comment|title|name)=/i;
        const sqliParamRe =
          /[?&](id|ids|user|user_id|uid|account|order|order_id|page|sort|filter|where|username|email|passwd|pwd|login)=/i;
        for (const u of s.paramUrlsForKali) {
          if (xssParamRe.test(u)) xssSignals = true;
          if (sqliParamRe.test(u)) sqliSignals = true;
          if (xssSignals && sqliSignals) break;
        }
        for (const f of findings) {
          if (f.type !== 'intel') continue;
          const v = String(f.value || '');
          if (/XSS candidate param/i.test(v)) xssSignals = true;
          if (/SQLi candidate param/i.test(v)) sqliSignals = true;
        }
        if (!xssSignals && !sqliSignals) {
          log(
            'Scan agressivo XSS/SQLi: sem sinais (URLs com parâmetros típicos nem candidatos intel) — nuclei tags xss/sqli, dalfox e xss_vibes em skip',
            'info',
          );
        } else {
          log(
            `Scan agressivo: sinais XSS=${xssSignals ? 'sim' : 'não'} SQLi=${sqliSignals ? 'sim' : 'não'}`,
            'info',
          );
        }

        const runKaliNuclei = Boolean(modules.includes('kali_nuclei'));
        const runKaliFfuf = Boolean(modules.includes('kali_ffuf'));
        const runKaliDirsearch = Boolean(modules.includes('kali_dirsearch'));
        const runKaliNmapAggressive = Boolean(modules.includes('kali_nmap_aggressive'));
        const runKaliNmapUdp = Boolean(modules.includes('kali_nmap_udp'));
        const runNmapCveMatch = Boolean(modules.includes('nmap_cve_match'));
        const runNmapBackportReview = Boolean(modules.includes('nmap_backport_review'));
        const runMysql3306Intel = Boolean(modules.includes('mysql_3306_intel'));
        const runKaliProxychains = Boolean(modules.includes('kali_proxychains'));
        const runInfoDisclosureErrors = Boolean(modules.includes('info_disclosure_errors'));
        const runInfoDisclosureHunter = Boolean(modules.includes('info_disclosure_hunter') || runInfoDisclosureErrors);

        await runKaliAggressiveScan({
          domain,
          subdomainsAlive,
          cap,
          log,
          addFinding,
          wordpressTargets,
          paramUrls: s.paramUrlsForKali,
          xssSignals,
          sqliSignals,
          runNuclei: runKaliNuclei,
          runFfuf: runKaliFfuf,
          runDirsearch: runKaliDirsearch,
          runNmapAggressive: runKaliNmapAggressive,
          runNmapUdp: runKaliNmapUdp,
          runNmapCveMatch,
          runNmapBackportReview,
          runMysql3306Intel: runMysql3306Intel,
          runInfoDisclosureHunter,
          runInfoDisclosureErrors,
          useProxychains: runKaliProxychains,
          auth,
          emit,
        });
      } else {
        log(`Modo Kali pedido mas ambiente não suporta: ${cap.message}`, 'warn');
        skipKaliSubPipe();
      }
      pipe('kali', 'done');
    } else {
      pipe('kali', 'skip');
      skipKaliSubPipe();
    }


}
