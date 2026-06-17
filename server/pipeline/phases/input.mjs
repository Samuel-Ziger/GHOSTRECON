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



export async function runInputPhase(s) {
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
    outOfScopeFromEnv,
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

    log(`Alvo: ${domain} | Módulos: ${modules.join(', ')} | Perfil: ${runtimeProfile.name}`, 'info');
    if (apexHostIsIp) {
      log(
        'Alvo é endereço IP — enumeração por CT/VirusTotal/subfinder e arquivo web por wildcard de domínio não se aplicam; HTTP/TLS/Kali seguem no IP.',
        'info',
      );
    }
    log(exactMatch ? 'Modo: exact match (aspas nos dorks)' : 'Modo: broad match', 'info');
    if (outOfScopeList.length) {
      log(`Fora de escopo (${outOfScopeList.length} regra(s)): ${outOfScopeList.join(', ')}`, 'info');
    }

    // ── INPUT ─────────────────────────────────────
    pipe('input', 'active');
    progress(5);
    pipe('input', 'done');

}
