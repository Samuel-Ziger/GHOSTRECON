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
import { isAbortError, throwIfAborted } from '../../modules/http-utils.js';
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



export async function runFingerprintPhase(s) {
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
    const signal = s.signal || null;
    const urlAllowed = (url) => s.urlInScope(url);
    throwIfAborted(signal);

    // ── LOVABLE FINGERPRINT ───────────────────────
    s.lovableContext = null;
    if (!apexHostIsIp && modules.includes('lovable_fingerprint')) {
      pipe('lovable_fingerprint', 'active');
      try {
        const targetUrl = `https://${hostLiteralForUrl(domain)}/`;
        log(`Lovable fingerprint: analisando ${targetUrl}`, 'info');
        const lov = await fingerprintLovable(targetUrl, {
          pocDir: path.join(ROOT, 'pocs', 'supabase'),
          storeRawSecrets: false,
          signal,
          urlAllowed,
        });
        s.lovableContext = lov?.context || null;
        const lovFindings = Array.isArray(lov?.findings) ? lov.findings : [];
        for (const f of lovFindings) addFinding(withProvenance(f, 'lovable_fingerprint'));
        if (lov?.context?.pocPath) {
          const rel = path.relative(ROOT, lov.context.pocPath);
          log(`Lovable fingerprint: PoC Supabase salva em ${rel}`, 'success');
        } else if (lov?.context?.pocError) {
          log(`Lovable fingerprint: falha ao salvar PoC Supabase (${lov.context.pocError})`, 'warn');
        }
        if (lovFindings.length) {
          log(`Lovable fingerprint: ${lovFindings.length} achado(s)`, 'success');
        } else {
          log('Lovable fingerprint: sem achados relevantes', 'info');
        }
      } catch (e) {
        if (isAbortError(e, signal)) throw e;
        log(`Lovable fingerprint: ${e?.message || e}`, 'warn');
      }
      pipe('lovable_fingerprint', 'done');
    }

    // ── SUPABASE AUDIT ────────────────────────────
    if (!apexHostIsIp && modules.includes('supabase_audit')) {
      pipe('supabase_audit', 'active');
      try {
        const targetUrl = `https://${hostLiteralForUrl(domain)}/`;

        // Reutiliza contexto do lovable_fingerprint; senão extrai URL/key/token dos bundles do alvo
        let auditCtx = s.lovableContext;
        if (!auditCtx?.supabaseUrl || !auditCtx?.anonKey) {
          log('Supabase audit: extraindo URL/key dos bundles JS do alvo', 'info');
          const discovered = await discoverSupabaseFromTarget(targetUrl, {
            log,
            signal,
            urlAllowed,
          });
          auditCtx = discovered?.context || null;
        } else if (s.lovableContext?.bundleText && !auditCtx.bundleText) {
          auditCtx = { ...auditCtx, bundleText: s.lovableContext.bundleText };
        }

        if (auditCtx?.supabaseUrl && auditCtx?.anonKey) {
          log(`Supabase audit: anon key encontrada — testes usarão credenciais extraídas do alvo`, 'info');
          const envAuth = String(process.env.GHOSTRECON_SUPABASE_AUTH_TOKEN || '').trim() || null;
          const { findings: auditFindings, summary } = await runSupabaseAudit(auditCtx, {
            authToken: envAuth,
            targetUrl,
            log,
            // Writes precisam de um fluxo dedicado de autorização; env/token
            // apenas habilita contexto autenticado de leitura.
            writeProbes: false,
            signal,
            urlAllowed,
          });
          for (const f of auditFindings) addFinding(withProvenance(f, 'supabase_audit'));
          const crit = summary?.critical || 0;
          const high = summary?.high || 0;
          if (auditFindings.length) {
            log(`Supabase audit: ${auditFindings.length} achado(s) — ${crit} crítico(s) / ${high} alto(s)`, crit > 0 ? 'warn' : 'success');
          } else {
            log('Supabase audit: nenhuma vulnerabilidade detectada', 'info');
          }
          if (summary?.authTokenSource) {
            log(`Supabase audit: token autenticado obtido automaticamente (fonte: ${summary.authTokenSource})`, 'success');
          } else if (!envAuth) {
            log('Supabase audit: probes autenticados limitados — signup/auth anônimo desabilitados no projeto', 'info');
          }
        } else {
          log('Supabase audit: Supabase URL/key não encontrados — alvo pode não usar Supabase', 'info');
        }
      } catch (e) {
        if (isAbortError(e, signal)) throw e;
        log(`Supabase audit: ${e?.message || e}`, 'warn');
      }
      pipe('supabase_audit', 'done');
    }

    // ── FIREBASE AUDIT ────────────────────────────
    s.firebaseContext = null;
    if (!apexHostIsIp && modules.includes('firebase_audit')) {
      pipe('firebase_audit', 'active');
      try {
        const targetUrl = `https://${hostLiteralForUrl(domain)}/`;
        log('Firebase audit: descobrindo config nos bundles JS', 'info');
        const { config, bundleText } = await discoverFirebaseFromTarget(targetUrl, {
          log,
          signal,
          urlAllowed,
        });
        s.firebaseContext = config;
        if (config?.apiKey || config?.projectId) {
          const writeProbes = false;
          const { findings: fbFindings, summary } = await runFirebaseAudit(
            { ...config, bundleText },
            { targetUrl, log, writeProbes, signal, urlAllowed },
          );
          for (const f of fbFindings) addFinding(withProvenance(f, 'firebase_audit'));
          const crit = summary?.critical || 0;
          const high = summary?.high || 0;
          if (fbFindings.length) {
            log(`Firebase audit: ${fbFindings.length} achado(s) — ${crit} crítico(s) / ${high} alto(s)`, crit > 0 ? 'warn' : 'success');
          } else {
            log('Firebase audit: nenhuma vulnerabilidade detectada nas rules/APIs', 'info');
          }
          if (!writeProbes) {
            log('Firebase audit: probes de escrita desabilitados; requerem autorização dedicada', 'info');
          }
        } else {
          log('Firebase audit: config Firebase não encontrada — alvo pode não usar Firebase', 'info');
        }
      } catch (e) {
        if (isAbortError(e, signal)) throw e;
        log(`Firebase audit: ${e?.message || e}`, 'warn');
      }
      pipe('firebase_audit', 'done');
    }
}
