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
import { runJwtLabPipeline } from '../../modules/jwt-forge-br.mjs';
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



export async function runValidationPhase(s) {
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

    // ── VERIFY (evidence-guided) ─────────────────
    pipe('verify', 'active');
    progress(84);
    try {
      if (identityCtrl?.enabled) {
        const st = identityCtrl.getStats();
        log(
          `Rotação de identidade: ativa (proxies=${st.proxies}, backoff≈${st.backoffMul.toFixed(1)})`,
          'info',
        );
      }
      const verified = await runEvidenceVerification({
        findings,
        auth,
        log,
        maxEndpoints: runtimeProfile.maxVerifyEndpoints,
        modules,
        identityCtrl,
      });
      for (const vf of verified) addFinding(vf, null);
      if (verified.length) log(`Verify: ${verified.length} resultado(s) xss/sqli/open_redirect/idor/lfi`, 'success');
    } catch (e) {
      log(`Verify: ${e.message}`, 'warn');
    }
    if (modules.includes('micro_exploit')) {
      try {
        const micro = await runMicroExploitVariants({
          findings,
          auth,
          log,
          modules,
          maxTests: 16,
          identityCtrl,
        });
        for (const mf of micro) addFinding(mf, null);
      } catch (e) {
        log(`Micro-exploit: ${e.message}`, 'warn');
      }
    }

    if (modules.includes('webshell_probe')) {
      pipe('webshell_probe', 'active');
      try {
        const origins = [];
        const seenO = new Set();
        for (const [, v] of s.originByHost) {
          const o = String(v?.origin || '').trim();
          if (!o || seenO.has(o) || origins.length >= 11) continue;
          seenO.add(o);
          origins.push(o.endsWith('/') ? o : `${o}/`);
        }
        try {
          const hl = hostLiteralForUrl(domain);
          for (const scheme of ['https', 'http']) {
            const o = `${scheme}://${hl}/`;
            if (!seenO.has(o) && origins.length < 12) {
              seenO.add(o);
              origins.push(o);
            }
          }
        } catch {
          /* ignore */
        }
        const ws = await runWebshellHeuristicProbe({ origins, auth, modules, log, maxOrigins: 10 });
        for (const w of ws) addFinding(w, null);
        if (ws.length) log(`Webshell heurístico: ${ws.length} achado(s) — rever manualmente`, 'warn');
        else log('Webshell heurístico: sem sinais fortes (cmd=id)', 'info');
      } catch (e) {
        log(`Webshell heurístico: ${e.message}`, 'warn');
      }
      pipe('webshell_probe', 'done');
    } else {
      pipe('webshell_probe', 'skip');
    }

    // Param discovery ativo (fase 2): tentar em endpoints sem query
    try {
      const candidates = findings
        .filter((f) => f.type === 'endpoint' && typeof f.value === 'string' && /^https?:\/\//i.test(f.value))
        .filter((f) => !/\?/.test(String(f.value)))
        .slice(0, Math.max(6, Math.round(runtimeProfile.maxVerifyEndpoints / 3)));
      for (const ep of candidates) {
        const r = await discoverParamsActive(ep.value, { timeoutMs: 70000 });
        const ps = [...new Set(r.params || [])].slice(0, 20);
        for (const p of ps) {
          addFinding(
            {
              type: 'param',
              prio: 'med',
              score: 62,
              value: `?${p}=`,
              meta: `active_discovery • tool=${r.tool || 'n/a'}`,
              url: `${ep.value}${ep.value.includes('?') ? '&' : '?'}${p}=X`,
            },
            'params',
          );
        }
        if (ps.length) log(`Param discovery: ${ps.length} em ${ep.value}`, 'info');
      }
    } catch (e) {
      log(`Param discovery: ${e.message}`, 'warn');
    }

    if (modules.includes('sqlmap')) {
      pipe('sqlmap', 'active');
      try {
        const maxT = Math.max(1, Math.min(6, Number(process.env.GHOSTRECON_SQLMAP_TARGETS) || 2));
        const sm = await runSqlmapModule({
          findings,
          auth,
          log,
          maxTargets: maxT,
          profile: runtimeProfile.name,
          identityCtrl,
        });
        for (const x of sm) addFinding(x, null);
        if (sm.length) log(`sqlmap: ${sm.length} achado(s) SQLi (ferramenta) registado(s)`, 'success');
      } catch (e) {
        log(`sqlmap: ${e.message}`, 'warn');
      }
      pipe('sqlmap', 'done');
    } else {
      pipe('sqlmap', 'skip');
    }

    if (modules.includes('curl_probe')) {
      pipe('curl_probe', 'active');
      try {
        const cp = await runCurlProbeModule({
          target: domain,
          findings,
          auth,
          profile: runtimeProfile.name,
          identityCtrl,
          log,
        });
        for (const x of cp) addFinding(x, null);
        if (cp.length) log(`curl_probe: ${cp.length} achado(s)`, 'success');
        else log('curl_probe: sem achados relevantes', 'info');
      } catch (e) {
        log(`curl_probe: ${e?.message || e}`, 'warn');
      }
      pipe('curl_probe', 'done');
    } else {
      pipe('curl_probe', 'skip');
    }

    pipe('verify', 'done');

    if (modules.includes('authz_matrix')) {
      pipe('authz_matrix', 'active');
      try {
        const endpointUrls = [...new Set(findings.filter((f) => f.type === 'endpoint' && /^https?:\/\//i.test(String(f.value || ''))).map((f) => f.value))].slice(0, 8);
        const requests = [];
        const reqSeen = new Set();
        const pushReq = (r) => {
          if (!r || !r.method || !r.path) return;
          const k = `${r.method}:${r.path}`;
          if (reqSeen.has(k)) return;
          reqSeen.add(k);
          requests.push(r);
        };
        for (const u of endpointUrls) {
          try {
            const uu = new URL(u);
            const pathOnly = uu.pathname || '/';
            const perUser = /\/(me|profile|account|user)/i.test(u);
            const adminOnly = /\/admin/i.test(u);
            pushReq({ method: 'GET', path: pathOnly, perUser, adminOnly, url: u });
            if (/\/(graphql|gql)(\/|$)/i.test(pathOnly)) {
              pushReq({
                method: 'POST',
                path: pathOnly,
                perUser: false,
                adminOnly: false,
                url: u,
                body: { query: '{ __typename }' },
                headers: { 'Content-Type': 'application/json' },
              });
            }
          } catch {
            /* ignore */
          }
        }
        const personas = [
          { id: 'anon', expectedRole: 'guest', headers: {} },
          ...(auth?.cookie || (auth?.headers && Object.keys(auth.headers).length)
            ? [{ id: 'auth', expectedRole: 'user', headers: { ...(auth?.headers || {}), ...(auth?.cookie ? { Cookie: auth.cookie } : {}) } }]
            : []),
        ];
        if (requests.length && personas.length > 1) {
          const plan = buildAuthzPlan(requests, personas);
          const matrix = await runAuthzMatrix({
            requests,
            personas,
            concurrency: 2,
            executor: async (reqShape, persona) => {
              const picked = reqShape.url || endpointUrls.find((u) => {
                try { return new URL(u).pathname === reqShape.path; } catch { return false; }
              });
              if (!picked) return { status: 0, fingerprint: null, bodyLen: 0 };
              const mergedHeaders = { ...(persona.headers || {}), ...(reqShape.headers || {}) };
              const reqBody =
                reqShape.method === 'POST' || reqShape.method === 'PUT'
                  ? (typeof reqShape.body === 'string' ? reqShape.body : JSON.stringify(reqShape.body || {}))
                  : undefined;
              const r = await fetch(picked, {
                method: reqShape.method || 'GET',
                headers: mergedHeaders,
                body: reqBody,
                signal: AbortSignal.timeout(12000),
              });
              const body = await r.text();
              let ownerMarker = null;
              try {
                const parsed = JSON.parse(body);
                const obj = parsed && typeof parsed === 'object' ? parsed : null;
                if (obj) {
                  const owner = obj.user_id || obj.userId || obj.owner_id || obj.ownerId || obj.account_id || obj.accountId || obj.tenant_id || obj.tenantId || obj.email || obj.username || null;
                  if (owner != null) ownerMarker = String(owner).slice(0, 120);
                }
              } catch {
                /* non-json */
              }
              return { status: r.status, fingerprint: fingerprintBody(body), bodyLen: body.length, ownerMarker };
            },
          });
          for (const f of matrix.findings || []) {
            addFinding({
              type: 'intel',
              prio: sevToPrio(f.severity),
              score: sevToScore(f.severity),
              value: f.title,
              meta: f.description,
            });
          }
          log(`AuthZ matrix: ${plan.length} tentativa(s), ${matrix.findings?.length || 0} sinal(is)`, 'info');
        } else {
          log('AuthZ matrix: insuficiente (requer endpoints HTTP + contexto autenticado)', 'info');
        }
      } catch (e) {
        log(`AuthZ matrix: ${e.message}`, 'warn');
      }
      pipe('authz_matrix', 'done');
    }

    if (modules.includes('jwt_lab')) {
      pipe('jwt_lab', 'active');
      try {
        await runJwtLabPipeline(s);
      } catch (e) {
        log(`JWT lab: ${e.message}`, 'warn');
      }
      pipe('jwt_lab', 'done');
    }

    if (modules.includes('dom_xss_verify')) {
      pipe('dom_xss_verify', 'active');
      try {
        const urls = [...new Set(findings.filter((f) => f.type === 'endpoint' && /\?/.test(String(f.value || ''))).map((f) => f.value))].slice(0, 6);
        const plan = buildVerificationPlan({ urls, params: ['q', 'search', 'id'], maxPerUrl: 3 });
        if (plan.length) {
          addFinding({
            type: 'intel',
            prio: 'med',
            score: 58,
            value: `DOM XSS verify plan: ${plan.length} probes`,
            meta: 'Plano gerado para validação browser-assisted (Playwright/manual).',
          });
        }
      } catch (e) {
        log(`DOM XSS verify: ${e.message}`, 'warn');
      }
      pipe('dom_xss_verify', 'done');
    }

    if (modules.includes('payload_mutator')) {
      pipe('payload_mutator', 'active');
      try {
        const variants = mutatePayload(`' OR 1=1--`, { context: 'generic' }).slice(0, 12);
        addFinding({
          type: 'intel',
          prio: 'low',
          score: 44,
          value: `Payload mutator ready: ${variants.length} variantes`,
          meta: `Amostra: ${variants.slice(0, 3).join(' | ').slice(0, 220)}`,
        });
      } catch (e) {
        log(`Payload mutator: ${e.message}`, 'warn');
      }
      pipe('payload_mutator', 'done');
    }

    if (modules.includes('race_harness')) {
      pipe('race_harness', 'active');
      try {
        const candidate = findings.find((f) => f.type === 'endpoint' && /coupon|payment|transfer|withdraw|cart|checkout/i.test(String(f.value || '')));
        if (candidate?.value) {
          const plan = buildRacePlan({ request: { method: 'POST', url: candidate.value, headers: auth?.headers || {}, body: '{}' }, parallel: 20 });
          addFinding({
            type: 'intel',
            prio: 'med',
            score: 60,
            value: `Race harness plan criado (${plan.total} paralelos)`,
            meta: `Alvo candidato: ${candidate.value}`,
            url: candidate.value,
          });
        } else {
          log('Race harness: sem endpoint financeiro óbvio para plano automático', 'info');
        }
      } catch (e) {
        log(`Race harness: ${e.message}`, 'warn');
      }
      pipe('race_harness', 'done');
    }

    if (modules.includes('oob_collaborator')) {
      pipe('oob_collaborator', 'active');
      try {
        const token = randomBytes(8).toString('hex');
        const host = String(process.env.GHOSTRECON_OOB_HOST || '127.0.0.1');
        const payloads = buildOobPayloads({ token, host, httpPort: Number(process.env.GHOSTRECON_OOB_HTTP_PORT || 8054) });
        addFinding({
          type: 'intel',
          prio: 'med',
          score: 57,
          value: `OOB payload pack gerado (${token})`,
          meta: `ssrf=${payloads.ssrf[0]} xxe=${payloads.xxe[0]}`.slice(0, 340),
        });
      } catch (e) {
        log(`OOB collaborator: ${e.message}`, 'warn');
      }
      pipe('oob_collaborator', 'done');
    }

    if (modules.includes('cred_spray')) {
      pipe('cred_spray', 'active');
      try {
        const users = String(process.env.GHOSTRECON_SPRAY_USERS || '')
          .split(',')
          .map((x) => x.trim())
          .filter(Boolean)
          .slice(0, 100);
        const passwords = String(process.env.GHOSTRECON_SPRAY_PASSWORDS || '')
          .split(',')
          .map((x) => x.trim())
          .filter(Boolean)
          .slice(0, 20);
        if (users.length && passwords.length) {
          const plan = planSpray({ users, passwords, usersPerBatch: 25 });
          addFinding({
            type: 'intel',
            prio: 'low',
            score: 38,
            value: `Cred spray plan: ${plan.estimateTotal} tentativas`,
            meta: `batches=${plan.batches.length} cooldownMs=${plan.cooldownMs}`,
          });
        } else {
          log('Cred spray: defina GHOSTRECON_SPRAY_USERS e GHOSTRECON_SPRAY_PASSWORDS para gerar plano', 'info');
        }
      } catch (e) {
        log(`Cred spray: ${e.message}`, 'warn');
      }
      pipe('cred_spray', 'done');
    }


}
