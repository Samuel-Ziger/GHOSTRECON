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
import { collectUniqueIpv4 } from '../../modules/ip-intel.js';
import { runShodanMembershipRecon } from '../../modules/shodan-client.mjs';
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
import { dispatchRegistryModule } from '../dispatcher.mjs';
import { pipelineCapabilityAllowed } from '../pipeline-state.mjs';

function rethrowIfProbeAborted(error, signal = null) {
  if (
    signal?.aborted
    || error?.name === 'AbortError'
    || error?.code === 'PROCESS_ABORTED'
    || error?.code === 'CLIENT_DISCONNECTED'
    || error?.code === 'ABORT_ERR'
  ) {
    throw error;
  }
}

export function shouldRunWafFingerprint(state) {
  if (!pipelineCapabilityAllowed(state, 'http_probe')) return false;
  if (state?.autoModeExecution === true) {
    return Array.isArray(state.modules) && state.modules.includes('wafw00f');
  }
  return (Array.isArray(state?.modules) && state.modules.includes('wafw00f'))
    || state?.runtimeProfile?.name !== 'quick';
}

export async function runProbePhase(s) {
  const {
    domain, exactMatch, modules, emit, kaliMode, auth, profile,
    outOfScopeClientRaw, projectNameRaw, shannonGithubRepos,
    identityCtrl, navegation, navigatorMode,
    apexHostIsIp, bountyCtx, runtimeProfile, domainStr, outOfScopeList,
    findings, stats, addFinding, log, pipe, skipKaliSubPipe, progress,
    subdomainsAlive, probedHosts, seenEp, vtHostnames, tlsSanHosts, dnsAForHost,
    lovableContext, firebaseContext, originByHost, probeResults,
    paramRows, paramUrlsForKali, interesting, urlCorpus, githubClonedItems,
  } = s;

    // ── ALIVE / PROBE ───────────────────────────
    const runHttpProbe = pipelineCapabilityAllowed(s, 'http_probe');
    pipe('alive', runHttpProbe ? 'active' : 'skip');
    progress(28);
    const hostsToProbe = [
      domain,
      ...new Set([...subdomainsAlive, ...(modules.includes('subdomains') ? [] : s.vtHostnames)]),
    ].filter((host) => s.hostInScope(host)).slice(0, runtimeProfile.maxHostsToProbe);
    const urlsToProbe = [];
    for (const h of hostsToProbe) {
      const hl = hostLiteralForUrl(h);
      urlsToProbe.push(`https://${hl}/`, `http://${hl}/`);
    }
    if (runHttpProbe) {
      log(`HTTP probing em ${hostsToProbe.length} hosts (GET, timeout ${limits.probeTimeoutMs}ms)...`, 'info');
      emit({
        type: 'pipe_detail',
        name: 'alive',
        current: 0,
        total: urlsToProbe.length,
        label: `${hostsToProbe.length} host(s), ${urlsToProbe.length} URL(s)`,
      });
    } else {
      log('HTTP probing omitido no Auto: capacidade http_probe não aprovada.', 'info');
    }

    let completedAliveProbes = 0;
    const emitAliveProgress = (url) => {
      completedAliveProbes += 1;
      const total = Math.max(1, urlsToProbe.length);
      const pct = Math.min(39, 28 + Math.floor((completedAliveProbes / total) * 11));
      progress(pct);
      emit({
        type: 'pipe_detail',
        name: 'alive',
        current: completedAliveProbes,
        total: urlsToProbe.length,
        label: url,
        pct,
      });
    };

    s.probeResults = runHttpProbe
      ? await mapPool(urlsToProbe, limits.probeConcurrency, async (u) => {
          let r;
          try {
            r = await probeHttp(u, {
              auth,
              modules,
              identityCtrl,
              signal: s.signal,
              urlAllowed: (url) => s.urlInScope(url),
            });
          } catch (e) {
            rethrowIfProbeAborted(e, s.signal);
            r = { ok: false, url: u, error: e?.message || String(e) };
          } finally {
            emitAliveProgress(u);
          }
          return { u, r };
        })
      : [];

    const seenTech = new Set();
    const seenHtmlCommentIntel = new Set();
    const runWafFingerprint = shouldRunWafFingerprint(s);
    pipe('wafw00f', runWafFingerprint ? 'active' : 'skip');
    for (const { r } of s.probeResults) {
      if (!r.ok) continue;
      if (!s.urlInScope(r.url)) continue;
      const host = new URL(r.url).hostname;
      if (r.status > 0 && r.status < 500) {
        log(`ALIVE ${r.url} → ${r.status} ${r.title ? `"${r.title.slice(0, 60)}"` : ''}`, 'success');
        // WAFW00F (fase 2 – opcional, melhor em quick<= off; standard/deep só se ferramenta existir)
        if (runWafFingerprint) {
          try {
            const wf = await wafw00fFingerprint(host);
            if (wf?.waf) {
              addFinding({
                type: 'intel',
                prio: 'low',
                score: 30,
                value: `WAF detected: ${wf.waf} @ ${host}`,
                meta: `waf=${wf.waf} • tool=wafw00f`,
                url: r.url,
              });
            }
          } catch {}
        }
        for (const t of r.tech || []) {
          const tk = `${host}::${t}`;
          if (seenTech.has(tk)) continue;
          seenTech.add(tk);
          addFinding({
            type: 'tech',
            prio: 'low',
            score: 28,
            value: t,
            meta: `Detectado em ${host}`,
          });
          if (String(t).toLowerCase().includes('cloudflare')) {
            addFinding({
              type: 'intel',
              prio: 'low',
              score: 28,
              value: `WAF hint @ ${host}`,
              meta: 'waf=cloudflare',
              url: r.url,
            });
          }
        }
        if (r.htmlSample && s.hostInScope(host)) {
          for (const h of extractSuspiciousHtmlComments(r.htmlSample)) {
            const key = `${host}::${h.slice(0, 48)}`;
            if (seenHtmlCommentIntel.has(key)) continue;
            seenHtmlCommentIntel.add(key);
            addFinding(
              {
                type: 'intel',
                prio: 'med',
                score: 52,
                value: `Comentário HTML suspeito @ ${host}`,
                meta: `html_comment • ${h.slice(0, 280)}`,
                url: r.url,
              },
              null,
            );
          }
        }
      }
    }
    if (runWafFingerprint) pipe('wafw00f', 'done');

    {
      let surfaceN = 0;
      const cap = limits.htmlSurfaceMaxEndpoints;
      for (const { r } of s.probeResults) {
        if (!r.ok || !r.surface) continue;
        if (surfaceN >= cap) break;
        let pageHost = '';
        try {
          pageHost = new URL(r.url).hostname;
        } catch {
          continue;
        }
        const merged = [...(r.surface.links || []), ...(r.surface.formActions || [])];
        for (const link of merged) {
          if (surfaceN >= cap) break;
          let u;
          try {
            u = new URL(link);
          } catch {
            continue;
          }
          if (!s.hostInScope(u.hostname)) continue;
          const href = u.href;
          if (seenEp.has(href)) continue;
          seenEp.add(href);
          const { score, prio } = scoreEndpointPath(u.pathname);
          addFinding(
            withProvenance(
              {
                type: 'endpoint',
                prio,
                score: Math.max(score, 42),
                value: href,
                meta: `HTML surface • ${pageHost}`,
                url: href,
              },
              {
                how: `Link extraído do HTML da resposta HTTP (atributos href / action) ao analisar a página **${pageHost}**.`,
                relation: `URL no âmbito do alvo **${domain}** (mesmo host ou host autorizado no recon). Indica superfície navegável descoberta a partir de conteúdo já obtido.`,
              },
            ),
            'endpoints',
          );
          surfaceN++;
        }
      }
      if (surfaceN) log(`Superfície HTML: +${surfaceN} URL(s) (href/forms)`, 'info');
    }

    await dispatchRegistryModule(s, 'cookie_session_audit');
    await dispatchRegistryModule(s, 'csrf_flow_audit');

    if (modules.includes('security_headers')) {
      pipe('security_headers', 'active');
      const seenHeaderGapHosts = new Set();
      for (const { r } of s.probeResults) {
        if (!r.ok || !r.securityHeaders) continue;
        if (r.status <= 0 || r.status >= 500) continue;
        let host;
        try {
          host = new URL(r.url).hostname;
        } catch {
          continue;
        }
        for (const issue of analyzeSecurityHeaders(r.url, r.securityHeaders)) {
          addFinding(
            {
              type: 'security',
              prio: issue.prio,
              score: issue.score,
              value: `${issue.text} @ ${host}`,
              meta: `HTTP ${r.status}`,
              url: r.url,
            },
            null,
          );
        }
        if (!seenHeaderGapHosts.has(host)) {
          seenHeaderGapHosts.add(host);
          const gap = summarizeSecurityHeaderGaps(r.url, r.securityHeaders);
          if (gap) {
            addFinding(
              withProvenance(
                {
                  type: 'security_headers_missing_bundle',
                  value: gap.text,
                  score: gap.score,
                  prio: gap.prio,
                  url: r.url,
                  meta: {
                    missing: gap.missing,
                    clickjackingRisk: gap.clickjackingRisk,
                    host: gap.host,
                    remediation: 'Configurar CSP, X-Frame-Options/frame-ancestors, X-Content-Type-Options e Referrer-Policy no CDN (vercel.json, CloudFront, nginx)',
                  },
                  owasp: 'A02:2021',
                  mitre: 'T1190',
                },
                'security_headers',
              ),
              null,
            );
          }
        }
        if (modules.includes('client_surface_audit')) {
          try {
            const hdrAudit = auditHeaderSurface(r.securityHeaders, { url: r.url });
            for (const f of hdrAudit.findings || []) addFinding(withProvenance(f, 'client_surface_audit'));
          } catch (e) {
            rethrowIfProbeAborted(e, s.signal);
            log(`Client surface (headers): ${e.message}`, 'warn');
          }
        }
      }
      pipe('security_headers', 'done');
    } else {
      pipe('security_headers', 'skip');
    }

    if (modules.includes('cors_audit')) {
      pipe('cors_audit', 'active');
      try {
        const { findings: corsFindings, summary } = await runCorsAudit({
          probeResults: s.probeResults,
          findings,
          domain: domainStr,
          log,
          signal: s.signal,
        });
        for (const f of corsFindings) addFinding(withProvenance(f, 'cors_audit'));
        if (corsFindings.length) {
          log(`CORS audit: ${corsFindings.length} achado(s) — ${summary?.critical || 0} crítico(s) / ${summary?.high || 0} alto(s)`, 'warn');
        } else {
          log(`CORS audit: nenhuma misconfig detectada (${summary?.probed || 0} URL(s) testadas)`, 'info');
        }
      } catch (e) {
        if (s.signal?.aborted) throw s.signal.reason || e;
        rethrowIfProbeAborted(e, s.signal);
        log(`CORS audit: ${e?.message || e}`, 'warn');
      }
      pipe('cors_audit', 'done');
    } else {
      pipe('cors_audit', 'skip');
    }

    if (modules.includes('header_intel')) {
      pipe('header_intel', 'active');
      for (const { r } of s.probeResults) {
        if (!r.ok || !r.responseHeadersFlat?.length) continue;
        if (r.status <= 0 || r.status >= 500) continue;
        let pageHost = '';
        try {
          pageHost = new URL(r.url).hostname;
        } catch {
          continue;
        }
        const pickIp =
          dnsAForHost.get(pageHost.toLowerCase()) ||
          dnsAForHost.get(String(domain).trim().toLowerCase()) ||
          (apexHostIsIp ? String(domain).trim() : '');
        for (const hit of analyzeSuspiciousResponseHeaders(r.responseHeadersFlat, {
          pageUrl: r.url,
          pageHost,
          apexDomain: domain,
          primaryIpv4: pickIp || '',
        })) {
          addFinding(
            {
              type: 'intel',
              prio: hit.prio,
              score: hit.score,
              value: hit.value,
              meta: hit.meta,
              url: r.url,
            },
            null,
          );
        }
      }
      pipe('header_intel', 'done');
    } else {
      pipe('header_intel', 'skip');
    }

    await dispatchRegistryModule(s, 'http3_quic_surface');
    await dispatchRegistryModule(s, 'nginx_http3_cve_2026_42530');

    s.originByHost = new Map();
    for (const { r } of s.probeResults) {
      if (!r.ok || r.status <= 0 || r.status >= 500) continue;
      let u;
      try {
        u = new URL(r.url);
      } catch {
        continue;
      }
      if (!s.hostInScope(u.hostname)) continue;
      const prefer = u.protocol === 'https:' ? 2 : 1;
      const cur = s.originByHost.get(u.hostname);
      if (!cur || prefer > cur.prefer) {
        const port = u.port ? `:${u.port}` : '';
        s.originByHost.set(u.hostname, { origin: `${u.protocol}//${u.hostname}${port}/`, prefer });
      }
    }

    const activeOrigins = [...s.originByHost.values()].map((v) => v.origin);

    await dispatchRegistryModule(s, 'panel_exposure_audit');
    await dispatchRegistryModule(s, 'jwt_jwks_audit');
    await dispatchRegistryModule(s, 'service_worker_audit');

    const runWellKnown = modules.includes('wellknown_security_txt') || modules.includes('wellknown_openid');
    const runSurface =
      modules.includes('security_headers') || modules.includes('robots_sitemap') || runWellKnown;
    if (runSurface) {
      pipe('surface', 'active');
      progress(33);
      if (modules.includes('security_headers')) {
        const hostsTls = [...s.originByHost.entries()].filter(([, v]) => v.prefer === 2).map(([h]) => h);
        if (hostsTls.length) log(`Inspeção TLS (${hostsTls.length} host HTTPS)...`, 'info');
        await mapPool(hostsTls, limits.surfaceConcurrency, async (hostname) => {
          const cert = await peekTlsCertificate(hostname, 443, limits.tlsProbeTimeoutMs);
          if (cert.ok) {
            const soon = cert.daysLeft != null && cert.daysLeft < 30;
            addFinding(
              {
                type: 'tls',
                prio: soon ? 'med' : 'low',
                score: soon ? 52 : 28,
                value: `${hostname} — cert válido até ${cert.validTo || '?'}`,
                meta: `Assunto: ${cert.subject || '—'} · Emissor: ${cert.issuer || '—'}${cert.daysLeft != null ? ` · ~${cert.daysLeft}d` : ''}`,
                url: `https://${hostLiteralForUrl(hostname)}/`,
              },
              null,
            );
            if (cert.subjectAltName) {
              const sanHosts = String(cert.subjectAltName)
                .split(',')
                .map((x) => x.replace(/DNS:/gi, '').trim().toLowerCase().replace(/^\*\./, ''))
                .filter((x) => /^[a-z0-9][a-z0-9.-]+\.[a-z]{2,}$/i.test(x))
                .filter((x) => s.hostInScope(x))
                .slice(0, 30);
              s.tlsSanHosts = [...new Set([...s.tlsSanHosts, ...sanHosts])];
            }
          }
        });
      }
      if (modules.includes('robots_sitemap')) {
        pipe('robots_sitemap', 'active');
        const bases = [...s.originByHost.values()].map((v) => v.origin);
        log(`robots.txt / sitemap (${bases.length} origem(ns))...`, 'info');
        await mapPool(bases, limits.surfaceConcurrency, async (baseOrigin) => {
          const crawl = await crawlRobotsAndSitemapsForOrigin(
            baseOrigin,
            domain,
            outOfScopeList,
            s.scopePolicy,
          );
          for (const p of (crawl.disallowHints || []).slice(0, 20)) {
            addFinding(
              {
                type: 'intel',
                prio: 'low',
                score: 36,
                value: `robots Disallow: ${p}`,
                meta: crawl.robotsUrl || baseOrigin,
                url: crawl.robotsUrl || baseOrigin,
              },
              null,
            );
          }
          for (const pageUrl of crawl.pageUrls || []) {
            let pathname = '/';
            try {
              pathname = new URL(pageUrl).pathname;
            } catch {
              continue;
            }
            const { score, prio } = scoreEndpointPath(pathname);
            if (seenEp.has(pageUrl)) continue;
            seenEp.add(pageUrl);
            addFinding(
              {
                type: 'endpoint',
                prio,
                score: Math.max(score, 44),
                value: pageUrl,
                meta: `robots/sitemap • ${new URL(baseOrigin).hostname}`,
                url: pageUrl,
              },
              'endpoints',
            );
          }
        });
        pipe('robots_sitemap', 'done');
      } else {
        pipe('robots_sitemap', 'skip');
      }

      // ── /.well-known (security.txt + OIDC discovery) ──
      if (runWellKnown) {
        const origins = [...s.originByHost.values()].map((v) => v.origin).slice(0, limits.wellKnownMaxHosts);
        if (origins.length) log(`/.well-known (${origins.length} origem(ns))...`, 'info');
        pipe('wellknown_security_txt', modules.includes('wellknown_security_txt') ? 'active' : 'skip');
        pipe('wellknown_openid', modules.includes('wellknown_openid') ? 'active' : 'skip');

        await mapPool(origins, limits.wellKnownConcurrency, async (baseOrigin) => {
          if (modules.includes('wellknown_security_txt')) {
            try {
              const sec = await fetchWellKnownSecurityTxt(baseOrigin, {
                urlAllowed: (url) => s.urlInScope(url),
              });
              if (sec.ok && sec.findings?.length) {
                for (const f of sec.findings) addFinding(f, null);
              }
            } catch (e) {
              rethrowIfProbeAborted(e, s.signal);
              log(`security.txt: ${e.message}`, 'warn');
            }
          }

          if (modules.includes('wellknown_openid') || modules.includes('client_surface_audit')) {
            try {
              const oid = await fetchWellKnownOpenIdConfiguration(baseOrigin, {
                urlAllowed: (url) => s.urlInScope(url),
              });
              if (oid.ok && oid.endpoints?.length) {
                for (const ep of oid.endpoints) {
                  let pathname = '/';
                  try {
                    pathname = new URL(ep.url).pathname;
                  } catch {
                    // keep default
                  }
                  const { score, prio } = scoreEndpointPath(pathname);
                  addFinding(
                    {
                      type: 'endpoint',
                      prio: prio === 'low' ? 'med' : prio,
                      score: Math.max(score, 55),
                      value: ep.url,
                      meta: `OIDC discovery (.well-known) • ${ep.label}`,
                      url: ep.url,
                    },
                    'endpoints',
                  );
                }
              }
              if (oid.metadata && modules.includes('client_surface_audit')) {
                let oHost = '';
                try { oHost = new URL(baseOrigin).hostname; } catch { /* skip */ }
                oid.metadata._url = new URL('/.well-known/openid-configuration', baseOrigin).href;
                for (const f of auditOidcMetadata(oid.metadata, { host: oHost })) {
                  addFinding(
                    withProvenance(
                      {
                        type: 'oidc_config',
                        value: f.title,
                        score: f.severity === 'high' ? 78 : f.severity === 'medium' ? 62 : 40,
                        prio: f.severity === 'high' ? 'high' : f.severity === 'medium' ? 'med' : 'low',
                        url: oid.metadata._url,
                        meta: { description: f.description, evidence: f.evidence, owasp: f.owasp },
                        owasp: Array.isArray(f.owasp) ? f.owasp[0] : f.owasp,
                      },
                      'client_surface_audit',
                    ),
                    null,
                  );
                }
              }
            } catch (e) {
              rethrowIfProbeAborted(e, s.signal);
              log(`OIDC discovery: ${e.message}`, 'warn');
            }
          }
        });
        if (modules.includes('wellknown_security_txt')) pipe('wellknown_security_txt', 'done');
        if (modules.includes('wellknown_openid')) pipe('wellknown_openid', 'done');
      } else {
        pipe('wellknown_security_txt', 'skip');
        pipe('wellknown_openid', 'skip');
      }
      pipe('surface', 'done');
    } else {
      emit({ type: 'pipe', name: 'surface', state: 'skip' });
      pipe('robots_sitemap', 'skip');
      pipe('wellknown_security_txt', 'skip');
      pipe('wellknown_openid', 'skip');
    }

    if (runHttpProbe) pipe('alive', 'done');
    progress(40);

    if (modules.includes('shodan')) {
      pipe('shodan', 'active');
      const sk = process.env.SHODAN_API_KEY?.trim();
      let shodanFailed = false;
      if (!sk) {
        log('Shodan: define SHODAN_API_KEY para lookup passivo (api.shodan.io)', 'warn');
      } else {
        log('Shodan: DNS domain + search + host lookup (membership, passivo)...', 'info');
        try {
          const shodanResult = await runShodanMembershipRecon({
            domain,
            hosts: hostsToProbe,
            apiKey: sk,
            hostInScope: (host) => s.hostInScope(host),
            limits,
            signal: s.signal,
            collectIpv4Impl: collectUniqueIpv4,
          });
          for (const entry of shodanResult.logs || []) {
            log(entry.message, entry.level || 'info');
          }
          if (shodanResult.subdomains?.length) {
            const beforeVt = s.vtHostnames.length;
            s.vtHostnames = [...new Set([...s.vtHostnames, ...shodanResult.subdomains])];
            if (Array.isArray(s.allSubs)) {
              s.allSubs = [...new Set([...s.allSubs, ...shodanResult.subdomains])];
            }
            const added = s.vtHostnames.length - beforeVt;
            if (added > 0) {
              log(`Shodan: +${added} hostname(s) fundido(s) no inventário`, 'info');
            }
          }
          for (const draft of shodanResult.findings || []) {
            const { how, relation, ...finding } = draft;
            addFinding(
              withProvenance(finding, {
                how: how || 'API Shodan passiva (membership).',
                relation: relation || 'Inventário passivo Shodan ligado ao domínio do programa.',
              }),
              null,
            );
          }
        } catch (e) {
          rethrowIfProbeAborted(e, s.signal);
          log(`Shodan: ${e.message}`, 'warn');
          shodanFailed = true;
          pipe('shodan', 'failed');
        }
      }
      if (!shodanFailed) pipe('shodan', 'done');
    } else {
      pipe('shodan', 'skip');
    }

    if (modules.includes('openapi_specs')) {
      pipe('openapi_specs', 'active');
      log('OpenAPI/Swagger: a procurar specs em paths comuns…', 'info');
      try {
        const specRows = await harvestOpenApiFromOrigins(
          activeOrigins,
          domain,
          outOfScopeList,
          modules,
          log,
          s.scopePolicy,
        );
        for (const row of specRows) {
          addFinding(row, row.type === 'param' ? 'params' : row.type === 'endpoint' ? 'endpoints' : null);
        }
        pipe('openapi_specs', 'done');
      } catch (e) {
        rethrowIfProbeAborted(e, s.signal);
        log(`OpenAPI harvest: ${e.message}`, 'warn');
        pipe('openapi_specs', 'failed');
      }
    } else {
      pipe('openapi_specs', 'skip');
    }

    await dispatchRegistryModule(s, 'api_contract_diff');

  s.originByHost = s.originByHost;
}
