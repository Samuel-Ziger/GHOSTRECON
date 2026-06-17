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
import { cloneGithubReposForTarget, githubCloneConfig, githubRepoHtmlUrl } from '../../modules/github-clone.js';
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
import { dispatchRegistryModule } from '../dispatcher.mjs';



export async function runContentDiscoveryPhase(s) {
  const {
    domain, exactMatch, modules, emit, kaliMode, auth, profile,
    outOfScopeClientRaw, projectNameRaw, shannonGithubRepos,
    identityCtrl, navegation, navigatorMode,
    apexHostIsIp, bountyCtx, runtimeProfile, domainStr, outOfScopeList,
    findings, stats, addFinding, log, pipe, skipKaliSubPipe, progress,
    subdomainsAlive, probedHosts, seenEp, vtHostnames, tlsSanHosts, dnsAForHost,
    lovableContext, originByHost, probeResults,
  } = s;

  let firebaseContext = s.firebaseContext;
  let paramRows = s.paramRows;
  let paramUrlsForKali = s.paramUrlsForKali;
  let interesting = s.interesting;
  let urlCorpus = s.urlCorpus;
  let githubClonedItems = s.githubClonedItems;
  let waybackUrls = [];
  let ccUrls = [];
  let archiveCliUrls = [];

    // ── WAYBACK / URLS ──────────────────────────
    pipe('urls', 'active');
    if (modules.includes('wayback')) {
      if (apexHostIsIp) {
        log('Wayback (CDX) omitido — índice *.domínio não se aplica a alvo só-IP.', 'info');
      } else {
        log('Coletando URLs do Wayback Machine (CDX)...', 'info');
        try {
          waybackUrls = await fetchWaybackUrls(domain);
          log(`${waybackUrls.length} URLs únicas (200) no escopo *.${domain}`, 'success');
        } catch (e) {
          log(`Wayback: ${e.message}`, 'warn');
        }
      }
    } else {
      log('Wayback desativado', 'info');
    }

    ccUrls = [];
    if (modules.includes('common_crawl')) {
      if (apexHostIsIp) {
        log('Common Crawl omitido — padrão *.domínio não se aplica a alvo só-IP.', 'info');
      } else {
        log('Common Crawl (índice CDX)...', 'info');
        try {
          ccUrls = await fetchCommonCrawlUrls(domain);
          log(`${ccUrls.length} URLs únicas (200) no Common Crawl`, 'success');
        } catch (e) {
          log(`Common Crawl: ${e.message}`, 'warn');
        }
      }
    }

    archiveCliUrls = [];
    if (runtimeProfile.includeCliArchives || modules.includes('gau') || modules.includes('waybackurls')) {
      if (apexHostIsIp) {
        log('gau / waybackurls (CLI) omitidos — arquivo por domínio não se aplica a alvo só-IP.', 'info');
      } else {
        try {
          archiveCliUrls = await fetchArchiveToolUrls(domain, log);
        } catch (e) {
          log(`Archive CLI: ${e.message}`, 'warn');
        }
      }
    }

    urlCorpus = [...new Set([...waybackUrls, ...ccUrls, ...archiveCliUrls])];
    if (runtimeProfile.name === 'deep') {
      const apexLit = hostLiteralForUrl(domain);
      const seeds = [`https://${apexLit}/`, `http://${apexLit}/`];
      for (const seed of seeds) {
        try {
          const k = await crawlWithKatana(seed, { depth: 3 });
          if (k.ok && k.urls.length) {
            let added = 0;
            for (const u of k.urls.slice(0, 300)) {
              if (!urlInReconScope(u, domain, outOfScopeList)) continue;
              if (!urlCorpus.includes(u)) {
                urlCorpus.push(u);
                added++;
              }
            }
            log(`Katana: +${added} URL(s) no escopo via crawl JS (${k.urls.length} brutas)`, 'info');
          }
        } catch (e) {
          log(`Katana: ${e.message}`, 'warn');
        }
      }
    }
    urlCorpus = urlCorpus.filter((u) => urlInReconScope(u, domain, outOfScopeList));

    if (modules.includes('graphql_probe')) {
      const gqlUrls = [...new Set(urlCorpus.filter((u) => /graphql/i.test(u)))].slice(0, 10);
      if (!gqlUrls.length) {
        log(
          'GraphQL: módulo activo mas nenhuma URL com "graphql" no corpus — liga Wayback/Common Crawl ou outras fontes de URLs.',
          'info',
        );
      } else {
        try {
          const gqlFindings = await tryGraphqlMinimalProbe(gqlUrls, domain, outOfScopeList, modules, log);
          for (const gf of gqlFindings) addFinding(gf, null);
        } catch (e) {
          log(`GraphQL probe: ${e.message}`, 'warn');
        }
      }
    }

    if (modules.includes('graphql_recon')) {
      const gqlUrls = [...new Set(urlCorpus.filter((u) => /graphql/i.test(u)))].slice(0, 8);
      if (!gqlUrls.length) {
        log('GraphQL recon: sem endpoints com "graphql" no corpus', 'info');
      } else {
        pipe('graphql_recon', 'active');
        try {
          const headers = { ...(auth?.headers || {}) };
          if (auth?.cookie) headers.Cookie = auth.cookie;
          for (const gqlUrl of gqlUrls) {
            const out = await probeGraphqlEndpoint(gqlUrl, {
              headers,
              executor: async (query, variables, extraHeaders) => {
                const r = await fetch(gqlUrl, {
                  method: 'POST',
                  headers: { 'content-type': 'application/json', ...headers, ...(extraHeaders || {}) },
                  body: JSON.stringify({ query, variables }),
                  signal: AbortSignal.timeout(15000),
                });
                try {
                  return await r.json();
                } catch {
                  return { errors: [{ message: `HTTP ${r.status}` }] };
                }
              },
            });
            for (const f of out.findings || []) {
              addFinding({
                type: 'intel',
                prio: sevToPrio(f.severity),
                score: sevToScore(f.severity),
                value: f.title,
                meta: f.description,
                url: gqlUrl,
              });
            }
          }
        } catch (e) {
          log(`GraphQL recon: ${e.message}`, 'warn');
        }
        pipe('graphql_recon', 'done');
      }
    }

    const waybackSet = new Set(waybackUrls);
    const ccSet = new Set(ccUrls);
    interesting = filterInterestingUrls(urlCorpus);
    log(`${interesting.length} URLs marcadas como interessantes (filtro heurístico)`, 'info');

    // URLs com query string (bons alvos para templates de XSS/SQLi no modo Kali)
    paramUrlsForKali = [...new Set(urlCorpus.filter((u) => /\?.+=/i.test(u)))].slice(0, 40);

    for (const rawUrl of interesting.slice(0, runtimeProfile.maxInterestingUrls)) {
      let pathname = '/';
      try {
        pathname = new URL(rawUrl).pathname;
      } catch {
        continue;
      }
      const { score, prio } = scoreEndpointPath(pathname);
      if (seenEp.has(rawUrl)) continue;
      seenEp.add(rawUrl);
      const src = waybackSet.has(rawUrl) ? 'Wayback' : ccSet.has(rawUrl) ? 'Common Crawl' : 'arquivo web';
      addFinding(
        withProvenance(
          {
            type: 'endpoint',
            prio,
            score,
            value: rawUrl,
            meta: `Score ${score}/100 • ${src}`,
            url: rawUrl,
          },
          {
            how: `URL recolhida do corpus passivo (**${src}** / CDX ou índice), filtrada pelo escopo *.${domain} e heurísticas de caminho.`,
            relation: `Endereço histórico ou indexado associado ao domínio alvo **${domain}**. Pode ou não responder hoje; confirma manualmente antes de reportar.`,
          },
        ),
        'endpoints',
      );
    }
    pipe('urls', 'done');
    progress(52);

    // ── PARAMS ──────────────────────────────────
    pipe('params', 'active');
    paramRows = extractParamsFromUrls(urlCorpus.length ? urlCorpus : interesting);
    // Evidência REAL de WordPress: caminhos/recursos que só existem em WP de verdade.
    const wpCorpusBlob = [
      ...(urlCorpus || []),
      ...(interesting || []),
      ...findings.filter((f) => f.type === 'tech' || f.type === 'endpoint').map((f) => `${f.value || ''} ${f.url || ''}`),
    ]
      .map((u) => String(typeof u === 'string' ? u : u?.url || u?.value || ''))
      .join('\n')
      .toLowerCase();
    const hasWordpressEvidence =
      /wp-content\/|wp-includes\/|\/wp-json\b|wp-login\.php|\/wp-admin\b|<meta name="generator" content="wordpress|x-pingback/i.test(wpCorpusBlob);
    // Params/endpoints exclusivos de WordPress que viram falso positivo em alvo não-WP.
    const WP_ONLY_PARAMS = new Set(['rsd', 'pingback', 'wp-json', 'wlwmanifest']);
    const WP_ONLY_URL_RE = /\/(?:xmlrpc\.php|wlwmanifest\.xml|wp-login\.php|wp-cron\.php)\b/i;
    for (const { name, count, sampleUrl } of paramRows.slice(0, 60)) {
      // Pula artefatos WordPress quando não há nenhuma evidência real de WordPress no alvo.
      if (!hasWordpressEvidence
        && (WP_ONLY_PARAMS.has(String(name).toLowerCase()) || WP_ONLY_URL_RE.test(String(sampleUrl || '')))) {
        continue;
      }
      const { score, prio } = scoreParamName(name);
      const vuln =
        ['redirect', 'url', 'file', 'path', 'callback'].includes(name.toLowerCase()) ? ' → Open Redirect/SSRF?' : '';
      addFinding(
        withProvenance(
          {
            type: 'param',
            prio,
            score,
            value: `?${name}=`,
            meta: `~${count} ocorrências em URLs${vuln}`,
            url: sampleUrl || undefined,
          },
          {
            how: 'Nome de parâmetro de query extraído do agregado de URLs do recon (Wayback, CSE, HTML, JS, etc.).',
            relation: `Parâmetro observado em URLs cujo host está no âmbito do alvo **${domain}** — candidato a testes manuais no programa.`,
          },
        ),
        'params',
      );

      // Heurística (passivo): marcar parâmetros comuns para XSS / SQLi como candidatos (não confirmados)
      const n = String(name).toLowerCase();
      const xssCandidates = new Set(['q', 'query', 'search', 's', 'keyword', 'term', 'message', 'comment', 'title', 'name']);
      const sqliCandidates = new Set([
        'id',
        'ids',
        'user',
        'user_id',
        'uid',
        'account',
        'order',
        'order_id',
        'page',
        'sort',
        'filter',
        'where',
        'username',
        'email',
        'passwd',
        'pwd',
        'login',
      ]);
      if (xssCandidates.has(n)) {
        addFinding(
          {
            type: 'intel',
            prio: prio === 'high' ? 'med' : 'low',
            score: 54,
            value: `XSS candidate param: ?${name}=`,
            meta: 'Heurístico (passivo) — priorizar testes de reflexão/encoding • confidence=heuristic',
            url: sampleUrl || undefined,
          },
          null,
        );
      }
      if (sqliCandidates.has(n)) {
        addFinding(
          {
            type: 'intel',
            prio: prio === 'high' ? 'med' : 'low',
            score: 56,
            value: `SQLi candidate param: ?${name}=`,
            meta: 'Heurístico (passivo) — priorizar filtros/IDs/ordenação • confidence=heuristic',
            url: sampleUrl || undefined,
          },
          null,
        );
      }
    }
    log(`${paramRows.length} nomes de parâmetros distintos (amostra Wayback)`, 'success');
    pipe('params', 'done');

    await dispatchRegistryModule(s, 'hpp_param_pollution');

    progress(60);

    // ── JS ANALYSIS ─────────────────────────────
    pipe('js', 'active');
    const jsList = extractJsUrls(urlCorpus.length ? urlCorpus : [], 120).slice(0, limits.maxJsFetch);
    log(`Analisando ${jsList.length} arquivos JS (passivo)...`, 'info');
    const clientAuthResults = [];
    const clientSurfaceResults = [];
    const jsAuditBodies = [];
    for (const jsUrl of jsList) {
      const a = await analyzeJsUrl(jsUrl, { modules });
      if (!a.ok) {
        log(`JS skip: ${jsUrl} (${a.error || a.status})`, 'warn');
        continue;
      }
      jsAuditBodies.push({ url: jsUrl, body: a.body || '' });
      if (modules.includes('client_surface_audit')) {
        try {
          clientSurfaceResults.push(auditJsSurface(a.body || '', {
            url: jsUrl,
            target: domain,
            includeAuth: !modules.includes('client_auth_audit'),
          }));
          const mapUrl = extractSourceMapUrl(a.body || '', jsUrl);
          if (mapUrl) {
            const smFinding = await probeSourceMapDisclosure(mapUrl);
            if (smFinding) clientSurfaceResults.push({ findings: [smFinding], summary: {} });
          }
        } catch (e) {
          log(`Client surface audit (JS): ${e.message}`, 'warn');
        }
      }
      if (modules.includes('client_auth_audit')) {
        try {
          clientAuthResults.push(auditClientSideAuth(a.body || '', { url: jsUrl, target: domain }));
        } catch (e) {
          log(`Client auth audit: ${e.message}`, 'warn');
        }
      }
      if (modules.includes('firebase_audit') && !firebaseContext) {
        try {
          const cfg = extractFirebaseConfig(a.body || '', { targetOrigin: `https://${hostLiteralForUrl(domain)}` });
          if (cfg?.apiKey || cfg?.projectId) {
            firebaseContext = { ...cfg, bundleText: a.body || '', _auditPending: true };
            log(`Firebase audit: config extraída de ${jsUrl} — probes após fase JS`, 'info');
          }
        } catch { /* skip */ }
      }
      if (modules.includes('js_intel')) {
        try {
          const intel = jsBundleToFindings(a.body || '', { url: jsUrl, target: domain });
          for (const jf of intel.findings || []) {
            addFinding({
              type: 'intel',
              prio: sevToPrio(jf.severity),
              score: sevToScore(jf.severity),
              value: jf.title,
              meta: jf.description,
              url: jsUrl,
            });
          }
        } catch (e) {
          log(`JS intel: ${e.message}`, 'warn');
        }
      }
      for (const ep of a.endpoints.slice(0, 25)) {
        const { score, prio } = scoreEndpointPath(ep);
        addFinding(
          {
            type: 'js',
            prio: prio === 'low' ? 'med' : prio,
            score: Math.max(score, 55),
            value: ep,
            meta: `Extraído de ${jsUrl}`,
            url: jsUrl,
          },
          'endpoints',
        );
      }
      for (const ins of a.insights || []) {
        addFinding(
          {
            type: 'intel',
            prio: ins.kind === 'role_admin_hint' ? 'high' : 'med',
            score: ins.kind === 'role_admin_hint' ? 72 : 58,
            value: `JS insight (${ins.kind}): ${ins.snippet.slice(0, 160)}`,
            meta: `js_context • kind=${ins.kind} • confidence=heuristic`,
            url: jsUrl,
          },
          null,
        );
      }
      const sec = scanSecrets(a.body || '');
      for (const s of sec) {
        const fpMeta = s.correlationFp ? `value_fp=${s.correlationFp}` : '';
        addFinding(
          {
            type: 'secret',
            prio: 'high',
            score: 92,
            value: `[${s.kind}] ${s.masked}`,
            meta: ['Possível segredo em JS (verificar falso positivo)', fpMeta].filter(Boolean).join(' • '),
            url: jsUrl,
          },
          'secrets',
        );
      }
    }
    if (modules.includes('client_surface_audit')) {
      try {
        for (const { r } of probeResults) {
          if (!r.ok || !r.htmlSample) continue;
          const isHttps = String(r.url || '').toLowerCase().startsWith('https:');
          clientSurfaceResults.push(auditHtmlSurface(r.htmlSample, { url: r.url, target: domain, isHttps }));
        }
        const mergedSurface = mergeClientSurfaceFindings(clientSurfaceResults);
        for (const f of mergedSurface) addFinding(withProvenance(f, 'client_surface_audit'));
        if (mergedSurface.length) {
          const crit = mergedSurface.filter((f) => f.score >= 85).length;
          log(`Client surface audit: ${mergedSurface.length} achado(s)${crit ? ` — ${crit} crítico(s)` : ''}`, crit ? 'warn' : 'success');
        }
      } catch (e) {
        log(`Client surface audit: ${e.message}`, 'warn');
      }
    }
    if (modules.includes('client_auth_audit') && clientAuthResults.length) {
      try {
        const merged = mergeClientAuthFindings(clientAuthResults);
        for (const f of merged) addFinding(withProvenance(f, 'client_auth_audit'));
        if (merged.length) {
          log(`Client auth audit: ${merged.length} achado(s) em bundles JS`, merged.some((f) => f.score >= 85) ? 'warn' : 'success');
        }
      } catch (e) {
        log(`Client auth audit: ${e.message}`, 'warn');
      }
    }
    if (modules.includes('firebase_audit') && firebaseContext?._auditPending) {
      try {
        const targetUrl = `https://${hostLiteralForUrl(domain)}/`;
        const writeProbes = String(process.env.GHOSTRECON_FIREBASE_WRITE_PROBES || '1').trim() !== '0';
        const { findings: fbFindings, summary } = await runFirebaseAudit(firebaseContext, {
          targetUrl,
          log,
          writeProbes,
        });
        for (const f of fbFindings) addFinding(withProvenance(f, 'firebase_audit'));
        if (fbFindings.length) {
          log(`Firebase audit (pós-JS): ${fbFindings.length} achado(s)`, 'warn');
        }
        delete firebaseContext._auditPending;
      } catch (e) {
        log(`Firebase audit (pós-JS): ${e.message}`, 'warn');
      }
    }
    const htmlAuditBodies = probeResults
      .map(({ r }) => (r?.ok && r.htmlSample ? { url: r.url, body: r.htmlSample } : null))
      .filter(Boolean);
    s._jsAuditBodies = jsAuditBodies;
    await dispatchRegistryModule(s, 'websocket_recon');
    await dispatchRegistryModule(s, 'dom_clobbering_audit');
    pipe('js', 'done');
    progress(72);

    // ── DORKS (URLs apenas) ─────────────────────
    pipe('dorks', 'active');
    const techHintsForDorks = findings.filter((f) => f.type === 'tech').map((f) => f.value);
    const dorks = buildDorks(domainStr, modules, techHintsForDorks);
    for (const d of dorks) {
      emit({
        type: 'dork',
        googleUrl: d.googleUrl,
        query: d.query,
        mod: d.mod,
        prio: d.prio,
      });
      addFinding(
        {
          type: 'dork',
          prio: d.prio,
          score: d.prio === 'high' ? 68 : 55,
          value: d.query,
          meta: `Categoria: ${d.mod}`,
          url: d.googleUrl,
        },
        'dorks',
      );
    }
    log(`${dorks.length} dorks gerados (abertura no browser com fila configurável)`, 'success');

    if (modules.includes('google_cse')) {
      const gKey = process.env.GOOGLE_CSE_KEY;
      const gCx = process.env.GOOGLE_CSE_CX;
      if (!gKey || !gCx) {
        log(
          'Google CSE desativado: defina GOOGLE_CSE_KEY e GOOGLE_CSE_CX (Programmable Search Engine) para descobrir URLs reais via API.',
          'warn',
        );
      } else if (dorks.length === 0) {
        log('Google CSE: nenhum dork gerado — ative categorias de dork na sidebar.', 'warn');
      } else {
        log(
          `Google Custom Search: até ${limits.googleCseMaxQueries} queries neste run (quota diária típica 100 grátis).`,
          'info',
        );
        const seenG = new Set();
        const slice = dorks.slice(0, limits.googleCseMaxQueries);
        for (let i = 0; i < slice.length; i++) {
          const d = slice[i];
          if (i > 0) await sleep(limits.googleCseDelayMs);
          try {
            const items = await googleCseSearch(d.query, gKey, gCx);
            for (const it of items) {
              if (!urlInReconScope(it.link, domain, outOfScopeList)) continue;
              if (seenG.has(it.link)) continue;
              seenG.add(it.link);
              let pathname = '/';
              try {
                pathname = new URL(it.link).pathname;
              } catch {
                continue;
              }
              const { score, prio } = scoreEndpointPath(pathname);
              addFinding(
                {
                  type: 'endpoint',
                  prio,
                  score: Math.max(score, 62),
                  value: it.link,
                  meta: `Google CSE • ${d.mod} • ${it.title ? it.title.slice(0, 60) : d.query.slice(0, 60)}`,
                  url: it.link,
                },
                'endpoints',
              );
              log(`CSE → ${it.link}`, 'find');
            }
          } catch (e) {
            log(`CSE [${d.mod}]: ${e.message}`, 'warn');
          }
        }
        log(`${seenG.size} URL(s) no alvo descoberta(s) via Google CSE`, seenG.size ? 'success' : 'info');
      }
    }

    pipe('dorks', 'done');
    progress(82);

    // ── GITHUB API (opcional) ───────────────────
    pipe('secrets', 'active');
    /** Clones bem-sucedidos neste run (para Shannon white-box). */
    githubClonedItems = [];
    const manualGithubRepos = parseGithubManualRepoList(shannonGithubRepos);
    if (manualGithubRepos.length) {
      log(`GitHub: ${manualGithubRepos.length} repositório(s) indicado(s) manualmente (UI Shannon)`, 'info');
    }

    const recordClonedFindings = (clonedList) => {
      for (const item of clonedList) {
        addFinding({
          type: 'intel',
          prio: 'low',
          score: 38,
          value: `GitHub clone local: ${item.full_name}`,
          meta: `path=${item.local_path} • size=${Math.round((item.size_bytes || 0) / (1024 * 1024))}MB`,
          url: `https://github.com/${item.full_name}`,
        });
      }
    };

    if (modules.includes('github')) {
      log('GitHub Code Search (API pública, rate limit)...', 'info');
      const gh = await githubCodeSearch(domain, process.env.GITHUB_TOKEN);
      if (gh.ok && gh.items?.length) {
        for (const it of gh.items) {
          const ghMat = `${it.repo || ''}|${it.path || ''}`;
          const ghf = secretMaterialFingerprint('github_code_hit', ghMat);
          addFinding(
            {
              type: 'secret',
              prio: 'high',
              score: 78,
              value: `${it.repo || ''}/${it.path || ''}`,
              meta: `Resultado GitHub Code Search — revisar manualmente • value_fp=${ghf}`,
              url: it.html_url,
            },
            'secrets',
          );
        }
        log(`${gh.items.length} resultados GitHub (total estimado ${gh.total})`, 'warn');
      } else {
        log(gh.note || 'Sem resultados GitHub ou limite atingido', 'info');
      }

      log('GitHub Repo Search (candidatos para clone local)...', 'info');
      const ghRepos = await githubRepoSearch(domain, process.env.GITHUB_TOKEN, { perPage: 8 });
      const codeRepos = (gh.items || []).map((x) => String(x.repo || '').trim()).filter(Boolean);
      const repoMap = new Map();

      if (ghRepos.ok && ghRepos.items?.length) {
        for (const r of ghRepos.items || []) {
          if (!r?.full_name) continue;
          repoMap.set(r.full_name, r);
        }
      }

      for (const fullName of codeRepos) {
        if (!fullName || repoMap.has(fullName)) continue;
        repoMap.set(fullName, {
          full_name: fullName,
          clone_url: `https://github.com/${fullName}.git`,
          html_url: `https://github.com/${fullName}`,
        });
      }

      for (const m of manualGithubRepos) {
        repoMap.set(m.full_name, m);
      }

      const repoCandidates = [...repoMap.values()];
      if (repoCandidates.length) {
        log(`GitHub repos candidatos: ${repoCandidates.length}`, 'success');
        for (const r of repoCandidates.slice(0, 12)) {
          const url = githubRepoHtmlUrl(r);
          if (url) log(`${r.full_name} → ${url}`, 'find');
        }
        if (repoCandidates.length > 12) {
          log(`+${repoCandidates.length - 12} candidato(s) adicionais (não listados)`, 'info');
        }

        const cloneCfg = githubCloneConfig();
        if (cloneCfg.enabled) {
          log(
            `Clone local ativo: até ${cloneCfg.maxRepos} repo(s), timeout ${cloneCfg.cloneTimeoutMs}ms, retenção ${Math.round(cloneCfg.retentionMs / (24 * 60 * 60 * 1000))} dia(s)`,
            'info',
          );
        } else {
          log('Clone local desativado (GHOSTRECON_GITHUB_CLONE_ENABLED=1 para ativar).', 'info');
        }

        try {
          const cloned = await cloneGithubReposForTarget({
            targetDomain: domain,
            repos: repoCandidates,
            log,
          });
          if (cloned.skipped) {
            // clone desativado por config
          } else {
            if (cloned.cloned?.length) {
              githubClonedItems = cloned.cloned;
              recordClonedFindings(cloned.cloned);
              log(`Clone local concluído: ${cloned.cloned.length} repo(s) em ${cloned.base_dir}`, 'success');
            } else {
              log('Clone local: nenhum repositório clonado nesta execução.', 'info');
            }
            if (cloned.failed?.length) {
              for (const item of cloned.failed.slice(0, 4)) {
                const url = githubRepoHtmlUrl(item);
                log(
                  `Clone falhou (${item.full_name}): ${item.error}${url ? ` — ${url}` : ''}`,
                  'warn',
                );
              }
              if (cloned.failed.length > 4) {
                log(`+${cloned.failed.length - 4} falha(s) de clone adicionais`, 'warn');
              }
            }
          }
        } catch (e) {
          log(`Clone local GitHub: ${e.message}`, 'warn');
        }
      } else {
        log(ghRepos.note || 'GitHub Repo Search sem resultados (e sem repos manuais válidos)', 'info');
      }
    } else if (manualGithubRepos.length && modules.includes('shannon_whitebox')) {
      const cloneCfg = githubCloneConfig();
      if (!cloneCfg.enabled) {
        log('Repos GitHub manuais: clone local desativado — define GHOSTRECON_GITHUB_CLONE_ENABLED=1.', 'warn');
      } else {
        log(
          `Clone só de repos manuais (${manualGithubRepos.length}) — módulo «GitHub leaks» desligado; Shannon white-box activo.`,
          'info',
        );
        try {
          const cloned = await cloneGithubReposForTarget({
            targetDomain: domain,
            repos: manualGithubRepos,
            log,
          });
          if (!cloned.skipped && cloned.cloned?.length) {
            githubClonedItems = cloned.cloned;
            recordClonedFindings(cloned.cloned);
            log(`Clone local concluído: ${cloned.cloned.length} repo(s) em ${cloned.base_dir}`, 'success');
          } else if (!cloned.skipped && cloned.failed?.length) {
            for (const item of cloned.failed.slice(0, 4)) {
              const url = githubRepoHtmlUrl(item);
              log(
                `Clone falhou (${item.full_name}): ${item.error}${url ? ` — ${url}` : ''}`,
                'warn',
              );
            }
          }
        } catch (e) {
          log(`Clone local GitHub (manual): ${e.message}`, 'warn');
        }
      }
    } else if (manualGithubRepos.length) {
      log(
        'Repos GitHub na caixa manual ignorados: activa «GitHub leaks» ou «Shannon white-box» para clonar.',
        'info',
      );
    }
    if (modules.includes('pastebin')) {
      log('Pastebin: sem API pública confiável — use os dorks gerados', 'info');
    }
    // Validação activa de tokens/secrets (fase 3)
    try {
      const sv = await validateSecretFindings(findings, log);
      for (const row of sv) {
        const isLive     = row.status === 'live';
        const isProbable = row.status === 'probable';
        const tokenLabel = row.tokenType && row.tokenType !== 'unknown'
          ? ` [${row.tokenType}]` : '';
        const statusLabel =
          row.tokenStatus === 'valid'    ? 'VALID'    :
          row.tokenStatus === 'expired'  ? 'EXPIRED'  :
          row.tokenStatus === 'invalid'  ? 'INVALID'  :
          row.tokenStatus === 'revoked'  ? 'REVOKED'  :
          row.tokenStatus === 'probable' ? 'PROBABLE' :
          row.status.toUpperCase();
        addFinding({
          type:  'secret_validation',
          prio:  isLive ? 'high' : isProbable ? 'med' : 'low',
          score: isLive ? 86     : isProbable ? 62    : 24,
          value: `Token ${statusLabel}${tokenLabel} • ${row.ref}`,
          meta:  [
            `tokenStatus=${row.tokenStatus ?? row.status}`,
            `tokenType=${row.tokenType ?? 'unknown'}`,
            row.offlineExpired            ? `offlineExpired=true`           : null,
            row.expiredAt                 ? `expiredAt=${row.expiredAt}`    : null,
            row.expiresAt                 ? `expiresAt=${row.expiresAt}`    : null,
            row.noExpiration              ? `noExpiration=true`             : null,
            row.jwtClaims?.iss            ? `iss=${row.jwtClaims.iss}`      : null,
            row.jwtClaims?.role           ? `role=${row.jwtClaims.role}`    : null,
            `reason=${row.reason}`,
          ].filter(Boolean).join('|'),
          tokenValidation: {
            status:         row.tokenStatus ?? row.status,
            tokenType:      row.tokenType,
            offlineExpired: row.offlineExpired,
            expiredAt:      row.expiredAt    ?? null,
            expiresAt:      row.expiresAt    ?? null,
            noExpiration:   row.noExpiration ?? false,
            jwtClaims:      row.jwtClaims    ?? null,
            evidence:       row.reason,
            probes:         row.probes       ?? [],
          },
        });
      }
      const live    = sv.filter((r) => r.status === 'live').length;
      const expired = sv.filter((r) => r.tokenStatus === 'expired').length;
      if (sv.length) log(`Token validation: ${sv.length} token(s) — ${live} válido(s), ${expired} expirado(s)`, 'info');
    } catch (e) {
      log(`Secret validation: ${e.message}`, 'warn');
    }
    pipe('secrets', 'done');

    await dispatchRegistryModule(s, 'secrets_context_ranker');

    if (!modules.includes('shannon_whitebox')) {
      emit({ type: 'pipe', name: 'shannon', state: 'skip' });
    } else {
      log(
        'Shannon white-box: fase após PRIORITIZE e antes de PentestGPT HTTP (verify/Kali/score correm primeiro).',
        'info',
      );
    }


  s.paramRows = paramRows;
  s.paramUrlsForKali = paramUrlsForKali;
  s.interesting = interesting;
  s.urlCorpus = urlCorpus;
  s.githubClonedItems = githubClonedItems;
  s.firebaseContext = firebaseContext;
}
