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
  dnsResolvedAddressesEligibleForProbe,
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
import { dispatchRegistryModule } from '../dispatcher.mjs';



export function filterDiscoveredHostsInScope(hosts, state) {
  const allowed = typeof state?.hostInScope === 'function'
    ? (host) => state.hostInScope(host)
    : () => false;
  return [...new Set((Array.isArray(hosts) ? hosts : [])
    .map((host) => String(host || '').trim().toLowerCase())
    .filter((host) => host && allowed(host)))];
}

export async function runDiscoveryPhase(s) {
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

    // ── SUBDOMAINS ──────────────────────────────
    if (!apexHostIsIp && modules.includes('virustotal')) {
      const vt = await fetchVirustotalSubdomains(domain, process.env.VIRUSTOTAL_API_KEY);
      if (vt.ok && vt.items?.length) {
        s.vtHostnames = vt.items.filter((host) => s.hostInScope(host));
        log(`VirusTotal: ${s.vtHostnames.length} hostname(s)`, 'success');
      } else {
        log(vt.note || 'VirusTotal: sem dados', vt.ok ? 'info' : 'warn');
      }
    }

    s.allSubs = [];
    /** Hostnames normalizados devolvidos pelo subfinder (para meta `tool=subfinder` na UI). */
    const subfinderHostsNorm = new Set();
    const runCrtSubdomains = modules.includes('subdomains');
    const runKaliSubfinderAmass = Boolean(kaliMode) && (modules.includes('subfinder') || modules.includes('amass'));
    if (runCrtSubdomains || runKaliSubfinderAmass) {
      pipe('subdomains', 'active');
      progress(12);
      if (apexHostIsIp) {
        log(
          'Alvo é endereço IP — Certificate Transparency, VirusTotal (subdomínios), subfinder e amass são omitidos nesta fase.',
          'info',
        );
      } else {
        if (runCrtSubdomains) {
          log('Consultando crt.sh (Certificate Transparency)...', 'info');
          try {
            s.allSubs = await fetchCrtShSubdomains(domain, { signal: s.signal });
            log(`${s.allSubs.length} nomes únicos em CT logs`, 'success');
          } catch (e) {
            if (s.signal?.aborted) throw s.signal.reason || e;
            log(`crt.sh: ${e.message}`, 'warn');
          }
          if (s.vtHostnames.length) {
            const before = s.allSubs.length;
            s.allSubs = [...new Set([...s.allSubs, ...s.vtHostnames])];
            if (s.allSubs.length > before) log(`VirusTotal fundido em enum: +${s.allSubs.length - before} nome(s)`, 'info');
          }
        } else {
          log('crt.sh (subdomains) desativado — usando enum Kali (se selecionado).', 'info');
        }

        if (runKaliSubfinderAmass) {
          if (modules.includes('subfinder')) {
            try {
              const extra = await enumerateSubdomainsWithSubfinder(domain, log);
              for (const h of extra) {
                const hn = String(h).trim().toLowerCase();
                if (hn) subfinderHostsNorm.add(hn);
              }
              if (extra.length) {
                s.allSubs = [...new Set([...s.allSubs, ...extra])];
              }
            } catch (e) {
              log(`subfinder: ${e.message}`, 'warn');
            }
          }
          if (modules.includes('amass')) {
            try {
              const extra = await enumerateSubdomainsWithAmass(domain, log);
              if (extra.length) {
                s.allSubs = [...new Set([...s.allSubs, ...extra])];
              }
            } catch (e) {
              log(`amass: ${e.message}`, 'warn');
            }
          }
        }
      }

      const discoveredCount = s.allSubs.length;
      s.allSubs = filterDiscoveredHostsInScope(s.allSubs, s);
      const scopeRejected = discoveredCount - s.allSubs.length;
      if (scopeRejected > 0) {
        log(
          `Escopo formal: ${scopeRejected} hostname(s) descoberto(s) ignorado(s) antes de DNS`,
          'info',
        );
      }
      const capped = s.allSubs.filter((candidate) => candidate !== domain).slice(0, 150);
      const vtHostSet = new Set(s.vtHostnames.map((h) => String(h).trim().toLowerCase()));
      log(`Resolvendo DNS (máx. ${capped.length} hosts)...`, 'info');
      for (const host of capped) {
        const r = await resolves(host);
        if (r.ok) {
          const dnsGate = dnsResolvedAddressesEligibleForProbe(
            r.records,
            domain,
            s.outOfScopeList,
            s.scopePolicy,
          );
          if (!dnsGate.eligible) {
            log(
              `Escopo formal: ${host} → ${dnsGate.rejectedIps.slice(0, 3).join(', ')} `
              + 'fora da allowlist IP — ignorado para alive/probe',
              'warn',
            );
            continue;
          }
          const probeRecords = dnsGate.allowedIps.length
            ? dnsGate.allowedIps
            : r.records;
          log(`✓ ${host} → ${probeRecords.slice(0, 2).join(', ')}`, 'success');
          const { score, prio } = { score: 52, prio: 'med' };
          const hn = String(host).trim().toLowerCase();
          const viaSubfinder = subfinderHostsNorm.has(hn);
          const fromVt = vtHostSet.has(hn);
          const sources = [];
          if (runCrtSubdomains) sources.push('Certificate Transparency (crt.sh)');
          if (s.vtHostnames.length) sources.push('API VirusTotal');
          if (runKaliSubfinderAmass && modules.includes('subfinder')) sources.push('subfinder (Kali)');
          if (runKaliSubfinderAmass && modules.includes('amass')) sources.push('amass (Kali)');
          const how =
            (sources.length > 0
              ? `Nomes candidatos obtidos com: ${sources.join(', ')}. `
              : '') +
            'Este nome foi confirmado com consulta DNS recursiva (A/AAAA).';
          const relation =
            `**${host}** pertence ao âmbito do alvo **${domain}** (subdomínio ou host relacionado). ` +
            `Os registos DNS provam que o nome resolve na Internet — integra a superfície do recon.` +
            (fromVt ? ' Consta também da lista VirusTotal para este domínio.' : '');
          addFinding(
            withProvenance(
              {
                type: 'subdomain',
                prio,
                score,
                value: host,
                meta: `DNS: ${probeRecords.join(', ')}${viaSubfinder ? ' · tool=subfinder' : ''}`,
                url: `https://${hostLiteralForUrl(host)}/`,
              },
              { how, relation },
            ),
            'subs',
          );
          subdomainsAlive.push(host);
          probedHosts.add(host);
          const ipv4 = firstIpv4FromDnsRecords(probeRecords);
          if (ipv4) dnsAForHost.set(String(host).trim().toLowerCase(), ipv4);
        } else {
          log(`✗ ${host} (sem A/AAAA)`, 'warn');
        }
      }
      pipe('subdomains', 'done');
    } else {
      log('Subdomain discovery desativado', 'info');
      pipe('subdomains', 'done');
    }

    if (!apexHostIsIp && modules.includes('ct_monitor')) {
      pipe('ct_monitor', 'active');
      try {
        const ct = await monitorCt(domain, {
          fetcher: async (url) => {
            const r = await fetch(url, { signal: AbortSignal.timeout(20000) });
            return r.ok ? r.json() : [];
          },
        });
        const scopedFresh = (ct.fresh || []).filter((host) => s.hostInScope(host));
        const scopedFindings = (ct.findings || []).filter(
          (finding) => s.hostInScope(finding?.evidence?.host),
        );
        for (const f of scopedFindings) {
          addFinding({
            type: 'intel',
            prio: sevToPrio(f.severity),
            score: sevToScore(f.severity),
            value: f.title,
            meta: f.description,
            url: f.evidence?.host ? `https://${hostLiteralForUrl(f.evidence.host)}/` : undefined,
          });
        }
        const hot = classifyNewSubs(scopedFresh).filter((x) => x.hot);
        if (hot.length) {
          log(`CT monitor: ${scopedFresh.length} novo(s) no escopo, ${hot.length} subdomínio(s) sensível(is)`, 'warn');
        } else {
          log(`CT monitor: ${scopedFresh.length} novo(s) no escopo`, 'info');
        }
      } catch (e) {
        log(`CT monitor: ${e.message}`, 'warn');
      }
      pipe('ct_monitor', 'done');
    }

    if (!apexHostIsIp && modules.includes('origin_discovery')) {
      pipe('origin_discovery', 'active');
      try {
        const discovered = await resolveSubsForOrigin(domain, {
          hostAllowed: (host) => s.hostInScope(host),
        });
        const report = detectOriginCandidates({ apex: domain, subdomainIps: discovered });
        for (const f of originDiscoveryToFindings(report, { target: domain })) {
          addFinding({
            type: 'intel',
            prio: sevToPrio(f.severity),
            score: sevToScore(f.severity),
            value: f.title,
            meta: f.description,
            url: f.evidence?.host ? `https://${hostLiteralForUrl(f.evidence.host)}/` : undefined,
          });
        }
        log(`Origin discovery: ${report.candidates?.length || 0} candidato(s)`, 'info');
      } catch (e) {
        log(`Origin discovery: ${e.message}`, 'warn');
      }
      pipe('origin_discovery', 'done');
    }

    // ── DNS ENRICHMENT (TXT/MX/SPF/DMARC) ─────────
    if (modules.includes('dns_enrichment')) {
      pipe('dns_enrichment', 'active');
      progress(14);
      log('Enriquecimento DNS (MX/TXT/SPF/DMARC)...', 'info');
      try {
        const { findings } = await fetchDnsEnrichment(domain, subdomainsAlive, {
          maxHosts: limits.dnsEnrichMaxHosts,
          hostAllowed: (host) => s.hostInScope(host),
        });
        if (findings.length) log(`DNS intel: ${findings.length} achado(s)`, 'success');
        for (const f of findings) addFinding(f, null);
      } catch (e) {
        log(`DNS Enrichment: ${e.message}`, 'warn');
      }
      pipe('dns_enrichment', 'done');
    }

    if (modules.includes('email_security_deep')) {
      if (apexHostIsIp) {
        log('Email security deep omitido: alvo e endereco IP, sem dominio para MX/TXT.', 'info');
        emit({ type: 'pipe', name: 'email_security_deep', state: 'skip' });
      } else {
        await dispatchRegistryModule(s, 'email_security_deep');
      }
    }

    if (modules.includes('rdap')) {
      if (apexHostIsIp) {
        log('RDAP omitido — alvo é endereço IP (este módulo consulta registo de domínio por FQDN).', 'info');
        emit({ type: 'pipe', name: 'rdap', state: 'skip' });
      } else {
        pipe('rdap', 'active');
        progress(18);
        log('Consultando RDAP (registo de domínio)...', 'info');
        try {
          const rd = await fetchRdapSummary(domain);
          addFinding(
            {
              type: 'rdap',
              prio: 'low',
              score: 24,
              value: rd.handle || domain,
              meta: `Estado: ${rd.statuses || '—'} · NS: ${(rd.nameservers || []).slice(0, 10).join(', ') || '—'}`,
            },
            null,
          );
          if (rd.events?.length) log(`RDAP: ${rd.events.join(' | ')}`, 'info');
        } catch (e) {
          log(`RDAP: ${e.message}`, 'warn');
        }
        pipe('rdap', 'done');
      }
    } else {
      emit({ type: 'pipe', name: 'rdap', state: 'skip' });
    }

    if (apexHostIsIp) {
      dnsAForHost.set(String(domain).trim(), String(domain).trim());
    } else {
      const hn = String(domain).trim().toLowerCase();
      if (!dnsAForHost.has(hn)) {
        try {
          const rApex = await resolves(domain);
          if (rApex.ok) {
            const dnsGate = dnsResolvedAddressesEligibleForProbe(
              rApex.records,
              domain,
              s.outOfScopeList,
              s.scopePolicy,
            );
            if (!dnsGate.eligible) {
              log(
                `Escopo formal: apex ${domain} resolve fora da allowlist IP `
                + `(${dnsGate.rejectedIps.slice(0, 3).join(', ')}) — IP não entra em probe`,
                'warn',
              );
            } else {
              const ipv4 = firstIpv4FromDnsRecords(
                dnsGate.allowedIps.length ? dnsGate.allowedIps : rApex.records,
              );
              if (ipv4) dnsAForHost.set(hn, ipv4);
            }
          }
        } catch {
          /* ignore */
        }
      }
    }
}
