import { compareRuns } from '../../modules/db-compare.js';
import { postReconWebhook, postAiReportWebhook, postReconDeltaFullWebhook } from '../../modules/webhook-notify.js';
import { correlate } from '../../modules/correlation.js';
import { suggestVectors, buildExploitChecklist } from '../../modules/intelligence.js';
import { applyPrioritizationV2, topHighProbability } from '../../modules/prioritization.js';
import { extractCveHintsFromTechStrings } from '../../modules/cve-hints.js';
import { buildMysqlConfigSurfaceCorrelationFindings } from '../../modules/mysql-config-correlation.js';
import { dedupeBySemanticFamily } from '../../modules/semantic-dedupe.js';
import { buildReportTemplates } from '../../modules/report-template.js';
import { summarizeValue, prioritize as prioritizeBounty } from '../../modules/bounty-estimator.mjs';
import { applyScopeFilter, dedupeFindings as dedupeBountyFindings } from '../../modules/bounty-scope.mjs';
import { applyChains } from '../../modules/chaining.mjs';
import { runHighPrioHttpRecheck } from '../../modules/recheck-high.js';
import { runOptionalPlaywrightXssProbe } from '../../modules/browser-xss-verify.js';
import { getKaliCapabilities } from '../../modules/kali-scan.js';
import { buildReconCoverageSnapshot } from '../../modules/recon-coverage.js';
import { runShannonOnClone, shannonMaxClonesPerRun } from '../../modules/shannon-runner.js';
import { runPentestGptValidation } from '../../modules/pentestgpt-local.js';
import {
  runDualAiReports,
  aiKeysConfigured,
  pickAiReportForWebhook,
  normalizeOpenrouterOnlyFlag,
} from '../../modules/ai-dual-report.js';
import { applyOwaspTagsToFindings } from '../../modules/owasp-top10.js';
import { applyMitreTagsToFindings } from '../../modules/mitre-recon.js';
import { applyRiskExplanations } from '../../modules/risk-explainer.mjs';
import { serializeFindingsForRunSnapshot } from '../../modules/finding-serialize.js';
import { saveRun, listRuns, storageLabel } from '../../modules/db.js';
import { attachRunToEngagement } from '../../modules/engagement.mjs';
import { recordAction } from '../../modules/team-concurrency.mjs';
import {
  aiAutoReportsServerAllowed,
  buildPipelineExportPayloadForAi,
  emitIaProximosPassosToLog,
} from '../pipeline-helpers.mjs';
import { pipelineCapabilityAllowed } from '../pipeline-state.mjs';
import { dispatchRegistryModule } from '../dispatcher.mjs';

/**
 * Priorização, correlação, Shannon, PentestGPT, persistência, IA automática e webhooks.
 */
export async function runFinalizePhase(ctx) {
  const {
    domain,
    exactMatch,
    modules,
    emit,
    kaliMode,
    auth,
    bountyCtx,
    outOfScopeList = [],
    findings,
    stats,
    addFinding,
    log,
    pipe,
    progress,
    subdomainsAlive,
    paramRows,
    githubClonedItems,
    projectNameRaw,
    autoAiReports,
    aiProviderMode,
    aiUseOpenrouter,
    aiOpenrouterOnly,
    aiPrimaryCloud,
    shannonSkipDepsVerify,
    pentestgptUrlOverride,
    engagementIdRaw,
    engagementOperatorRaw,
    ROOT,
  } = ctx;

  let reconCoverageSnapshot = ctx.reconCoverageSnapshot ?? null;
  let pipelineAiOut = ctx.pipelineAiOut ?? null;

    // Correlação passiva de CVEs web (dataset local + NVD opt-in) antes do score.
    await dispatchRegistryModule(ctx, 'cve_correlation');

    // ── PRIORIZAÇÃO V2 + CVE hints + CORRELATION + INTEL ──
    pipe('score', 'active');
    progress(93);
    log('═══ Priorização v2 (composite + HIGH PROBABILITY) ═══', 'section');
    applyPrioritizationV2(findings, bountyCtx);
    for (const f of findings) {
      if (f.type === 'endpoint' && f.url && /\?.+=/i.test(f.url)) {
        f.meta = [f.meta, 'status_consistent=true'].filter(Boolean).join(' • ');
      }
      if (f.type === 'endpoint' && /\/(admin|dashboard|account|profile|settings|billing)(\/|$)/i.test(String(f.value || ''))) {
        f.meta = [f.meta, 'auth=required'].filter(Boolean).join(' • ');
      }
    }
    const techStrs = findings.filter((f) => f.type === 'tech').map((f) => f.value);
    const cveHints = extractCveHintsFromTechStrings(techStrs);
    for (const f of findings) {
      if (cveHints.length && f.type === 'tech') {
        f.meta = [f.meta, 'cve_hint=true'].filter(Boolean).join(' • ');
      }
    }
    try {
      const mysqlCorr = buildMysqlConfigSurfaceCorrelationFindings(findings, { max: 16 });
      for (const c of mysqlCorr) addFinding(c, null);
      if (mysqlCorr.length) log(`Correlação MySQL 3306 + ficheiros de config: ${mysqlCorr.length} achado(s)`, 'info');
    } catch (e) {
      log(`Correlação MySQL + config: ${e.message}`, 'warn');
    }
    applyPrioritizationV2(findings, bountyCtx);

    const semantic = dedupeBySemanticFamily(findings);
    if (semantic.merged > 0) {
      findings.length = 0;
      findings.push(...semantic.findings);
      log(`Dedupe semântico: ${semantic.merged} achado(s) colapsado(s) por família`, 'info');
    }

    if (modules.includes('chaining')) {
      try {
        const chained = applyChains({ findings });
        if (chained?.chains?.length) {
          findings.length = 0;
          findings.push(...(chained.findings || []));
          log(`Chaining: ${chained.chains.length} cadeia(s) detectada(s)`, 'warn');
        }
      } catch (e) {
        log(`Chaining: ${e.message}`, 'warn');
      }
    }

    if (modules.includes('bounty_scope')) {
      try {
        const scope = Array.isArray(bountyCtx?.scope) ? bountyCtx.scope : [];
        if (scope.length) {
          const shaped = findings.map((f) => ({
            category: f.type || 'intel',
            title: String(f.value || ''),
            evidence: { url: f.url || undefined, target: domain },
          }));
          const filtered = applyScopeFilter(shaped, scope);
          const removed = (filtered.outOfScope || []).length;
          if (removed > 0) log(`Bounty scope: ${removed} achado(s) fora de escopo no contexto atual`, 'warn');
        } else {
          log('Bounty scope: sem bountyContext.scope no payload, skip filtro', 'info');
        }
        const dedupe = await dedupeBountyFindings(
          findings.map((f) => ({
            category: f.type || 'intel',
            title: String(f.value || ''),
            evidence: { url: f.url || undefined, target: domain },
          })),
        );
        if ((dedupe.duplicate || []).length) {
          log(`Bounty dedupe: ${(dedupe.duplicate || []).length} potencial(is) duplicado(s) de submissão`, 'info');
        }
      } catch (e) {
        log(`Bounty scope/dedupe: ${e.message}`, 'warn');
      }
    }

    if (modules.includes('bounty_estimator')) {
      try {
        const normalized = findings.map((f) => ({
          severity: f.prio === 'high' ? 'high' : f.prio === 'med' ? 'medium' : 'low',
          category: f.type || 'intel',
        }));
        const value = summarizeValue(normalized, { tier: String(bountyCtx?.tier || 'standard').toLowerCase() });
        const top = prioritizeBounty(normalized, { tier: String(bountyCtx?.tier || 'standard').toLowerCase() }).slice(0, 3);
        log(`Bounty estimator: total esperado ~${value.totalExpected} (${Object.entries(value.byRecommendation).map(([k, v]) => `${k}:${v}`).join(', ')})`, 'info');
        for (const t of top) {
          addFinding({
            type: 'intel',
            prio: t.estimate.recommendation === 'go-now' ? 'high' : t.estimate.recommendation === 'priority' ? 'med' : 'low',
            score: Math.min(98, Math.max(30, Math.round(t.estimate.ratio / 2))),
            value: `Bounty value hint: ${t.estimate.recommendation}`,
            meta: `expected=${t.estimate.expectedPayout} ratio=${t.estimate.ratio}/h`,
          });
        }
      } catch (e) {
        log(`Bounty estimator: ${e.message}`, 'warn');
      }
    }
    stats.high = findings.filter((f) => f.prio === 'high').length;
    emit({ type: 'stats', stats: { ...stats } });
    emit({ type: 'findings_rescore', findings });

    const runHighRecheck = pipelineCapabilityAllowed(ctx, 'high_recheck');
    if (runHighRecheck) {
      try {
        await runHighPrioHttpRecheck({ findings, auth, modules, log, signal: ctx.signal });
        emit({ type: 'findings_rescore', findings: [...findings] });
      } catch (e) {
        if (ctx.signal?.aborted) throw ctx.signal.reason || e;
        log(`Recheck HIGH: ${e.message}`, 'warn');
      }
    } else {
      emit({ type: 'pipe', name: 'high_recheck', state: 'skip' });
    }
    const runBrowserXssVerify = pipelineCapabilityAllowed(ctx, 'browser_xss_verify');
    if (runBrowserXssVerify) {
      try {
        const pwFindings = await runOptionalPlaywrightXssProbe({
          findings,
          log,
          limit: 4,
          signal: ctx.signal,
        });
        for (const pf of pwFindings) addFinding(pf, null);
      } catch (e) {
        if (ctx.signal?.aborted) throw ctx.signal.reason || e;
        log(`Playwright XSS: ${e.message}`, 'warn');
      }
    } else {
      emit({ type: 'pipe', name: 'browser_xss_verify', state: 'skip' });
    }
    try {
      const kaliCapSnap = await getKaliCapabilities({ signal: ctx.signal });
      reconCoverageSnapshot = buildReconCoverageSnapshot({
        domain,
        modules,
        kaliMode,
        findings,
        kaliCap: kaliCapSnap,
      });
      emit({ type: 'recon_coverage', snapshot: reconCoverageSnapshot });
    } catch (e) {
      if (e?.name === 'AbortError' || e?.code === 'PROCESS_ABORTED') throw e;
      log(`Cobertura recon: ${e.message}`, 'warn');
    }

    if (cveHints.length) {
      log('═══ Versões detectadas → lookup CVE (manual) ═══', 'section');
      for (const h of cveHints) {
        const label = `${h.product}${h.version ? ` ${h.version}` : ''}`;
        log(`🔎 ${label} — NVD: ${h.nvdUrl}`, 'info');
        log(`   OSV: ${h.osvUrl}`, 'info');
      }
    }

    const hpt = topHighProbability(findings, 8);
    if (hpt.length) {
      log(`═══ HIGH PROBABILITY TARGET (${hpt.length}) ═══`, 'section');
      for (const t of hpt) {
        const w = (t.priorityWhy || []).slice(0, 3).join('; ');
        log(`🎯 [${t.compositeScore}] ${t.type}: ${String(t.value).slice(0, 100)}${w ? ` — ${w}` : ''}`, 'warn');
      }
      emit({
        type: 'priority_pass',
        top: hpt.map((f) => ({
          value: f.value,
          type: f.type,
          compositeScore: f.compositeScore,
          attackTier: f.attackTier,
          why: f.priorityWhy || [],
        })),
      });
    }

    progress(96);
    const corr = correlate({
      subdomainsAlive,
      endpoints: findings.filter((f) => f.type === 'endpoint').map((f) => f.value),
      params: paramRows,
    });
    log('═══ Correlação ═══', 'section');
    log(corr.summary, 'info');
    if (corr.riskyParams.length) {
      log(`Parâmetros de risco presentes: ${corr.riskyParams.join(', ')}`, 'warn');
    }

    log('═══ Workflow de testes (checklist) ═══', 'section');
    const checklist = buildExploitChecklist(findings);
    for (const c of checklist) {
      emit({ type: 'intel', line: `☐ CHECKLIST: ${c}` });
    }

    const hints = suggestVectors({ findings, selectedMods: modules });
    for (const h of hints) {
      emit({ type: 'intel', line: h });
    }
    const reportTemplates = buildReportTemplates(findings, domain);
    for (const tpl of reportTemplates) {
      emit({ type: 'report_template', template: tpl });
      emit({ type: 'intel', line: `REPORT: ${tpl.title}` });
    }
    pipe('score', 'done');
    progress(97);

    // Shannon white-box: após priorização/correlação (payload PentestGPT inclui achados Shannon).
    if (modules.includes('shannon_whitebox')) {
      if (shannonSkipDepsVerify) {
        log('Shannon white-box: verificação de dependências omitida pelo utilizador.', 'warn');
      } else {
        log('Shannon white-box: dependências já validadas no início do pedido HTTP.', 'info');
      }
      const autoOff = Boolean(String(process.env.GHOSTRECON_SHANNON_AUTO_RUN || '1').trim().match(/^(0|false|no)$/i));
      if (autoOff) {
        log('Shannon: GHOSTRECON_SHANNON_AUTO_RUN=0 — não executar ./shannon start (só diagnóstico / clone).', 'info');
        emit({ type: 'pipe', name: 'shannon', state: 'skip' });
      } else if (!githubClonedItems.length) {
        log(
          'Shannon: nenhum clone local neste run — activa o módulo GitHub + clone (GHOSTRECON_GITHUB_CLONE_ENABLED) para analisar código.',
          'warn',
        );
        emit({ type: 'pipe', name: 'shannon', state: 'skip' });
      } else {
        pipe('shannon', 'active');
        const max = shannonMaxClonesPerRun();
        const slice = githubClonedItems.slice(0, max);
        log(`Shannon: a correr até ${slice.length} scan(s) (máx. por run = ${max})…`, 'info');
        for (const item of slice) {
          try {
            const out = await runShannonOnClone({
              ghostRoot: ROOT,
              domain,
              clonePath: item.local_path,
              repoFullName: item.full_name,
              log,
              emit,
              signal: ctx.signal,
            });
            if (out.ok && out.report?.ok) {
              const excerpt = String(out.report.content || '')
                .replace(/\s+/g, ' ')
                .trim()
                .slice(0, 480);
              addFinding(
                {
                  type: 'intel',
                  prio: 'high',
                  score: 72,
                  value: `Shannon white-box: ${item.full_name}`,
                  meta: `workspace=${out.workspaceId} • report=${out.report.path} • excerpt=${excerpt}`,
                  url: `https://github.com/${item.full_name}`,
                },
                null,
              );
            } else {
              const hint = out.detail || out.logTail || out.note || JSON.stringify({ phase: out.phase, exitCode: out.exitCode });
              log(`Shannon falhou (${item.full_name}): ${String(hint).slice(0, 600)}`, 'warn');
              addFinding(
                {
                  type: 'intel',
                  prio: 'med',
                  score: 48,
                  value: `Shannon falhou: ${item.full_name}`,
                  meta: `workspace=${out.workspaceId || '—'} • phase=${out.phase || '—'} • ${String(hint).slice(0, 400)}`,
                  url: `https://github.com/${item.full_name}`,
                },
                null,
              );
            }
          } catch (e) {
            if (e?.name === 'AbortError' || e?.code === 'PROCESS_ABORTED') throw e;
            log(`Shannon: excepção (${item.full_name}): ${e.message}`, 'error');
          }
        }
        pipe('shannon', 'done');
        applyPrioritizationV2(findings, bountyCtx);
      }
    }

    const modulesForDb = kaliMode ? [...modules, '__kali_scan__'] : modules;

    let pentestgptSummary = null;
    progress(98);
    if (modules.includes('pentestgpt_validate')) {
      pipe('pentestgpt', 'active');
      try {
        const pgPayload = buildPipelineExportPayloadForAi({
          target: domain,
          projectName: String(projectNameRaw || '').trim(),
          stats,
          findings,
          correlation: corr,
          reportTemplates,
          runId: null,
          storage: storageLabel(),
          intelMerge: null,
          kaliMode: Boolean(kaliMode),
          modules: modulesForDb,
          bountyContext: bountyCtx,
          auth,
        });
        const pg = await runPentestGptValidation(pgPayload, { log, urlOverride: pentestgptUrlOverride });
        pentestgptSummary = pg.summary || null;
        if (pg.findings?.length) {
          for (const f of pg.findings) addFinding(f, null);
        } else if (pg.summary && !pg.skipped) {
          addFinding(
            {
              type: 'intel',
              prio: 'med',
              score: 44,
              value: 'PentestGPT (resumo)',
              meta: String(pg.summary).slice(0, 900),
            },
            null,
          );
        }
      } catch (e) {
        log(`PentestGPT: ${e.message}`, 'warn');
      }
      pipe('pentestgpt', 'done');
    } else {
      emit({ type: 'pipe', name: 'pentestgpt', state: 'skip' });
    }

    progress(100);
    stats.high = findings.filter((f) => f.prio === 'high').length;
    emit({ type: 'stats', stats: { ...stats } });

    applyOwaspTagsToFindings(findings);
    applyMitreTagsToFindings(findings);
    if (modules.includes('risk_explainer')) {
      pipe('risk_explainer', 'active');
      const risk = applyRiskExplanations(findings);
      log(`Risk explainer: contexto adicionado a ${risk.changed} achado(s)`, 'info');
      pipe('risk_explainer', 'done');
    } else {
      emit({ type: 'pipe', name: 'risk_explainer', state: 'skip' });
    }
    emit({ type: 'findings_rescore', findings: [...findings] });
    log('OWASP Top 10 (2025): etiquetas heurísticas aplicadas a cada achado', 'info');
    log('MITRE ATT&CK (recon): mapa fixo aplicado quando recon-bundle.json existe', 'info');

    const findingsSnapshotJson = serializeFindingsForRunSnapshot(findings);
    const statsForSave = {
      ...stats,
      outOfScope: Array.isArray(outOfScopeList) ? [...outOfScopeList] : [],
    };
    const saved = await saveRun({
      target: domain,
      exactMatch,
      modules: modulesForDb,
      stats: statsForSave,
      findings,
      correlation: corr,
      localProjectName: String(projectNameRaw || '').trim(),
      findingsJson: findingsSnapshotJson,
    });
    let runId = null;
    let intelMerge = null;
    if (saved != null) {
      runId = saved.runId;
      intelMerge = saved.intelMerge;
      log(`Recon gravado — run #${runId} → ${storageLabel()}`, 'success');
      const eid = engagementIdRaw != null ? String(engagementIdRaw).trim() : '';
      if (eid && runId != null) {
        try {
          await attachRunToEngagement(eid, {
            runId,
            target: domain,
            by: engagementOperatorRaw != null ? String(engagementOperatorRaw).trim() || null : null,
          });
        } catch (e) {
          log(`Engagement: falha ao anexar run — ${e?.message || e}`, 'warn');
        }
        try {
          await recordAction({
            operator: engagementOperatorRaw != null ? String(engagementOperatorRaw).trim() || 'api' : 'api',
            target: domain,
            action: 'run-complete',
            runId,
            metadata: { engagementId: eid },
          });
        } catch (e) {
          log(`Team trail: falha ao registar — ${e?.message || e}`, 'warn');
        }
      }
      const sqlitePath = saved.localMirrorPath || saved.localFallbackPath || saved.dbPath;
      if (sqlitePath) {
        log(`SQLite no disco: ${sqlitePath}`, 'success');
      }
      if (saved.remoteSaveFailed) {
        log('Aviso: gravação remota falhou — este run ficou no SQLite local acima.', 'warn');
      }
      if (intelMerge?.newArtifacts > 0) {
        log(
          `Corpus do alvo: +${intelMerge.newArtifacts} artefacto(s) novo(s) na base; ${intelMerge.alreadyKnown} já existiam; total único para ${domain}: ${intelMerge.totalKnownForTarget}`,
          'success',
        );
      } else if (findings.length > 0 && intelMerge) {
        log(
          `Corpus do alvo: sem linhas novas (todos os ${intelMerge.alreadyKnown} achados deste run já estavam na base). Total único: ${intelMerge.totalKnownForTarget}`,
          'info',
        );
      }
      if (saved.projectSecretDuplicates?.length) {
        emit({ type: 'project_secret_peers', duplicates: saved.projectSecretDuplicates });
        log(
          `Correlação de segredos (mesmo projeto): ${saved.projectSecretDuplicates.length} valor(es) aparecem em 2+ alvos — Ghostmap / GET /api/project-secret-peers`,
          'warn',
        );
      }
      try {
        const runs = await listRuns(120);
        const nt = domain.trim().toLowerCase();
        const prev = runs.find((r) => String(r.target).trim().toLowerCase() === nt && r.id < runId);
        if (prev) {
          const diff = await compareRuns(prev.id, runId);
          if (!diff.error) {
            emit({
              type: 'delta_summary',
              baselineRunId: prev.id,
              newerRunId: runId,
              addedCount: diff.addedCount,
              removedCount: diff.removedCount,
              addedSample: diff.added.slice(0, 8).map((x) => ({
                type: x.type,
                prio: x.prio,
                value: String(x.value || '').slice(0, 180),
              })),
            });
            log(`Delta runs: +${diff.addedCount} novo(s), -${diff.removedCount} removido(s) vs run #${prev.id}`, diff.addedCount ? 'info' : 'success');
            const hotAdded = diff.added.filter((x) => {
              const t = String(x.type || '').toLowerCase();
              const v = String(x.value || '').toLowerCase();
              return ['xss', 'sqli', 'open_redirect', 'idor', 'lfi', 'secret', 'exploit', 'nuclei', 'takeover'].includes(t)
                || /\/(admin|api|graphql|internal|debug)|token|key|secret/.test(v);
            });
            if (hotAdded.length) {
              emit({
                type: 'delta_hot',
                baselineRunId: prev.id,
                newerRunId: runId,
                hotAddedCount: hotAdded.length,
                sample: hotAdded.slice(0, 12).map((x) => ({
                  type: x.type,
                  prio: x.prio,
                  value: String(x.value || '').slice(0, 180),
                })),
              });
              log(`Delta hot: ${hotAdded.length} novidade(s) crítica(s) vs run #${prev.id}`, 'warn');
            }
          }
        }
      } catch {
        /* ignore delta hot */
      }
    } else {
      log(`Não foi possível gravar na base (${storageLabel()}) — ver consola do servidor`, 'warn');
    }

    emit({
      type: 'done',
      target: domain,
      findings,
      stats,
      correlation: corr,
      runId,
      intelMerge,
      kaliMode: Boolean(kaliMode),
      storage: storageLabel(),
      reportTemplates,
      localSqlitePath: saved?.localMirrorPath || saved?.localFallbackPath || saved?.dbPath || null,
      remoteSaveFailed: Boolean(saved?.remoteSaveFailed),
      reconCoverage: reconCoverageSnapshot,
    });

    if (autoAiReports && aiAutoReportsServerAllowed() && aiKeysConfigured().any) {
      emit({ type: 'ai_report', phase: 'start', target: domain });
      const pri =
        String(aiPrimaryCloud || '').toLowerCase() === 'openrouter' || normalizeOpenrouterOnlyFlag(aiOpenrouterOnly)
          ? 'OpenRouter'
          : 'Gemini';
      const alt = pri === 'OpenRouter' ? 'Gemini' : 'OpenRouter';
      const iaOrder =
        aiUseOpenrouter === false
          ? 'Gemini (sem OpenRouter) → LM Studio → Claude se configurado'
          : `${pri} (primeiro) → LM Studio → ${alt} → Claude se configurado`;
      log(`IA: recon concluído — a gerar relatórios (${iaOrder}) com o JSON deste run…`, 'info');
      const pn = String(projectNameRaw || '').trim();
      const aiPayload = buildPipelineExportPayloadForAi({
        target: domain,
        projectName: pn,
        stats,
        findings,
        correlation: corr,
        reportTemplates,
        runId,
        storage: storageLabel(),
        intelMerge,
        kaliMode: Boolean(kaliMode),
        modules: modulesForDb,
        bountyContext: bountyCtx,
        auth,
      });
      try {
        const aiOut = await runDualAiReports(aiPayload, {
          projectName: pn,
          targetDomain: domain,
          aiProviderMode,
          aiUseOpenrouter,
          aiOpenrouterOnly,
          aiPrimaryCloud,
          onStatus: (message, level = 'info') => log(message, level),
        });
        pipelineAiOut = aiOut;
        emit({
          type: 'ai_report',
          phase: 'done',
          target: domain,
          outputDir: aiOut.outputDir,
          pipelineJsonPath: aiOut.pipelineJsonPath,
          gemini: { ok: Boolean(aiOut.gemini?.ok), error: aiOut.gemini?.error || null },
          openrouter: { ok: Boolean(aiOut.openrouter?.ok), error: aiOut.openrouter?.error || null },
          claude: { ok: Boolean(aiOut.claude?.ok), error: aiOut.claude?.error || null },
          lmstudio: { ok: Boolean(aiOut.lmstudio?.ok), error: aiOut.lmstudio?.error || null },
        });
        emitIaProximosPassosToLog(aiOut, log);
      } catch (e) {
        emit({
          type: 'ai_report',
          phase: 'error',
          target: domain,
          message: e?.message || String(e),
        });
        log(`IA: ${e?.message || e}`, 'error');
      }
    }

    let reconDeltaForWebhook = null;
    try {
      if (runId != null) {
        const runs = await listRuns(120);
        const nt = domain.trim().toLowerCase();
        const prev = runs.find((r) => String(r.target).trim().toLowerCase() === nt && r.id < runId);
        if (prev) {
          const diff = await compareRuns(prev.id, runId);
          if (!diff.error) {
            reconDeltaForWebhook = {
              baselineId: diff.baselineId,
              baselineCreatedAt: diff.baselineCreatedAt,
              newerCreatedAt: diff.newerCreatedAt,
              added: diff.added,
              removedCount: diff.removedCount,
              removedSample: diff.removed.slice(0, 10).map((x) => ({
                type: x.type,
                prio: x.prio,
                value: String(x.value ?? '').slice(0, 240),
              })),
            };
          }
        }
      }
    } catch (e) {
      console.warn('[GHOSTRECON webhook diff]', e?.message || e);
    }

    const whUrl = process.env.GHOSTRECON_WEBHOOK_URL?.trim();
    if (whUrl && runId != null) {
      const findingsByType = {};
      for (const f of findings) {
        const t = f?.type || 'unknown';
        findingsByType[t] = (findingsByType[t] || 0) + 1;
      }
      let runDiffSummary = null;
      if (reconDeltaForWebhook) {
        const d = reconDeltaForWebhook;
        runDiffSummary = {
          baselineId: d.baselineId,
          newerId: runId,
          baselineCreatedAt: d.baselineCreatedAt,
          newerCreatedAt: d.newerCreatedAt,
          addedCount: d.added.length,
          removedCount: d.removedCount,
          addedSample: d.added.slice(0, 10).map((x) => ({
            type: x.type,
            prio: x.prio,
            value: String(x.value ?? '').slice(0, 240),
          })),
          removedSample: d.removedSample || [],
        };
      }
      const shannonSummary =
        findings
          .filter((f) => f?.type === 'intel' && /shannon/i.test(`${f.value || ''} ${f.meta || ''}`))
          .map((f) => `${String(f.value || '').slice(0, 140)} — ${String(f.meta || '').slice(0, 120)}`)
          .slice(0, 4)
          .join(' | ') || null;

      void postReconWebhook(whUrl, {
        target: domain,
        runId,
        stats,
        intelMerge,
        kaliMode: Boolean(kaliMode),
        modules: modulesForDb,
        highCount: findings.filter((f) => f.prio === 'high').length,
        findingsByType,
        runDiffSummary,
        shannonSummary,
        pentestgptSummary,
      });
    }

    const whAi = process.env.GHOSTRECON_WEBHOOK_URL?.trim();
    if (whAi) {
      const picked = pickAiReportForWebhook(pipelineAiOut);
      if (picked) {
        void postAiReportWebhook(whAi, {
          target: domain,
          runId,
          provider: picked.provider,
          relatorio: picked.relatorio,
          proximos_passos: picked.proximos_passos,
        });
        if (reconDeltaForWebhook) {
          void postReconDeltaFullWebhook(whAi, {
            target: domain,
            runId,
            baselineId: reconDeltaForWebhook.baselineId,
            baselineCreatedAt: reconDeltaForWebhook.baselineCreatedAt,
            newerCreatedAt: reconDeltaForWebhook.newerCreatedAt,
            added: reconDeltaForWebhook.added,
            removedCount: reconDeltaForWebhook.removedCount,
          });
        }
      } else if (reconDeltaForWebhook) {
        void postReconDeltaFullWebhook(whAi, {
          target: domain,
          runId,
          baselineId: reconDeltaForWebhook.baselineId,
          baselineCreatedAt: reconDeltaForWebhook.baselineCreatedAt,
          newerCreatedAt: reconDeltaForWebhook.newerCreatedAt,
          added: reconDeltaForWebhook.added,
          removedCount: reconDeltaForWebhook.removedCount,
        });
      }
    }

}
