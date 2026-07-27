import { parseReconTarget } from '../modules/recon-target.js';
import { requireScope, reconBodyIsIntrusive, audit as auditAuth } from '../modules/auth.js';
import { getEngagement, preRunChecklist } from '../modules/engagement.mjs';
import { reconHttpContext } from '../lib/http-history.mjs';
import { runAutoRecon } from '../auto-agent/orchestrator.mjs';
import {
  listAutoRagMarkdown,
  searchAutoRagMarkdown,
  writeAutoLesson,
  writeAutoRagNote,
} from '../auto-agent/rag-memory.mjs';
import {
  compareForgeVersions,
  createForgeEngagementBinding,
  listForgePackages,
  manageForgePackage,
  readForgePackage,
  recordForgeRuntimeResult,
  sameForgeEngagementBinding,
  transitionForgePackage,
} from '../auto-agent/forge/lifecycle.mjs';
import { runActiveDynamicModules } from '../auto-agent/forge/runtime-loader.mjs';
import {
  autoSessionOwnership,
  bindActiveAutoSessionOwner,
  cancelActiveAutoSession,
  getActiveAutoSession,
  listActiveAutoSessions,
} from '../auto-agent/active-sessions.mjs';
import { readAutoSessionSnapshot, reconcileOrphanedAutoSessions } from '../auto-agent/session-store.mjs';
import {
  getFrameSevenApproval,
  readFrameSevenPublicReport,
  readFrameSevenReportAccess,
  resolveFrameSevenApproval,
} from '../integrations/frameseven-runner.mjs';
import { redactAutoValue } from '../auto-agent/redaction.mjs';
import { createBubblewrapForgeSandboxRunner } from '../auto-agent/forge/bwrap-runner.mjs';

const INTRUSIVE_AUTO_LEVELS = new Set(['authorized', 'authorized_opsec']);
const DEFAULT_FORGE_CANARY_TIMEOUT_MS = 5 * 60_000;
const MAX_FORGE_CANARY_TIMEOUT_MS = 60 * 60_000;

const PRIVATE_ARTIFACT_KEYS = new Set([
  'baseDir',
  'binary',
  'command',
  'dir',
  'filePath',
  'outputDir',
  'path',
  'pendingDir',
  'revisionDir',
  'stack',
]);

export function publicArtifactValue(item) {
  const redacted = redactAutoValue(item);
  const sanitize = (value) => {
    if (Array.isArray(value)) return value.map(sanitize);
    if (!value || typeof value !== 'object') return value;
    const safe = {};
    for (const [key, child] of Object.entries(value)) {
      if (PRIVATE_ARTIFACT_KEYS.has(key)) continue;
      safe[key] = sanitize(child);
    }
    return safe;
  };
  return sanitize(redacted);
}

function publicForgeItem(item) {
  return publicArtifactValue(item);
}

function publicRagMemory(item) {
  return publicArtifactValue(item);
}

export function validateForgeCanaryEngagement({ candidate, engagement, engagementId } = {}) {
  const selectedEngagementId = String(engagementId || '').trim();
  if (!selectedEngagementId) {
    throw new Error('engagementId formal é obrigatório para aprovar e executar o canário Forge');
  }
  if (!engagement) throw new Error(`engagement "${selectedEngagementId}" não encontrado`);
  const parsedTarget = parseReconTarget(candidate?.target);
  if (!parsedTarget.ok) throw new Error('alvo original do pacote Forge é inválido');
  const checklist = preRunChecklist({
    engagement,
    target: parsedTarget.target,
    modules: [candidate?.moduleId].filter(Boolean),
    requireFormalAuthorization: true,
  });
  if (!checklist.ok) {
    throw new Error(`canário Forge fora da autorização: ${checklist.errors.join(' ')}`);
  }
  return {
    target: parsedTarget.target,
    checklist,
    engagementBinding: createForgeEngagementBinding({
      engagement,
      engagementId: selectedEngagementId,
      target: parsedTarget.target,
    }),
  };
}

async function loadForgeCanaryAuthorization({
  candidate,
  engagementId,
  getEngagementImpl,
} = {}) {
  const engagement = await getEngagementImpl(engagementId);
  return validateForgeCanaryEngagement({
    candidate,
    engagement,
    engagementId,
  });
}

function boundedForgeTimeout(value) {
  const parsed = Number(value);
  if (!Number.isFinite(parsed) || parsed < 100) return DEFAULT_FORGE_CANARY_TIMEOUT_MS;
  return Math.min(MAX_FORGE_CANARY_TIMEOUT_MS, Math.floor(parsed));
}

/**
 * Estado mínimo do primeiro canário Forge. Este objeto nunca é entregue ao
 * pipeline legado: somente o loader dinâmico e o runner de sandbox o recebem.
 */
export function buildForgeCanaryPipelineContext({
  result,
  manifest = {},
  emit,
  signal = null,
  forgeSandboxRunner = null,
  addFinding = () => {},
  log = () => {},
  pipe = () => {},
} = {}) {
  const moduleId = String(result?.moduleId || '').trim();
  const target = String(result?.target || '').trim();
  if (!moduleId || !target) throw new Error('canário Forge exige módulo e alvo válidos');
  return {
    domain: target,
    exactMatch: false,
    modules: [moduleId],
    profile: 'standard',
    opsecProfile: 'standard',
    autoAiReports: false,
    autoModeExecution: true,
    enablePhaseTimeouts: true,
    continueOnPhaseError: false,
    phaseTimeoutsMs: {
      dynamic_modules: boundedForgeTimeout(manifest?.timeoutMs),
    },
    phaseSettleGraceMs: 2_000,
    requestRunId: `forge-canary-${String(result?.forgeId || moduleId).slice(0, 96)}`,
    forgeCanaryId: String(result?.forgeId || '').trim(),
    forgeCanaryActivation: {
      activationId: String(result?.activationId || '').trim(),
      expectedTarget: target,
      expectedArtifactIntegrity: result?.artifactIntegrity || null,
      engagementBinding: result?.engagementBinding || null,
    },
    forgeSandboxRunner,
    signal,
    emit,
    addFinding,
    log,
    pipe,
    throwIfAborted() {
      signal?.throwIfAborted?.();
    },
  };
}

export async function executeForgeCanaryDirect({
  root,
  result,
  manifest = {},
  signal = null,
  forgeSandboxRunner,
  emit = () => {},
} = {}) {
  const findings = [];
  const events = [];
  const state = buildForgeCanaryPipelineContext({
    result,
    manifest,
    signal,
    forgeSandboxRunner,
    addFinding: (finding) => findings.push(finding),
    emit: (event) => {
      events.push(event);
      emit(event);
    },
  });
  const summary = await runActiveDynamicModules(state, {
    root,
    isolatedRunner: forgeSandboxRunner,
  });
  const completed = events.find((event) => (
    event.type === 'dynamic_module_completed'
    && event.forgeId === result.forgeId
  ));
  const failed = events.find((event) => (
    ['dynamic_module_error', 'dynamic_module_timeout', 'dynamic_module_cancelled'].includes(event.type)
    && event.forgeId === result.forgeId
  ));
  if (!completed || failed || summary.completed !== 1 || summary.executed !== 1) {
    throw new Error(
      failed?.error
      || `canário Forge direto não concluiu exclusivamente o módulo aprovado (executed=${summary.executed}, completed=${summary.completed})`,
    );
  }
  return { summary, events, findings };
}

export function autoReconRequestIsIntrusive(body = {}) {
  return INTRUSIVE_AUTO_LEVELS.has(String(body?.autonomyLevel || '').trim().toLowerCase())
    || body?.frameSevenAuth === true
    || body?.includeVigolium === true
    || reconBodyIsIntrusive(body);
}

function principalCanRunIntrusive(principal) {
  if (principal?.role === 'admin') return true;
  const scopes = principal?._scopeSet instanceof Set
    ? principal._scopeSet
    : new Set(Array.isArray(principal?.scopes) ? principal.scopes : []);
  return scopes.has('*') || scopes.has('recon.intrusive') || scopes.has('recon.*');
}

function principalCanReadAllFrameSevenReports(principal) {
  if (principal?.role === 'admin') return true;
  const scopes = principal?._scopeSet instanceof Set
    ? principal._scopeSet
    : new Set(Array.isArray(principal?.scopes) ? principal.scopes : []);
  return scopes.has('*');
}

export function registerAutoReconRoutes(app, deps = {}) {
  const {
    runPipeline,
    validateCsrfToken,
    allowReconRequest,
    ROOT,
    audit: auditEvent = auditAuth,
    env = process.env,
    forgeSandboxRunner: configuredForgeSandboxRunner = null,
    createForgeSandboxRunner = createBubblewrapForgeSandboxRunner,
    getEngagementImpl = getEngagement,
  } = deps;
  let forgeSandboxRunnerPromise = null;
  const getForgeSandboxRunner = async () => {
    if (configuredForgeSandboxRunner) return configuredForgeSandboxRunner;
    if (typeof createForgeSandboxRunner !== 'function') return null;
    if (!forgeSandboxRunnerPromise) {
      forgeSandboxRunnerPromise = Promise.resolve()
        .then(() => createForgeSandboxRunner({ env }))
        .catch(() => null);
    }
    return forgeSandboxRunnerPromise;
  };

  void reconcileOrphanedAutoSessions(ROOT).catch(() => []);

  app.get('/api/recon/auto/sessions', requireScope('recon.read'), (req, res) => {
    res.json({ ok: true, sessions: listActiveAutoSessions({ principal: req.principal }) });
  });

  app.get(
    '/api/frameseven/reports/:reportId/:file',
    requireScope('recon.read'),
    async (req, res) => {
      const reportId = String(req.params.reportId || '');
      const fileName = String(req.params.file || '');
      try {
        const access = await readFrameSevenReportAccess(ROOT, reportId);
        if (!access) {
          auditEvent(req, req.principal, 'deny', {
            action: 'frameseven.report.read',
            reportId,
            reason: 'access_metadata_missing_or_invalid',
          });
          res.status(404).type('text/plain').send('report not found');
          return;
        }

        const principalSub = String(req.principal?.sub || '').trim() || null;
        const privileged = principalCanReadAllFrameSevenReports(req.principal);
        if (!privileged && (!access.ownerSub || access.ownerSub !== principalSub)) {
          auditEvent(req, req.principal, 'deny', {
            action: 'frameseven.report.read',
            reportId,
            reason: 'report_owned_by_other_principal',
          });
          res.status(403).type('text/plain').send('report access denied');
          return;
        }
        if (access.authenticated && !access.engagementId) {
          auditEvent(req, req.principal, 'deny', {
            action: 'frameseven.report.read',
            reportId,
            reason: 'authenticated_report_without_engagement_binding',
          });
          res.status(403).type('text/plain').send('report access denied');
          return;
        }
        if (access.engagementId) {
          const engagement = await getEngagementImpl(access.engagementId);
          const parsedTarget = parseReconTarget(access.target);
          const historicalScope = engagement
            ? preRunChecklist({
                engagement: {
                  ...engagement,
                  // A leitura histórica não reabre uma execução e, portanto,
                  // não depende da janela/status atuais. Escopo, exclusões e
                  // vínculo de ROE permanecem obrigatórios.
                  status: 'active',
                  window: null,
                },
                target: parsedTarget.ok ? parsedTarget.target : access.target,
                modules: ['frameseven_active'],
                requireFormalAuthorization: true,
                intrusiveModules: ['frameseven_active'],
              })
            : null;
          if (!historicalScope?.ok) {
            auditEvent(req, req.principal, 'deny', {
              action: 'frameseven.report.read',
              reportId,
              engagementId: access.engagementId,
              reason: 'engagement_binding_invalid',
            });
            res.status(403).type('text/plain').send('report access denied');
            return;
          }
        }

        const report = await readFrameSevenPublicReport(ROOT, reportId, fileName);
        if (!report) {
          res.status(404).type('text/plain').send('report not found');
          return;
        }
        const contentTypes = {
          'report.html': 'text/html; charset=utf-8',
          'report.json': 'application/json; charset=utf-8',
          'report.md': 'text/markdown; charset=utf-8',
        };
        res.setHeader('Content-Type', contentTypes[fileName]);
        res.setHeader('Content-Disposition', `inline; filename="${fileName}"`);
        res.setHeader('Content-Length', String(report.size));
        res.setHeader('Cache-Control', 'private, no-store');
        res.setHeader('Referrer-Policy', 'no-referrer');
        res.setHeader('X-Content-Type-Options', 'nosniff');
        if (fileName === 'report.html') {
          res.setHeader(
            'Content-Security-Policy',
            "sandbox; default-src 'none'; style-src 'unsafe-inline'",
          );
        }
        auditEvent(req, req.principal, 'allow', {
          action: 'frameseven.report.read',
          reportId,
          file: fileName,
          engagementId: access.engagementId,
          authenticated: access.authenticated,
        });
        res.send(report.body);
      } catch {
        res.status(404).type('text/plain').send('report not found');
      }
    },
  );

  app.post('/api/recon/auto/:sessionId/cancel', requireScope('recon.run'), async (req, res) => {
    const sessionId = String(req.params.sessionId || '');
    if (!validateCsrfToken(req)) {
      auditEvent(req, req.principal, 'deny', { action: 'recon.auto.cancel', sessionId, reason: 'csrf' });
      res.status(403).json({ ok: false, error: 'CSRF invalido/ausente' });
      return;
    }
    const session = getActiveAutoSession(sessionId);
    if (!session) {
      try {
        const snapshot = await readAutoSessionSnapshot(ROOT, sessionId);
        const ownership = autoSessionOwnership(snapshot, req.principal);
        if (ownership !== 'owned') {
          auditEvent(req, req.principal, 'deny', { action: 'recon.auto.cancel', sessionId, reason: `session_${ownership}` });
          res.status(403).json({ ok: false, sessionId, error: 'sessão AUTO pertence a outro principal' });
          return;
        }
        if (snapshot.status !== 'running') {
          auditEvent(req, req.principal, 'allow', {
            action: 'recon.auto.cancel', sessionId, result: 'already_terminal', status: snapshot.status,
          });
          res.status(200).json({
            ok: true,
            sessionId,
            accepted: false,
            terminal: true,
            status: snapshot.status,
            error: null,
          });
          return;
        }
        auditEvent(req, req.principal, 'deny', { action: 'recon.auto.cancel', sessionId, reason: 'session_not_active' });
        res.status(409).json({
          ok: false,
          sessionId,
          accepted: false,
          terminal: false,
          status: snapshot.status,
          error: 'sessão AUTO registrada como running, mas não está ativa',
        });
        return;
      } catch {
        auditEvent(req, req.principal, 'deny', { action: 'recon.auto.cancel', sessionId, reason: 'session_not_found' });
        res.status(404).json({ ok: false, sessionId, error: 'sessão AUTO não encontrada' });
        return;
      }
    }
    const ownership = autoSessionOwnership(session, req.principal);
    if (ownership !== 'owned') {
      auditEvent(req, req.principal, 'deny', { action: 'recon.auto.cancel', sessionId, reason: `session_${ownership}` });
      res.status(403).json({ ok: false, sessionId, error: 'sessão AUTO pertence a outro principal' });
      return;
    }
    if (session.state.status !== 'running') {
      auditEvent(req, req.principal, 'allow', {
        action: 'recon.auto.cancel', sessionId, result: 'already_terminal', status: session.state.status,
      });
      res.status(200).json({
        ok: true,
        sessionId,
        accepted: false,
        terminal: true,
        status: session.state.status,
        error: null,
      });
      return;
    }
    const cancelled = cancelActiveAutoSession(
      sessionId,
      `cancelled_by_${req.principal?.sub || 'operator'}`,
      { principal: req.principal },
    );
    auditEvent(req, req.principal, cancelled ? 'allow' : 'deny', {
      action: 'recon.auto.cancel',
      sessionId,
      result: cancelled ? 'accepted' : 'not_active',
    });
    res.status(cancelled ? 202 : 404).json({
      ok: cancelled,
      sessionId,
      accepted: cancelled,
      terminal: false,
      status: cancelled ? 'cancelling' : null,
      error: cancelled ? null : 'sessão AUTO ativa não encontrada',
    });
  });

  app.post('/api/recon/auto/:sessionId/approval', requireScope('recon.run', {
    intrusiveCheck: (req) => getActiveAutoSession(req.params.sessionId)?.state?.pendingApproval?.intrusive === true,
  }), (req, res) => {
    const sessionId = String(req.params.sessionId || '');
    if (!validateCsrfToken(req)) {
      auditEvent(req, req.principal, 'deny', { action: 'recon.auto.approval', sessionId, reason: 'csrf' });
      res.status(403).json({ ok: false, error: 'CSRF invalido/ausente' });
      return;
    }
    const session = getActiveAutoSession(sessionId);
    const approvalId = String(req.body?.approvalId || '');
    const approved = req.body?.approved === true;
    if (!session) {
      auditEvent(req, req.principal, 'deny', { action: 'recon.auto.approval', sessionId, approvalId, reason: 'session_not_found' });
      res.status(404).json({ ok: false, error: 'sessão AUTO ativa não encontrada' });
      return;
    }
    const ownership = autoSessionOwnership(session, req.principal);
    if (ownership !== 'owned') {
      auditEvent(req, req.principal, 'deny', {
        action: 'recon.auto.approval', sessionId, approvalId, reason: `session_${ownership}`,
      });
      res.status(403).json({ ok: false, error: 'sessão AUTO pertence a outro principal' });
      return;
    }
    const pendingApproval = session.state.pendingApproval;
    if (pendingApproval?.intrusive === true && !principalCanRunIntrusive(req.principal)) {
      auditEvent(req, req.principal, 'deny', {
        action: 'recon.auto.approval', sessionId, approvalId, reason: 'missing_intrusive_scope',
      });
      res.status(403).json({ ok: false, error: 'missing scope: recon.intrusive' });
      return;
    }
    const resolved = session?.resolveApproval?.(approvalId, approved, String(req.body?.reason || '')) || false;
    auditEvent(req, req.principal, resolved ? 'allow' : 'deny', {
      action: 'recon.auto.approval',
      sessionId,
      approvalId,
      operatorDecision: approved ? 'approved' : 'denied',
      intrusive: pendingApproval?.intrusive === true,
      result: resolved ? 'accepted' : 'approval_not_pending',
    });
    res.status(resolved ? 202 : 404).json({ ok: resolved, error: resolved ? null : 'aprovação pendente não encontrada' });
  });

  app.post('/api/recon/frameseven/:approvalId/approval', requireScope('recon.run', {
    intrusiveCheck: () => true,
  }), (req, res) => {
    if (!validateCsrfToken(req)) {
      auditEvent(req, req.principal, 'deny', {
        action: 'recon.frameseven.approval', approvalId: String(req.params.approvalId || ''), reason: 'csrf',
      });
      return res.status(403).json({ ok: false, error: 'CSRF invalido/ausente' });
    }
    const approval = getFrameSevenApproval(req.params.approvalId);
    const principalSub = String(req.principal?.sub || '').trim() || null;
    if (approval?.ownerSub && approval.ownerSub !== principalSub) {
      auditEvent(req, req.principal, 'deny', {
        action: 'recon.frameseven.approval',
        approvalId: String(req.params.approvalId || ''),
        reason: 'approval_owned_by_other_principal',
      });
      return res.status(403).json({ ok: false, error: 'aprovação FrameSeven pertence a outro principal' });
    }
    const ok = resolveFrameSevenApproval(
      req.params.approvalId,
      req.body?.approved === true,
      { principal: req.principal },
    );
    auditEvent(req, req.principal, ok ? 'allow' : 'deny', {
      action: 'recon.frameseven.approval',
      approvalId: String(req.params.approvalId || ''),
      operatorDecision: req.body?.approved === true ? 'approved' : 'denied',
      result: ok ? 'accepted' : 'approval_not_pending',
    });
    return res.status(ok ? 202 : 404).json({ ok });
  });

  app.get('/api/auto-forge', requireScope('forge.review'), async (_req, res) => {
    try {
      res.json({ ok: true, items: (await listForgePackages(ROOT)).map(publicForgeItem) });
    } catch (e) {
      res.status(500).json({ ok: false, error: e?.message || String(e) });
    }
  });

  app.get('/api/auto-forge/:forgeId', requireScope('forge.review'), async (req, res) => {
    try {
      res.json({
        ok: true,
        item: publicForgeItem(await readForgePackage(ROOT, String(req.params.forgeId || ''))),
      });
    } catch (e) {
      res.status(404).json({ ok: false, error: e?.message || String(e) });
    }
  });

  app.get('/api/auto-forge-module/:moduleId/compare', requireScope('forge.review'), async (req, res) => {
    try {
      res.json({ ok: true, moduleId: req.params.moduleId, versions: await compareForgeVersions(ROOT, String(req.params.moduleId || '')) });
    } catch (error) {
      res.status(400).json({ ok: false, error: error?.message || String(error) });
    }
  });

  app.post(
    '/api/auto-forge/:forgeId/verdict',
    requireScope('forge.review'),
    requireScope('recon.run'),
    async (req, res) => {
    if (!validateCsrfToken(req)) {
      res.status(403).json({ ok: false, error: 'CSRF invalido/ausente' });
      return;
    }
    const controller = new AbortController();
    req.once?.('aborted', () => controller.abort(new Error('cliente desconectado durante canário Forge')));
    res.once?.('close', () => {
      if (!res.writableEnded) controller.abort(new Error('resposta encerrada durante canário Forge'));
    });
    try {
      const decision = String(req.body?.decision || '');
      let canarySandboxRunner = null;
      let candidate = null;
      let engagementId = '';
      let approvalAuthorization = null;
      let expectedArtifactIntegrity = null;
      if (decision === 'approve') {
        candidate = await readForgePackage(ROOT, String(req.params.forgeId || ''));
        engagementId = String(req.body?.engagementId || '').trim();
        approvalAuthorization = await loadForgeCanaryAuthorization({
          candidate,
          engagementId,
          getEngagementImpl,
        });
        expectedArtifactIntegrity =
          candidate?.artifacts?.['verdict.json']?.validation?.artifactIntegrity || null;
        canarySandboxRunner = await getForgeSandboxRunner();
        if (!canarySandboxRunner) {
          const unavailable = new Error('sandbox forte Bubblewrap indisponível para o canário Forge');
          unavailable.code = 'AUTO_FORGE_STRONG_SANDBOX_REQUIRED';
          throw unavailable;
        }
      }
      const result = await transitionForgePackage({
        root: ROOT,
        forgeId: String(req.params.forgeId || ''),
        decision,
        reason: String(req.body?.reason || ''),
        percentage: req.body?.percentage,
        operator: req.principal?.sub || 'local',
        expectedTarget: approvalAuthorization?.target,
        expectedArtifactIntegrity,
        engagementBinding: approvalAuthorization?.engagementBinding,
        verifyEngagementBinding: decision === 'approve'
          ? async () => (
              await loadForgeCanaryAuthorization({
                candidate: await readForgePackage(
                  ROOT,
                  String(req.params.forgeId || ''),
                ),
                engagementId,
                getEngagementImpl,
              })
            ).engagementBinding
          : null,
      });
      if (result.decision !== 'approve') {
        res.json(publicForgeItem(result));
        return;
      }
      const runtimeEvents = [];
      let runtime;
      try {
        controller.signal.throwIfAborted();
        const approvedPackage = await readForgePackage(ROOT, result.forgeId);
        const immediateAuthorization = await loadForgeCanaryAuthorization({
          candidate: approvedPackage,
          engagementId,
          getEngagementImpl,
        });
        if (!sameForgeEngagementBinding(
          result.engagementBinding,
          immediateAuthorization.engagementBinding,
        )) {
          const stale = new Error('engagement Forge mudou/expirou antes do canário');
          stale.code = 'FORGE_APPROVAL_STALE';
          throw stale;
        }
        const execution = await executeForgeCanaryDirect({
          root: ROOT,
          result,
          manifest: approvedPackage?.artifacts?.['manifest.json'] || {},
          signal: controller.signal,
          forgeSandboxRunner: canarySandboxRunner,
          emit: (event) => runtimeEvents.push(event),
        });
        const postRunAuthorization = await loadForgeCanaryAuthorization({
          candidate: approvedPackage,
          engagementId,
          getEngagementImpl,
        });
        if (!sameForgeEngagementBinding(
          result.engagementBinding,
          postRunAuthorization.engagementBinding,
        )) {
          const stale = new Error('engagement Forge mudou/expirou durante o canário');
          stale.code = 'FORGE_APPROVAL_STALE';
          throw stale;
        }
        runtime = await recordForgeRuntimeResult({
          root: ROOT,
          forgeId: result.forgeId,
          activationId: result.activationId,
          expectedTarget: result.target,
          expectedArtifactIntegrity: result.artifactIntegrity,
          engagementBinding: result.engagementBinding,
          success: true,
          findings: execution.findings.length,
        });
      } catch (error) {
        if (error?.code === 'AUTO_FORGE_SANDBOX_UNTERMINATED') throw error;
        runtime = await recordForgeRuntimeResult({
          root: ROOT,
          forgeId: result.forgeId,
          activationId: result.activationId,
          expectedTarget: result.target,
          expectedArtifactIntegrity: result.artifactIntegrity,
          engagementBinding: result.engagementBinding,
          success: false,
          error: error?.message || String(error),
        });
      }
      res.status(runtime.ok ? 200 : 422).json({
        ...publicForgeItem(result),
        ok: runtime.ok,
        runtime,
        eventCount: runtimeEvents.length,
      });
    } catch (e) {
      if (!res.writableEnded) {
        res.status(400).json({ ok: false, error: e?.message || String(e) });
      }
    }
  });

  app.post('/api/auto-forge/:forgeId/lifecycle', requireScope('forge.manage'), async (req, res) => {
    if (!validateCsrfToken(req)) {
      res.status(403).json({ ok: false, error: 'CSRF invalido/ausente' });
      return;
    }
    try {
      res.json(publicForgeItem(await manageForgePackage({
        root: ROOT,
        forgeId: String(req.params.forgeId || ''),
        action: String(req.body?.action || ''),
        reason: String(req.body?.reason || ''),
        percentage: req.body?.percentage,
        operator: req.principal?.sub || 'local',
      })));
    } catch (error) {
      res.status(400).json({ ok: false, error: error?.message || String(error) });
    }
  });

  app.get('/api/auto-rag/status', requireScope('recon.read'), async (_req, res) => {
    try {
      const memories = await listAutoRagMarkdown({ root: ROOT, limit: 500 });
      const counts = memories.reduce((acc, item) => {
        acc[item.folder || 'decisions'] = (acc[item.folder || 'decisions'] || 0) + 1;
        return acc;
      }, {});
      res.json({
        ok: true,
        vault: 'auto-rag',
        count: memories.length,
        counts,
        recent: memories.slice(0, 12).map(publicRagMemory),
      });
    } catch (e) {
      res.status(500).json({ ok: false, error: e?.message || String(e) });
    }
  });

  app.get('/api/auto-rag/search', requireScope('recon.read'), async (req, res) => {
    try {
      const query = String(req.query?.q || req.query?.query || '').trim();
      const limit = Math.max(1, Math.min(50, Number(req.query?.limit || 8)));
      res.json({
        ok: true,
        vault: 'auto-rag',
        query,
        memories: (await searchAutoRagMarkdown({ root: ROOT, query, limit })).map(publicRagMemory),
      });
    } catch (e) {
      res.status(500).json({ ok: false, error: e?.message || String(e) });
    }
  });

  app.post('/api/auto-rag/note', requireScope('notes.write'), async (req, res) => {
    if (!validateCsrfToken(req)) {
      res.status(403).json({ ok: false, error: 'CSRF invalido/ausente' });
      return;
    }
    try {
      const body = req.body || {};
      const note = body.kind === 'lesson'
        ? await writeAutoLesson({
          root: ROOT,
          target: body.target,
          problem: body.problem,
          decision: body.decision,
          outcome: body.outcome,
          modules: Array.isArray(body.modules) ? body.modules : [],
          commanders: body.commanders || null,
          confidence: body.confidence,
          tags: Array.isArray(body.tags) ? body.tags : [],
          metadata: body.metadata || null,
        })
        : await writeAutoRagNote({
          root: ROOT,
          kind: body.kind || 'note',
          title: body.title || 'Auto note',
          body: body.body || '',
          target: body.target || '',
          tags: Array.isArray(body.tags) ? body.tags : [],
          metadata: body.metadata || null,
        });
      res.json({ ok: true, note: publicRagMemory(note) });
    } catch (e) {
      res.status(500).json({ ok: false, error: e?.message || String(e) });
    }
  });

  app.post('/api/recon/auto/stream', requireScope('recon.run', {
    intrusiveCheck: (req) => autoReconRequestIsIntrusive(req.body),
  }), async (req, res) => {
    res.setHeader('Content-Type', 'application/x-ndjson; charset=utf-8');
    res.setHeader('Cache-Control', 'no-cache, no-transform');
    res.setHeader('X-Accel-Buffering', 'no');

    const send = (obj) => {
      if (obj?.type === 'auto_session' && obj?.phase === 'started' && obj?.sessionId) {
        const bound = bindActiveAutoSessionOwner(obj.sessionId, req.principal);
        auditEvent(req, req.principal, bound ? 'allow' : 'deny', {
          action: 'recon.auto.session.bind',
          sessionId: obj.sessionId,
          reason: bound ? null : 'owner_binding_failed',
        });
        if (!bound) getActiveAutoSession(obj.sessionId)?.abort('session_owner_binding_failed');
      }
      res.write(`${JSON.stringify(obj)}\n`);
    };

    if (!validateCsrfToken(req)) {
      send({ type: 'error', message: 'CSRF token invalido/ausente' });
      res.end();
      return;
    }

    if (!allowReconRequest(req)) {
      send({ type: 'error', message: 'Rate limit - aguarde antes de novo recon auto' });
      res.end();
      return;
    }

    const parsed = parseReconTarget(req.body?.domain || req.body?.target);
    if (!parsed.ok) {
      send({ type: 'error', message: parsed.message || 'Alvo invalido' });
      res.end();
      return;
    }

    const body = {
      ...req.body,
      domain: parsed.target,
    };

    if (body.resumeSessionId) {
      try {
        const snapshot = await readAutoSessionSnapshot(ROOT, String(body.resumeSessionId));
        const ownership = autoSessionOwnership(snapshot, req.principal);
        if (ownership !== 'owned') {
          auditEvent(req, req.principal, 'deny', {
            action: 'recon.auto.resume',
            sessionId: String(body.resumeSessionId),
            reason: `session_${ownership}`,
          });
          send({ type: 'error', message: 'sessão AUTO pertence a outro principal' });
          res.end();
          return;
        }
      } catch (error) {
        auditEvent(req, req.principal, 'deny', {
          action: 'recon.auto.resume',
          sessionId: String(body.resumeSessionId),
          reason: 'snapshot_invalid_or_missing',
        });
        send({ type: 'error', message: error?.message || 'snapshot de sessão AUTO inválido' });
        res.end();
        return;
      }
    }

    auditEvent(req, req.principal, 'allow', {
      action: 'recon.auto.start',
      target: parsed.target,
      commanders: Array.isArray(body.commanders) ? body.commanders : [],
      mode: body.autoMode || body.mode || 'balanced',
      autonomyLevel: String(body.autonomyLevel || 'observation'),
      intrusive: autoReconRequestIsIntrusive(body),
    });

    const requestRunId = `auto-http-${Date.now().toString(36)}`;
    const controller = new AbortController();
    req.once('aborted', () => controller.abort(new Error('cliente desconectado')));
    res.once('close', () => {
      if (!res.writableEnded) controller.abort(new Error('stream encerrado pelo cliente'));
    });
    try {
      const forgeSandboxRunner = await getForgeSandboxRunner();
      await reconHttpContext.run({ requestRunId, target: parsed.target, emit: send }, async () => {
        await runAutoRecon({
          body,
          runPipeline,
          emit: send,
          ROOT,
          env,
          forgeSandboxRunner,
          signal: controller.signal,
          principal: req.principal,
        });
      });
    } catch (e) {
      send({ type: 'error', message: e?.message || String(e) });
    } finally {
      res.end();
    }
  });
}
