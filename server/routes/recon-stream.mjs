import { randomBytes } from 'node:crypto';
import { parseReconTarget } from '../modules/recon-target.js';
import { getEngagement, preRunChecklist } from '../modules/engagement.mjs';
import { gateModules, applyWatermarkHeaders } from '../modules/opsec.mjs';
import { createIdentityController, normalizeIdentityOptions } from '../modules/identity-controller.mjs';
import { prependExtraPathToEnvPath } from '../modules/tool-path.js';
import { getShannonCapabilities } from '../modules/shannon-capabilities.js';
import { quickValidateTor, isNavigatorModeActive } from '../modules/navegation.js';
import {
  requireScope,
  reconBodyIsIntrusive,
  audit as auditAuth,
} from '../modules/auth.js';
import { newnym as torNewnym } from '../modules/tor-control.js';
import {
  beginTorStrictScope,
  refuseToRun as torRefuseToRun,
} from '../modules/tor-strict.js';
import { normalizeOpenrouterOnlyFlag } from '../modules/ai-dual-report.js';
import { reconHttpContext } from '../lib/http-history.mjs';

export function registerReconStreamRoutes(app, deps) {
  const {
    runPipeline,
    validateCsrfToken,
    allowReconRequest,
    ROOT,
    httpHistory,
  } = deps;
  const {
    normalizeHeadersForHistory,
    recordReconHttpHistory,
    safeJsonBodyForHistory,
  } = httpHistory;

  app.post('/api/recon/stream', requireScope('recon.run', { intrusiveCheck: (req) => reconBodyIsIntrusive(req.body) }), async (req, res) => {
  res.setHeader('Content-Type', 'application/x-ndjson; charset=utf-8');
  res.setHeader('Cache-Control', 'no-cache, no-transform');
  res.setHeader('X-Accel-Buffering', 'no');

  const send = (obj) => {
    res.write(`${JSON.stringify(obj)}\n`);
  };

  if (!validateCsrfToken(req)) {
    send({ type: 'error', message: 'CSRF token inválido/ausente' });
    res.end();
    return;
  }

  if (!allowReconRequest(req)) {
    send({ type: 'error', message: 'Rate limit — aguarde antes de novo recon' });
    res.end();
    return;
  }

  const domainRaw = req.body?.domain;
  let modules = Array.isArray(req.body?.modules) ? [...req.body.modules] : [];
  const exactMatch = Boolean(req.body?.exactMatch);
  const kaliMode = Boolean(req.body?.kaliMode);
  const profile = String(req.body?.profile || 'standard')
    .trim()
    .toLowerCase();
  const auth =
    req.body?.auth && typeof req.body.auth === 'object'
      ? {
          headers: req.body.auth.headers && typeof req.body.auth.headers === 'object' ? req.body.auth.headers : {},
          cookie: req.body.auth.cookie ? String(req.body.auth.cookie) : '',
        }
      : null;

  const parsed = parseReconTarget(domainRaw);
  if (!parsed.ok) {
    send({ type: 'error', message: parsed.message || 'Alvo inválido' });
    res.end();
    return;
  }

  const domain = parsed.target;

  const engagementIdRaw = req.body?.engagementId != null ? String(req.body.engagementId).trim() : '';
  const operatorRaw = req.body?.operator != null ? String(req.body.operator).trim() : '';
  const confirmActive = Boolean(req.body?.confirmActive);
  const rawOpsec = String(req.body?.opsecProfile || process.env.GHOSTRECON_OPSEC_PROFILE || 'standard')
    .trim()
    .toLowerCase();
  const allowedOpsec = new Set(['passive', 'stealth', 'standard', 'aggressive']);
  const opsecProfile = allowedOpsec.has(rawOpsec) ? rawOpsec : 'standard';
  const playbookNameForCheck =
    req.body?.playbook != null ? String(req.body.playbook).trim() : '';
  const navigatorMode = Boolean(req.body?.navigatorMode === true);
  const navegationBody =
    req.body?.navegation && typeof req.body.navegation === 'object' ? req.body.navegation : null;
  const navigatorActive = isNavigatorModeActive({ navigatorMode, navegation: navegationBody });
  const isFullPresetRun =
    req.body?.fullPreset === true || playbookNameForCheck === 'full-recon';

  if (!navigatorActive || isFullPresetRun) {
    modules = modules.filter((m) => m !== 'navegation');
  }

  let engagement = null;
  if (engagementIdRaw) {
    try {
      engagement = await getEngagement(engagementIdRaw);
    } catch (e) {
      send({ type: 'error', message: `engagement: ${e?.message || e}` });
      res.end();
      return;
    }
    if (!engagement) {
      send({ type: 'error', message: `engagement "${engagementIdRaw}" não encontrado` });
      res.end();
      return;
    }
  }

  const checklist = preRunChecklist({
    engagement,
    target: domain,
    modules,
    playbook: playbookNameForCheck || null,
  });
  if (!checklist.ok) {
    send({
      type: 'error',
      message: 'Pré-checklist (engagement / escopo) falhou — ver campo checklist',
      checklist,
    });
    res.end();
    return;
  }
  for (const w of checklist.warnings || []) {
    send({ type: 'log', msg: `[engagement] ${w}`, level: 'warn' });
  }

  let gate;
  try {
    gate = gateModules({
      modules,
      profile: opsecProfile,
      confirm: confirmActive || process.env.GHOSTRECON_CONFIRM_ACTIVE === '1',
      engagement,
    });
  } catch (e) {
    send({ type: 'error', message: `OPSEC: ${e?.message || e}` });
    res.end();
    return;
  }
  if (!gate.ok) {
    send({
      type: 'error',
      message: gate.reason || 'Módulos bloqueados por perfil OPSEC',
      opsec: { blocked: gate.blocked, needsConfirm: gate.needsConfirm, profile: gate.profile },
    });
    res.end();
    return;
  }

  let authForPipeline = auth;
  if (engagementIdRaw) {
    const baseHeaders = { ...(auth?.headers && typeof auth.headers === 'object' ? auth.headers : {}) };
    authForPipeline = {
      headers: applyWatermarkHeaders(baseHeaders, {
        engagementId: engagementIdRaw,
        operator: operatorRaw || undefined,
      }),
      cookie: auth?.cookie ? String(auth.cookie) : '',
    };
  }

  const shannonPrecheck = req.body?.shannonPrecheck !== false;
  const shannonSkipDepsVerify = Boolean(req.body?.shannonSkipDepsVerify);
  if (modules.includes('shannon_whitebox') && shannonPrecheck && !shannonSkipDepsVerify) {
    try {
      const sc = await getShannonCapabilities({ ghostRoot: ROOT });
      if (!sc.ok) {
        send({
          type: 'error',
          message: `Shannon: dependências incompletas — ${sc.message}`,
        });
        res.end();
        return;
      }
    } catch (e) {
      send({ type: 'error', message: `Shannon: falha ao verificar dependências — ${e?.message || e}` });
      res.end();
      return;
    }
  }

  const extraPathRaw = typeof req.body?.extraPath === 'string' ? req.body.extraPath : '';
  let savedEnvPath = null;
  if (extraPathRaw.trim()) {
    savedEnvPath = process.env.PATH;
    process.env.PATH = prependExtraPathToEnvPath(extraPathRaw, savedEnvPath);
  }

  // ── Tor enforcement ────────────────────────────────────────────────────
  // Body shape:
  //   tor: {
  //     required: true,            // aborta o run se o tunnel não validar
  //     strict: true,              // exige tor-strict prereqs (proxychains, DNS lockdown…)
  //     newnymBeforeRun: true,     // sinaliza NEWNYM antes do pipeline iniciar
  //     perTargetCircuit: true,    // injeta isolation user/pass no SOCKS5 (IsolateSOCKSAuth)
  //     dnsLeakHost: 'check.tor…' // host usado para o DNS leak test (opt)
  //   }
  // Default: se GHOSTRECON_TOR_REQUIRED=1 ou GHOSTRECON_TOR_STRICT=1, força.
  const torOpts = req.body?.tor && typeof req.body.tor === 'object' ? req.body.tor : {};
  const torStrictWanted =
    torOpts.strict === true ||
    String(process.env.GHOSTRECON_TOR_STRICT || '').trim() === '1';
  const torRequired =
    torOpts.required === true ||
    torStrictWanted ||
    String(process.env.GHOSTRECON_TOR_REQUIRED || '').trim() === '1';
  let cleanupTorStrictScope = null;

  // STRICT prereq check — se faltar algo (proxychains, DNS lockdown, SOCKS,
  // ControlPort, conf), abortamos antes do pipeline para evitar leaks parciais.
  if (torStrictWanted) {
    cleanupTorStrictScope = beginTorStrictScope();
    const refusal = torRefuseToRun();
    if (refusal) {
      if (cleanupTorStrictScope) cleanupTorStrictScope();
      auditAuth(req, req.principal, 'deny', {
        action: 'recon.stream.tor_strict_prereqs',
        target: domain,
        reason: 'strict_prereqs_failed',
        missing: refusal.missing,
      });
      send({
        type: 'error',
        message: 'tor.strict: pré-requisitos em falta — ver `missing`',
        missing: refusal.missing,
        checks: refusal.checks,
      });
      res.end();
      return;
    }
  }
  let torValidation = null;
  if (torRequired) {
    send({ type: 'log', msg: '[tor] enforcement activo — a validar tunnel antes do recon', level: 'info' });
    try {
      torValidation = await quickValidateTor({ timeoutMs: 12_000 });
    } catch (e) {
      torValidation = { validated: false, error: e?.message || String(e) };
    }
    if (!torValidation.validated) {
      if (cleanupTorStrictScope) cleanupTorStrictScope();
      auditAuth(req, req.principal, 'deny', {
        action: 'recon.stream.tor_required',
        target: domain,
        reason: 'tor_validation_failed',
        torValidation,
      });
      send({
        type: 'error',
        message: 'Tor enforcement: tunnel não validado — ver detalhes em torValidation',
        torValidation,
      });
      res.end();
      return;
    }
    send({
      type: 'log',
      msg: `[tor] OK — exitIp=${torValidation.tor?.ip} bootstrap=${torValidation.control?.bootstrap?.tag} (${torValidation.durationMs}ms)`,
      level: 'info',
    });
    if (torOpts.newnymBeforeRun === true) {
      try {
        await torNewnym({ timeoutMs: 5_000 });
        send({ type: 'log', msg: '[tor] NEWNYM sinalizado', level: 'info' });
      } catch (e) {
        send({ type: 'log', msg: `[tor] NEWNYM falhou: ${e?.message || e}`, level: 'warn' });
      }
    }
  }

  const identityOpts = normalizeIdentityOptions(modules, req.body?.identity);
  // ID temporário para telemetria do tor-strict (correlacionável com runId
  // depois que saveRun emitir um). Emitimos no stream para o cliente saber.
  const requestRunId = `req-${Date.now().toString(36)}-${randomBytes(4).toString('hex')}`;
  identityOpts.runId = requestRunId;
  identityOpts.target = domain;
  // Quando torRequired + perTargetCircuit, propagamos para identity-controller
  // ativar IsolateSOCKSAuth com user/pass únicos (circuit dedicado por target).
  if (torRequired && torOpts.perTargetCircuit !== false) {
    identityOpts.isolate = true;
    identityOpts.isolationKey = `${domain}-${Date.now().toString(36)}`;
  }
  const identityCtrl = createIdentityController({ ...identityOpts, modules });
  send({ type: 'meta', requestRunId, torStrict: torStrictWanted, torRequired });
  recordReconHttpHistory({
    requestRunId,
    target: domain,
    source: 'browser',
    method: 'POST',
    url: '/api/recon/stream',
    requestHeaders: normalizeHeadersForHistory(req.headers),
    requestBody: safeJsonBodyForHistory(req.body),
    status: 200,
    statusText: 'stream',
    ok: true,
    durationMs: 0,
    emit: send,
  });

  // Auditoria operacional do início do pipeline (após CSRF/rate-limit/escopo).
  auditAuth(req, req.principal, 'allow', {
    action: 'recon.stream.start',
    target: domain,
    modules,
    kaliMode,
    opsecProfile,
    profile,
    intrusive: reconBodyIsIntrusive(req.body),
    engagementId: engagementIdRaw || null,
    tor: torRequired
      ? {
          required: true,
          exitIp: torValidation?.tor?.ip || null,
          bootstrap: torValidation?.control?.bootstrap?.tag || null,
          perTargetCircuit: torOpts.perTargetCircuit !== false,
          newnymBefore: Boolean(torOpts.newnymBeforeRun),
        }
      : { required: false },
  });

  try {
    await reconHttpContext.run({ requestRunId, target: domain, emit: send }, async () => {
      await runPipeline({
        domain,
        exactMatch,
        modules,
        emit: send,
        kaliMode,
        auth: authForPipeline,
        profile,
        outOfScope: req.body?.outOfScope,
        projectName: req.body?.projectName,
        autoAiReports: Boolean(req.body?.autoAiReports),
        aiProviderMode: String(req.body?.aiProviderMode || 'auto'),
        aiUseOpenrouter: req.body?.aiUseOpenrouter !== false,
        aiOpenrouterOnly: normalizeOpenrouterOnlyFlag(req.body?.aiOpenrouterOnly),
        aiPrimaryCloud:
          typeof req.body?.aiPrimaryCloud === 'string'
            ? req.body.aiPrimaryCloud
            : typeof req.body?.aiPrimaryReport === 'string'
              ? req.body.aiPrimaryReport
              : null,
        shannonPrecheck,
        shannonSkipDepsVerify,
        shannonGithubRepos: req.body?.shannonGithubRepos,
        pentestgptUrl: req.body?.pentestgptUrl != null ? String(req.body.pentestgptUrl) : null,
        bountyContext:
          req.body?.bountyContext && typeof req.body.bountyContext === 'object' ? req.body.bountyContext : null,
        engagementId: engagementIdRaw || null,
        engagementOperator: operatorRaw || null,
        identityCtrl,
        navegation: navegationBody,
        navigatorMode: navigatorActive,
      });
    });
  } catch (e) {
    send({ type: 'error', message: e?.message || String(e) });
  } finally {
    if (savedEnvPath !== null) process.env.PATH = savedEnvPath;
    if (cleanupTorStrictScope) cleanupTorStrictScope();
  }
  res.end();
  });
}
