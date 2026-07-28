import {
  createHmac,
  createHash,
  randomBytes,
  timingSafeEqual,
} from 'node:crypto';

const DEFAULT_TTL_MS = 2 * 60_000;
const DEFAULT_MAX_ENTRIES = 512;
const DEFAULT_MAX_ENTRIES_PER_OWNER = 8;
const SHA256_RE = /^[a-f0-9]{64}$/i;
const GIT_OBJECT_ID_RE = /^(?:[a-f0-9]{40}|[a-f0-9]{64})$/i;

function approvalError(code, message) {
  const error = new Error(message);
  error.code = code;
  return error;
}

function cleanString(value, fallback = '') {
  const normalized = String(value ?? '').trim();
  return normalized || fallback;
}

function cleanStringList(value, { sort = false } = {}) {
  const out = [...new Set(
    (Array.isArray(value) ? value : [])
      .map((item) => cleanString(item))
      .filter(Boolean),
  )];
  return sort ? out.sort((a, b) => a.localeCompare(b)) : out;
}

function cleanBoolean(value) {
  return value === true;
}

function cleanInteger(value, fallback = null, min = 0, max = Number.MAX_SAFE_INTEGER) {
  const numeric = Number(value);
  if (!Number.isFinite(numeric)) return fallback;
  return Math.max(min, Math.min(max, Math.trunc(numeric)));
}

function normalizeIdentity(identity) {
  if (!identity || typeof identity !== 'object') return null;
  const sha256 = cleanString(identity.sha256).toLowerCase();
  if (!SHA256_RE.test(sha256)) return null;
  return {
    algorithm: cleanString(identity.algorithm, 'sha256').toLowerCase(),
    sha256,
    size: cleanInteger(identity.size, 0),
    dev: cleanInteger(identity.dev, null),
    ino: cleanInteger(identity.ino, null),
    mtimeMs: cleanInteger(identity.mtimeMs, null),
    mode: cleanInteger(identity.mode, null),
  };
}

function normalizeSourceIdentity(identity) {
  if (!identity || typeof identity !== 'object') return null;
  const commit = cleanString(identity.commit).toLowerCase();
  const tree = cleanString(identity.tree).toLowerCase();
  const objectFormat = cleanString(identity.objectFormat).toLowerCase();
  const expectedLength = objectFormat === 'sha256' ? 64 : 40;
  if (
    identity.version !== 1
    || cleanString(identity.kind) !== 'git-worktree'
    || !['sha1', 'sha256'].includes(objectFormat)
    || !GIT_OBJECT_ID_RE.test(commit)
    || !GIT_OBJECT_ID_RE.test(tree)
    || commit.length !== expectedLength
    || tree.length !== expectedLength
  ) {
    return null;
  }
  return {
    version: 1,
    kind: 'git-worktree',
    objectFormat,
    commit,
    tree,
    trackedEntries: cleanInteger(identity.trackedEntries, 0),
  };
}

function normalizeExecution(execution = {}) {
  const source = execution && typeof execution === 'object' ? execution : {};
  return {
    exactMatch: cleanBoolean(source.exactMatch),
    kaliMode: cleanBoolean(source.kaliMode),
    profile: cleanString(source.profile, 'standard').toLowerCase(),
    opsecProfile: cleanString(source.opsecProfile, 'standard').toLowerCase(),
    engine: cleanString(source.engine, 'node').toLowerCase(),
    playbook: cleanString(source.playbook) || null,
    fullPreset: cleanBoolean(source.fullPreset),
    navigatorMode: cleanBoolean(source.navigatorMode),
    navigatorExec: cleanBoolean(source.navigatorExec),
    navigatorUserMode: cleanBoolean(source.navigatorUserMode),
    torRequired: cleanBoolean(source.torRequired),
    torStrict: cleanBoolean(source.torStrict),
    torNewnymBeforeRun: cleanBoolean(source.torNewnymBeforeRun),
    torPerTargetCircuit: cleanBoolean(source.torPerTargetCircuit),
    torDnsLeakHostBinding: cleanString(source.torDnsLeakHostBinding) || null,
    identityEnabled: cleanBoolean(source.identityEnabled),
    identityBehavior: cleanBoolean(source.identityBehavior),
    identityRotation: cleanString(source.identityRotation) || null,
    identityIsolate: cleanBoolean(source.identityIsolate),
    proxyCount: cleanInteger(source.proxyCount, 0, 0, 32),
    proxyPoolBinding: cleanString(source.proxyPoolBinding) || null,
    outOfScope: cleanStringList(source.outOfScope, { sort: true }),
  };
}

function normalizeAuthentication(authentication = {}) {
  const source = authentication && typeof authentication === 'object'
    ? authentication
    : {};
  const pipeline = source.pipeline && typeof source.pipeline === 'object'
    ? source.pipeline
    : {};
  const vigolium = source.vigolium && typeof source.vigolium === 'object'
    ? source.vigolium
    : {};
  return {
    pipeline: {
      enabled: cleanBoolean(pipeline.enabled),
      hasCookie: cleanBoolean(pipeline.hasCookie),
      hasAuthorization: cleanBoolean(pipeline.hasAuthorization),
      headerCount: cleanInteger(pipeline.headerCount, 0),
    },
    vigolium: {
      enabled: cleanBoolean(vigolium.enabled),
      sharesPipelineContext: cleanBoolean(vigolium.sharesPipelineContext),
      inlineEntryCount: cleanInteger(vigolium.inlineEntryCount, 0),
      authFileCount: cleanInteger(vigolium.authFileCount, 0),
    },
  };
}

function normalizeFrameSeven(frameSeven = {}) {
  const source = frameSeven && typeof frameSeven === 'object' ? frameSeven : {};
  return {
    enabled: cleanBoolean(source.enabled),
    authenticated: cleanBoolean(source.authenticated),
    profile: cleanString(source.profile) || null,
    tools: cleanStringList(source.tools),
    timeoutMs: cleanInteger(source.timeoutMs, null, 1),
    toolTimeoutMs: cleanInteger(source.toolTimeoutMs, null, 1),
    concurrency: cleanInteger(source.concurrency, null, 1),
    rate: cleanInteger(source.rate, null, 1),
    identity: normalizeIdentity(source.identity),
  };
}

function normalizeVigolium(vigolium = {}) {
  const source = vigolium && typeof vigolium === 'object' ? vigolium : {};
  return {
    enabled: cleanBoolean(source.enabled),
    agent: cleanString(source.agent, 'none').toLowerCase(),
    strategy: cleanString(source.strategy) || null,
    useCodex: cleanBoolean(source.useCodex),
    modules: cleanStringList(source.modules),
    moduleTags: cleanStringList(source.moduleTags),
    auditMode: cleanString(source.auditMode) || null,
    only: cleanString(source.only) || null,
    reportOnly: cleanString(source.reportOnly) || null,
    htmlReport: cleanBoolean(source.htmlReport),
    preferPath: cleanBoolean(source.preferPath),
    vpsProfile: cleanBoolean(source.vpsProfile),
    skipExternalHarvest: cleanBoolean(source.skipExternalHarvest),
    scanTimeoutMs: cleanInteger(source.scanTimeoutMs, null, 1),
    agentTimeoutMs: cleanInteger(source.agentTimeoutMs, null, 1),
    binarySource: cleanString(source.binarySource) || null,
    binaryPathBinding: cleanString(source.binaryPathBinding) || null,
    sourceMode: cleanString(source.sourceMode) || null,
    sourceBinding: cleanString(source.sourceBinding) || null,
    sourceIdentity: normalizeSourceIdentity(source.sourceIdentity),
    childEnvBinding: cleanString(source.childEnvBinding) || null,
    authMaterialBinding: cleanString(source.authMaterialBinding) || null,
    authFileIdentityCount: cleanInteger(source.authFileIdentityCount, 0),
    identity: normalizeIdentity(source.identity),
  };
}

function hashCanonical(value) {
  return createHash('sha256').update(JSON.stringify(value), 'utf8').digest('hex');
}

function stablePrivateValue(value, {
  depth = 0,
  key = '',
  seen = new WeakSet(),
} = {}) {
  if (value === null) return null;
  if (depth > 64) {
    throw approvalError(
      'MANUAL_RECON_PRIVATE_CONTEXT_INVALID',
      'contexto privado excede a profundidade aceita',
    );
  }
  if (typeof value === 'string' || typeof value === 'boolean') return value;
  if (typeof value === 'number' && Number.isFinite(value)) return value;
  if (typeof value !== 'object') {
    throw approvalError(
      'MANUAL_RECON_PRIVATE_CONTEXT_INVALID',
      'contexto privado contém um tipo não suportado',
    );
  }
  if (seen.has(value)) {
    throw approvalError(
      'MANUAL_RECON_PRIVATE_CONTEXT_INVALID',
      'contexto privado contém referência circular',
    );
  }
  seen.add(value);
  try {
    if (Array.isArray(value)) {
      return value.map((item) => stablePrivateValue(item, {
        depth: depth + 1,
        key,
        seen,
      }));
    }
    const out = {};
    for (const childKey of Object.keys(value).sort()) {
      if (depth === 0 && childKey === 'manualApproval') continue;
      if (key === 'auth' && childKey === 'ghostreconApiKey') continue;
      out[childKey] = stablePrivateValue(value[childKey], {
        depth: depth + 1,
        key: childKey,
        seen,
      });
    }
    return out;
  } finally {
    seen.delete(value);
  }
}

/**
 * Material privado usado apenas pelo store efêmero. Ele pode conter valores
 * sensíveis e nunca deve ser retornado, logado ou persistido. O store conserva
 * somente um HMAC process-local deste objeto.
 */
export function buildManualReconPrivateContext(body = {}) {
  return stablePrivateValue(body);
}

export function summarizeManualReconAuthentication(body = {}, {
  vigoliumEnabled = false,
} = {}) {
  const auth = body?.auth && typeof body.auth === 'object' ? body.auth : {};
  const headers = auth.headers && typeof auth.headers === 'object'
    ? Object.entries(auth.headers)
      .filter(([, value]) => value != null && String(value).trim())
    : [];
  const headerNames = headers.map(([name]) => String(name).trim().toLowerCase());
  const hasCookie = Boolean(String(auth.cookie || '').trim())
    || headerNames.includes('cookie');
  const hasAuthorization = headerNames.includes('authorization')
    || headerNames.includes('proxy-authorization');
  const pipelineEnabled = hasCookie || hasAuthorization || headers.length > 0;
  const inlineEntries = [
    ...(Array.isArray(body?.vigoliumAuthEntries) ? body.vigoliumAuthEntries : []),
    ...(body?.vigoliumAuth != null && String(body.vigoliumAuth).trim()
      ? String(body.vigoliumAuth)
        .split(/[\n|,]+/)
        .map((value) => value.trim())
        .filter(Boolean)
      : []),
  ].filter((value) => value != null && String(value).trim());
  const authFiles = [
    ...(Array.isArray(body?.vigoliumAuthFiles) ? body.vigoliumAuthFiles : []),
    ...(body?.vigoliumAuthFile != null && String(body.vigoliumAuthFile).trim()
      ? [body.vigoliumAuthFile]
      : []),
  ].filter((value) => value != null && String(value).trim());
  const vigoliumHasContext = vigoliumEnabled
    && (pipelineEnabled || inlineEntries.length > 0 || authFiles.length > 0);
  return normalizeAuthentication({
    pipeline: {
      enabled: pipelineEnabled,
      hasCookie,
      hasAuthorization,
      headerCount: headers.length,
    },
    vigolium: {
      enabled: vigoliumHasContext,
      sharesPipelineContext: vigoliumEnabled && pipelineEnabled,
      inlineEntryCount: vigoliumEnabled ? inlineEntries.length : 0,
      authFileCount: vigoliumEnabled ? authFiles.length : 0,
    },
  });
}

/**
 * Produz o contrato seguro exibido ao operador e posteriormente consumido pelo
 * RUN manual. A função aceita apenas campos operacionais explícitos: auth,
 * cookies, headers, senhas, paths e demais campos desconhecidos não entram no
 * plano nem no hash.
 */
export function buildManualReconPlan({
  target,
  engagementId = null,
  engagementBinding = null,
  selectedModules = [],
  expandedModules = [],
  intrusiveModules = [],
  execution = {},
  authentication = {},
  frameSeven = {},
  vigolium = {},
} = {}) {
  const normalizedTarget = cleanString(target).toLowerCase();
  if (!normalizedTarget) {
    throw approvalError('MANUAL_RECON_PLAN_INVALID', 'alvo ausente no plano manual');
  }

  const canonical = {
    schemaVersion: 1,
    kind: 'ghostrecon.manual-recon.plan',
    target: normalizedTarget,
    engagement: {
      id: cleanString(engagementId) || null,
      authorizationBinding: cleanString(engagementBinding) || null,
    },
    selectedModules: cleanStringList(selectedModules),
    expandedModules: cleanStringList(expandedModules),
    intrusiveModules: cleanStringList(intrusiveModules),
    execution: normalizeExecution(execution),
    authentication: normalizeAuthentication(authentication),
    engines: {
      frameseven: normalizeFrameSeven(frameSeven),
      vigolium: normalizeVigolium(vigolium),
    },
  };
  const hash = hashCanonical(canonical);
  return Object.freeze({
    ...canonical,
    hash,
    requiresHumanApproval: canonical.intrusiveModules.length > 0,
  });
}

function safeEqual(left, right) {
  const a = Buffer.from(cleanString(left), 'utf8');
  const b = Buffer.from(cleanString(right), 'utf8');
  return a.length === b.length && timingSafeEqual(a, b);
}

function publicRecord(record) {
  return Object.freeze({
    approvalId: record.approvalId,
    planHash: record.planHash,
    target: record.target,
    status: record.status,
    createdAt: record.createdAt,
    expiresAt: record.expiresAt,
  });
}

/**
 * Store efêmero, owner-bound, com TTL e consumo único. Não persiste segredos,
 * plano completo ou identidade de caminho; somente os bindings necessários
 * para provar que a decisão corresponde ao plano recomputado.
 */
export function createManualReconApprovalStore({
  clock = () => Date.now(),
  ttlMs = DEFAULT_TTL_MS,
  maxEntries = DEFAULT_MAX_ENTRIES,
  maxEntriesPerOwner = DEFAULT_MAX_ENTRIES_PER_OWNER,
  randomId = () => randomBytes(18).toString('base64url'),
  bindingKey = randomBytes(32),
} = {}) {
  const boundedTtlMs = cleanInteger(ttlMs, DEFAULT_TTL_MS, 1_000, 15 * 60_000);
  const boundedMaxEntries = cleanInteger(maxEntries, DEFAULT_MAX_ENTRIES, 1, 4_096);
  const boundedMaxEntriesPerOwner = cleanInteger(
    maxEntriesPerOwner,
    DEFAULT_MAX_ENTRIES_PER_OWNER,
    1,
    128,
  );
  const privateBindingKey = Buffer.from(bindingKey);
  if (privateBindingKey.length < 16) {
    throw approvalError(
      'MANUAL_RECON_APPROVAL_BINDING_KEY_INVALID',
      'chave privada do store de aprovação é inválida',
    );
  }
  const records = new Map();

  const privateBinding = (privateContext) => createHmac('sha256', privateBindingKey)
    .update(JSON.stringify(stablePrivateValue(privateContext)), 'utf8')
    .digest('hex');

  const removeExpired = () => {
    const now = clock();
    for (const [approvalId, record] of records) {
      if (record.expiresAt <= now) records.delete(approvalId);
    }
  };

  const requireRecord = (approvalId) => {
    const id = cleanString(approvalId);
    const record = records.get(id);
    if (!record) {
      throw approvalError(
        'MANUAL_RECON_APPROVAL_NOT_FOUND',
        'aprovação manual ausente, expirada ou já consumida',
      );
    }
    if (record.expiresAt <= clock()) {
      records.delete(id);
      throw approvalError('MANUAL_RECON_APPROVAL_EXPIRED', 'aprovação manual expirada');
    }
    return record;
  };

  const assertBindings = (record, {
    ownerSub,
    planHash,
    target = record.target,
    engagementBinding = record.engagementBinding,
  }) => {
    if (!safeEqual(record.ownerSub, ownerSub)) {
      throw approvalError('MANUAL_RECON_APPROVAL_OWNER_MISMATCH', 'aprovação pertence a outro operador');
    }
    if (!safeEqual(record.planHash, planHash)) {
      throw approvalError('MANUAL_RECON_APPROVAL_PLAN_MISMATCH', 'hash do plano aprovado não corresponde ao RUN');
    }
    if (!safeEqual(record.target, cleanString(target).toLowerCase())) {
      throw approvalError('MANUAL_RECON_APPROVAL_TARGET_MISMATCH', 'alvo do plano aprovado mudou');
    }
    if (!safeEqual(record.engagementBinding, cleanString(engagementBinding))) {
      throw approvalError(
        'MANUAL_RECON_APPROVAL_ENGAGEMENT_MISMATCH',
        'autorização do engagement mudou depois da aprovação',
      );
    }
  };

  return Object.freeze({
    issue({ plan, ownerSub, privateContext = {} }) {
      removeExpired();
      const owner = cleanString(ownerSub);
      if (!owner) {
        throw approvalError('MANUAL_RECON_APPROVAL_OWNER_REQUIRED', 'operador ausente');
      }
      if (!plan?.requiresHumanApproval || !SHA256_RE.test(cleanString(plan?.hash))) {
        throw approvalError(
          'MANUAL_RECON_APPROVAL_NOT_REQUIRED',
          'o plano informado não exige aprovação manual',
        );
      }
      if (records.size >= boundedMaxEntries) {
        throw approvalError(
          'MANUAL_RECON_APPROVAL_CAPACITY',
          'limite global de aprovações manuais pendentes atingido',
        );
      }
      const ownerEntries = [...records.values()]
        .filter((record) => safeEqual(record.ownerSub, owner))
        .length;
      if (ownerEntries >= boundedMaxEntriesPerOwner) {
        throw approvalError(
          'MANUAL_RECON_APPROVAL_OWNER_CAPACITY',
          'limite de aprovações manuais pendentes deste operador atingido',
        );
      }
      const now = clock();
      const approvalId = `manual-${cleanString(randomId())}`;
      if (approvalId === 'manual-' || records.has(approvalId)) {
        throw approvalError('MANUAL_RECON_APPROVAL_ID_INVALID', 'não foi possível gerar aprovação única');
      }
      const record = {
        approvalId,
        ownerSub: owner,
        planHash: plan.hash,
        target: plan.target,
        engagementBinding: cleanString(plan.engagement?.authorizationBinding),
        privateBinding: privateBinding(privateContext),
        status: 'pending',
        createdAt: new Date(now).toISOString(),
        expiresAt: now + boundedTtlMs,
      };
      records.set(approvalId, record);
      return publicRecord(record);
    },

    decide({ approvalId, ownerSub, planHash, approved }) {
      const record = requireRecord(approvalId);
      assertBindings(record, { ownerSub, planHash });
      if (record.status !== 'pending') {
        throw approvalError(
          'MANUAL_RECON_APPROVAL_ALREADY_DECIDED',
          'aprovação manual já recebeu uma decisão',
        );
      }
      record.status = approved === true ? 'approved' : 'denied';
      record.decidedAt = new Date(clock()).toISOString();
      const result = publicRecord(record);
      if (record.status === 'denied') records.delete(record.approvalId);
      return result;
    },

    consume({
      approvalId,
      ownerSub,
      planHash,
      target,
      engagementBinding,
      privateContext = {},
    }) {
      const record = requireRecord(approvalId);
      try {
        assertBindings(record, {
          ownerSub,
          planHash,
          target,
          engagementBinding,
        });
        if (!safeEqual(record.privateBinding, privateBinding(privateContext))) {
          throw approvalError(
            'MANUAL_RECON_APPROVAL_CONTEXT_MISMATCH',
            'contexto privado de execução mudou depois da aprovação',
          );
        }
        if (record.status !== 'approved') {
          throw approvalError(
            'MANUAL_RECON_APPROVAL_NOT_APPROVED',
            'plano manual não foi aprovado',
          );
        }
      } catch (error) {
        records.delete(record.approvalId);
        throw error;
      }
      records.delete(record.approvalId);
      return Object.freeze({
        ...publicRecord({ ...record, status: 'consumed' }),
        approved: true,
      });
    },

    size() {
      removeExpired();
      return records.size;
    },
  });
}
