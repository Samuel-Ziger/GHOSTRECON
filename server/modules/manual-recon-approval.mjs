import {
  createHash,
  randomBytes,
  timingSafeEqual,
} from 'node:crypto';

const DEFAULT_TTL_MS = 2 * 60_000;
const DEFAULT_MAX_ENTRIES = 128;
const SHA256_RE = /^[a-f0-9]{64}$/i;

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
    torRequired: cleanBoolean(source.torRequired),
    torStrict: cleanBoolean(source.torStrict),
    identityEnabled: cleanBoolean(source.identityEnabled),
    identityBehavior: cleanBoolean(source.identityBehavior),
    identityRotation: cleanString(source.identityRotation) || null,
    proxyCount: cleanInteger(source.proxyCount, 0, 0, 32),
    outOfScope: cleanStringList(source.outOfScope, { sort: true }),
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
    sourceBinding: cleanString(source.sourceBinding) || null,
    identity: normalizeIdentity(source.identity),
  };
}

function hashCanonical(value) {
  return createHash('sha256').update(JSON.stringify(value), 'utf8').digest('hex');
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
  randomId = () => randomBytes(18).toString('base64url'),
} = {}) {
  const boundedTtlMs = cleanInteger(ttlMs, DEFAULT_TTL_MS, 1_000, 15 * 60_000);
  const boundedMaxEntries = cleanInteger(maxEntries, DEFAULT_MAX_ENTRIES, 1, 4_096);
  const records = new Map();

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
    issue({ plan, ownerSub }) {
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
      while (records.size >= boundedMaxEntries) {
        records.delete(records.keys().next().value);
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
      return publicRecord(record);
    },

    consume({
      approvalId,
      ownerSub,
      planHash,
      target,
      engagementBinding,
    }) {
      const record = requireRecord(approvalId);
      try {
        assertBindings(record, {
          ownerSub,
          planHash,
          target,
          engagementBinding,
        });
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
