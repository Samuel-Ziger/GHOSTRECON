const ACTIONS = new Set([
  'run_modules',
  'continue_with_context',
  'finish',
  'ask_operator',
  'forge_module',
  'abstain',
]);

const ACTION_ALIASES = new Map([
  ['request_modules', 'run_modules'],
  ['execute_modules', 'run_modules'],
]);

const DECISION_FIELDS = new Set([
  'action',
  'objective',
  'reasoningSummary',
  'evidenceRefs',
  'requestedModules',
  'rejectedModules',
  'confidence',
  'assumptions',
  'operatorQuestion',
  'forgeRequest',
]);

const FORGE_FIELDS = new Set([
  'proposedId',
  'gap',
  'benefit',
  'evidenceRefs',
  'intrusive',
  'expectedInputs',
  'expectedOutputs',
  'testStrategy',
  'risks',
]);

function strings(value, maxItems = 100, maxLength = 2000) {
  if (!Array.isArray(value)) return [];
  return value
    .slice(0, maxItems)
    .map((x) => String(x ?? '').trim().slice(0, maxLength))
    .filter(Boolean);
}

function uniqueStrings(value, maxItems = 100, maxLength = 2000) {
  return [...new Set(strings(value, maxItems, maxLength))];
}

function normalizeRejectedModules(value) {
  if (!Array.isArray(value)) return [];
  return value.slice(0, 100).map((x) => ({
    id: String(x?.id || '').trim().slice(0, 128),
    reason: String(x?.reason || '').trim().slice(0, 2000),
  })).filter((x) => x.id && x.reason);
}

function normalizeForgeRequest(value) {
  if (value == null) return null;
  if (!value || typeof value !== 'object' || Array.isArray(value)) return value;
  return {
    proposedId: String(value.proposedId || '').trim().slice(0, 128),
    gap: String(value.gap || '').trim().slice(0, 4000),
    benefit: String(value.benefit || '').trim().slice(0, 4000),
    evidenceRefs: uniqueStrings(value.evidenceRefs, 100, 500),
    intrusive: value.intrusive,
    expectedInputs: uniqueStrings(value.expectedInputs, 100, 500),
    expectedOutputs: uniqueStrings(value.expectedOutputs, 100, 500),
    testStrategy: String(value.testStrategy || '').trim().slice(0, 4000),
    risks: String(value.risks || '').trim().slice(0, 4000),
  };
}

export function parseAgentDecisionText(text) {
  const raw = String(text || '').trim();
  if (!raw) throw new Error('decisão vazia');
  try {
    return JSON.parse(raw);
  } catch {
    const fenced = /```(?:json)?\s*([\s\S]*?)```/i.exec(raw)?.[1]?.trim();
    if (fenced) return JSON.parse(fenced);
    const start = raw.indexOf('{');
    const end = raw.lastIndexOf('}');
    if (start >= 0 && end > start) return JSON.parse(raw.slice(start, end + 1));
    throw new Error('resposta da IA não contém JSON válido');
  }
}

export function normalizeDecisionAliases(input) {
  if (!input || typeof input !== 'object' || Array.isArray(input)) return input;
  const action = String(input.action || '').trim();
  return {
    ...input,
    action: ACTION_ALIASES.get(action) || action,
  };
}

// Repairs only missing envelope fields. It never invents modules or evidence;
// an incomplete model response is converted to a safe low-confidence abstain.
export function repairDecisionEnvelope(input, { objective = 'authorized_recon', action = 'abstain' } = {}) {
  if (!input || typeof input !== 'object' || Array.isArray(input)) return input;
  const repaired = normalizeDecisionAliases(input);
  const missingAction = !String(repaired.action || '').trim();
  const missingObjective = !String(repaired.objective || '').trim();
  const missingConfidence = !Number.isFinite(Number(repaired.confidence));
  if (missingAction || missingObjective || missingConfidence) {
    repaired.action = action;
    repaired.requestedModules = [];
    repaired.evidenceRefs = [];
    repaired.forgeRequest = null;
    repaired.operatorQuestion = null;
  }
  if (missingObjective) repaired.objective = objective;
  if (missingConfidence) repaired.confidence = 0;
  if (!Array.isArray(repaired.reasoningSummary)) repaired.reasoningSummary = ['Resposta reparada: campos estruturais ausentes.'];
  if (!Array.isArray(repaired.requestedModules)) repaired.requestedModules = [];
  if (!Array.isArray(repaired.evidenceRefs)) repaired.evidenceRefs = [];
  if (repaired.forgeRequest === undefined) repaired.forgeRequest = null;
  if (repaired.operatorQuestion === undefined) repaired.operatorQuestion = null;
  return repaired;
}

function validateNormalizedDecision(input, { catalogModuleIds = [], availableEvidenceRefs = null } = {}) {
  if (!input || typeof input !== 'object' || Array.isArray(input)) {
    return { ok: false, errors: ['decisão deve ser um objeto'] };
  }

  const errors = [];
  const unknownFields = Object.keys(input).filter((key) => !DECISION_FIELDS.has(key));
  if (unknownFields.length) errors.push(`campos desconhecidos na decisão: ${unknownFields.join(', ')}`);

  const action = String(input.action || '').trim();
  if (!ACTIONS.has(action)) errors.push(`action inválida: ${action || '(vazia)'}`);
  const objective = String(input.objective || '').trim().slice(0, 1000);
  if (!objective) errors.push('objective obrigatório');
  if (!Array.isArray(input.reasoningSummary)) errors.push('reasoningSummary deve ser array');
  if (!Array.isArray(input.requestedModules)) errors.push('requestedModules deve ser array');

  const confidence = Number(input.confidence);
  if (!Number.isFinite(confidence) || confidence < 0 || confidence > 1) {
    errors.push('confidence deve estar entre 0 e 1');
  }

  const allowed = new Set(uniqueStrings(catalogModuleIds, 1000, 128));
  const requestedModules = uniqueStrings(input.requestedModules, 100, 128);
  const unknownModules = requestedModules.filter((id) => !allowed.has(id));
  if (unknownModules.length) errors.push(`módulos fora do catálogo: ${unknownModules.join(', ')}`);

  const evidenceRefs = uniqueStrings(input.evidenceRefs, 100, 500);
  if (availableEvidenceRefs) {
    const refs = new Set(uniqueStrings(availableEvidenceRefs, 5000, 500));
    const unknownEvidence = evidenceRefs.filter((ref) => !refs.has(ref));
    if (unknownEvidence.length) errors.push(`referências de evidência inexistentes: ${unknownEvidence.join(', ')}`);
  }

  const normalizedQuestion = input.operatorQuestion == null
    ? ''
    : String(input.operatorQuestion).trim().slice(0, 2000);
  const operatorQuestion = normalizedQuestion || null;
  const forgeRequest = normalizeForgeRequest(input.forgeRequest);

  if (['run_modules', 'continue_with_context'].includes(action) && requestedModules.length === 0) {
    errors.push(`${action} exige requestedModules não vazio`);
  }
  if (['finish', 'ask_operator', 'forge_module', 'abstain'].includes(action) && requestedModules.length > 0) {
    errors.push(`${action} não pode solicitar módulos`);
  }
  if (action === 'ask_operator' && !operatorQuestion) {
    errors.push('operatorQuestion obrigatório para ask_operator');
  }
  if (action !== 'ask_operator' && operatorQuestion != null) {
    errors.push(`operatorQuestion não permitido para ${action || 'action inválida'}`);
  }
  if (action === 'forge_module' && (!forgeRequest || typeof forgeRequest !== 'object' || Array.isArray(forgeRequest))) {
    errors.push('forgeRequest obrigatório para forge_module');
  }
  if (action !== 'forge_module' && forgeRequest != null) {
    errors.push(`forgeRequest não permitido para ${action || 'action inválida'}`);
  }

  if (forgeRequest && typeof forgeRequest === 'object' && !Array.isArray(forgeRequest)) {
    const rawForge = input.forgeRequest;
    const unknownForgeFields = Object.keys(rawForge).filter((key) => !FORGE_FIELDS.has(key));
    if (unknownForgeFields.length) errors.push(`campos desconhecidos em forgeRequest: ${unknownForgeFields.join(', ')}`);
    if (!/^[a-z][a-z0-9_]{2,127}$/.test(forgeRequest.proposedId)) errors.push('forgeRequest.proposedId inválido');
    for (const field of ['gap', 'benefit', 'testStrategy', 'risks']) {
      if (!forgeRequest[field]) errors.push(`forgeRequest.${field} obrigatório`);
    }
    for (const field of ['evidenceRefs', 'expectedInputs', 'expectedOutputs']) {
      if (!forgeRequest[field]?.length) errors.push(`forgeRequest.${field} obrigatório`);
    }
    if (forgeRequest.intrusive !== false) {
      errors.push(forgeRequest.intrusive === true
        ? 'Module Forge intrusivo não permitido nesta fase'
        : 'forgeRequest.intrusive deve ser false');
    }
    if (availableEvidenceRefs) {
      const refs = new Set(uniqueStrings(availableEvidenceRefs, 5000, 500));
      const missing = forgeRequest.evidenceRefs.filter((ref) => !refs.has(ref));
      if (missing.length) errors.push(`forgeRequest contém evidências inexistentes: ${missing.join(', ')}`);
    }
  }

  if (errors.length) return { ok: false, errors, unknownModules };
  return {
    ok: true,
    decision: {
      action,
      objective,
      reasoningSummary: uniqueStrings(input.reasoningSummary, 20, 2000),
      evidenceRefs,
      requestedModules,
      rejectedModules: normalizeRejectedModules(input.rejectedModules),
      confidence,
      assumptions: uniqueStrings(input.assumptions, 20, 1000),
      operatorQuestion,
      forgeRequest,
    },
  };
}

export function normalizeAndValidateAgentDecision(input, {
  repairEnvelope = false,
  repairOptions = {},
  ...validationOptions
} = {}) {
  const normalized = repairEnvelope
    ? repairDecisionEnvelope(input, repairOptions)
    : normalizeDecisionAliases(input);
  return validateNormalizedDecision(normalized, validationOptions);
}

export function validateAgentDecision(input, options = {}) {
  return normalizeAndValidateAgentDecision(input, options);
}
