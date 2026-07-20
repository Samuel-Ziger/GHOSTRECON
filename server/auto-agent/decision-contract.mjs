const ACTIONS = new Set([
  'run_modules',
  'continue_with_context',
  'finish',
  'ask_operator',
  'forge_module',
  'abstain',
]);

function strings(value, maxItems = 100, maxLength = 2000) {
  if (!Array.isArray(value)) return [];
  return value
    .slice(0, maxItems)
    .map((x) => String(x ?? '').trim().slice(0, maxLength))
    .filter(Boolean);
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

// Repairs only missing envelope fields. It never invents modules, evidence or
// confidence; an incomplete model response remains explicitly low confidence.
export function repairDecisionEnvelope(input, { objective = 'authorized_recon', action = 'abstain' } = {}) {
  if (!input || typeof input !== 'object' || Array.isArray(input)) return input;
  const repaired = { ...input };
  // Compatibilidade com versões do prompt que chamavam esta ação de
  // request_modules. O significado é idêntico a run_modules.
  if (repaired.action === 'request_modules' || repaired.action === 'execute_modules') repaired.action = 'run_modules';
  const missingAction = !String(repaired.action || '').trim();
  const missingObjective = !String(repaired.objective || '').trim();
  const missingConfidence = !Number.isFinite(Number(repaired.confidence));
  if (missingAction || missingObjective || missingConfidence) {
    repaired.action = action;
    repaired.requestedModules = [];
    repaired.evidenceRefs = [];
    repaired.forgeRequest = null;
  }
  if (missingObjective) repaired.objective = objective;
  if (missingConfidence) repaired.confidence = 0;
  if (!Array.isArray(repaired.reasoningSummary)) repaired.reasoningSummary = ['Resposta reparada: campos estruturais ausentes.'];
  if (!Array.isArray(repaired.requestedModules)) repaired.requestedModules = [];
  if (!Array.isArray(repaired.evidenceRefs)) repaired.evidenceRefs = [];
  return repaired;
}

export function validateAgentDecision(input, { catalogModuleIds = [], availableEvidenceRefs = null } = {}) {
  if (!input || typeof input !== 'object' || Array.isArray(input)) {
    return { ok: false, errors: ['decisão deve ser um objeto'] };
  }
  const errors = [];
  const action = String(input.action || '').trim();
  if (!ACTIONS.has(action)) errors.push(`action inválida: ${action || '(vazia)'}`);
  const objective = String(input.objective || '').trim().slice(0, 1000);
  if (!objective) errors.push('objective obrigatório');
  const confidence = Number(input.confidence);
  if (!Number.isFinite(confidence) || confidence < 0 || confidence > 1) {
    errors.push('confidence deve estar entre 0 e 1');
  }
  const allowed = new Set(strings(catalogModuleIds, 1000, 128));
  const requestedModules = strings(input.requestedModules, 100, 128);
  const unknownModules = requestedModules.filter((id) => !allowed.has(id));
  if (unknownModules.length) errors.push(`módulos fora do catálogo: ${unknownModules.join(', ')}`);
  const evidenceRefs = strings(input.evidenceRefs, 100, 500);
  if (availableEvidenceRefs) {
    const refs = new Set(strings(availableEvidenceRefs, 5000, 500));
    const unknownEvidence = evidenceRefs.filter((ref) => !refs.has(ref));
    if (unknownEvidence.length) errors.push(`referências de evidência inexistentes: ${unknownEvidence.join(', ')}`);
  }
  if (action === 'forge_module' && (!input.forgeRequest || typeof input.forgeRequest !== 'object')) {
    errors.push('forgeRequest obrigatório para forge_module');
  }
  if (input.forgeRequest?.intrusive === true) {
    errors.push('Module Forge intrusivo não permitido nesta fase');
  }
  if (input.forgeRequest) {
    const request = input.forgeRequest;
    for (const field of ['proposedId', 'gap', 'benefit', 'testStrategy', 'risks']) {
      if (!String(request[field] || '').trim()) errors.push(`forgeRequest.${field} obrigatório`);
    }
    for (const field of ['evidenceRefs', 'expectedInputs', 'expectedOutputs']) {
      if (!Array.isArray(request[field]) || !request[field].length) errors.push(`forgeRequest.${field} obrigatório`);
    }
    if (availableEvidenceRefs && Array.isArray(request.evidenceRefs)) {
      const refs = new Set(strings(availableEvidenceRefs, 5000, 500));
      const missing = strings(request.evidenceRefs, 100, 500).filter((ref) => !refs.has(ref));
      if (missing.length) errors.push(`forgeRequest contém evidências inexistentes: ${missing.join(', ')}`);
    }
  }
  if (errors.length) return { ok: false, errors, unknownModules };
  return {
    ok: true,
    decision: {
      action,
      objective,
      reasoningSummary: strings(input.reasoningSummary, 20, 2000),
      evidenceRefs,
      requestedModules,
      rejectedModules: Array.isArray(input.rejectedModules)
        ? input.rejectedModules.slice(0, 100).map((x) => ({
          id: String(x?.id || '').trim().slice(0, 128),
          reason: String(x?.reason || '').trim().slice(0, 2000),
        })).filter((x) => x.id && x.reason)
        : [],
      confidence,
      assumptions: strings(input.assumptions, 20, 1000),
      operatorQuestion: input.operatorQuestion == null ? null : String(input.operatorQuestion).trim().slice(0, 2000),
      forgeRequest: input.forgeRequest || null,
    },
  };
}
