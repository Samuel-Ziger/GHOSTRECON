import { parseAgentDecisionText, validateAgentDecision } from '../decision-contract.mjs';
import { availableCatalogIds, availableEvidenceRefs, buildAgentPrompt, extractOpenAiContent } from './shared.mjs';

export async function decideWithOpenAiCompatible({
  provider,
  baseUrl,
  apiKey = '',
  model,
  target,
  mode,
  catalog,
  ragContext,
  role = 'planner',
  iteration = 1,
  peerDecisions = [],
  observationBundle = null,
  fetchImpl = globalThis.fetch,
  timeoutMs = 180_000,
  extraHeaders = {},
  signal,
  retries = 1,
  maxContextChars = 120_000,
} = {}) {
  if (typeof fetchImpl !== 'function') throw new Error(`${provider}: fetch indisponível`);
  if (!baseUrl || !model) throw new Error(`${provider}: baseUrl/model ausente`);
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  const startedAt = Date.now();
  try {
    const headers = { 'Content-Type': 'application/json', ...extraHeaders };
    if (apiKey) headers.Authorization = `Bearer ${apiKey}`;
    const request = {
      method: 'POST', headers,
      body: JSON.stringify({
        model,
        messages: [
          { role: 'system', content: 'Você é um agente decisor do GHOSTRECON. Retorne somente JSON válido.' },
          { role: 'user', content: buildAgentPrompt({ target, mode, catalog, ragContext, role, iteration, peerDecisions, observationBundle, maxContextChars }) },
        ],
        temperature: 0.2,
        max_tokens: 8192,
        response_format: { type: 'json_object' },
      }),
      signal: signal ? AbortSignal.any([controller.signal, signal]) : controller.signal,
    };
    let res;
    let lastError;
    for (let attempt = 0; attempt <= Math.max(0, Math.min(2, retries)); attempt += 1) {
      try {
        res = await fetchImpl(`${String(baseUrl).replace(/\/+$/, '')}/chat/completions`, request);
        if (res.status < 500 && res.status !== 429) break;
        lastError = new Error(`${provider} HTTP ${res.status}`);
      } catch (error) {
        lastError = error;
        if (signal?.aborted || controller.signal.aborted) throw error;
      }
    }
    if (!res) throw lastError || new Error(`${provider}: chamada falhou`);
    const data = await res.json().catch(() => ({}));
    if (!res.ok) throw new Error(`${provider} HTTP ${res.status}: ${String(data?.error?.message || data?.message || 'erro').slice(0, 500)}`);
    const validate = (value) => validateAgentDecision(value, {
      catalogModuleIds: availableCatalogIds(catalog),
      availableEvidenceRefs: availableEvidenceRefs({ ragContext, observationBundle }),
    });
    const originalContent = extractOpenAiContent(data);
    let validated;
    let repaired = false;
    try { validated = validate(parseAgentDecisionText(originalContent)); } catch (error) {
      validated = { ok: false, errors: [error?.message || String(error)] };
    }
    if (!validated.ok && !/^(0|false|no|off)$/i.test(String(process.env.GHOSTRECON_AUTO_JSON_REPAIR || '1'))) {
      const originalBody = JSON.parse(request.body);
      const repairResponse = await fetchImpl(`${String(baseUrl).replace(/\/+$/, '')}/chat/completions`, {
        ...request,
        body: JSON.stringify({
          ...originalBody,
          temperature: 0,
          messages: [
            ...originalBody.messages,
            { role: 'assistant', content: originalContent },
            { role: 'user', content: `Repare uma única vez o JSON anterior. Erros: ${(validated.errors || []).join('; ')}. Retorne somente o objeto JSON completo.` },
          ],
        }),
      });
      const repairData = await repairResponse.json().catch(() => ({}));
      if (repairResponse.ok) {
        try { validated = validate(parseAgentDecisionText(extractOpenAiContent(repairData))); repaired = validated.ok; } catch { /* manter erro original */ }
      }
    }
    if (!validated.ok) throw new Error(`${provider}: decisão rejeitada: ${validated.errors.join('; ')}`);
    return {
      ok: true,
      provider,
      model,
      role,
      iteration,
      latencyMs: Date.now() - startedAt,
      decision: validated.decision,
      usage: data?.usage || null,
      transport: { type: 'openai-compatible', baseUrl: String(baseUrl).replace(/\/+$/, ''), repaired },
    };
  } catch (e) {
    if (e?.name === 'AbortError') throw new Error(`${provider}: timeout (${timeoutMs}ms)`);
    throw e;
  } finally {
    clearTimeout(timer);
  }
}
