/**
 * Race condition harness — single-packet attack helper para HTTP/2.
 *
 * Lógica:
 *   - Gera N requests "preparadas" (mesma URL, mesmos headers, mesmo body)
 *     usando técnica de "last-byte sync" — caller envia tudo menos o último
 *     byte, espera, depois envia o último byte de cada uma simultaneamente.
 *
 * Este módulo NÃO faz HTTP por si — provê o plano e o comparador de respostas.
 * A camada de transporte (HTTP/2 com preload) fica fora.
 */

import crypto from 'node:crypto';

export function buildRacePlan({ request, parallel = 30, label = null }) {
  if (!request || !request.url) throw new Error('buildRacePlan: request.url obrigatório');
  const id = label || crypto.randomBytes(4).toString('hex');
  const slots = Array.from({ length: parallel }, (_, i) => ({
    nth: i + 1,
    url: request.url,
    method: request.method || 'POST',
    headers: { ...(request.headers || {}) },
    body: request.body || '',
    correlationId: `${id}-${i}`,
  }));
  return { id, total: parallel, slots, technique: 'last-byte-sync', request };
}

/**
 * Compara respostas. Retorna:
 *   - duplicates: respostas que aparentemente "passaram" mais de uma vez
 *     (ex: status=200 e body indica sucesso de operação que devia ser único)
 *   - rejections: bloqueios/duplicates legítimos (rate-limit, idempotency)
 *   - inconsistency: status code variation suspeita
 */
export function analyzeRaceResults({ responses = [], successHeuristic = (r) => r?.status >= 200 && r.status < 300, dedupKey = (r) => r?.body?.id || r?.body?.token || r?.body?.code }) {
  const successes = responses.filter(successHeuristic);
  const failures = responses.filter((r) => !successHeuristic(r));
  const codes = new Set(responses.map((r) => r?.status));

  // dedup detection: se "sucesso" indica criação de recurso único, mais de 1
  // sucesso = race confirmada
  const successKeys = new Map();
  for (const r of successes) {
    const k = dedupKey(r);
    if (k == null) continue;
    successKeys.set(k, (successKeys.get(k) || 0) + 1);
  }
  const dupSuccessCount = successes.length - successKeys.size;

  return {
    total: responses.length,
    successes: successes.length,
    failures: failures.length,
    statusCodes: [...codes],
    raceConfirmed: successes.length > 1 && (dupSuccessCount > 0 || successKeys.size === 0),
    successKeys: Object.fromEntries(successKeys),
    sample: { first: responses[0], last: responses[responses.length - 1] },
  };
}

/**
 * Emite finding pronto.
 */
export function raceToFinding(plan, analysis, { target = null, contextHint = null } = {}) {
  if (!analysis.raceConfirmed) return null;
  return {
    severity: 'high', category: 'race-condition',
    title: `Race condition em ${plan.request.method || 'POST'} ${plan.request.url}${contextHint ? ` (${contextHint})` : ''}`,
    description: `${analysis.successes}/${analysis.total} requests retornaram sucesso paralelos — operação que deveria ser idempotente foi executada múltiplas vezes.`,
    evidence: {
      target, request: plan.request, parallel: plan.total,
      successes: analysis.successes, statusCodes: analysis.statusCodes,
      successKeys: analysis.successKeys,
    },
  };
}
