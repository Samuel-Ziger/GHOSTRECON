/**
 * Authorization matrix tester — BOLA/IDOR sistemático.
 *
 * Modelo: dado N "personas" (cookies/tokens) e M "requests observadas",
 * replica cada request com cada persona, compara respostas e marca:
 *
 *   - SAME: mesma resposta de outra persona (esperado para públicos)
 *   - LEAK: persona X recebe dados que deveria pertencer a persona Y
 *   - BLOCKED: persona X corretamente recebe 401/403
 *   - PRIVESC: persona "user" consegue executar ação "admin"
 *
 * Tudo síncrono na lógica de comparação — execução real é injeção de função.
 */

import crypto from 'node:crypto';

/**
 * Persona shape:
 *   { id: 'alice', headers: {...}, cookies: 'sid=...', expectedRole: 'user' }
 */
export function buildAuthzPlan(requests = [], personas = []) {
  const plan = [];
  for (const req of requests) {
    for (const persona of personas) {
      plan.push({
        id: `${stableId(req)}::${persona.id}`,
        request: req, persona,
      });
    }
  }
  return plan;
}

function stableId(req) {
  const k = `${req.method || 'GET'} ${req.path || req.url || ''}`;
  return crypto.createHash('sha1').update(k).digest('hex').slice(0, 10);
}

/**
 * Caller injeta `executor(request, persona) => Promise<{status, headers, bodyHash, bodyLen, fingerprint, ownerMarker}>`
 * — assim o módulo nunca dispara HTTP por si só (usável em testes).
 *
 * fingerprint deve ser estável (hash do body normalizado, mas operador escolhe).
 */
export async function runAuthzMatrix({ requests = [], personas = [], executor, concurrency = 4 }) {
  if (typeof executor !== 'function') throw new Error('runAuthzMatrix: executor obrigatório');
  const plan = buildAuthzPlan(requests, personas);
  const results = [];
  let i = 0;
  async function worker() {
    while (i < plan.length) {
      const idx = i++;
      const slot = plan[idx];
      try {
        const resp = await executor(slot.request, slot.persona);
        results.push({ ...slot, response: resp });
      } catch (e) {
        results.push({ ...slot, error: e?.message || String(e) });
      }
    }
  }
  await Promise.all(Array.from({ length: Math.min(concurrency, plan.length || 1) }, worker));
  return analyzeAuthzResults(results, { personas, requests });
}

/**
 * Analisa resultados de execução e detecta:
 *   - LEAK: 2 personas com fingerprint igual em endpoint que deveria ser per-user
 *   - PRIVESC: persona não-admin obtém 200 em endpoint que admin obtém 200
 *               E user-low é bloqueado em outro endpoint admin (controle)
 *   - INCONSISTENT: status code diferente entre personas
 *
 * Lógica conservadora — produz findings com severity calibrada.
 */
export function analyzeAuthzResults(results, { personas = [], requests = [] } = {}) {
  const byReq = {};
  for (const r of results) {
    const k = stableId(r.request);
    (byReq[k] = byReq[k] || []).push(r);
  }
  const findings = [];
  const matrix = [];
  for (const [reqId, attempts] of Object.entries(byReq)) {
    const req = attempts[0].request;
    const cells = attempts.map((a) => ({
      persona: a.persona.id,
      role: a.persona.expectedRole || 'unknown',
      status: a.response?.status ?? null,
      fingerprint: a.response?.fingerprint ?? null,
      bodyLen: a.response?.bodyLen ?? null,
      ownerMarker: a.response?.ownerMarker ?? null,
      error: a.error || null,
    }));
    matrix.push({ reqId, request: req, cells });

    // 1. LEAK: dois personas distintos com fingerprint identical e ambos 200.
    // Para reduzir FPs em respostas curtas/genéricas, exige corpo mínimo.
    const fps = new Map();
    for (const c of cells) {
      if (c.status >= 200 && c.status < 300 && c.fingerprint && Number(c.bodyLen || 0) >= 24) {
        const arr = fps.get(c.fingerprint) || [];
        arr.push(c);
        fps.set(c.fingerprint, arr);
      }
    }
    for (const arr of fps.values()) {
      if (arr.length >= 2 && req.perUser) {
        const owners = [...new Set(arr.map((c) => String(c.ownerMarker || '').trim()).filter(Boolean))];
        const ownerEvidence = owners.length ? `ownerMarkers=${owners.join(',')}` : 'ownerMarkers=none';
        findings.push({
          severity: 'high', category: 'authz-bola',
          title: `BOLA: ${arr.length} personas recebem mesma resposta em ${req.method || 'GET'} ${req.path}`,
          description: `Endpoint marcado como per-user (perUser:true) retornou fingerprint idêntico para personas distintas — possível IDOR/BOLA (${ownerEvidence}).`,
          evidence: { request: req, personas: arr.map((c) => c.persona) },
        });
      }
    }

    // 2. PRIVESC: persona role=user com 2xx em request marcada admin-only
    if (req.adminOnly) {
      const privesc = cells.filter((c) => c.status >= 200 && c.status < 300 && c.role !== 'admin');
      if (privesc.length) {
        findings.push({
          severity: 'critical', category: 'authz-privesc',
          title: `Privesc: persona não-admin acessa ${req.method || 'GET'} ${req.path}`,
          description: 'Endpoint marcado adminOnly retornou sucesso para personas com role!=admin.',
          evidence: { request: req, personas: privesc.map((c) => c.persona) },
        });
      }
    }

    // 3. INCONSISTENT: variação anômala (1 persona 200, outras 403) — útil só pra investigação
    const codes = new Set(cells.map((c) => c.status).filter((s) => s != null));
    if (codes.size > 1 && req.expectedConsistent) {
      findings.push({
        severity: 'low', category: 'authz-inconsistent',
        title: `Inconsistência de status em ${req.method || 'GET'} ${req.path}`,
        description: `Status codes variam entre personas: ${[...codes].join(', ')}.`,
        evidence: { request: req, cells },
      });
    }
  }
  return {
    findings,
    matrix,
    summary: { requests: requests.length, personas: personas.length, attempts: results.length },
  };
}

/**
 * Helper: hash determinístico de body para fingerprint.
 * Remove timestamps óbvios pra reduzir falsos negativos.
 */
export function fingerprintBody(body) {
  if (body == null) return null;
  const s = String(body)
    .replace(/\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?Z?/g, '<TS>')
    .replace(/\b\d{10,13}\b/g, '<EPOCH>')
    .replace(/[a-f0-9]{32,}/gi, '<HEX>');
  return crypto.createHash('sha1').update(s).digest('hex').slice(0, 16);
}
