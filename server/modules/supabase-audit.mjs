/**
 * supabase-audit.mjs
 *
 * Auditoria de segurança aprofundada para backends Supabase expostos.
 * Cobre as classes de vulnerabilidade documentadas em campo:
 *
 *  1. Rate Limiting ausente  — /auth/v1/token sem limitação de tentativas
 *  2. 2FA ausente            — login sem segundo fator após auth bem-sucedida
 *  3. IDOR em user_plans     — qualquer autenticado lê dados de outros usuários
 *  4. Business Logic Flaw    — study_records aceita valores absurdos sem validação
 *  5. Stripe field bypass    — PATCH direto em campos stripe_* sem validação
 *  6. Payment privilege esc. — PATCH plan_type=premium sem pagamento real
 *
 * Probes de leitura: usam anonKey (extraído pelo lovable-fingerprint).
 * Probes de escrita: requerem opts.authToken (GHOSTRECON_SUPABASE_AUTH_TOKEN).
 *
 * Todos os probes destrutivos tentam cleanup após a coleta de evidências.
 */

import https from 'node:https';
import http from 'node:http';

const TIMEOUT_MS = 12_000;
const UA = 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36';
const AUDIT_MARKER = 'GHOSTRECON_AUDIT_PoC';

// ── HELPERS ───────────────────────────────────────────────────────────────────

function decodeJwtPayload(token) {
  try {
    const parts = String(token || '').split('.');
    if (parts.length < 2) return null;
    const pad = '='.repeat((4 - (parts[1].length % 4)) % 4);
    const json = Buffer.from(parts[1].replace(/-/g, '+').replace(/_/g, '/') + pad, 'base64').toString('utf8');
    return JSON.parse(json);
  } catch {
    return null;
  }
}

function extractUserId(jwtToken) {
  return decodeJwtPayload(jwtToken)?.sub || null;
}

function makeFinding({ type, value, score, url, meta, owasp, mitre, cvss }) {
  const prio = score >= 85 ? 'critical' : score >= 70 ? 'high' : score >= 50 ? 'medium' : score >= 30 ? 'low' : 'info';
  return { type, value, score, prio, url, meta: meta || {}, owasp, mitre, cvss: cvss || null, source: 'supabase_audit' };
}

async function rawRequest(url, { method = 'GET', headers = {}, body = null } = {}) {
  return new Promise((resolve) => {
    let parsed;
    try { parsed = new URL(url); } catch { return resolve({ status: null, headers: {}, body: '', error: 'invalid_url' }); }

    const mod = parsed.protocol === 'https:' ? https : http;
    const opts = {
      hostname: parsed.hostname,
      port: parsed.port || (parsed.protocol === 'https:' ? 443 : 80),
      path: parsed.pathname + parsed.search,
      method,
      timeout: TIMEOUT_MS,
      headers: {
        'User-Agent': UA,
        Accept: 'application/json, */*',
        ...headers,
        ...(body ? { 'Content-Length': Buffer.byteLength(body) } : {}),
      },
    };

    const req = mod.request(opts, (res) => {
      const resHeaders = {};
      for (const [k, v] of Object.entries(res.headers || {})) resHeaders[k.toLowerCase()] = v;
      let buf = '';
      res.setEncoding('utf8');
      res.on('data', (c) => { buf += c; if (buf.length > 32768) req.destroy(); });
      res.on('end', () => resolve({ status: res.statusCode, headers: resHeaders, body: buf, error: null }));
    });

    req.on('error', (e) => resolve({ status: null, headers: {}, body: '', error: e.message }));
    req.on('timeout', () => { req.destroy(); resolve({ status: null, headers: {}, body: '', error: 'timeout' }); });
    if (body) req.write(body);
    req.end();
  });
}

function supabaseHeaders(key, authToken) {
  return {
    apikey: key,
    Authorization: `Bearer ${authToken || key}`,
    'Content-Type': 'application/json',
    Prefer: 'return=representation',
  };
}

function sleep(ms) { return new Promise((r) => setTimeout(r, ms)); }

// ── PROBE 1: Rate Limiting ────────────────────────────────────────────────────

async function probeRateLimiting(supabaseUrl, anonKey, log) {
  const endpoint = `${supabaseUrl}/auth/v1/token?grant_type=password`;
  log?.(`[supabase-audit] Rate limiting: enviando ${5} requisições ao ${endpoint}`, 'info');

  const results = [];
  const RATE_LIMIT_HEADERS = [
    'x-ratelimit-limit', 'x-ratelimit-remaining', 'x-ratelimit-reset',
    'ratelimit-limit', 'ratelimit-remaining', 'retry-after',
  ];

  const fakeEmail = `audit_probe_${Date.now()}@ghostrecon.invalid`;
  const body = JSON.stringify({ email: fakeEmail, password: 'GHOSTRECONauditProbe123!', gotrue_meta_security: {} });

  for (let i = 0; i < 5; i++) {
    const res = await rawRequest(endpoint, {
      method: 'POST',
      headers: {
        apikey: anonKey,
        Authorization: `Bearer ${anonKey}`,
        'Content-Type': 'application/json',
        'X-Supabase-Api-Version': '2024-01-01',
      },
      body,
    });
    results.push({ attempt: i + 1, status: res.status, headers: res.headers });
    if (res.status === 429) break;
    await sleep(200);
  }

  const got429 = results.some((r) => r.status === 429);
  const hasRateLimitHeaders = results.some((r) =>
    RATE_LIMIT_HEADERS.some((h) => r.headers[h] !== undefined),
  );
  const hasRetryAfter = results.some((r) => r.headers['retry-after'] !== undefined);

  if (got429 || hasRateLimitHeaders) {
    log?.('[supabase-audit] Rate limiting: detectado (429 ou headers)', 'info');
    return null;
  }

  const statuses = results.map((r) => r.status).join(', ');
  log?.(`[supabase-audit] Rate limiting: ausente (respostas: ${statuses})`, 'warn');

  return makeFinding({
    type: 'supabase_missing_rate_limit',
    value: 'Ausência de rate limiting no endpoint de autenticação Supabase',
    score: 55,
    url: endpoint,
    meta: {
      attempts: results.length,
      statuses: results.map((r) => r.status),
      got429,
      hasRateLimitHeaders,
      hasRetryAfter,
      description: 'POST /auth/v1/token?grant_type=password sem limitação de tentativas — permite brute force irrestrito.',
      cvss_vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N',
      recommendation: 'Implementar rate limiting (máx. 5-10 tentativas/IP/janela) com backoff progressivo. Habilitar 2FA.',
    },
    owasp: 'A07:2021',
    mitre: 'T1110',
    cvss: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N',
  });
}

// ── PROBE 2: 2FA ausente ──────────────────────────────────────────────────────

async function probe2FA(supabaseUrl, anonKey, log) {
  const settingsUrl = `${supabaseUrl}/auth/v1/settings`;
  log?.('[supabase-audit] 2FA: verificando configuração MFA', 'info');

  const res = await rawRequest(settingsUrl, {
    headers: { apikey: anonKey, Authorization: `Bearer ${anonKey}` },
  });

  if (!res.status || res.status >= 400) {
    log?.(`[supabase-audit] 2FA: /auth/v1/settings inacessível (HTTP ${res.status})`, 'info');
    return null;
  }

  let settings = null;
  try { settings = JSON.parse(res.body); } catch { return null; }

  const mfaEnabled = settings?.mfa_enabled === true ||
    settings?.external?.mfa?.enabled === true ||
    settings?.totp?.enabled === true;

  if (mfaEnabled) {
    log?.('[supabase-audit] 2FA: MFA habilitado no projeto', 'info');
    return null;
  }

  log?.('[supabase-audit] 2FA: MFA não habilitado', 'warn');
  return makeFinding({
    type: 'supabase_missing_2fa',
    value: 'Autenticação de dois fatores (MFA/TOTP) não habilitada no projeto Supabase',
    score: 45,
    url: settingsUrl,
    meta: {
      settingsSnapshot: JSON.stringify(settings).slice(0, 400),
      description: 'Sem 2FA, uma senha comprometida garante acesso total imediato à conta.',
      recommendation: 'Habilitar TOTP/MFA no painel Supabase → Auth → Providers → MFA.',
    },
    owasp: 'A07:2021',
    mitre: 'T1078',
    cvss: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N',
  });
}

// ── PROBE 3: IDOR em user_plans ───────────────────────────────────────────────

async function probeIdorUserPlans(supabaseUrl, anonKey, authToken, log) {
  const findings = [];

  // 3a. Leitura com anon key (sem autenticação de usuário)
  const urlAnon = `${supabaseUrl}/rest/v1/user_plans?select=*&limit=5`;
  log?.('[supabase-audit] IDOR: lendo user_plans com anon key', 'info');
  const resAnon = await rawRequest(urlAnon, { headers: supabaseHeaders(anonKey, null) });

  if (resAnon.status === 200) {
    let rows = [];
    try { rows = JSON.parse(resAnon.body); } catch {}
    const hasSensitiveFields = rows.some((r) =>
      'stripe_customer_id' in r || 'stripe_subscription_id' in r || 'plan_type' in r,
    );
    log?.(`[supabase-audit] IDOR: user_plans acessível com anon key (${rows.length} row(s))`, 'warn');
    findings.push(makeFinding({
      type: 'supabase_idor_user_plans_anon',
      value: 'Tabela user_plans acessível com anon key — dados de assinatura expostos sem autenticação de usuário',
      score: 72,
      url: urlAnon,
      meta: {
        rowCount: rows.length,
        hasSensitiveFields,
        fieldsExposed: rows[0] ? Object.keys(rows[0]) : [],
        sampleIds: rows.map((r) => r.user_id || r.id).filter(Boolean).slice(0, 3),
        description: 'RLS SELECT ausente ou mal configurado em user_plans — stripe_customer_id e stripe_subscription_id expostos.',
        fix: 'CREATE POLICY "user sees own plans" ON user_plans FOR SELECT USING (auth.uid() = user_id);',
        cvss_vector: 'CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N',
      },
      owasp: 'A01:2021',
      mitre: 'T1213',
      cvss: 'CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N',
    }));
  }

  // 3b. Leitura com auth token — verifica se retorna dados de outros usuários
  if (authToken) {
    const userId = extractUserId(authToken);
    const urlAuth = `${supabaseUrl}/rest/v1/user_plans?select=*&limit=10`;
    log?.('[supabase-audit] IDOR: lendo user_plans com auth token de usuário', 'info');
    const resAuth = await rawRequest(urlAuth, { headers: supabaseHeaders(anonKey, authToken) });

    if (resAuth.status === 200) {
      let rows = [];
      try { rows = JSON.parse(resAuth.body); } catch {}
      const otherUsers = rows.filter((r) => r.user_id && r.user_id !== userId);
      if (otherUsers.length > 0) {
        log?.(`[supabase-audit] IDOR confirmado: ${otherUsers.length} registro(s) de outros usuários visível(is)`, 'warn');
        findings.push(makeFinding({
          type: 'supabase_idor_user_plans_authenticated',
          value: `IDOR confirmado: usuário autenticado lê user_plans de ${otherUsers.length} outro(s) usuário(s)`,
          score: 82,
          url: urlAuth,
          meta: {
            ownUserId: userId,
            foreignUserCount: otherUsers.length,
            foreignUserIds: otherUsers.map((r) => r.user_id).slice(0, 3),
            description: 'Política RLS SELECT não restringe acesso ao próprio registro — dados de assinatura de terceiros visíveis.',
            fix: 'USING (auth.uid() = user_id) na policy SELECT de user_plans.',
            cvss_vector: 'CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N',
          },
          owasp: 'A01:2021',
          mitre: 'T1213',
          cvss: 'CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N',
        }));
      }
    }
  }

  return findings;
}

// ── PROBE 4: Business Logic — study_records ───────────────────────────────────

async function probeBusinessLogic(supabaseUrl, anonKey, authToken, log) {
  if (!authToken) {
    log?.('[supabase-audit] Business logic: sem authToken — probe ignorado (definir GHOSTRECON_SUPABASE_AUTH_TOKEN)', 'info');
    return null;
  }

  const userId = extractUserId(authToken);
  if (!userId) {
    log?.('[supabase-audit] Business logic: não foi possível extrair user_id do token', 'warn');
    return null;
  }

  const endpoint = `${supabaseUrl}/rest/v1/study_records`;
  const payload = {
    user_id: userId,
    record_date: '2099-12-31',
    subject: AUDIT_MARKER,
    duration_seconds: 2147483647,
    questions_count: 99999,
    correct_count: 99999,
  };

  log?.('[supabase-audit] Business logic: inserindo registro de estudo com valores absurdos', 'info');
  const res = await rawRequest(endpoint, {
    method: 'POST',
    headers: { ...supabaseHeaders(anonKey, authToken), Prefer: 'return=representation' },
    body: JSON.stringify(payload),
  });

  if (res.status === 201 || res.status === 200) {
    let inserted = [];
    try { inserted = JSON.parse(res.body); } catch {}
    const insertedId = Array.isArray(inserted) ? inserted[0]?.id : inserted?.id;
    log?.(`[supabase-audit] Business logic: VULNERÁVEL — registro aceito (id=${insertedId})`, 'warn');

    // Cleanup imediato
    if (insertedId) {
      await rawRequest(`${endpoint}?id=eq.${insertedId}`, {
        method: 'DELETE',
        headers: supabaseHeaders(anonKey, authToken),
      });
      log?.(`[supabase-audit] Business logic: cleanup — registro ${insertedId} removido`, 'info');
    } else {
      // Tenta limpar pelo marcador
      await rawRequest(`${endpoint}?subject=eq.${AUDIT_MARKER}`, {
        method: 'DELETE',
        headers: supabaseHeaders(anonKey, authToken),
      });
    }

    return makeFinding({
      type: 'supabase_business_logic_study_records',
      value: 'Business Logic Flaw: study_records aceita valores completamente irreais sem validação server-side',
      score: 72,
      url: endpoint,
      meta: {
        testedPayload: payload,
        httpStatus: res.status,
        insertedId: insertedId || null,
        description: 'Backend aceita duration_seconds=2147483647 (~596k horas), correct_count>questions_count e datas futuras. Compromete ranking, metas e analytics.',
        recommendation: 'Validação server-side: max duration_seconds ≈ 43200 (12h), correct_count ≤ questions_count, record_date ≤ hoje.',
        cvss_vector: 'CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:N',
      },
      owasp: 'A04:2021',
      mitre: 'T1565',
      cvss: 'CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:N',
    });
  }

  log?.(`[supabase-audit] Business logic: servidor rejeitou valores inválidos (HTTP ${res.status})`, 'info');
  return null;
}

// ── PROBE 5: Manipulação de campos Stripe ─────────────────────────────────────

async function probeStripeFieldManipulation(supabaseUrl, anonKey, authToken, log) {
  if (!authToken) {
    log?.('[supabase-audit] Stripe fields: sem authToken — probe ignorado', 'info');
    return null;
  }

  const userId = extractUserId(authToken);
  if (!userId) return null;

  const endpoint = `${supabaseUrl}/rest/v1/user_plans?user_id=eq.${userId}`;
  const fakeStripe = { stripe_subscription_id: 'sub_GHOSTRECON_test', stripe_customer_id: 'cus_GHOSTRECON_test' };

  log?.('[supabase-audit] Stripe fields: tentando PATCH de campos stripe_* com valores falsos', 'info');

  // Leitura prévia para backup
  const backup = await rawRequest(endpoint + '&select=stripe_subscription_id,stripe_customer_id', {
    headers: supabaseHeaders(anonKey, authToken),
  });
  let original = null;
  try { original = JSON.parse(backup.body)?.[0] || null; } catch {}

  const res = await rawRequest(endpoint, {
    method: 'PATCH',
    headers: supabaseHeaders(anonKey, authToken),
    body: JSON.stringify(fakeStripe),
  });

  const accepted = res.status >= 200 && res.status < 300;

  // Cleanup imediato
  if (accepted && original) {
    await rawRequest(endpoint, {
      method: 'PATCH',
      headers: supabaseHeaders(anonKey, authToken),
      body: JSON.stringify({
        stripe_subscription_id: original.stripe_subscription_id ?? null,
        stripe_customer_id: original.stripe_customer_id ?? null,
      }),
    });
    log?.('[supabase-audit] Stripe fields: cleanup — valores originais restaurados', 'info');
  }

  if (!accepted) {
    log?.(`[supabase-audit] Stripe fields: PATCH rejeitado (HTTP ${res.status})`, 'info');
    return null;
  }

  log?.('[supabase-audit] Stripe fields: VULNERÁVEL — campos stripe_* modificados sem validação', 'warn');
  return makeFinding({
    type: 'supabase_stripe_field_manipulation',
    value: 'Manipulação direta de campos Stripe via PATCH sem validação com provedor de pagamento',
    score: 72,
    url: endpoint,
    meta: {
      patchedFields: Object.keys(fakeStripe),
      httpStatus: res.status,
      description: 'Usuário autenticado pode alterar stripe_subscription_id e stripe_customer_id diretamente, gerando estado inconsistente entre banco e Stripe.',
      recommendation: 'Bloquear UPDATE em campos stripe_* via RLS WITH CHECK. Sincronizar via webhooks Stripe validados no backend.',
      cvss_vector: 'CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:N',
    },
    owasp: 'A01:2021',
    mitre: 'T1565',
    cvss: 'CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:N',
  });
}

// ── PROBE 6: Payment Privilege Escalation ─────────────────────────────────────

async function probePaymentBypass(supabaseUrl, anonKey, authToken, log) {
  if (!authToken) {
    log?.('[supabase-audit] Payment bypass: sem authToken — probe ignorado', 'info');
    return null;
  }

  const userId = extractUserId(authToken);
  if (!userId) return null;

  const endpoint = `${supabaseUrl}/rest/v1/user_plans?user_id=eq.${userId}`;

  // Lê estado atual para backup
  log?.('[supabase-audit] Payment bypass: lendo plan atual para backup', 'info');
  const backupRes = await rawRequest(endpoint + '&select=plan_type,premium_expires_at', {
    headers: supabaseHeaders(anonKey, authToken),
  });
  let original = null;
  try { original = JSON.parse(backupRes.body)?.[0] || null; } catch {}

  const attackPayload = { plan_type: 'premium', premium_expires_at: '9999-12-31T23:59:59Z' };
  log?.('[supabase-audit] Payment bypass: tentando PATCH plan_type=premium sem pagamento', 'info');

  const res = await rawRequest(endpoint, {
    method: 'PATCH',
    headers: supabaseHeaders(anonKey, authToken),
    body: JSON.stringify(attackPayload),
  });

  const bypassed = res.status >= 200 && res.status < 300;

  // Cleanup imediato — restaurar plan original
  if (bypassed && original) {
    await rawRequest(endpoint, {
      method: 'PATCH',
      headers: supabaseHeaders(anonKey, authToken),
      body: JSON.stringify({
        plan_type: original.plan_type ?? 'free',
        premium_expires_at: original.premium_expires_at ?? null,
      }),
    });
    log?.('[supabase-audit] Payment bypass: cleanup — plan restaurado para original', 'info');
  }

  if (!bypassed) {
    log?.(`[supabase-audit] Payment bypass: PATCH rejeitado (HTTP ${res.status}) — RLS parece proteger o campo`, 'info');
    return null;
  }

  log?.('[supabase-audit] Payment bypass: VULNERABILIDADE CRÍTICA — premium ativado sem pagamento!', 'warn');
  return makeFinding({
    type: 'supabase_payment_bypass',
    value: 'CRÍTICO: Escalada de privilégio de pagamento — plano premium ativado sem pagamento via PATCH direto',
    score: 96,
    url: endpoint,
    meta: {
      attackPayload,
      httpStatus: res.status,
      originalPlan: original?.plan_type ?? 'unknown',
      description: 'Qualquer usuário autenticado pode ativar premium com expiração em 9999 via PATCH em /rest/v1/user_plans. Bypass completo do sistema de cobrança.',
      recommendation: 'Implementar RLS WITH CHECK para bloquear alteração de plan_type e premium_expires_at. Gerenciar mudanças exclusivamente via webhook Stripe verificado no backend.',
      fix: `CREATE POLICY "block plan change by user" ON user_plans FOR UPDATE
USING (auth.uid() = user_id)
WITH CHECK (
  plan_type = (SELECT plan_type FROM user_plans WHERE user_id = auth.uid())
  AND premium_expires_at = (SELECT premium_expires_at FROM user_plans WHERE user_id = auth.uid())
);`,
      cvss_vector: 'CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:N',
    },
    owasp: 'A01:2021',
    mitre: 'T1548',
    cvss: 'CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:N',
  });
}

// ── PONTO DE ENTRADA PRINCIPAL ────────────────────────────────────────────────

/**
 * Executa auditoria completa de segurança Supabase.
 *
 * @param {object} context  - Contexto do lovable-fingerprint (supabaseUrl, anonKey)
 * @param {object} opts
 * @param {string}  [opts.authToken]  - JWT de usuário autenticado (GHOSTRECON_SUPABASE_AUTH_TOKEN)
 * @param {string}  [opts.targetUrl]  - URL da aplicação alvo
 * @param {Function}[opts.log]        - Função de log (msg, level)
 * @returns {Promise<{findings: object[], summary: object}>}
 */
export async function runSupabaseAudit(context, opts = {}) {
  const { supabaseUrl, anonKey } = context || {};
  const { authToken = null, targetUrl = '', log = null } = opts;

  if (!supabaseUrl || !anonKey) {
    return { findings: [], summary: { skipped: 'sem supabaseUrl ou anonKey' } };
  }

  log?.(`[supabase-audit] Iniciando auditoria em ${supabaseUrl}`, 'info');
  if (authToken) {
    const uid = extractUserId(authToken);
    log?.(`[supabase-audit] Auth token presente — probes de escrita habilitados (user_id=${uid || '?'})`, 'info');
  } else {
    log?.('[supabase-audit] Sem auth token — probes de escrita desabilitados (definir GHOSTRECON_SUPABASE_AUTH_TOKEN)', 'info');
  }

  const findings = [];
  const results = {};

  // 1. Rate Limiting
  try {
    const f = await probeRateLimiting(supabaseUrl, anonKey, log);
    if (f) findings.push(f);
    results.rateLimiting = f ? 'vulneravel' : 'ok';
  } catch (e) {
    log?.(`[supabase-audit] Rate limiting probe erro: ${e.message}`, 'warn');
    results.rateLimiting = 'erro';
  }

  // 2. 2FA
  try {
    const f = await probe2FA(supabaseUrl, anonKey, log);
    if (f) findings.push(f);
    results.mfa = f ? 'ausente' : 'ok_ou_desconhecido';
  } catch (e) {
    log?.(`[supabase-audit] 2FA probe erro: ${e.message}`, 'warn');
    results.mfa = 'erro';
  }

  // 3. IDOR user_plans
  try {
    const fs = await probeIdorUserPlans(supabaseUrl, anonKey, authToken, log);
    findings.push(...fs);
    results.idorUserPlans = fs.length ? `${fs.length} achado(s)` : 'ok';
  } catch (e) {
    log?.(`[supabase-audit] IDOR probe erro: ${e.message}`, 'warn');
    results.idorUserPlans = 'erro';
  }

  // 4. Business Logic — study_records
  try {
    const f = await probeBusinessLogic(supabaseUrl, anonKey, authToken, log);
    if (f) findings.push(f);
    results.businessLogic = f ? 'vulneravel' : (authToken ? 'ok' : 'ignorado_sem_token');
  } catch (e) {
    log?.(`[supabase-audit] Business logic probe erro: ${e.message}`, 'warn');
    results.businessLogic = 'erro';
  }

  // 5. Stripe field manipulation
  try {
    const f = await probeStripeFieldManipulation(supabaseUrl, anonKey, authToken, log);
    if (f) findings.push(f);
    results.stripeFields = f ? 'vulneravel' : (authToken ? 'ok' : 'ignorado_sem_token');
  } catch (e) {
    log?.(`[supabase-audit] Stripe fields probe erro: ${e.message}`, 'warn');
    results.stripeFields = 'erro';
  }

  // 6. Payment bypass — executado por último pois é o mais impactante
  try {
    const f = await probePaymentBypass(supabaseUrl, anonKey, authToken, log);
    if (f) findings.push(f);
    results.paymentBypass = f ? 'CRITICO' : (authToken ? 'ok' : 'ignorado_sem_token');
  } catch (e) {
    log?.(`[supabase-audit] Payment bypass probe erro: ${e.message}`, 'warn');
    results.paymentBypass = 'erro';
  }

  const critical = findings.filter((f) => f.prio === 'critical').length;
  const high = findings.filter((f) => f.prio === 'high').length;

  log?.(`[supabase-audit] Concluído: ${findings.length} achado(s) — ${critical} crítico(s), ${high} alto(s)`, findings.length ? 'warn' : 'info');

  return {
    findings,
    summary: {
      supabaseUrl,
      targetUrl,
      authTokenPresent: Boolean(authToken),
      totalFindings: findings.length,
      critical,
      high,
      medium: findings.filter((f) => f.prio === 'medium').length,
      probeResults: results,
    },
  };
}

export default runSupabaseAudit;
