/**
 * Auditoria Supabase generalista e somente leitura.
 *
 * O módulo coleta inventário observável de RLS, Storage, Auth e GraphQL. Probes
 * específicos de uma aplicação e qualquer INSERT/PATCH/DELETE pertencem a uma
 * capability laboratorial separada e não existem neste entrypoint.
 */

import { isAbortError, throwIfAborted } from './http-utils.js';
import {
  runSupabaseRlsAudit,
  detectServiceRoleExposure,
  SUPABASE_VULN_TAXONOMY,
  extractSupabaseCredentials,
  resolveSupabaseAuthToken,
  discoverSupabaseFromTarget,
  fetchClientBundleText,
  validateSupabasePublicApiKey,
} from './supabase-rls-audit.mjs';

export {
  detectServiceRoleExposure,
  SUPABASE_VULN_TAXONOMY,
  extractSupabaseCredentials,
  discoverSupabaseFromTarget,
};

function rethrowAbort(error, signal) {
  if (isAbortError(error, signal) || signal?.aborted) {
    throw signal?.reason || error;
  }
}

/**
 * Executa a auditoria Supabase somente leitura.
 *
 * `authToken` é aceito apenas quando configurado explicitamente pelo operador.
 * Tokens de usuário ou service_role encontrados em bundle nunca são usados.
 */
export async function runSupabaseAudit(context, opts = {}) {
  throwIfAborted(opts.signal);
  let { supabaseUrl, anonKey, bundleText = '' } = context || {};
  const {
    authToken: explicitAuthToken = null,
    targetUrl = '',
    log = null,
    writeProbes = false,
    allowServiceRole = false,
    requestImpl = null,
  } = opts;

  if (writeProbes === true || allowServiceRole === true) {
    log?.('[supabase-audit] Writes/service_role recusados: o módulo geral é somente leitura', 'warn');
  }

  if ((!supabaseUrl || !anonKey) && targetUrl) {
    if (!bundleText) {
      bundleText = await fetchClientBundleText(targetUrl, {
        fetchImpl: opts.fetchImpl || null,
        signal: opts.signal,
        urlAllowed: opts.urlAllowed,
      });
    }
    const extracted = extractSupabaseCredentials(bundleText);
    supabaseUrl = supabaseUrl || extracted.supabaseUrl;
    anonKey = anonKey || extracted.anonKey;
  }

  if (!supabaseUrl || !anonKey) {
    return { findings: [], summary: { skipped: 'sem supabaseUrl ou anonKey no alvo', writeProbes: false } };
  }
  const publicApiKeyValidation = validateSupabasePublicApiKey(anonKey, supabaseUrl);
  if (!publicApiKeyValidation.ok) {
    log?.(`[supabase-audit] Chave pública recusada (${publicApiKeyValidation.reason}); nenhuma requisição foi enviada`, 'warn');
    return {
      findings: [],
      summary: {
        skipped: 'unsafe_or_invalid_public_api_key',
        apiKeyRejectedReason: publicApiKeyValidation.reason,
        writeProbes: false,
      },
    };
  }
  if (typeof opts.urlAllowed === 'function' && opts.urlAllowed(supabaseUrl) !== true) {
    log?.('[supabase-audit] Endpoint Supabase descoberto fora do escopo autorizado — probes ignorados', 'info');
    return {
      findings: [],
      summary: {
        skipped: 'supabase_out_of_scope',
        supabaseUrl,
        targetUrl,
        writeProbes: false,
      },
    };
  }

  log?.(`[supabase-audit] Iniciando auditoria somente leitura em ${supabaseUrl}`, 'info');

  const configuredToken = String(
    explicitAuthToken || process.env.GHOSTRECON_SUPABASE_AUTH_TOKEN || '',
  ).trim() || null;
  const resolved = await resolveSupabaseAuthToken(supabaseUrl, anonKey, {
    bundleText,
    log,
    envToken: configuredToken,
    writeProbes: false,
    allowServiceRole: false,
    requestImpl,
    signal: opts.signal,
    urlAllowed: opts.urlAllowed,
    now: opts.now,
  });
  throwIfAborted(opts.signal);

  if (resolved.authToken) {
    log?.('[supabase-audit] Contexto autenticado explicitamente configurado — identidade omitida e somente leitura', 'info');
  } else {
    log?.('[supabase-audit] Sem token autenticado explícito — auditoria anônima somente leitura', 'info');
  }

  const findings = [];
  const results = {
    authTokenSource: resolved.source || null,
    rateLimiting: 'not_tested_by_general_audit',
    mfa: 'not_tested_by_general_audit',
    idorUserPlans: 'removed_app_specific_probe',
    businessLogic: 'removed_app_specific_probe',
    stripeFields: 'removed_app_specific_probe',
    paymentBypass: 'removed_app_specific_probe',
    writeProbes: 'disabled',
  };

  try {
    const rlsAudit = await runSupabaseRlsAudit(
      { supabaseUrl, anonKey, authToken: resolved.authToken, bundleText },
      {
        log,
        targetUrl,
        writeProbes: false,
        requestImpl,
        signal: opts.signal,
        urlAllowed: opts.urlAllowed,
        tables: Array.isArray(opts.tables) ? opts.tables : null,
        edgeFunctions: Array.isArray(opts.edgeFunctions) ? opts.edgeFunctions : [],
        now: opts.now,
      },
    );
    findings.push(...(rlsAudit.findings || []));
    results.rlsAudit = rlsAudit.summary?.results || {};
    results.rlsAuditStatus = rlsAudit.summary?.status || 'partial';
  } catch (error) {
    rethrowAbort(error, opts.signal);
    log?.('[supabase-audit] RLS audit: falha operacional; conteúdo externo omitido', 'warn');
    results.rlsAudit = 'erro';
    results.rlsAuditStatus = 'partial';
  }

  const critical = findings.filter((finding) => finding.prio === 'critical').length;
  const high = findings.filter((finding) => finding.prio === 'high').length;
  log?.(
    `[supabase-audit] Concluído: ${findings.length} observação(ões) — ${critical} crítica(s), ${high} alta(s)`,
    'info',
  );

  return {
    findings,
    summary: {
      supabaseUrl,
      targetUrl,
      authTokenPresent: Boolean(resolved.authToken),
      authTokenSource: resolved.source || null,
      authTokenRejectedReason: resolved.rejectedReason || null,
      authTokenSignatureVerified: resolved.authToken ? resolved.signatureVerified === true : null,
      writeProbes: false,
      status: results.rlsAuditStatus || 'partial',
      coverageVerified: false,
      totalFindings: findings.length,
      critical,
      high,
      medium: findings.filter((finding) => finding.prio === 'med' || finding.prio === 'medium').length,
      probeResults: results,
    },
  };
}

export default runSupabaseAudit;
