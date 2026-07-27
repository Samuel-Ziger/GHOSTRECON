import { validateToken } from './token-validator.js';
import {
  rawSecretFromFinding,
  redactSecretText,
  safeSecretReference,
} from './secret-safety.js';

export function shouldValidateSecretFindings(modules = []) {
  return Array.isArray(modules) && modules.includes('secret_validation');
}

/**
 * Analisa cada finding de 'secret' offline por padrão. Probes de rede só são
 * executados quando o módulo secret_validation foi autorizado pelo caller:
 * - Detecta tipo do token (JWT, Supabase, API key)
 * - Verifica expiração offline (campo `exp` do JWT)
 * - Faz probes HTTP com os headers de auth corretos
 *
 * Retorna array de { ref, status, reason, tokenType, tokenStatus, offlineExpired, jwtClaims }
 * compatível com o caller em index.js (que espera status 'live'|'probable'|'dead').
 */
export async function validateSecretFindings(
  findings = [],
  log,
  {
    network = false,
    probeImpl = null,
    signal = null,
    urlAllowed = null,
  } = {},
) {
  const out = [];
  const secrets = findings.filter((f) => f?.type === 'secret').slice(0, 30);

  for (const f of secrets) {
    if (signal?.aborted) throw signal.reason || new DOMException('The operation was aborted', 'AbortError');
    const url = String(f.url || '').trim();
    const raw = rawSecretFromFinding(f);
    const safeRef = safeSecretReference(raw || f.value);
    if (!raw) {
      out.push({ ref: '', status: 'dead', reason: 'no_value', tokenStatus: 'unknown' });
      continue;
    }

    try {
      const result = await validateToken(raw, url || null, {
        network,
        probeImpl,
        signal,
        urlAllowed,
      });
      const safeResult = JSON.parse(redactSecretText(JSON.stringify(result), raw));

      // Mapeia para o formato legado esperado pelo caller
      const legacyStatus =
        safeResult.status === 'valid'    ? 'live'     :
        safeResult.status === 'probable' ? 'probable' :
        safeResult.status === 'expired'  ? 'dead'     :
        safeResult.status === 'invalid'  ? 'dead'     :
        safeResult.status === 'revoked'  ? 'dead'     :
        /* unknown */                  'dead';

      out.push({
        ref:            safeRef.ref,
        fingerprint:    safeRef.fingerprint,
        status:         legacyStatus,
        reason:         safeResult.evidence || safeResult.status,
        // Campos enriquecidos (usados pelo novo index.js)
        tokenType:      safeResult.tokenType,
        tokenStatus:    safeResult.status,
        offlineExpired: safeResult.offlineExpired,
        expiredAt:      safeResult.expiredAt ?? null,
        expiresAt:      safeResult.expiresAt ?? null,
        noExpiration:   safeResult.noExpiration ?? false,
        jwtClaims:      safeResult.jwtClaims ?? null,
        probes:         safeResult.probes ?? [],
      });
    } catch (e) {
      if (signal?.aborted || e?.name === 'AbortError' || e?.code === 'ABORT_ERR') throw e;
      out.push({
        ref:         safeRef.ref,
        fingerprint: safeRef.fingerprint,
        status:      'dead',
        reason:      redactSecretText(e.message, raw),
        tokenStatus: 'unknown',
      });
      if (typeof log === 'function') {
        log(`secret validation: ${redactSecretText(e.message, raw)}`, 'warn');
      }
    }
  }

  return out;
}
