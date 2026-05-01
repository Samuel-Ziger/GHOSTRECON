import { validateToken } from './token-validator.js';

/**
 * Valida ativamente cada finding de 'secret':
 * - Detecta tipo do token (JWT, Supabase, API key)
 * - Verifica expiração offline (campo `exp` do JWT)
 * - Faz probes HTTP com os headers de auth corretos
 *
 * Retorna array de { ref, status, reason, tokenType, tokenStatus, offlineExpired, jwtClaims }
 * compatível com o caller em index.js (que espera status 'live'|'probable'|'dead').
 */
export async function validateSecretFindings(findings = [], log) {
  const out = [];
  const secrets = findings.filter((f) => f?.type === 'secret').slice(0, 30);

  for (const f of secrets) {
    const url = String(f.url || '').trim();
    if (!f.value) {
      out.push({ ref: '', status: 'dead', reason: 'no_value', tokenStatus: 'unknown' });
      continue;
    }

    try {
      const result = await validateToken(f.value, url || null);

      // Mapeia para o formato legado esperado pelo caller
      const legacyStatus =
        result.status === 'valid'    ? 'live'     :
        result.status === 'probable' ? 'probable' :
        result.status === 'expired'  ? 'dead'     :
        result.status === 'invalid'  ? 'dead'     :
        result.status === 'revoked'  ? 'dead'     :
        /* unknown */                  'dead';

      out.push({
        ref:            String(f.value || '').slice(0, 160),
        status:         legacyStatus,
        reason:         result.evidence || result.status,
        // Campos enriquecidos (usados pelo novo index.js)
        tokenType:      result.tokenType,
        tokenStatus:    result.status,
        offlineExpired: result.offlineExpired,
        expiredAt:      result.expiredAt ?? null,
        expiresAt:      result.expiresAt ?? null,
        noExpiration:   result.noExpiration ?? false,
        jwtClaims:      result.jwtClaims ?? null,
        probes:         result.probes ?? [],
      });
    } catch (e) {
      out.push({
        ref:         String(f.value || '').slice(0, 160),
        status:      'dead',
        reason:      e.message,
        tokenStatus: 'unknown',
      });
      if (typeof log === 'function') log(`secret validation: ${e.message}`, 'warn');
    }
  }

  return out;
}
