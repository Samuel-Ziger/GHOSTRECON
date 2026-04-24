/**
 * Identity surface — OAuth/OIDC/SAML checks a partir de `.well-known` público.
 *
 * Todos os checks são passivos (GET em metadata pública). Não envia
 * authorization_code, não tenta login — só audita config.
 *
 * Sinais:
 *   - redirect_uris wildcard/HTTP/localhost registrados em produção
 *   - PKCE não suportado (code_challenge_methods_supported ausente ou sem S256)
 *   - public clients (token_endpoint_auth_methods_supported inclui 'none')
 *   - response_types inseguros (token implicit sem resposta nativa)
 *   - metadata excessiva (endpoints admin expostos, issuer diverge)
 *   - scopes muito permissivos (openid profile email + read:all / write:all)
 *   - algs fracos (HS256, none) em id_token_signing_alg_values_supported
 */

const OIDC_CONFIG_PATHS = [
  '/.well-known/openid-configuration',
  '/.well-known/oauth-authorization-server',
];

const SEV = (s) => String(s || 'info').toLowerCase();

/**
 * Audita metadata OIDC/OAuth. Aceita objeto JSON já fetched.
 * Retorna lista de findings.
 */
export function auditOidcMetadata(meta, { host = null } = {}) {
  const findings = [];
  if (!meta || typeof meta !== 'object') return findings;

  const issuer = meta.issuer || '';
  const target = host || (issuer ? tryHost(issuer) : null) || 'unknown';

  // --- PKCE ---
  const pkce = Array.isArray(meta.code_challenge_methods_supported)
    ? meta.code_challenge_methods_supported.map((x) => String(x).toLowerCase())
    : [];
  if (!pkce.length) {
    findings.push({
      severity: 'medium', category: 'oidc-config',
      title: 'PKCE não declarado em /.well-known',
      description: 'code_challenge_methods_supported ausente. Clientes mobile/SPA sem PKCE ficam suscetíveis a authorization code interception.',
      owasp: ['A07:2021'], mitre: 'T1550',
      evidence: { target, issuer, url: meta._url || null, check: 'code_challenge_methods_supported' },
    });
  } else if (!pkce.includes('s256')) {
    findings.push({
      severity: 'low', category: 'oidc-config',
      title: 'PKCE apenas com plain (sem S256)',
      description: 'code_challenge_methods_supported não inclui S256. `plain` é considerado inseguro.',
      owasp: ['A07:2021'],
      evidence: { target, issuer, pkce },
    });
  }

  // --- public clients ---
  const authMethods = Array.isArray(meta.token_endpoint_auth_methods_supported)
    ? meta.token_endpoint_auth_methods_supported.map((x) => String(x).toLowerCase())
    : [];
  if (authMethods.includes('none')) {
    findings.push({
      severity: 'low', category: 'oidc-config',
      title: 'Public clients aceitos em token endpoint',
      description: 'token_endpoint_auth_methods_supported inclui "none" — SPAs/CLIs podem obter tokens sem client secret. Combinar com PKCE check.',
      owasp: ['A07:2021'],
      evidence: { target, issuer, authMethods },
    });
  }

  // --- weak algorithms ---
  const algs = Array.isArray(meta.id_token_signing_alg_values_supported)
    ? meta.id_token_signing_alg_values_supported.map((x) => String(x))
    : [];
  const weakAlgs = algs.filter((a) => /^(none|hs256|hs384|hs512)$/i.test(a));
  if (weakAlgs.length) {
    findings.push({
      severity: weakAlgs.includes('none') ? 'high' : 'medium',
      category: 'oidc-config',
      title: `Algoritmos de assinatura fracos permitidos: ${weakAlgs.join(', ')}`,
      description: `id_token_signing_alg_values_supported contém ${weakAlgs.join(', ')}. "none" = CRÍTICO (sem assinatura). HSxxx = shared secret (compromisso de servidor permite forjar tokens).`,
      owasp: ['A02:2021'], mitre: 'T1606',
      evidence: { target, issuer, weakAlgs },
    });
  }

  // --- implicit flow ---
  const respTypes = Array.isArray(meta.response_types_supported) ? meta.response_types_supported : [];
  const hasImplicit = respTypes.some((rt) => /\btoken\b/i.test(String(rt)) && !/code/i.test(String(rt)));
  if (hasImplicit) {
    findings.push({
      severity: 'low', category: 'oidc-config',
      title: 'Implicit flow suportado',
      description: 'response_types_supported inclui `token` — implicit flow é desencorajado pelo OAuth 2.1.',
      owasp: ['A07:2021'],
      evidence: { target, issuer, responseTypes: respTypes },
    });
  }

  // --- admin-looking endpoints expostos em metadata ---
  const adminEndpoints = [];
  for (const [k, v] of Object.entries(meta)) {
    if (typeof v !== 'string') continue;
    if (/admin|internal|dev|staging/i.test(v)) adminEndpoints.push({ key: k, value: v });
  }
  if (adminEndpoints.length) {
    findings.push({
      severity: 'low', category: 'oidc-config',
      title: 'Endpoints admin/internal expostos em OIDC metadata',
      description: 'Metadata pública referencia endpoints sensíveis — útil para enumeração. Rever discovery doc.',
      evidence: { target, issuer, endpoints: adminEndpoints.slice(0, 10) },
    });
  }

  // --- issuer diverge do host ---
  if (host && issuer && !issuer.includes(host) && !host.includes(tryHost(issuer) || '')) {
    findings.push({
      severity: 'info', category: 'oidc-config',
      title: `Issuer diverge do host (${issuer} vs ${host})`,
      description: 'Não necessariamente vulnerável, mas pode indicar proxy/CDN mal configurado ou mix de tenants.',
      evidence: { target, issuer, host },
    });
  }

  // --- scopes excessivos ---
  const scopes = Array.isArray(meta.scopes_supported) ? meta.scopes_supported : [];
  const dangerous = scopes.filter((s) => /admin|write|\*|all|full_access|root/i.test(String(s)));
  if (dangerous.length) {
    findings.push({
      severity: 'medium', category: 'oidc-config',
      title: `Scopes potentes declarados: ${dangerous.slice(0, 5).join(', ')}`,
      description: 'Scopes como `admin`, `write:*`, `full_access` sendo concedíveis via consent flow aumentam risco de phishing/consent grant abuse.',
      owasp: ['A07:2021'], mitre: 'T1528',
      evidence: { target, issuer, dangerousScopes: dangerous },
    });
  }

  return findings;
}

function tryHost(u) { try { return new URL(u).hostname; } catch { return null; } }

/**
 * Parse redirect_uri list de client_id metadata (para quando operador já tem
 * `/register` ou `registered_clients` público disponível).
 */
export function auditRedirectUris(uris, { host = null } = {}) {
  const findings = [];
  for (const u of uris || []) {
    const s = String(u || '');
    if (!s) continue;
    if (s.includes('*')) {
      findings.push({
        severity: 'high', category: 'oauth-redirect',
        title: `redirect_uri com wildcard: ${s}`,
        description: 'Wildcards em redirect_uri permitem open redirect → roubo de authorization code.',
        owasp: ['A01:2021'], mitre: 'T1557',
        evidence: { target: host, redirect_uri: s },
      });
    } else if (/^http:\/\//i.test(s) && !/localhost|127\.0\.0\.1/.test(s)) {
      findings.push({
        severity: 'medium', category: 'oauth-redirect',
        title: `redirect_uri em HTTP (não-TLS): ${s}`,
        description: 'Código de autorização trafega em claro se redirect_uri é HTTP.',
        owasp: ['A02:2021'],
        evidence: { target: host, redirect_uri: s },
      });
    } else if (/^(localhost|127\.0\.0\.1)/.test(s.replace(/^https?:\/\//, ''))) {
      findings.push({
        severity: 'info', category: 'oauth-redirect',
        title: `redirect_uri localhost registrado em produção: ${s}`,
        description: 'Se este client é de produção, localhost é provavelmente sobra de dev.',
        evidence: { target: host, redirect_uri: s },
      });
    }
  }
  return findings;
}

// ============================================================================
// Cloud surface hints (passivos — URLs only)
// ============================================================================

/**
 * Detecta padrões de storage público / endpoints metadata em URLs/hosts
 * conhecidos. Não faz requests — só reconhece o padrão.
 */
export function detectCloudSurface(urlOrHost) {
  const s = String(urlOrHost || '').toLowerCase();
  const hints = [];
  // AWS
  if (/\.s3\.amazonaws\.com\b|\.s3\.[a-z0-9-]+\.amazonaws\.com\b|\.s3-website[.-]/.test(s)) {
    hints.push({ cloud: 'aws', kind: 's3-bucket', detail: 'S3 bucket — validar ACL público/list via bucket-test passivo.' });
  }
  if (/\.cloudfront\.net\b/.test(s)) hints.push({ cloud: 'aws', kind: 'cloudfront', detail: 'CloudFront CDN — origin pode estar exposto.' });
  if (/\.elb\.amazonaws\.com\b|\.elb\.[a-z0-9-]+\.amazonaws\.com\b/.test(s)) hints.push({ cloud: 'aws', kind: 'elb', detail: 'ELB/ALB direto — pode indicar DNS/CDN mal configurado.' });
  if (/\.execute-api\.[a-z0-9-]+\.amazonaws\.com\b/.test(s)) hints.push({ cloud: 'aws', kind: 'api-gateway', detail: 'API Gateway execute-api — stage exposto?' });
  // Azure
  if (/\.blob\.core\.windows\.net\b/.test(s)) hints.push({ cloud: 'azure', kind: 'blob-storage', detail: 'Azure Blob — validar ?restype=container&comp=list.' });
  if (/\.azurewebsites\.net\b/.test(s)) hints.push({ cloud: 'azure', kind: 'app-service', detail: 'Azure App Service default hostname.' });
  if (/\.azurefd\.net\b/.test(s)) hints.push({ cloud: 'azure', kind: 'front-door', detail: 'Azure Front Door.' });
  if (/\.cloudapp\.azure\.com\b/.test(s)) hints.push({ cloud: 'azure', kind: 'cloudapp', detail: 'Azure VM default DNS.' });
  // GCP
  if (/storage\.googleapis\.com\b|\.storage\.googleapis\.com\b/.test(s)) hints.push({ cloud: 'gcp', kind: 'gcs', detail: 'GCS bucket — validar listing público.' });
  if (/\.appspot\.com\b/.test(s)) hints.push({ cloud: 'gcp', kind: 'appengine', detail: 'GAE default hostname.' });
  if (/\.run\.app\b/.test(s)) hints.push({ cloud: 'gcp', kind: 'cloud-run', detail: 'Cloud Run service.' });
  // Takeover candidatos
  if (/\.github\.io\b|\.herokuapp\.com\b|\.netlify\.app\b|\.vercel\.app\b|\.readthedocs\.io\b/.test(s)) {
    hints.push({ cloud: 'saas', kind: 'takeover-candidate', detail: 'SaaS hosting — candidato a subdomain takeover se CNAME órfão.' });
  }
  // Metadata endpoints (para contexto — só alerta quando SSRF é encontrado)
  if (/169\.254\.169\.254|metadata\.google\.internal/.test(s)) {
    hints.push({ cloud: 'meta', kind: 'imds-target', detail: 'Referência direta a endpoint de metadata — usar em cadeia de SSRF.' });
  }
  return hints;
}

/**
 * Converte hints em findings (severity info por padrão — contexto, não bug).
 */
export function cloudSurfaceToFindings(urls = [], { target = null } = {}) {
  const findings = [];
  const seen = new Set();
  for (const u of urls) {
    for (const h of detectCloudSurface(u)) {
      const key = `${h.cloud}|${h.kind}|${u}`;
      if (seen.has(key)) continue;
      seen.add(key);
      findings.push({
        severity: h.kind === 'takeover-candidate' ? 'low' : 'info',
        category: `cloud-${h.cloud}`,
        title: `${h.cloud.toUpperCase()} ${h.kind} detectado`,
        description: h.detail,
        evidence: { target: target || tryHost(u) || u, url: u, cloud: h.cloud, kind: h.kind },
      });
    }
  }
  return findings;
}

export { OIDC_CONFIG_PATHS };
