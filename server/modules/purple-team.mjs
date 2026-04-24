/**
 * Purple team — anota findings com origem (lab/prod) e exporta para o blue
 * team com controle sugerido, log source e regra Sigma.
 *
 * Origens suportadas:
 *   - observed-prod : finding real em produção (default)
 *   - simulated-lab : finding reproduzido em lab/isolado
 *   - hypothetical  : não validado, só sinal de surface
 *   - blue-validated: confirmado pelo blue team (via feedback)
 *
 * Útil para relatórios: separa "o que a gente achou no alvo" vs "o que a gente
 * conseguiu reproduzir em lab" — evita claims errados no debrief.
 */

/**
 * Anota um finding com origem.
 */
export function annotateOrigin(finding, { origin = 'observed-prod', by = null, at = null, note = null } = {}) {
  const ALLOWED = new Set(['observed-prod', 'simulated-lab', 'hypothetical', 'blue-validated']);
  const o = String(origin || 'observed-prod').toLowerCase();
  if (!ALLOWED.has(o)) throw new Error(`origem inválida: ${origin} (use: ${[...ALLOWED].join(', ')})`);
  return {
    ...finding,
    origin: o,
    origin_meta: {
      at: at || new Date().toISOString(),
      by: by || null,
      note: note || null,
    },
  };
}

/**
 * Filtra por origem (útil em relatórios).
 */
export function filterByOrigin(findings, origins) {
  const set = new Set(Array.isArray(origins) ? origins : [origins]);
  return (findings || []).filter((f) => set.has(f.origin || 'observed-prod'));
}

// ============================================================================
// Control suggestion library (detection-side)
// ============================================================================

/**
 * Mapa finding.category → {control, logSource, sigmaQuery}.
 * Simples, extensível, e intencionalmente genérico — blue team refina.
 */
export const CONTROL_LIBRARY = {
  'rce': {
    control: 'Restringir upload de extensões executáveis; WAF rule bloqueando payloads de deserialize/code eval.',
    logSources: ['proxy/waf', 'webserver/access', 'app/stderr'],
    sigmaTitle: 'Suspicious RCE payload in HTTP request',
    sigmaDetection: {
      selection: {
        'http.method': 'POST',
        'http.request.body|contains': ['<?php', 'eval(', 'exec(', 'system(', 'phpinfo()', '/bin/sh', 'cmd.exe'],
      },
      condition: 'selection',
    },
    level: 'critical',
  },
  'sqli': {
    control: 'Usar prepared statements; WAF com OWASP CRS nível 3; monitorar erros 500 + strings de DB.',
    logSources: ['proxy/waf', 'webserver/access', 'db/errorlog'],
    sigmaTitle: 'SQL injection patterns in HTTP request',
    sigmaDetection: {
      selection: {
        'http.request.query|contains': ["' OR '1'='1", 'UNION SELECT', 'sleep(', 'benchmark(', 'information_schema'],
      },
      condition: 'selection',
    },
    level: 'high',
  },
  'xss': {
    control: 'CSP (script-src self), HttpOnly+SameSite nos cookies, output encoding consistente.',
    logSources: ['proxy/waf', 'csp-report', 'browser-telemetry'],
    sigmaTitle: 'XSS payload in HTTP request',
    sigmaDetection: {
      selection: {
        'http.request.query|contains': ['<script', 'javascript:', 'onerror=', 'onload=', 'svg/onload'],
      },
      condition: 'selection',
    },
    level: 'medium',
  },
  'ssrf': {
    control: 'Bloquear egress para 169.254.169.254, metadata.google.internal, RFC1918 a partir de servidores web; IMDSv2.',
    logSources: ['egress-firewall', 'cloudtrail/audit', 'webserver/access'],
    sigmaTitle: 'SSRF probe to cloud metadata endpoint',
    sigmaDetection: {
      selection: {
        'http.request.query|contains': ['169.254.169.254', 'metadata.google.internal', 'metadata.azure.com', '/latest/meta-data'],
      },
      condition: 'selection',
    },
    level: 'high',
  },
  'open-port': {
    control: 'Reduzir superfície externa (security group / firewall). Alertar em portas não mapeadas ao inventário.',
    logSources: ['vpc-flow', 'firewall/edge', 'asset-inventory'],
    sigmaTitle: 'Unexpected open port from external scan',
    sigmaDetection: {
      selection: { 'network.direction': 'outbound', 'network.src': 'external' },
      condition: 'selection',
    },
    level: 'low',
  },
  'content-discovery': {
    control: 'Remover paths sensíveis (.git, .env, backup/); WAF bloqueando enumeração; rate-limit por IP.',
    logSources: ['proxy/waf', 'webserver/access'],
    sigmaTitle: 'Content discovery probes (fuzzing)',
    sigmaDetection: {
      selection: {
        'http.request.uri|contains': ['/.env', '/.git/', '/backup', '/phpmyadmin', '/.htpasswd', '/.svn'],
      },
      condition: 'selection',
    },
    level: 'medium',
  },
  'security-headers': {
    control: 'Configurar CSP/HSTS/X-Frame-Options/Referrer-Policy via gateway central (CDN ou reverse proxy).',
    logSources: ['cdn-config', 'csp-report'],
    sigmaTitle: 'N/A (configuração, não evento)',
    sigmaDetection: null,
    level: 'low',
  },
  'oidc-config': {
    control: 'Revisar discovery document: PKCE S256 obrigatório, sem algs fracos, sem endpoints admin em metadata pública.',
    logSources: ['idp/audit', 'auth-service/log'],
    sigmaTitle: 'OIDC config drift (manual review)',
    sigmaDetection: null,
    level: 'medium',
  },
  'oauth-redirect': {
    control: 'Whitelist rígida de redirect_uri, sem wildcards, apenas HTTPS.',
    logSources: ['idp/audit'],
    sigmaTitle: 'OAuth open redirect attempt',
    sigmaDetection: {
      selection: { 'http.request.uri|contains': ['redirect_uri='], 'http.request.query|re': '(?i)redirect_uri=.*(http://|evil\\.|\\..*\\@)' },
      condition: 'selection',
    },
    level: 'high',
  },
  'phishing-infra': {
    control: 'Monitorar registrations parecidos (typo-squat) via cert transparency; DMARC p=reject + BIMI.',
    logSources: ['ct-log-feeder', 'mail-security-gateway'],
    sigmaTitle: 'Suspicious email auth failure (SPF/DKIM/DMARC)',
    sigmaDetection: {
      selection: { 'email.dmarc.result': ['fail', 'softfail'] },
      condition: 'selection',
    },
    level: 'medium',
  },
  'secrets-leak': {
    control: 'Git pre-commit hooks (gitleaks), rotação após incidente, scanner de código + secret manager para tokens.',
    logSources: ['github-audit', 'secret-vault/access'],
    sigmaTitle: 'API key / token pattern observed in public surface',
    sigmaDetection: null,
    level: 'high',
  },
};

/**
 * Produz bloco Sigma (YAML-like em JS object) para um finding.
 */
export function buildSigmaForFinding(finding) {
  const cat = String(finding?.category || '').toLowerCase();
  const entry = CONTROL_LIBRARY[cat];
  if (!entry || !entry.sigmaDetection) return null;
  return {
    title: entry.sigmaTitle,
    id: `ghostrecon-${cat}-${hashish(finding)}`,
    status: 'experimental',
    description: `Auto-generated by GHOSTRECON for category "${cat}". Finding title: ${finding.title || '-'}`,
    references: ['https://github.com/ghostrecon'],
    author: 'ghostrecon',
    date: new Date().toISOString().slice(0, 10),
    logsource: { product: entry.logSources[0]?.split('/')[0] || 'web', service: entry.logSources[0] || 'unknown' },
    detection: entry.sigmaDetection,
    falsepositives: ['Legitimate testing', 'Internal security scans'],
    level: entry.level,
  };
}

function hashish(f) {
  const s = `${f.category || ''}|${f.title || ''}|${f.evidence?.url || ''}`;
  let h = 5381;
  for (let i = 0; i < s.length; i++) h = ((h << 5) + h + s.charCodeAt(i)) | 0;
  return (h >>> 0).toString(16).slice(0, 8);
}

/**
 * Renderiza um objeto Sigma como string YAML simples (sem dep).
 */
export function sigmaToYaml(obj, indent = 0) {
  if (obj == null) return '';
  if (typeof obj === 'string') return yamlString(obj);
  if (typeof obj === 'number' || typeof obj === 'boolean') return String(obj);
  const pad = '  '.repeat(indent);
  if (Array.isArray(obj)) {
    return obj.map((v) => `\n${pad}- ${sigmaToYaml(v, indent + 1).trimStart()}`).join('');
  }
  if (typeof obj === 'object') {
    const out = [];
    for (const [k, v] of Object.entries(obj)) {
      if (v && typeof v === 'object' && !Array.isArray(v)) {
        out.push(`${pad}${k}:\n${sigmaToYaml(v, indent + 1)}`);
      } else if (Array.isArray(v)) {
        out.push(`${pad}${k}:${sigmaToYaml(v, indent + 1)}`);
      } else {
        out.push(`${pad}${k}: ${sigmaToYaml(v, indent + 1)}`);
      }
    }
    return out.join('\n');
  }
  return String(obj);
}

function yamlString(s) {
  // Force quoting quando contém caracteres especiais
  if (/[:#\-{}\[\]&*!|>'"%@`]/.test(s) || /^[\s]|[\s]$/.test(s)) {
    return `"${s.replace(/"/g, '\\"')}"`;
  }
  return s;
}

/**
 * Export purple-team completo: para cada finding, emite block com finding +
 * controle + Sigma YAML.
 */
export function exportPurpleTeamReport(run, { minSeverity = 'low' } = {}) {
  const SEV = { info: 0, low: 1, medium: 2, high: 3, critical: 4 };
  const floor = SEV[String(minSeverity).toLowerCase()] ?? 1;
  const findings = (run.findings || []).filter((f) => (SEV[String(f.severity).toLowerCase()] ?? 0) >= floor);

  const lines = [];
  lines.push(`# Purple team report — run #${run.id} · ${run.target}`);
  lines.push('');
  lines.push(`Findings: ${findings.length} · min severity: ${minSeverity}`);
  lines.push('');

  for (const f of findings) {
    const cat = String(f.category || '').toLowerCase();
    const ctrl = CONTROL_LIBRARY[cat];
    const sigma = buildSigmaForFinding(f);
    lines.push(`## [${(f.severity || 'info').toUpperCase()}] ${f.title || f.category || 'finding'}`);
    lines.push('');
    lines.push(`**Origem:** \`${f.origin || 'observed-prod'}\` · **Categoria:** \`${f.category || '-'}\``);
    if (f.evidence?.target) lines.push(`**Alvo:** \`${f.evidence.target}\``);
    if (f.evidence?.url) lines.push(`**URL:** ${f.evidence.url}`);
    lines.push('');
    if (f.description) { lines.push(f.description); lines.push(''); }

    lines.push('### Controle sugerido (blue team)');
    lines.push('');
    if (ctrl) {
      lines.push(ctrl.control);
      lines.push('');
      lines.push(`**Log sources:** ${ctrl.logSources.join(', ')}`);
    } else {
      lines.push('_Sem controle mapeado — documentar manualmente._');
    }
    lines.push('');

    if (sigma) {
      lines.push('### Regra Sigma (draft)');
      lines.push('');
      lines.push('```yaml');
      lines.push(sigmaToYaml(sigma));
      lines.push('```');
    } else {
      lines.push('### Regra Sigma');
      lines.push('');
      lines.push('_N/A — categoria sem detecção event-based (config ou postura)._');
    }
    lines.push('');
    lines.push('---');
    lines.push('');
  }
  return lines.join('\n');
}
