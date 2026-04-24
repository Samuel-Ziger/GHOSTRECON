/**
 * Attack narrative — organiza findings como kill chain / ATT&CK path.
 *
 * 7 fases canônicas (inspiradas em Lockheed Martin + ATT&CK):
 *   1. recon           — subdomains, techs, banners, SSL, wayback, dorks
 *   2. exposure        — credenciais, secrets, configs, leaks
 *   3. auth-surface    — login, SSO, OIDC, 2FA, reset flows
 *   4. auth-bypass     — IDOR, weak JWT, auth flaws
 *   5. injection       — SQLi, XSS, SSRF, LFI, RCE surface
 *   6. execution       — upload, webshell, deserialize, CVE conhecida
 *   7. lateral-impact  — subdomain takeover, cloud takeover, supply-chain
 *
 * Sem refactor nos findings existentes — classifica por heurística sobre
 * category/title/tags/owasp/mitre.
 */

export const PHASES = [
  { id: 'recon',          order: 1, label: 'Reconnaissance',        mitreTactic: 'TA0043' },
  { id: 'exposure',       order: 2, label: 'Credential/Info Exposure', mitreTactic: 'TA0009' },
  { id: 'auth-surface',   order: 3, label: 'Auth Surface',          mitreTactic: 'TA0001' },
  { id: 'auth-bypass',    order: 4, label: 'Auth Bypass / IDOR',    mitreTactic: 'TA0004' },
  { id: 'injection',      order: 5, label: 'Injection / SSRF / XSS', mitreTactic: 'TA0001' },
  { id: 'execution',      order: 6, label: 'Execution / RCE',       mitreTactic: 'TA0002' },
  { id: 'lateral-impact', order: 7, label: 'Lateral / Impact',      mitreTactic: 'TA0040' },
];

const PHASE_RULES = [
  { phase: 'execution',      patterns: /\b(rce|remote.code|webshell|deserialize|command.injection|runtime.exec|cve-)\b/i },
  { phase: 'injection',      patterns: /\b(sqli|sql.inject|xss|cross-site|ssrf|xxe|lfi|rfi|template.inject|nosql.inject|ldap.inject)\b/i },
  { phase: 'auth-bypass',    patterns: /\b(idor|privilege|broken.access|bac|weak.jwt|jwt.alg.none|session.fixation|bypass.2fa|auth.bypass)\b/i },
  { phase: 'auth-surface',   patterns: /\b(login|sso|oidc|oauth|saml|2fa|mfa|password.reset|reset.token|recaptcha|basic.auth|forgot.password)\b/i },
  { phase: 'exposure',       patterns: /\b(secret|api.?key|token|password|credential|env|\.env|dotenv|backup|s3.bucket.public|blob.public|\.git|\.svn|\.hg|aws.key|gcp.key|azure.key)\b/i },
  { phase: 'lateral-impact', patterns: /\b(takeover|subdomain.takeover|cname.dangl|supply.chain|dependency.confusion|s3.takeover|dns.?takeover)\b/i },
  { phase: 'recon',          patterns: /\b(subdomain|banner|tls|ssl|port|crt\.sh|wayback|dns|spf|dkim|dmarc|tech|header|robots|sitemap|exposed.path)\b/i },
];

const OWASP_TO_PHASE = {
  'a01:2021': 'auth-bypass',        // broken access
  'a02:2021': 'exposure',            // crypto failures
  'a03:2021': 'injection',           // injection
  'a04:2021': 'auth-surface',        // insecure design
  'a05:2021': 'recon',               // misconfig (surface-side)
  'a06:2021': 'execution',           // vulnerable components (CVE)
  'a07:2021': 'auth-surface',        // auth failures
  'a08:2021': 'execution',           // integrity failures / deserialize
  'a09:2021': 'exposure',            // logging failures → logs leak
  'a10:2021': 'injection',           // SSRF
};

function normalizeFindingText(f) {
  return [
    f.category, f.type, f.title, f.description,
    ...(Array.isArray(f.tags) ? f.tags : []),
  ].filter(Boolean).map((s) => String(s)).join(' · ').toLowerCase();
}

function pickPhaseForFinding(f) {
  // OWASP → phase direto
  const owasp = Array.isArray(f.owasp) ? f.owasp : (f.owasp ? [f.owasp] : []);
  for (const o of owasp) {
    const key = String(o).toLowerCase();
    if (OWASP_TO_PHASE[key]) return OWASP_TO_PHASE[key];
  }
  const text = normalizeFindingText(f);
  for (const rule of PHASE_RULES) {
    if (rule.patterns.test(text)) return rule.phase;
  }
  return 'recon'; // fallback defensivo
}

/**
 * Devolve `{phases:[{id,label,findings:[],score}], totalFindings}` para um run.
 * score = Σ weightBySeverity — ordena visualmente as fases "quentes".
 */
export function narrate(run, { includeInfo = false } = {}) {
  const SEV_WEIGHT = { critical: 10, high: 6, medium: 3, low: 1, info: 0 };
  const buckets = Object.fromEntries(PHASES.map((p) => [p.id, { ...p, findings: [], score: 0 }]));
  const findings = (run.findings || []).filter((f) => includeInfo || String(f.severity || '').toLowerCase() !== 'info');
  for (const f of findings) {
    const phaseId = pickPhaseForFinding(f);
    const bucket = buckets[phaseId] || buckets.recon;
    bucket.findings.push(f);
    bucket.score += SEV_WEIGHT[String(f.severity || '').toLowerCase()] ?? 0;
  }
  // Ordena findings por severidade dentro de cada fase
  for (const b of Object.values(buckets)) {
    b.findings.sort((a, z) => (SEV_WEIGHT[z.severity?.toLowerCase()] ?? 0) - (SEV_WEIGHT[a.severity?.toLowerCase()] ?? 0));
  }
  return {
    target: run.target,
    runId: run.id,
    phases: PHASES.map((p) => buckets[p.id]),
    totalFindings: findings.length,
  };
}

/**
 * Gera bloco "pré-condição → impacto" exportável para debrief com blue team.
 */
export function buildAttackPath(narrative) {
  const hot = narrative.phases.filter((p) => p.findings.length).map((p) => ({
    phase: p.id, label: p.label, mitreTactic: p.mitreTactic,
    topFindings: p.findings.slice(0, 3).map((f) => ({
      severity: f.severity, title: f.title || f.category,
      mitre: f.mitre || f.mitreTechnique || null,
      cve: Array.isArray(f.cve) ? f.cve : (f.cve ? [f.cve] : []),
    })),
    score: p.score,
  }));

  const preconditions = [];
  const impacts = [];
  for (const p of hot) {
    if (p.phase === 'recon' || p.phase === 'exposure' || p.phase === 'auth-surface') {
      preconditions.push(`${p.label} (${p.topFindings.length} finding(s))`);
    }
    if (p.phase === 'execution' || p.phase === 'lateral-impact' || p.phase === 'injection' || p.phase === 'auth-bypass') {
      impacts.push(`${p.label} (${p.topFindings.length} finding(s))`);
    }
  }
  return {
    target: narrative.target,
    runId: narrative.runId,
    hotPhases: hot,
    preconditions,
    impacts,
    story: buildStoryLine(hot),
  };
}

function buildStoryLine(hot) {
  if (!hot.length) return 'Sem narrativa ofensiva: nenhum finding classificável.';
  const order = { recon: 1, exposure: 2, 'auth-surface': 3, 'auth-bypass': 4, injection: 5, execution: 6, 'lateral-impact': 7 };
  const sorted = [...hot].sort((a, b) => order[a.phase] - order[b.phase]);
  const steps = sorted.map((p, i) => {
    const ex = p.topFindings[0];
    return `${i + 1}. **${p.label}** — ${ex?.title || p.label}${ex?.severity ? ` [${ex.severity}]` : ''}`;
  });
  return steps.join('\n');
}

/**
 * Renderiza narrativa como markdown (para colar em debrief).
 */
export function narrativeToMarkdown(narrative) {
  const lines = [];
  lines.push(`# Attack narrative — run #${narrative.runId} · ${narrative.target}`);
  lines.push('');
  const ap = buildAttackPath(narrative);
  lines.push('## Storyline');
  lines.push('');
  lines.push(ap.story);
  lines.push('');
  if (ap.preconditions.length) { lines.push('## Pré-condições'); ap.preconditions.forEach((x) => lines.push(`- ${x}`)); lines.push(''); }
  if (ap.impacts.length) { lines.push('## Impacto potencial'); ap.impacts.forEach((x) => lines.push(`- ${x}`)); lines.push(''); }

  lines.push('## Fases');
  for (const p of narrative.phases) {
    if (!p.findings.length) continue;
    lines.push(`### ${p.order}. ${p.label} (score=${p.score}, tactic=${p.mitreTactic})`);
    lines.push('');
    for (const f of p.findings.slice(0, 10)) {
      const sev = String(f.severity || 'info').toUpperCase();
      lines.push(`- **[${sev}]** ${f.title || f.category || 'finding'}${f.cve ? ` · ${[].concat(f.cve).join(', ')}` : ''}`);
    }
    if (p.findings.length > 10) lines.push(`- _... mais ${p.findings.length - 10}_`);
    lines.push('');
  }
  return lines.join('\n');
}

// ============================================================================
// Scenarios nomeados (templates de storyline)
// ============================================================================

export const SCENARIOS = {
  'initial-access-admin': {
    id: 'initial-access-admin',
    label: 'Initial access via exposed admin',
    triggers: { phases: ['auth-surface'], patterns: [/wp-admin/i, /\/admin\b/i, /login\.(asp|php|html)/i] },
    description: 'Painel administrativo exposto — combinar com credenciais leaked ou brute force em baunilha.',
    recommendedNext: ['secrets-leak playbook', 'wordpress playbook', 'cve-enrichment'],
  },
  'subdomain-takeover-cookie': {
    id: 'subdomain-takeover-cookie',
    label: 'Subdomain takeover → cookie scope',
    triggers: { phases: ['lateral-impact'], patterns: [/takeover/i, /cname.dangl/i] },
    description: 'Subdomain órfão sob domínio pai com cookies de escopo abrangente — ataque tipo *.target.com.',
    recommendedNext: ['cloud-takeover playbook', 'verificar cookie Domain= em auth flows'],
  },
  'api-token-to-rce': {
    id: 'api-token-to-rce',
    label: 'API token → RCE',
    triggers: { phases: ['exposure', 'execution'], patterns: [/api.?key|bearer/i, /rce|webshell/i] },
    description: 'Token leaked + CVE em componente conhecido ou upload endpoint.',
    recommendedNext: ['api-first playbook', 'secrets-leak playbook'],
  },
  'ssrf-to-cloud-meta': {
    id: 'ssrf-to-cloud-meta',
    label: 'SSRF → cloud metadata',
    triggers: { phases: ['injection'], patterns: [/ssrf/i] },
    description: 'SSRF validado + alvo hospedado em cloud → tentar 169.254.169.254 / metadata.google / etc.',
    recommendedNext: ['module cloud-meta', 'module imds-probe'],
  },
  'xss-to-account-takeover': {
    id: 'xss-to-account-takeover',
    label: 'XSS → account takeover',
    triggers: { phases: ['injection', 'auth-surface'], patterns: [/xss/i] },
    description: 'XSS stored/reflected + cookies sem HttpOnly/SameSite em fluxo de sessão.',
    recommendedNext: ['verificar Set-Cookie flags', 'testar session reuse'],
  },
  'leaked-secrets-to-admin': {
    id: 'leaked-secrets-to-admin',
    label: 'Leaked secrets → admin',
    triggers: { phases: ['exposure'], patterns: [/secret|password|\.env|\/\.git/i] },
    description: 'Credenciais ou tokens em repositório/JS bundle + painel administrativo acessível.',
    recommendedNext: ['secrets-leak playbook', 'validar credenciais em login'],
  },
};

/**
 * Sugere cenários ativáveis com base no narrative atual.
 */
export function matchScenarios(narrative) {
  const activePhases = new Set(narrative.phases.filter((p) => p.findings.length).map((p) => p.id));
  const allText = narrative.phases.flatMap((p) => p.findings.map((f) => normalizeFindingText(f))).join(' | ');

  const matches = [];
  for (const sc of Object.values(SCENARIOS)) {
    const phaseOk = sc.triggers.phases.some((p) => activePhases.has(p));
    const pattOk = (sc.triggers.patterns || []).some((re) => re.test(allText));
    if (phaseOk && pattOk) matches.push(sc);
  }
  return matches;
}
