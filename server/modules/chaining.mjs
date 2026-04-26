/**
 * Chaining engine — transforma findings isolados em cadeias com severidade
 * promovida quando pré-condições se combinam.
 *
 * Ex:
 *   subdomain-takeover (low) + cookie-scope-wildcard (info)
 *     => account-takeover-via-takeover (critical)
 *
 * Saída integra com `attack-narrative` (cada chain vira um nó "scenario").
 */

const SEV_RANK = { info: 0, low: 1, medium: 2, high: 3, critical: 4 };
const SEV_LIST = ['info', 'low', 'medium', 'high', 'critical'];

/**
 * Cada regra:
 *   id: identificador estável
 *   needs: array de predicates(finding) — TODOS devem matchar (em findings distintos)
 *   produces: { title, severity, category, description }
 *   tactic: ATT&CK tag opcional
 */
export const CHAIN_RULES = [
  {
    id: 'takeover-to-ato',
    needs: [
      (f) => /subdomain.takeover|cname.dangl|takeover-candidate/i.test(`${f.category} ${f.title}`),
      (f) => /cookie.scope|set-cookie.*domain=\.|wildcard.cookie/i.test(`${f.category} ${f.title} ${f.description || ''}`),
    ],
    produces: {
      title: 'Account Takeover via subdomain takeover (cookie scope wildcard)',
      severity: 'critical', category: 'chain-ato',
      description: 'Subdomain takeover combinado com cookie scope `*.dominio` permite roubar sessão de qualquer subdomínio. Impacto: ATO completo.',
      tactic: 'TA0006',
    },
  },
  {
    id: 'leaked-secret-to-cloud-pivot',
    needs: [
      (f) => /secrets-leak|api.?key|aws.key|gcp.key|azure.key/i.test(`${f.category} ${f.title}`),
      (f) => /cloud-|s3-bucket|imds|metadata|gcs|blob/i.test(`${f.category} ${f.title}`),
    ],
    produces: {
      title: 'Cloud pivot via leaked credential',
      severity: 'critical', category: 'chain-cloud-pivot',
      description: 'Credencial vazada + superfície cloud exposta = potencial pivot para infra. Validar IAM scope da chave.',
      tactic: 'TA0008',
    },
  },
  {
    id: 'ssrf-to-imds',
    needs: [
      (f) => /\bssrf\b/i.test(`${f.category} ${f.title}`),
      (f) => /imds|169\.254\.169\.254|metadata.google|metadata.azure/i.test(`${f.category} ${f.title} ${JSON.stringify(f.evidence || {})}`),
    ],
    produces: {
      title: 'SSRF → cloud metadata extraction',
      severity: 'critical', category: 'chain-ssrf-imds',
      description: 'SSRF + endpoint metadata cloud detectado = chave IAM exfiltrável via SSRF. Próximo passo: validar credencial.',
      tactic: 'TA0008',
    },
  },
  {
    id: 'oauth-redirect-to-account-takeover',
    needs: [
      (f) => /oauth-redirect|redirect_uri.wildcard|open.redirect/i.test(`${f.category} ${f.title}`),
      (f) => /oidc|oauth|sso|jwt|session/i.test(`${f.category} ${f.title}`),
    ],
    produces: {
      title: 'OAuth redirect_uri abuse → ATO',
      severity: 'high', category: 'chain-oauth-ato',
      description: 'redirect_uri permissivo + fluxo OAuth ativo = roubo de code/token via host atacante. POC: registar redirect attacker-controlled e fluir o flow.',
      tactic: 'TA0006',
    },
  },
  {
    id: 'admin-exposed-to-rce',
    needs: [
      (f) => /(admin|console|wp-admin|jenkins|kibana|grafana)/i.test(`${f.category} ${f.title} ${JSON.stringify(f.evidence || {})}`),
      (f) => /default.cred|weak.password|no.auth|anon.access|exposed/i.test(`${f.category} ${f.title} ${f.description || ''}`),
    ],
    produces: {
      title: 'Admin painel exposto + sem auth → execução remota',
      severity: 'critical', category: 'chain-admin-rce',
      description: 'Painel administrativo acessível sem autenticação ou com credencial default. Maioria dessas consoles permite execução (jobs, scripts, plugins).',
      tactic: 'TA0001',
    },
  },
  {
    id: 'jwt-alg-none-to-impersonation',
    needs: [
      (f) => /jwt|json.web.token/i.test(`${f.category} ${f.title}`),
      (f) => /alg.none|alg=none|hs->rs|key.confusion/i.test(`${f.category} ${f.title} ${f.description || ''}`),
    ],
    produces: {
      title: 'JWT alg=none/key-confusion → impersonation',
      severity: 'critical', category: 'chain-jwt-impersonation',
      description: 'Validador JWT aceita assinatura fraca/none — forjar token de admin é trivial.',
      tactic: 'TA0006',
    },
  },
  {
    id: 'graphql-introspection-to-bola',
    needs: [
      (f) => /graphql.introspection|__schema/i.test(`${f.category} ${f.title}`),
      (f) => /idor|bola|broken.access|authz/i.test(`${f.category} ${f.title}`),
    ],
    produces: {
      title: 'GraphQL introspection + BOLA → enumeration de qualquer recurso',
      severity: 'high', category: 'chain-graphql-bola',
      description: 'Introspection expõe schema → operador mapeia mutations/queries por ID e BOLA já confirma falha de authz. Combinação = exfiltração estruturada.',
      tactic: 'TA0009',
    },
  },
  {
    id: 'origin-leak-to-waf-bypass',
    needs: [
      (f) => /origin.discovered|origin.ip.leak|cloudflare.bypass/i.test(`${f.category} ${f.title}`),
      (f) => /waf|cdn|cloudflare|akamai/i.test(`${f.category} ${f.title}`),
    ],
    produces: {
      title: 'Origin IP leak → WAF/CDN bypass',
      severity: 'high', category: 'chain-origin-bypass',
      description: 'IP de origem identificado → atacar diretamente bypass do WAF/CDN. Próximo: replay payloads bloqueados contra origin.',
      tactic: 'TA0043',
    },
  },
  {
    id: 'js-bundle-leak-to-internal-api',
    needs: [
      (f) => /js-bundle|source.map|webpack/i.test(`${f.category} ${f.title}`),
      (f) => /admin|internal|debug|\/api\/v\d|graphql|feature.flag/i.test(`${f.title} ${f.description || ''} ${JSON.stringify(f.evidence || {})}`),
    ],
    produces: {
      title: 'JS bundle leak → endpoints internos',
      severity: 'medium', category: 'chain-js-internal',
      description: 'Bundle exposto revela endpoints/admin internos não documentados. Material direto pra próxima fase de teste.',
      tactic: 'TA0007',
    },
  },
  {
    id: 'race-on-coupon-payment',
    needs: [
      (f) => /race|race.condition|toctou/i.test(`${f.category} ${f.title}`),
      (f) => /coupon|payment|transfer|withdraw|balance|credit/i.test(`${f.category} ${f.title} ${f.description || ''}`),
    ],
    produces: {
      title: 'Race condition em endpoint financeiro',
      severity: 'high', category: 'chain-race-financial',
      description: 'Race em coupon/payment/transfer = duplicação de saldo/uso. Bounty alto.',
      tactic: 'TA0040',
    },
  },
];

function maxSev(a, b) {
  return SEV_RANK[a] >= SEV_RANK[b] ? a : b;
}

/**
 * Encontra todas as cadeias possíveis num run.
 *
 * Política: cada finding pode contribuir para múltiplas chains, mas dentro de
 * uma chain os predicates devem matchar findings distintos (índices diferentes).
 */
export function detectChains(findings = [], { rules = CHAIN_RULES, maxPerRule = 5 } = {}) {
  const chains = [];
  for (const rule of rules) {
    const matches = findChainCandidates(findings, rule.needs);
    for (const m of matches.slice(0, maxPerRule)) {
      chains.push({
        id: rule.id,
        ...rule.produces,
        evidence: {
          components: m.map((idx) => ({
            index: idx,
            title: findings[idx]?.title,
            category: findings[idx]?.category,
            severity: findings[idx]?.severity,
          })),
        },
      });
    }
  }
  return chains;
}

function findChainCandidates(findings, predicates) {
  // Combinatório simples: produto cartesiano com restrição "índices distintos".
  // Para N pequeno (<200 findings, <5 predicates) isto é aceitável.
  if (!predicates.length) return [];
  const buckets = predicates.map((p) =>
    findings.map((f, i) => (p(f) ? i : -1)).filter((i) => i >= 0),
  );
  if (buckets.some((b) => !b.length)) return [];
  const out = [];
  function recurse(level, picked) {
    if (level === buckets.length) {
      out.push([...picked]);
      return;
    }
    for (const idx of buckets[level]) {
      if (picked.includes(idx)) continue;
      picked.push(idx);
      recurse(level + 1, picked);
      picked.pop();
      if (out.length > 50) return; // hard cap
    }
  }
  recurse(0, []);
  return out;
}

/**
 * Aplica chains a um run e devolve um novo run com:
 *   - findings originais preservados
 *   - chains adicionadas em `findings` (com flag `chain: true`)
 *   - severidade do run reavaliada (se chain critical → run prioritized)
 */
export function applyChains(run, opts = {}) {
  if (!run || !Array.isArray(run.findings)) return run;
  const chains = detectChains(run.findings, opts);
  const chainFindings = chains.map((c, i) => ({
    chain: true,
    chainId: c.id,
    severity: c.severity,
    category: c.category,
    title: c.title,
    description: c.description,
    evidence: c.evidence,
    tactic: c.tactic || null,
    promotedAt: new Date().toISOString(),
    nth: i + 1,
  }));
  return {
    ...run,
    chains,
    findings: [...run.findings, ...chainFindings],
    chainSummary: summarizeChains(chains),
  };
}

export function summarizeChains(chains) {
  const out = { total: chains.length, byId: {}, topSeverity: 'info' };
  for (const c of chains) {
    out.byId[c.id] = (out.byId[c.id] || 0) + 1;
    out.topSeverity = maxSev(out.topSeverity, c.severity);
  }
  return out;
}

export function chainsToMarkdown(chains) {
  if (!chains.length) return '_(sem cadeias detectadas)_\n';
  const order = SEV_LIST.slice().reverse();
  const sorted = [...chains].sort((a, b) => order.indexOf(a.severity) - order.indexOf(b.severity));
  const lines = ['# Attack chains detectadas\n'];
  for (const c of sorted) {
    lines.push(`## [${c.severity.toUpperCase()}] ${c.title}`);
    lines.push(`- **chain id**: ${c.id}`);
    if (c.tactic) lines.push(`- **MITRE tactic**: ${c.tactic}`);
    lines.push(`- ${c.description}`);
    if (c.evidence?.components?.length) {
      lines.push(`- componentes:`);
      for (const cmp of c.evidence.components) lines.push(`  - [${cmp.severity}] ${cmp.title} (${cmp.category})`);
    }
    lines.push('');
  }
  return lines.join('\n');
}
