/**
 * Bounty $/hora estimator — score heurístico para priorizar findings em
 * bug bounty.
 *
 * Inputs:
 *   - finding (severity + category)
 *   - program tier ($/critical médio histórico)
 *   - effort restante para POC validável
 *   - probabilidade de ser único (não dup)
 *
 * Output:
 *   { expectedPayout, estimatedHours, ratio, recommendation }
 */

const SEVERITY_PAYOUT = {
  critical: 5000, high: 1500, medium: 500, low: 100, info: 0,
};

// Multiplicador por tier do programa (HackerOne/Bugcrowd "VIP" pagam 3-10x)
export const PROGRAM_TIERS = {
  basic: 1.0, standard: 1.5, plus: 2.5, vip: 4.0, enterprise: 6.0,
};

// Categorias com bounty médio bem estabelecido
const CATEGORY_MULTIPLIER = {
  rce: 3.0, sqli: 2.5, ssrf: 2.0, 'auth-bypass': 2.5, 'authz-privesc': 2.5, 'authz-bola': 1.8,
  xss: 0.7, 'xss-dom-confirmed': 1.0, 'open-redirect': 0.4, 'oauth-redirect': 1.5,
  'subdomain-takeover': 1.2, 'cloud-public-bucket': 1.4, 'secrets-leak': 2.0,
  'graphql-introspection': 0.3, 'security-headers': 0.1, 'phishing-infra': 0.2,
  'race-condition': 2.0, 'chain-': 2.5, 'idor': 1.8,
};

const EFFORT_PER_SEVERITY = {
  critical: 6, high: 4, medium: 2, low: 1, info: 0.5, // horas estimadas até POC limpo
};

function categoryMultiplier(cat) {
  if (!cat) return 1.0;
  if (CATEGORY_MULTIPLIER[cat]) return CATEGORY_MULTIPLIER[cat];
  // chain-* prefix
  for (const k of Object.keys(CATEGORY_MULTIPLIER)) {
    if (cat.startsWith(k)) return CATEGORY_MULTIPLIER[k];
  }
  return 1.0;
}

export function estimateBounty(finding, { tier = 'standard', uniqueProb = 0.6, hoursToPoc = null } = {}) {
  const sev = String(finding.severity || 'info').toLowerCase();
  const base = SEVERITY_PAYOUT[sev] ?? 0;
  const tierMult = PROGRAM_TIERS[tier] || 1;
  const catMult = categoryMultiplier(finding.category);
  const expectedPayout = Math.round(base * tierMult * catMult * uniqueProb);
  const effort = hoursToPoc != null ? hoursToPoc : EFFORT_PER_SEVERITY[sev] ?? 2;
  const ratio = effort > 0 ? Math.round((expectedPayout / effort) * 100) / 100 : expectedPayout;

  let recommendation = 'low';
  if (expectedPayout >= 1000 && ratio >= 200) recommendation = 'go-now';
  else if (expectedPayout >= 500 && ratio >= 100) recommendation = 'priority';
  else if (expectedPayout >= 100) recommendation = 'eventual';
  else recommendation = 'skip';

  return {
    expectedPayout, estimatedHours: effort, ratio,
    recommendation,
    breakdown: { base, tierMult, catMult, uniqueProb, sev, category: finding.category || null },
  };
}

/**
 * Ranking de uma lista de findings — devolve lista ordenada por ratio desc.
 */
export function prioritize(findings = [], opts = {}) {
  const ranked = findings.map((f) => ({
    finding: f, estimate: estimateBounty(f, opts),
  }));
  ranked.sort((a, b) => b.estimate.ratio - a.estimate.ratio);
  return ranked;
}

/**
 * Sumariza valor potencial total do run.
 */
export function summarizeValue(findings = [], opts = {}) {
  let total = 0; const byRecommendation = { 'go-now': 0, priority: 0, eventual: 0, skip: 0 };
  for (const f of findings) {
    const e = estimateBounty(f, opts);
    total += e.expectedPayout;
    byRecommendation[e.recommendation] = (byRecommendation[e.recommendation] || 0) + 1;
  }
  return { totalExpected: total, byRecommendation };
}
