import { HexstrikeClient } from '../integrations/hexstrike-client.mjs';

export const moduleManifest = {
  id: 'hexstrike_orchestrator',
  name: 'HexStrike Intelligence Orchestrator',
  category: 'intel',
  intrusive: false,
  requiresAuth: false,
  requiresKali: false,
  timeoutMs: 60_000,
  concurrency: 1,
  outputs: ['finding', 'intel'],
};

function compact(value, max = 240) {
  const s = String(value ?? '').replace(/\s+/g, ' ').trim();
  return s.length > max ? `${s.slice(0, max - 3)}...` : s;
}

function arrayOfStrings(value, limit = 20) {
  if (!Array.isArray(value)) return [];
  return value.map((x) => String(x)).filter(Boolean).slice(0, limit);
}

function scoreForRisk(riskLevel, attackSurfaceScore, confidenceScore) {
  const risk = String(riskLevel || '').toLowerCase();
  const base = risk === 'critical' ? 82 : risk === 'high' ? 72 : risk === 'medium' ? 58 : risk === 'low' ? 38 : 30;
  const surface = Number.isFinite(Number(attackSurfaceScore)) ? Math.min(12, Math.max(0, Number(attackSurfaceScore))) : 0;
  const confidence = Number.isFinite(Number(confidenceScore)) ? Math.min(6, Math.max(0, Number(confidenceScore) * 6)) : 0;
  return Math.round(Math.min(88, base + surface + confidence));
}

function prioForScore(score) {
  if (score >= 75) return 'high';
  if (score >= 55) return 'med';
  if (score >= 35) return 'low';
  return 'info';
}

function safeTargetUrl(target) {
  try {
    const u = new URL(String(target));
    if (/^https?:$/i.test(u.protocol)) return u.href;
  } catch {}
  return null;
}

export function extractHexstrikeProfile(data) {
  const profile = data?.target_profile || data?.profile || data?.targetAnalysis || data?.analysis || null;
  return profile && typeof profile === 'object' ? profile : null;
}

export function normalizeHexstrikeAnalysis(data, { target = '' } = {}) {
  const profile = extractHexstrikeProfile(data);
  if (!profile) return [];

  const targetValue = String(profile.target || target || '').trim();
  const targetType = String(profile.target_type || profile.type || 'unknown');
  const riskLevel = String(profile.risk_level || 'unknown');
  const technologies = arrayOfStrings(profile.technologies, 12);
  const ports = arrayOfStrings(profile.open_ports, 20);
  const subdomains = arrayOfStrings(profile.subdomains, 20);
  const endpoints = arrayOfStrings(profile.endpoints, 20);
  const score = scoreForRisk(riskLevel, profile.attack_surface_score, profile.confidence_score);

  const fields = [
    'source=hexstrike',
    `target_type=${compact(targetType, 80)}`,
    `risk=${compact(riskLevel, 40)}`,
    Number.isFinite(Number(profile.confidence_score)) ? `confidence=${Number(profile.confidence_score).toFixed(2)}` : '',
    Number.isFinite(Number(profile.attack_surface_score)) ? `attack_surface=${Number(profile.attack_surface_score).toFixed(2)}` : '',
    technologies.length ? `technologies=${technologies.join(',')}` : '',
    ports.length ? `ports=${ports.join(',')}` : '',
    subdomains.length ? `subdomains=${subdomains.slice(0, 8).join(',')}` : '',
    endpoints.length ? `endpoints=${endpoints.slice(0, 8).join(',')}` : '',
    profile.cms_type ? `cms=${compact(profile.cms_type, 80)}` : '',
    profile.cloud_provider ? `cloud=${compact(profile.cloud_provider, 80)}` : '',
  ].filter(Boolean);

  return [{
    type: 'hexstrike_intel',
    prio: prioForScore(score),
    score,
    value: `HexStrike target profile: ${targetType} / risk ${riskLevel}`,
    meta: fields.join(' - ').slice(0, 1200),
    url: safeTargetUrl(targetValue) || undefined,
    verification: {
      classification: 'informational',
      confidenceScore: Number.isFinite(Number(profile.confidence_score)) ? Number(profile.confidence_score) : 0.7,
      verifiedAt: new Date().toISOString(),
      evidence: {
        source: 'hexstrike_orchestrator',
        target: targetValue || target || null,
        targetType,
        riskLevel,
        technologies,
        openPorts: ports,
        subdomainCount: Array.isArray(profile.subdomains) ? profile.subdomains.length : 0,
        endpointCount: Array.isArray(profile.endpoints) ? profile.endpoints.length : 0,
      },
    },
  }];
}

export function normalizeHexstrikeToolPlan(data, { target = '' } = {}) {
  const tools = arrayOfStrings(data?.selected_tools || data?.tools || data?.recommended_tools, 30);
  if (!tools.length) return [];
  return [{
    type: 'hexstrike_tool_plan',
    prio: 'info',
    score: 34,
    value: `HexStrike recommended ${tools.length} tool(s)`,
    meta: [
      'source=hexstrike',
      `target=${compact(data?.target || target, 160)}`,
      data?.objective ? `objective=${compact(data.objective, 80)}` : '',
      `tools=${tools.join(',')}`,
    ].filter(Boolean).join(' - ').slice(0, 900),
    verification: {
      classification: 'informational',
      confidenceScore: 0.65,
      verifiedAt: new Date().toISOString(),
      evidence: {
        source: 'hexstrike_orchestrator',
        selectedTools: tools,
      },
    },
  }];
}

export async function runHexstrikeOrchestrator({
  target = '',
  domain = '',
  objective = 'comprehensive',
  client = null,
  fetchImpl,
  timeoutMs = 60_000,
  log = () => {},
} = {}) {
  const scanTarget = String(target || domain || '').trim();
  if (!scanTarget) {
    return { findings: [], logOk: 'HexStrike: alvo ausente para analise', logLevel: 'warn' };
  }

  const hex = client || new HexstrikeClient({ fetchImpl, timeoutMs });
  const findings = [];

  const analysis = await hex.post('/api/intelligence/analyze-target', { target: scanTarget }, { timeoutMs });
  if (!analysis.ok) {
    return {
      findings,
      logOk: `HexStrike intelligence indisponivel: ${analysis.data?.error || analysis.status || 'sem resposta'}`,
      logLevel: 'warn',
    };
  }
  findings.push(...normalizeHexstrikeAnalysis(analysis.data, { target: scanTarget }));

  const toolPlan = await hex.post(
    '/api/intelligence/select-tools',
    { target: scanTarget, objective },
    { timeoutMs: Math.min(timeoutMs, 30_000) },
  );
  if (toolPlan.ok) {
    findings.push(...normalizeHexstrikeToolPlan(toolPlan.data, { target: scanTarget }));
  } else {
    log(`HexStrike select-tools: ${toolPlan.data?.error || toolPlan.status || 'sem resposta'}`, 'info');
  }

  return {
    findings,
    logOk: findings.length
      ? `HexStrike intelligence: ${findings.length} item(ns) importado(s)`
      : 'HexStrike intelligence: analise concluida sem achados importaveis',
    logLevel: findings.length ? 'success' : 'info',
  };
}
