const SKILL_ID = /^[a-z][a-z0-9-]{1,63}$/;

export const MIND_SKILLS = Object.freeze([
  {
    id: 'artex',
    name: 'ARTEX',
    category: 'authorized-hunt',
    risk: 'active',
    requiresEngagement: true,
    recommendedAgents: ['orchestrator'],
    description: 'Exploração autônoma e contínua de escopos amplos autorizados.',
  },
  {
    id: 'fullhunt',
    name: 'Full Hunt',
    category: 'authorized-hunt',
    risk: 'active',
    requiresEngagement: true,
    recommendedAgents: ['orchestrator', 'researcher'],
    description: 'Pipeline completo de reconhecimento, validação, triagem e relatório.',
  },
  {
    id: 'jevgrep',
    name: 'JevGrep',
    category: 'code-review',
    risk: 'passive',
    requiresDocument: true,
    recommendedAgents: ['document_analyst', 'researcher'],
    description: 'Busca semântica em repositórios por perguntas em linguagem natural.',
  },
  {
    id: 'mdpsec-hunt',
    name: 'MDPSec Hunt',
    category: 'authorized-hunt',
    risk: 'active',
    requiresEngagement: true,
    recommendedAgents: ['orchestrator'],
    description: 'Hunting estruturado, auditável e orientado a evidências em 14 fases.',
  },
  {
    id: 'vulnhunt-fix-verify',
    name: 'VulnHunt Fix Verify',
    category: 'code-review',
    risk: 'passive',
    requiresDocument: true,
    recommendedAgents: ['document_analyst', 'analyst'],
    description: 'Verifica, em código autorizado, se achados anteriores foram corrigidos.',
  },
  {
    id: 'vulnhunt',
    name: 'VulnHunt',
    category: 'code-review',
    risk: 'passive',
    requiresDocument: true,
    recommendedAgents: ['document_analyst', 'analyst'],
    description: 'Audita entradas controláveis, sinks, explorabilidade e correções no código.',
  },
  {
    id: 'ywh-gotchas',
    name: 'YWH Gotchas',
    category: 'quality',
    risk: 'passive',
    recommendedAgents: ['analyst', 'orchestrator'],
    description: 'Aplica requisitos mínimos de evidência e filtros de falso positivo por classe.',
  },
  {
    id: 'ywh-triage',
    name: 'YWH Triage',
    category: 'quality',
    risk: 'passive',
    recommendedAgents: ['analyst', 'orchestrator'],
    description: 'Classifica um relatório antes da submissão e aponta lacunas concretas.',
  },
  {
    id: 'ywh-write',
    name: 'YWH Write',
    category: 'reporting',
    risk: 'passive',
    recommendedAgents: ['analyst', 'orchestrator'],
    description: 'Estrutura relatórios de bug bounty para plataformas como HackerOne e YesWeHack.',
  },
]);

const BY_ID = new Map(MIND_SKILLS.map((skill) => [skill.id, skill]));
const ACTIVE_SKILLS = new Set(MIND_SKILLS.filter((skill) => skill.requiresEngagement).map((skill) => skill.id));
const DOCUMENT_SKILLS = new Set(MIND_SKILLS.filter((skill) => skill.requiresDocument).map((skill) => skill.id));
const MODES = new Set(['off', 'auto', 'manual']);

function uniqueSkills(value, { max = 6 } = {}) {
  const output = [];
  for (const raw of Array.isArray(value) ? value : []) {
    const id = String(raw || '').trim().toLowerCase();
    if (!SKILL_ID.test(id) || !BY_ID.has(id)) throw new Error(`skill Mind desconhecida: ${id.slice(0, 80)}`);
    if (!output.includes(id)) output.push(id);
    if (output.length > max) throw new Error(`no máximo ${max} skills Mind podem compor um fluxo`);
  }
  if (output.includes('artex') && output.includes('fullhunt')) {
    throw new Error('artex e fullhunt são alternativas de exploração; selecione apenas uma por execução');
  }
  return output;
}

export function normalizeMindSkillRequest(value) {
  const row = value && typeof value === 'object' ? value : {};
  const mode = String(row.mode || 'off').trim().toLowerCase();
  if (!MODES.has(mode)) throw new Error('modo de skills Mind inválido');
  const skills = uniqueSkills(row.skills);
  if (mode === 'manual' && !skills.length) throw new Error('selecione ao menos uma skill Mind no modo manual');
  return {
    mode,
    skills: mode === 'manual' ? skills : [],
    target: String(row.target || '').trim().slice(0, 500),
    engagementId: String(row.engagementId || '').trim().slice(0, 120),
    authorizationConfirmed: row.authorizationConfirmed === true,
    syncCortex: row.syncCortex !== false,
  };
}

function includesAny(text, expressions) {
  return expressions.some((expression) => expression.test(text));
}

export function autoRouteMindSkills({ prompt, agent = 'orchestrator', hasDocument = false } = {}) {
  const text = String(prompt || '').normalize('NFKD').replace(/[\u0300-\u036f]/g, '').toLowerCase();
  if (includesAny(text, [/corrig|retest|fix verify|foi resolvid|ainda vulneravel|regress/])) {
    return ['vulnhunt-fix-verify', 'ywh-triage'];
  }
  if (hasDocument || includesAny(text, [/codigo|codebase|repositorio|source code|audita.*repo|review.*code/])) {
    return ['jevgrep', 'vulnhunt', 'ywh-gotchas'];
  }
  if (includesAny(text, [/estruturad|auditavel|14 fases|por fases|mdpsec/])) {
    return ['mdpsec-hunt', 'ywh-gotchas', 'ywh-triage', 'ywh-write'];
  }
  if (includesAny(text, [/autonom|continu|escopo amplo|alvo amplo|site inteiro|whole target/])) {
    return ['artex', 'ywh-gotchas', 'ywh-triage', 'ywh-write'];
  }
  if (includesAny(text, [/scan|pentest|bug bounty|mapear.*(?:site|alvo)|hunt.*alvo|find bugs|hackear.*site/])) {
    return ['fullhunt', 'ywh-gotchas', 'ywh-triage', 'ywh-write'];
  }
  if (includesAny(text, [/escrev|relatorio|report|hackerone|yeswehack|submiss/])) {
    return ['ywh-gotchas', 'ywh-triage', 'ywh-write'];
  }
  if (includesAny(text, [/falso positivo|evidencia|minima prova|idor|bola|ssrf|cors|jwt|race/])) {
    return ['ywh-gotchas', 'ywh-triage'];
  }
  return agent === 'document_analyst'
    ? ['jevgrep', 'vulnhunt']
    : ['ywh-triage'];
}

export function resolveMindSkillPlan({ request, prompt, agent, hasDocument = false } = {}) {
  const normalized = normalizeMindSkillRequest(request);
  if (normalized.mode === 'off') return { enabled: false, mode: 'off', skills: [] };
  const skills = normalized.mode === 'manual'
    ? normalized.skills
    : uniqueSkills(autoRouteMindSkills({ prompt, agent, hasDocument }));
  const requiresEngagement = skills.some((id) => ACTIVE_SKILLS.has(id));
  const requiresDocument = skills.some((id) => DOCUMENT_SKILLS.has(id));
  return {
    enabled: true,
    mode: normalized.mode,
    skills,
    workflow: skills.map((id, order) => ({ order: order + 1, ...BY_ID.get(id) })),
    target: normalized.target || null,
    engagementId: normalized.engagementId || null,
    authorizationConfirmed: normalized.authorizationConfirmed,
    syncCortex: normalized.syncCortex,
    requiresEngagement,
    requiresDocument,
    risk: requiresEngagement ? 'active' : 'passive',
  };
}

export function publicMindSkillCatalog() {
  return MIND_SKILLS.map((skill) => ({ ...skill }));
}
