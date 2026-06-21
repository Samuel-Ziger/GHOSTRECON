export const moduleManifest = {
  id: 'risk_explainer',
  name: 'Risk Explainer',
  category: 'report',
  intrusive: false,
  requiresAuth: false,
  requiresKali: false,
  timeoutMs: 5_000,
  concurrency: 1,
  outputs: ['metadata'],
};

const RULES = [
  {
    match: (f) => f.type === 'secret',
    why: 'Pode expor credenciais, tokens ou material sensivel reutilizavel.',
    next: 'Validar escopo, rotacionar o segredo e confirmar se o valor ainda esta ativo.',
    fp: 'Tokens de exemplo, valores truncados ou chaves de teste podem parecer reais.',
    confidence: 'high',
  },
  {
    match: (f) => ['cve', 'cve_candidate', 'cve_match'].includes(String(f.type || '')),
    why: 'Versao/stack observada cruza com vulnerabilidade conhecida ou faixa de revisao.',
    next: 'Confirmar versao real do pacote e patch/backport antes de reportar impacto.',
    fp: 'Banners podem mentir e distribuicoes Linux frequentemente aplicam backport.',
    confidence: 'medium',
  },
  {
    match: (f) => String(f.type || '').includes('xss'),
    why: 'Entrada controlada pode atingir contexto de execucao no navegador.',
    next: 'Reproduzir com payload inofensivo e coletar evidencia sem roubar dados.',
    fp: 'Reflexao textual sem execucao de script nao confirma XSS.',
    confidence: 'medium',
  },
  {
    match: (f) => /sqli|sqlmap/i.test(`${f.type || ''} ${f.value || ''} ${f.meta || ''}`),
    why: 'Comportamento sugere possivel manipulacao de consulta SQL.',
    next: 'Confirmar com diferenca controlada de resposta/tempo e impacto minimo.',
    fp: 'Erros genericos e WAF podem simular sinais de SQLi.',
    confidence: 'medium',
  },
  {
    match: (f) => ['panel', 'endpoint'].includes(String(f.type || '')) && /admin|dashboard|console|actuator|metrics|grafana|kibana|jenkins/i.test(`${f.value || ''} ${f.url || ''}`),
    why: 'Superficie administrativa aumenta risco de exposicao, brute-force externo ou misconfig.',
    next: 'Confirmar autenticacao, escopo e se ha dados sensiveis sem tentar login.',
    fp: 'Painel protegido por SSO/403 pode ser apenas superficie esperada.',
    confidence: 'medium',
  },
  {
    match: (f) => String(f.type || '') === 'http3',
    why: 'HTTP/3/QUIC adiciona superficie UDP e modulo/proxy especifico para revisar.',
    next: 'Cruzar produto/versao e confirmar se UDP/443 e necessario no programa.',
    fp: 'CDNs podem anunciar HTTP/3 sem expor a origem real.',
    confidence: 'low',
  },
  {
    match: (f) => String(f.type || '') === 'security' || /headers|tls|cors/i.test(`${f.type || ''} ${f.value || ''}`),
    why: 'Configuracao de seguranca ausente ou fraca pode facilitar exploracao encadeada.',
    next: 'Validar impacto no fluxo real e propor ajuste de header/configuracao.',
    fp: 'Alguns headers dependem do contexto da aplicacao e nao sao obrigatorios em APIs puras.',
    confidence: 'medium',
  },
];

function fallbackRisk(f) {
  const prio = String(f?.prio || '').toLowerCase();
  if (prio === 'high') {
    return {
      confidence: 'medium',
      why: 'Achado priorizado como alto pelo pipeline e merece validacao manual.',
      next: 'Revisar evidencia, reproduzir de forma segura e confirmar escopo.',
      falsePositive: 'Heuristicas podem elevar sinais ruidosos em alvos com WAF/CDN.',
    };
  }
  return {
    confidence: 'low',
    why: 'Achado util para inventario ou possivel encadeamento.',
    next: 'Manter como contexto e priorizar se combinar com outro sinal.',
    falsePositive: 'Pode ser informativo sem impacto direto.',
  };
}

export function explainFindingRisk(finding) {
  for (const rule of RULES) {
    if (rule.match(finding)) {
      return {
        confidence: rule.confidence,
        why: rule.why,
        next: rule.next,
        falsePositive: rule.fp,
      };
    }
  }
  return fallbackRisk(finding);
}

export function applyRiskExplanations(findings = []) {
  let changed = 0;
  for (const f of findings || []) {
    if (!f || typeof f !== 'object') continue;
    if (!f.risk) {
      f.risk = explainFindingRisk(f);
      changed += 1;
    }
  }
  return { changed };
}
