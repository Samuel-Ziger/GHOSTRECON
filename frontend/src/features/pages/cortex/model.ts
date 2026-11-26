export type CortexTaxonomy = string | { id?: unknown };

export type CortexSnapshot = Record<string, unknown> & {
  cortex_marked?: boolean;
  meta?: unknown;
  mitre?: CortexTaxonomy[];
  owasp?: CortexTaxonomy[];
  prio?: unknown;
  type?: unknown;
  url?: unknown;
  value?: unknown;
};

export type CortexLink = {
  fingerprint?: unknown;
  linked_at?: unknown;
  notes?: unknown;
  snapshot?: CortexSnapshot | null;
  target?: unknown;
  url?: unknown;
};

export type CortexCategory = {
  created_at?: unknown;
  description?: unknown;
  id: number;
  linkCount?: unknown;
  title?: unknown;
};

export type CategoryTeach = { headline: string; text: string };

const DEMO_FP = {
  xssA: 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
  xssB: 'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb',
  sqli: 'cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc',
  ftp1: 'dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd',
  ftp2: 'eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee',
  idor: 'ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff',
};

export const CORTEX_DEMO_CATEGORIES: CortexCategory[] = [
  { id: 9001, title: 'XSS', description: 'Validações de Cross-Site Scripting confirmadas manualmente no fluxo do reporte.', linkCount: 2, created_at: '2026-01-01T12:00:00.000Z' },
  { id: 9002, title: 'SQL Injection', description: 'Achados de SQLi com evidência de erro SQL ou alteração de comportamento na query.', linkCount: 1, created_at: '2026-01-01T12:00:00.000Z' },
  { id: 9003, title: 'FTP Anonymous', description: 'Serviços FTP com acesso anónimo, listagem aberta ou upload sem autenticação forte.', linkCount: 2, created_at: '2026-01-01T12:00:00.000Z' },
  { id: 9004, title: 'IDOR', description: 'Referências diretas inseguras a objetos (IDs/UUIDs) sem controlo de autorização por recurso.', linkCount: 1, created_at: '2026-01-01T12:00:00.000Z' },
];

export const CORTEX_DEMO_LINKS: Record<number, CortexLink[]> = {
  9001: [
    { target: 'bounty-alvo.invalid', fingerprint: DEMO_FP.xssA, linked_at: '2026-04-10T14:22:00.000Z', notes: 'Reflected na página de pesquisa; confirmado com payload manual.', snapshot: { type: 'xss', prio: 'high', value: 'https://bounty-alvo.invalid/search?q=%3Cscript%3Ealert(1)%3C%2Fscript%3E', url: 'https://bounty-alvo.invalid/search', meta: 'Parâmetro q sem escape' } },
    { target: 'cliente-demo.example', fingerprint: DEMO_FP.xssB, linked_at: '2026-04-12T09:05:00.000Z', notes: 'DOM XSS via fragment; CSP fraco.', snapshot: { type: 'xss', prio: 'medium', value: 'https://cliente-demo.example/app#/callback=…', url: 'https://cliente-demo.example/app', meta: 'Router client-side' } },
  ],
  9002: [
    { target: 'legacy-api.test', fingerprint: DEMO_FP.sqli, linked_at: '2026-04-08T18:40:00.000Z', notes: 'Boolean-based; id param.', snapshot: { type: 'sqli', prio: 'high', value: "GET /v1/users?id=1' OR '1'='1", url: 'https://legacy-api.test/v1/users', meta: 'SQLite backend' } },
  ],
  9003: [
    { target: 'ftp-old.corp', fingerprint: DEMO_FP.ftp1, linked_at: '2026-03-28T11:00:00.000Z', notes: 'Anonymous upload permitido; banner vsftpd 3.0.3.', snapshot: { type: 'ftp', prio: 'high', value: 'ftp://ftp-old.corp/', url: 'ftp://ftp-old.corp/', meta: 'Porta 21 aberta' } },
    { target: 'backup-zone.internal', fingerprint: DEMO_FP.ftp2, linked_at: '2026-04-01T16:30:00.000Z', notes: 'Mesmo padrão; credenciais vazias aceites.', snapshot: { type: 'ftp', prio: 'high', value: 'ftp://backup-zone.internal/pub/', url: 'ftp://backup-zone.internal/pub/', meta: 'Read-only mas listável' } },
  ],
  9004: [
    { target: 'saas-app.io', fingerprint: DEMO_FP.idor, linked_at: '2026-04-15T10:10:00.000Z', notes: 'UUID sequencial em /api/invoices/{id}.', snapshot: { type: 'idor', prio: 'medium', value: 'https://saas-app.io/api/invoices/10042', url: 'https://saas-app.io/api/invoices/10042', meta: 'Acesso a fatura de outro tenant' } },
  ],
};

export function isCortexDemoLocation(locationLike: Pick<Location, 'hash' | 'search'>): boolean {
  try {
    const query = new URLSearchParams(locationLike.search || '').get('demo');
    if (query === '1' || query === 'true' || query === 'yes') return true;
    return String(locationLike.hash || '').replace(/^#/, '').trim().toLowerCase() === 'demo';
  } catch {
    return false;
  }
}

function taxonomyIds(value: unknown): string[] {
  return Array.isArray(value)
    ? value.map((entry) => String(
      entry && typeof entry === 'object' ? (entry as { id?: unknown }).id || '' : entry || '',
    ).trim()).filter(Boolean)
    : [];
}

export function linkDisplayUrl(link: CortexLink): string {
  const snapshot = link.snapshot && typeof link.snapshot === 'object' ? link.snapshot : null;
  let value = String(link.url || snapshot?.url || '').trim();
  if (!value && snapshot?.value != null) {
    const candidate = String(snapshot.value).trim();
    if (/^(https?|ftp):\/\//i.test(candidate)) value = candidate.split(/\s/)[0].slice(0, 400);
  }
  if (!value && link.target) value = String(link.target);
  return value || '(sem URL)';
}

export function snippetFromLink(link: CortexLink): string {
  const snapshot = link.snapshot;
  if (snapshot && typeof snapshot === 'object') {
    const value = snapshot.value == null ? '' : String(snapshot.value);
    const type = snapshot.type == null ? '' : String(snapshot.type);
    const taxonomy = [
      ...taxonomyIds(snapshot.owasp).slice(0, 2),
      ...taxonomyIds(snapshot.mitre).slice(0, 2),
    ].join(', ');
    const summary = [type, value].filter(Boolean).join(' — ');
    if (summary) return (taxonomy ? `${summary} · ${taxonomy}` : summary).slice(0, 250);
  }
  return link.notes ? String(link.notes).slice(0, 180) : '(sem resumo)';
}

export function taxonomyText(value: unknown): string {
  return taxonomyIds(value).join(', ');
}

export function getCategoryTeach(title: unknown): CategoryTeach {
  const normalized = String(title || '').toLowerCase();
  if (/xss/.test(normalized)) return {
    headline: 'O que é XSS?',
    text: 'Cross-Site Scripting: código (normalmente JavaScript) injectado numa página que outra pessoa vê no browser. Pode ser reflected (payload na resposta), stored (persistido na base) ou DOM-based (lógica client-side insegura). Risco típico: roubar sessão, alterar conteúdo ou redireccionar a vítima.',
  };
  if (/sql|inje(c|ç)/.test(normalized)) return {
    headline: 'O que é SQL Injection?',
    text: 'Parte da entrada do utilizador é concatenada a uma query SQL sem saneamento, permitindo ao atacante alterar a lógica da query (filtros, UNION, escrita). Pode levar a leitura ou destruição de dados. Defesa: consultas parametrizadas, ORM com cuidado e princípio do menor privilégio na base.',
  };
  if (/ftp/.test(normalized)) return {
    headline: 'O que é FTP inseguro?',
    text: 'Serviços FTP mal configurados (anónimo, sem TLS, credenciais fracas ou directórios graváveis) expõem ficheiros ou permitem upload abusivo. Em bug bounty costuma ser prioridade média a alta conforme exposição e dados acessíveis.',
  };
  if (/idor/.test(normalized)) return {
    headline: 'O que é IDOR?',
    text: 'Insecure Direct Object Reference: o servidor expõe objectos (IDs, ficheiros, APIs) sem verificar se o utilizador autenticado tem permissão para esse objecto específico. Muitas vezes basta alterar um ID na URL ou no corpo do pedido para aceder a dados de outro utilizador.',
  };
  if (/ssrf/.test(normalized)) return {
    headline: 'O que é SSRF?',
    text: 'Server-Side Request Forgery: o servidor faz pedidos HTTP (ou outros) a destinos escolhidos pelo atacante. Pode servir para ler metadata em clouds, varrer portas internas ou encadear com outros bugs.',
  };
  if (/lfi|path traversal|traversal|file include/.test(normalized)) return {
    headline: 'O que é LFI / path traversal?',
    text: 'Inclusão ou leitura de ficheiros fora do directório previsto (../, wrappers, etc.), por vezes levando a exposição de credenciais ou código. Validação estrita de caminhos e listas brancas reduzem o risco.',
  };
  if (/rce|remote code|command inj|exec/.test(normalized)) return {
    headline: 'O que é RCE / injecção de comandos?',
    text: 'Execução de código ou comandos no servidor (ou no cliente, em casos limitados) controlada pelo atacante. É das classes mais graves: pode implicar compromisso total do host.',
  };
  if (/csrf/.test(normalized)) return {
    headline: 'O que é CSRF?',
    text: 'Cross-Site Request Forgery: enganar o browser da vítima a enviar pedidos autenticados a um site onde ela já tem sessão. Mitigação: tokens anti-CSRF, SameSite em cookies e verificação de origem.',
  };
  if (/xxe/.test(normalized)) return {
    headline: 'O que é XXE?',
    text: 'XML External Entity: parsers XML mal configurados processam entidades externas e podem vazar ficheiros locais ou fazer SSRF. Desactivar entidades externas ou usar formatos mais seguros ajuda.',
  };
  return {
    headline: 'Sobre esta categoria',
    text: 'Esta pasta do Cérebro agrupa achados que ligaste manualmente a este tipo a partir da checklist no GHOSTRECON. Usa o mapa ou a grelha para ver alvos; clica num nó para notas, fingerprint e snapshot completos.',
  };
}

export function categoryTeach(title: unknown, description: unknown): CategoryTeach {
  const custom = String(description || '').trim();
  return custom ? { headline: 'Sobre esta categoria', text: custom } : getCategoryTeach(title);
}

export function cloneDemoCategories(): CortexCategory[] {
  return CORTEX_DEMO_CATEGORIES.map((category) => ({ ...category }));
}

export function cloneDemoLinks(categoryId: number): CortexLink[] {
  return (CORTEX_DEMO_LINKS[categoryId] || []).map((link) => ({
    ...link,
    snapshot: link.snapshot ? { ...link.snapshot } : link.snapshot,
  }));
}
