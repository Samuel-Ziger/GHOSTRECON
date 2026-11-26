export type Finding = {
  type?: string;
  prio?: string;
  value?: unknown;
  url?: unknown;
  meta?: unknown;
  source?: unknown;
  sourceEngine?: unknown;
  moduleId?: unknown;
  __idx?: number;
  [key: string]: unknown;
};

export function isDorkFindingType(type: unknown): boolean {
  const normalized = String(type || '').toLowerCase();
  return normalized === 'dork' || normalized === 'dorks';
}

export function isVigoliumFinding(finding: Finding | null | undefined): boolean {
  const source = String(finding?.sourceEngine || finding?.source || '').toLowerCase();
  const metadata = String(finding?.meta || '').toLowerCase();
  const moduleId = String(finding?.moduleId || '').toLowerCase();
  return source === 'vigolium'
    || source.includes('vigolium')
    || moduleId.includes('vigolium')
    || metadata.includes('source=vigolium');
}

export function findingMatchesFilter(finding: Finding, filter: string): boolean {
  if (filter === 'all') return !isDorkFindingType(finding.type);
  if (filter === 'dorks') return isDorkFindingType(finding.type);
  if (filter === 'vigolium') return isVigoliumFinding(finding);
  if (filter === 'subfinder') {
    return finding.type === 'subdomain' && /\btool=subfinder\b/.test(String(finding.meta || ''));
  }
  return finding.prio === filter || finding.type === filter;
}

export function findingMatchesSearch(finding: Finding, query: string): boolean {
  const normalized = String(query || '').trim().toLowerCase();
  if (!normalized) return true;
  return [finding.type, finding.prio, finding.value, finding.url, finding.meta, finding.source]
    .map((value) => String(value || '').toLowerCase())
    .join('\n')
    .includes(normalized);
}

const FINDING_RANK: Record<string, number> = {
  subs: 1,
  endpoint: 2,
  param: 3,
  xss: 4,
  sqli: 5,
  lfi: 6,
  open_redirect: 7,
  idor: 8,
  secret: 8,
  js: 9,
  dork: 10,
  tech: 11,
  nmap: 12,
  exploit: 13,
  nuclei: 14,
  vigolium: 15,
  security: 16,
  tls: 17,
  rdap: 18,
  intel: 19,
  wpscan: 20,
  takeover: 21,
  secret_validation: 22,
};

export function selectFindings(
  findings: Finding[],
  { filter = 'all', query = '' }: { filter?: string; query?: string } = {},
): Finding[] {
  const selected = findings.filter(
    (finding) => findingMatchesFilter(finding, filter) && findingMatchesSearch(finding, query),
  );
  if (filter !== 'all') return selected;
  return selected.sort((left, right) => {
    const leftRank = isVigoliumFinding(left) ? FINDING_RANK.vigolium : (FINDING_RANK[String(left.type)] ?? 999);
    const rightRank = isVigoliumFinding(right) ? FINDING_RANK.vigolium : (FINDING_RANK[String(right.type)] ?? 999);
    if (leftRank !== rightRank) return leftRank - rightRank;
    return (left.__idx ?? 0) - (right.__idx ?? 0);
  });
}
