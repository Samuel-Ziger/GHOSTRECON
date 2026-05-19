/**
 * Tool output triage engine.
 *
 * Recebe a saída crua de uma ferramenta (nmap, sqlmap, nuclei, linpeas,
 * ffuf, gobuster, etc.) e devolve uma sugestão estruturada para preencher
 * automaticamente os campos técnicos da vulnerabilidade.
 *
 * No protótipo: matching por regex + heurística (rápido, offline, determinístico).
 * No backend real: envia o output ao AIAdapter configurado, que devolve o
 * mesmo `TriageSuggestion` schema — UI permanece idêntica.
 */

import type { Severity } from '@/lib/types';

export type DetectedTool =
  | 'nmap'
  | 'sqlmap'
  | 'nuclei'
  | 'linpeas'
  | 'ffuf'
  | 'gobuster'
  | 'xsstrike'
  | 'burp'
  | 'curl_lfi'
  | 'curl_ssrf'
  | 'curl_cmd_injection'
  | 'metasploit'
  | 'nikto'
  | 'generic';

export interface TriageSuggestion {
  tool: DetectedTool;
  confidence: number; // 0..1
  title: string;
  severity: Severity;
  severityRationale: string;
  cvss?: { vector: string; score: number };
  cwe: string[];
  tags: string[];
  targets: string[];
  description: string; // HTML
  rawHighlights?: string[]; // linhas chave que justificam a triagem
}

/* ──────────────────────── Extractors ──────────────────────── */

const IP_RE = /\b(?:\d{1,3}\.){3}\d{1,3}\b/g;
const DOMAIN_RE =
  /\b(?:[a-z0-9](?:[-a-z0-9]*[a-z0-9])?\.)+[a-z]{2,}\b/gi;
const URL_RE = /\bhttps?:\/\/[^\s"'<>]+/gi;
const CVE_RE = /\bCVE-\d{4}-\d{4,7}\b/gi;
const NMAP_PORT_RE = /^(\d{1,5})\/(?:tcp|udp)\s+(open|closed|filtered)\s+(\S+)(?:\s+(.+))?$/gm;

function uniq<T>(arr: T[]): T[] {
  return Array.from(new Set(arr));
}

function extractTargets(text: string): string[] {
  const ips = text.match(IP_RE) ?? [];
  const urls = (text.match(URL_RE) ?? []).map((u) => {
    try {
      return new URL(u).hostname;
    } catch {
      return u;
    }
  });
  const domains = (text.match(DOMAIN_RE) ?? []).filter((d) => !d.match(/^\d+(\.\d+)+$/));
  // Filter out garbage like ".so", short TLDs accidentally caught, common false positives
  const cleaned = uniq([...ips, ...urls, ...domains])
    .filter((t) => t.length > 3)
    .filter((t) => !['version', 'release'].some((k) => t.toLowerCase().includes(k)))
    .slice(0, 8);
  return cleaned;
}

function p(text: string): string {
  return text
    .trim()
    .split(/\n\s*\n/)
    .map((para) => `<p>${escapeHtml(para.trim())}</p>`)
    .join('');
}

function escapeHtml(s: string): string {
  return s
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}

/* ──────────────────────── Detectors ──────────────────────── */

/**
 * Each detector returns `null` if it doesn't match, or a `TriageSuggestion`
 * if it does. The engine picks the highest-confidence match.
 */
type Detector = (raw: string) => TriageSuggestion | null;

const detectSqlmap: Detector = (raw) => {
  if (!/sqlmap|Parameter:|back-end DBMS|injection point|boolean-based blind|time-based blind|UNION query/i.test(raw)) {
    return null;
  }
  const targets = extractTargets(raw);
  const dbmsMatch = raw.match(/back-end DBMS:\s*([^\n]+)/i);
  const paramMatch = raw.match(/Parameter:\s*(\S+)\s*\(([^)]+)\)/i);
  const param = paramMatch?.[1] ?? 'parâmetro';
  const method = paramMatch?.[2] ?? 'desconhecido';

  return {
    tool: 'sqlmap',
    confidence: 0.95,
    title: `SQL Injection no parâmetro ${param}`,
    severity: 'critical',
    severityRationale:
      'sqlmap confirmou injeção SQL explorável (boolean/time/UNION-based). Permite leitura/escrita do banco — comprometimento direto de C/I/A.',
    cvss: {
      vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H',
      score: 9.8
    },
    cwe: ['CWE-89'],
    tags: ['SQLi', 'OWASP-A03', 'Easily-Exploitable', 'Web Application'],
    targets,
    description: p(
      `A aplicação web é vulnerável a SQL Injection no parâmetro ${param} (${method.toUpperCase()}). A ferramenta sqlmap confirmou a injeção utilizando técnicas de boolean-based blind, time-based blind e/ou UNION query.

Quando os dados enviados ao aplicativo não são tratados adequadamente antes de serem incorporados a consultas SQL, um atacante consegue alterar a estrutura da consulta original e executar comandos arbitrários contra o banco de dados.${
        dbmsMatch ? `\n\nO banco de dados identificado é: ${dbmsMatch[1].trim()}.` : ''
      }`
    ),
    rawHighlights: raw
      .split('\n')
      .filter((l) =>
        /Parameter:|Type:|Payload:|back-end DBMS|sqlmap identified|injectable/i.test(l)
      )
      .slice(0, 8)
  };
};

const detectNmap: Detector = (raw) => {
  if (!/Nmap scan report|Starting Nmap|PORT\s+STATE\s+SERVICE/i.test(raw)) {
    return null;
  }
  const targets = extractTargets(raw);
  const ports: { port: string; service: string; version?: string }[] = [];
  let m: RegExpExecArray | null;
  const re = new RegExp(NMAP_PORT_RE.source, 'gm');
  while ((m = re.exec(raw)) !== null) {
    if (m[2] === 'open') {
      ports.push({ port: m[1], service: m[3], version: m[4]?.trim() });
    }
  }
  const exposed = ports.filter((pp) => pp.version && /\d/.test(pp.version));
  const hasVersion = exposed.length > 0;

  return {
    tool: 'nmap',
    confidence: 0.92,
    title: hasVersion
      ? 'Exposição de versão de software em serviços expostos'
      : 'Serviços expostos identificados via scan de portas',
    severity: hasVersion ? 'low' : 'info',
    severityRationale: hasVersion
      ? 'Banners revelam versão completa do software, facilitando o mapeamento de CVEs aplicáveis e reduzindo o tempo de reconhecimento do atacante.'
      : 'Apenas exposição de portas identificada — registro informacional do estado da superfície de ataque.',
    cvss: hasVersion
      ? { vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N', score: 5.3 }
      : undefined,
    cwe: hasVersion ? ['CWE-200', 'CWE-756'] : ['CWE-200'],
    tags: ['Information Disclosure', 'Fingerprinting', 'Reconnaissance'],
    targets,
    description: p(
      `O scan de portas com nmap identificou ${ports.length} serviço${ports.length === 1 ? '' : 's'} ativo${ports.length === 1 ? '' : 's'}${hasVersion ? ' expondo versão completa do software' : ''}.

${ports.map((pp) => `• Porta ${pp.port}/tcp — ${pp.service}${pp.version ? ` (${pp.version})` : ''}`).join('\n')}

${hasVersion ? 'Banners expostos facilitam o mapeamento direto de CVEs aplicáveis pelo atacante, reduzindo o esforço de enumeração.' : 'A enumeração de portas é o primeiro passo de qualquer cadeia de ataque externa.'}`
    ),
    rawHighlights: ports.slice(0, 10).map((pp) => `${pp.port}/tcp open ${pp.service} ${pp.version ?? ''}`)
  };
};

const detectNuclei: Detector = (raw) => {
  if (!/\[(critical|high|medium|low|info)\]\s*\[/i.test(raw) && !/nuclei/i.test(raw)) {
    return null;
  }
  // Linhas típicas: [CVE-2024-XXXX] [http] [critical] https://target.com/path
  const sevMatch = raw.match(/\[(critical|high|medium|low|info)\]/i);
  const templateMatch = raw.match(/\[([a-z0-9\-]+)\]\s*\[(?:http|file|dns|tcp)\]/);
  const sev = (sevMatch?.[1]?.toLowerCase() as Severity) ?? 'medium';
  const template = templateMatch?.[1] ?? 'finding';
  const cves = uniq(raw.match(CVE_RE) ?? []);
  const targets = extractTargets(raw);

  const sevToCvss: Record<Severity, { vector: string; score: number }> = {
    critical: { vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H', score: 9.8 },
    high: { vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N', score: 7.5 },
    medium: { vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N', score: 5.4 },
    low: { vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N', score: 3.7 },
    info: { vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N', score: 0 }
  };

  return {
    tool: 'nuclei',
    confidence: 0.9,
    title: `[Nuclei] ${template.replace(/-/g, ' ')}`,
    severity: sev,
    severityRationale: `Detecção automatizada pelo Nuclei usando template "${template}" com severidade ${sev}.`,
    cvss: sev === 'info' ? undefined : sevToCvss[sev],
    cwe: [],
    tags: ['Nuclei', template.toUpperCase(), ...cves],
    targets,
    description: p(
      `O Nuclei detectou um finding utilizando o template "${template}" com severidade ${sev}.${cves.length > 0 ? `\n\nCVEs associadas: ${cves.join(', ')}.` : ''}\n\nValide a detecção manualmente, confirme exploração e ajuste a severidade caso o contexto exija (false positive, baixo impacto no ambiente específico, etc.).`
    ),
    rawHighlights: raw.split('\n').filter((l) => /\[(critical|high|medium|low|info)\]/i.test(l)).slice(0, 6)
  };
};

const detectLinPeas: Detector = (raw) => {
  if (!/LinPEAS|linpeas|PEASS-ng|Linux Privilege Escalation/i.test(raw)) {
    return null;
  }
  const cves = uniq(raw.match(CVE_RE) ?? []);
  const suid = /SUID/i.test(raw);
  const sudoNoPasswd = /NOPASSWD/i.test(raw);
  const writableSensitive = /writable.*\/etc\/(passwd|shadow|sudoers)/i.test(raw);
  const targets = extractTargets(raw);

  const isCritical = cves.length > 0 || writableSensitive || sudoNoPasswd;
  return {
    tool: 'linpeas',
    confidence: 0.88,
    title: cves.length > 0 ? `Escalada de privilégios via ${cves[0]}` : 'Vetores de escalada de privilégio local identificados',
    severity: isCritical ? 'critical' : 'high',
    severityRationale: isCritical
      ? 'LinPEAS identificou caminho explorável para escalada de privilégio local (CVE recente / sudo NOPASSWD / arquivo crítico writable).'
      : 'LinPEAS identificou indícios de configuração frágil que viabilizam escalada de privilégio mediante exploração adicional.',
    cvss: isCritical
      ? { vector: 'CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H', score: 7.8 }
      : { vector: 'CVSS:3.1/AV:L/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:H', score: 6.7 },
    cwe: ['CWE-269', ...(suid ? ['CWE-250'] : []), ...(writableSensitive ? ['CWE-732'] : [])],
    tags: ['Privilege Escalation', 'Local', ...cves, ...(sudoNoPasswd ? ['sudo NOPASSWD'] : []), ...(suid ? ['SUID'] : [])],
    targets,
    description: p(
      `O LinPEAS identificou vetores de escalada de privilégio local no host.${cves.length > 0 ? `\n\nCVEs aplicáveis: ${cves.join(', ')}.` : ''}${sudoNoPasswd ? '\n\nForam identificadas entradas sudo com NOPASSWD que permitem execução de binários como root sem autenticação adicional.' : ''}${suid ? '\n\nBinários SUID anômalos foram detectados — validar se algum permite escape para shell privilegiado.' : ''}${writableSensitive ? '\n\nArquivos críticos do sistema (passwd/shadow/sudoers) com permissão de escrita detectados.' : ''}`
    ),
    rawHighlights: raw
      .split('\n')
      .filter((l) =>
        /SUID|NOPASSWD|writable|CVE-|kernel|Vulnerable to/i.test(l)
      )
      .slice(0, 8)
  };
};

const detectFfuf: Detector = (raw) => {
  if (!/^.{0,80}\[Status:\s*\d+/m.test(raw) && !/ffuf/i.test(raw)) return null;
  const found = raw.match(/\[Status:\s*200[^\]]*\]/g)?.length ?? 0;
  const targets = extractTargets(raw);
  return {
    tool: 'ffuf',
    confidence: 0.85,
    title: 'Recursos sensíveis expostos via enumeração de diretórios',
    severity: found > 0 ? 'low' : 'info',
    severityRationale:
      'Enumeração de diretórios revelou recursos não listados. Avalie cada um — alguns podem expor backups, painéis administrativos ou endpoints internos.',
    cvss: { vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N', score: 5.3 },
    cwe: ['CWE-538', 'CWE-200'],
    tags: ['Information Disclosure', 'Directory Enumeration', 'OWASP-A05'],
    targets,
    description: p(
      `A enumeração de diretórios com ffuf identificou ${found} recurso${found === 1 ? '' : 's'} respondendo HTTP 200 que não fazem parte da estrutura pública da aplicação. Estes recursos devem ser auditados — backups, painéis administrativos, endpoints internos e arquivos de configuração frequentemente aparecem nessa enumeração.`
    ),
    rawHighlights: raw.split('\n').filter((l) => /\[Status:\s*200/.test(l)).slice(0, 8)
  };
};

const detectGobuster: Detector = (raw) => {
  if (!/Gobuster|gobuster/i.test(raw) && !/^\s*\/\S+\s+\(Status:\s*\d+/m.test(raw)) return null;
  const found = (raw.match(/\(Status:\s*200/g) ?? []).length;
  const targets = extractTargets(raw);
  return {
    tool: 'gobuster',
    confidence: 0.82,
    title: 'Recursos não listados expostos (gobuster)',
    severity: 'low',
    severityRationale: 'Recursos descobertos via brute-force de paths devem ser revisados.',
    cvss: { vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N', score: 5.3 },
    cwe: ['CWE-538', 'CWE-200'],
    tags: ['Information Disclosure', 'Directory Enumeration'],
    targets,
    description: p(
      `O gobuster identificou ${found} caminho${found === 1 ? '' : 's'} HTTP 200 não listado${found === 1 ? '' : 's'} publicamente. Faça triagem manual de cada recurso — backups, configs, painéis admin frequentemente aparecem.`
    ),
    rawHighlights: raw.split('\n').filter((l) => /\(Status:\s*200/.test(l)).slice(0, 8)
  };
};

const detectXSS: Detector = (raw) => {
  if (!/<script[^>]*>|alert\(|XSStrike|reflected XSS|stored XSS|onerror=|onload=|javascript:/i.test(raw)) {
    return null;
  }
  const stored = /stored XSS|XSS armazenado/i.test(raw);
  const targets = extractTargets(raw);
  return {
    tool: 'xsstrike',
    confidence: 0.86,
    title: stored ? 'Cross-Site Scripting Armazenado (Stored XSS)' : 'Cross-Site Scripting Refletido (Reflected XSS)',
    severity: stored ? 'high' : 'medium',
    severityRationale: stored
      ? 'XSS armazenado afeta todos os usuários que carregam o conteúdo persistido, permitindo roubo de sessão e ações como usuário autenticado.'
      : 'XSS refletido permite roubo de sessão e ações como usuário autenticado quando a vítima abre URL maliciosa.',
    cvss: stored
      ? { vector: 'CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:C/C:H/I:L/A:N', score: 7.4 }
      : { vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N', score: 6.1 },
    cwe: ['CWE-79'],
    tags: ['XSS', 'OWASP-A03', 'Web Application', ...(stored ? ['Stored'] : ['Reflected'])],
    targets,
    description: p(
      `A aplicação é vulnerável a Cross-Site Scripting ${stored ? 'armazenado' : 'refletido'}. Dados controlados pelo atacante são incorporados à resposta HTML sem sanitização/encoding adequados, permitindo execução arbitrária de JavaScript no contexto da vítima.

O impacto inclui roubo de tokens de sessão, execução de ações como usuário autenticado, defacement e redirecionamento para domínios maliciosos.`
    )
  };
};

const detectLFI: Detector = (raw) => {
  if (!/\.\.\/\.\.\/|etc\/passwd|root:[xX]:0|\/etc\/shadow|file:\/\//i.test(raw)) {
    return null;
  }
  const passwdLeaked = /root:[xX]:0:0:/i.test(raw);
  const targets = extractTargets(raw);
  return {
    tool: 'curl_lfi',
    confidence: 0.9,
    title: 'Local File Inclusion / Path Traversal',
    severity: passwdLeaked ? 'critical' : 'high',
    severityRationale: passwdLeaked
      ? 'Leitura confirmada de /etc/passwd. Qualquer arquivo legível pelo processo da aplicação pode ser exfiltrado, incluindo chaves SSH, configs, código-fonte e secrets.'
      : 'Travessia de diretório permite leitura arbitrária do filesystem dentro do contexto da aplicação.',
    cvss: passwdLeaked
      ? { vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N', score: 7.5 }
      : { vector: 'CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N', score: 6.5 },
    cwe: ['CWE-22', 'CWE-98'],
    tags: ['LFI', 'Path Traversal', 'OWASP-A01'],
    targets,
    description: p(
      `A aplicação concatena entrada controlada pelo usuário em operações de inclusão/leitura de arquivos sem normalização de caminhos. Sequências de travessia (../) permitem alcançar arquivos fora do diretório esperado.${
        passwdLeaked ? '\n\nA leitura de /etc/passwd foi confirmada na evidência, demonstrando inclusão arbitrária de arquivos do sistema.' : ''
      }`
    )
  };
};

const detectSSRF: Detector = (raw) => {
  if (!/gopher:\/\/|169\.254\.169\.254|metadata|file:\/\/.*\/proc|ssrf|SSRF/i.test(raw)) {
    return null;
  }
  const cloudMeta = /169\.254\.169\.254/i.test(raw);
  const targets = extractTargets(raw);
  return {
    tool: 'curl_ssrf',
    confidence: 0.88,
    title: cloudMeta ? 'SSRF com acesso ao Metadata Service da nuvem' : 'Server-Side Request Forgery',
    severity: cloudMeta ? 'critical' : 'high',
    severityRationale: cloudMeta
      ? 'SSRF capaz de alcançar o endpoint metadata da cloud (169.254.169.254). Permite roubo de credenciais IAM/instance role.'
      : 'O servidor faz requisições para destinos controlados pelo atacante, podendo alcançar serviços internos não expostos.',
    cvss: cloudMeta
      ? { vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:N', score: 10.0 }
      : { vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N', score: 7.5 },
    cwe: ['CWE-918'],
    tags: ['SSRF', 'OWASP-A10', ...(cloudMeta ? ['Cloud-Metadata'] : [])],
    targets,
    description: p(
      `A aplicação faz requisições HTTP/outros protocolos para URLs fornecidas pelo usuário sem validação adequada de destino. ${cloudMeta ? 'A exploração alcançou o endpoint metadata da cloud (169.254.169.254), permitindo extração de credenciais temporárias da instância.' : 'Isso permite atacar serviços internos da rede inacessíveis externamente, mapear infraestrutura e em alguns casos alcançar bancos, caches e serviços administrativos.'}`
    )
  };
};

const detectCmdInjection: Detector = (raw) => {
  if (!/command injection|RCE confirmed|backtick|;\s*id\s*$|`id`|\$\(id\)|uid=\d+\(/i.test(raw)) {
    return null;
  }
  const targets = extractTargets(raw);
  return {
    tool: 'curl_cmd_injection',
    confidence: 0.92,
    title: 'Execução remota de comandos (Command Injection)',
    severity: 'critical',
    severityRationale:
      'Execução arbitrária de comandos no contexto do servidor web — caminho direto para reverse shell e comprometimento total do host.',
    cvss: { vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H', score: 9.8 },
    cwe: ['CWE-78', 'CWE-77'],
    tags: ['RCE', 'Command Injection', 'OWASP-A03', 'Easily-Exploitable'],
    targets,
    description: p(
      `A aplicação concatena entrada do usuário diretamente em chamadas de shell, permitindo execução arbitrária de comandos no servidor. Esta é uma das classes de vulnerabilidade de maior severidade — leva diretamente a reverse shell e comprometimento total do host.

Toda chamada a exec/shell_exec/system/backticks/popen com entrada externa não-sanitizada é potencialmente vulnerável.`
    )
  };
};

const detectMetasploit: Detector = (raw) => {
  if (!/msf\d|metasploit|exploit\(.+\)\s*>/i.test(raw)) return null;
  const cves = uniq(raw.match(CVE_RE) ?? []);
  const sessionOpened = /session\s+\d+\s+opened|Meterpreter session/i.test(raw);
  const targets = extractTargets(raw);
  return {
    tool: 'metasploit',
    confidence: 0.9,
    title: cves[0] ? `Exploração de ${cves[0]} (Metasploit)` : 'Exploração via Metasploit Framework',
    severity: sessionOpened ? 'critical' : 'high',
    severityRationale: sessionOpened
      ? 'Sessão Meterpreter/shell estabelecida — execução remota e controle do alvo comprovados.'
      : 'Módulo Metasploit acionado contra o alvo — confirmar pós-exploração.',
    cvss: { vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H', score: 9.8 },
    cwe: cves.length > 0 ? [] : ['CWE-693'],
    tags: ['Metasploit', 'Exploit', ...cves, ...(sessionOpened ? ['Shell-Obtained'] : [])],
    targets,
    description: p(
      `Exploração via Metasploit Framework executada com sucesso.${cves.length > 0 ? `\n\nCVE explorada: ${cves.join(', ')}.` : ''}${sessionOpened ? '\n\nUma sessão Meterpreter/reverse shell foi estabelecida com o alvo, confirmando RCE.' : ''}`
    )
  };
};

const detectNikto: Detector = (raw) => {
  if (!/Nikto v\d|^\+\s+(OSVDB|Server:)/im.test(raw)) return null;
  const targets = extractTargets(raw);
  return {
    tool: 'nikto',
    confidence: 0.8,
    title: 'Findings de configuração web (Nikto)',
    severity: 'low',
    severityRationale:
      'Nikto identificou misconfigurações e arquivos legados. Cada finding deve ser triado individualmente.',
    cvss: { vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N', score: 5.3 },
    cwe: ['CWE-16', 'CWE-200'],
    tags: ['Misconfiguration', 'Web Application', 'Nikto'],
    targets,
    description: p(
      `O Nikto identificou um conjunto de findings de configuração web no alvo. Estes incluem tipicamente cabeçalhos faltantes, métodos HTTP permissivos, arquivos legados (test.php, /admin/, /backup/) e versões expostas em banners. Cada item deve ser triado e priorizado individualmente.`
    )
  };
};

const detectGeneric: Detector = (raw) => {
  const targets = extractTargets(raw);
  const cves = uniq(raw.match(CVE_RE) ?? []);
  return {
    tool: 'generic',
    confidence: 0.4,
    title: cves[0]
      ? `Finding relacionado a ${cves[0]}`
      : 'Finding identificado durante o engajamento',
    severity: 'medium',
    severityRationale:
      'Engine não reconheceu o formato da ferramenta. Os campos foram preenchidos com defaults conservadores — revise antes de salvar.',
    cwe: cves.length > 0 ? [] : ['CWE-200'],
    tags: cves.length > 0 ? [...cves] : ['Manual Review'],
    targets,
    description: p(
      raw.length > 400
        ? `${raw.slice(0, 400).trim()}...

(saída truncada; o texto completo permanece na evidência)`
        : raw.trim() || 'Sem conteúdo na saída fornecida.'
    )
  };
};

/* ──────────────────────── Engine ──────────────────────── */

const DETECTORS: Detector[] = [
  detectSqlmap,
  detectCmdInjection,
  detectMetasploit,
  detectLFI,
  detectSSRF,
  detectXSS,
  detectLinPeas,
  detectNuclei,
  detectNmap,
  detectFfuf,
  detectGobuster,
  detectNikto
];

/**
 * Tenta cada detector. Retorna o de maior confiança, ou o genérico se
 * nenhum atingir o limiar.
 */
export async function triageToolOutput(raw: string): Promise<TriageSuggestion> {
  // Simula o tempo de inferência do provider (no backend, é o `await adapter.triage(...)`)
  await new Promise((r) => setTimeout(r, 650));

  if (!raw.trim()) {
    return {
      ...detectGeneric('')!,
      confidence: 0,
      title: '',
      description: ''
    };
  }

  const matches = DETECTORS.map((d) => d(raw)).filter(
    (m): m is TriageSuggestion => m !== null
  );

  if (matches.length === 0) {
    return detectGeneric(raw)!;
  }

  matches.sort((a, b) => b.confidence - a.confidence);
  return matches[0];
}

export const TOOL_LABEL: Record<DetectedTool, string> = {
  nmap: 'Nmap',
  sqlmap: 'sqlmap',
  nuclei: 'Nuclei',
  linpeas: 'LinPEAS',
  ffuf: 'ffuf',
  gobuster: 'gobuster',
  xsstrike: 'XSStrike / Manual XSS',
  burp: 'Burp Suite',
  curl_lfi: 'curl · LFI',
  curl_ssrf: 'curl · SSRF',
  curl_cmd_injection: 'curl · Command Injection',
  metasploit: 'Metasploit',
  nikto: 'Nikto',
  generic: 'Genérico (sem detecção específica)'
};
