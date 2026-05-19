import type { EnhanceableField, Project } from '@/lib/types';
import type { EnhanceFieldInput } from './adapter';

export const SYSTEM_OFFENSIVE = `Você é copiloto de redação técnica para relatórios de pentest/red team em português (Brasil).
Regras obrigatórias:
- NUNCA invente CVEs, hosts, credenciais, comandos ou evidências que não estejam no texto do operador.
- Preserve fatos, IPs, domínios e payloads exatamente como fornecidos.
- Melhore clareza, estrutura e tom profissional (OWASP/CWE/CVSS quando relevante).
- Responda apenas com o conteúdo do campo solicitado, em HTML simples (<p>, <ul>, <li>, <strong>, <code>).`;

const FIELD_GUIDANCE: Record<EnhanceableField, string> = {
  description:
    'Expandir a descrição técnica: contexto, vetor, componente afetado, impacto na confidencialidade/integridade/disponibilidade.',
  attackScenario:
    'Descrever a cadeia de exploração provável em linguagem de relatório, do pré-requisito ao impacto de negócio.',
  recommendation:
    'Listar ações corretivas: imediatas, configuração, código e processo — priorizadas.',
  remediationNotes:
    'Resumir estado da remediação e próximos passos de reteste, sem inventar status.'
};

export function buildEnhanceUserPrompt(
  field: EnhanceableField,
  input: string,
  vuln: EnhanceFieldInput['vuln']
): string {
  const meta = [
    `Título: ${vuln.title}`,
    `Severidade: ${vuln.severity}`,
    vuln.cwe.length ? `CWE: ${vuln.cwe.join(', ')}` : '',
    vuln.tags.length ? `Tags: ${vuln.tags.join(', ')}` : '',
    vuln.targets.length ? `Ativos: ${vuln.targets.join(', ')}` : ''
  ]
    .filter(Boolean)
    .join('\n');

  return `Campo: ${field}
Instrução: ${FIELD_GUIDANCE[field]}

Metadados da vulnerabilidade:
${meta}

Texto atual do operador:
---
${input || '(vazio — redija com base apenas nos metadados, sem inventar evidências)'}
---`;
}

export function buildExecutiveSummaryPrompt(project: Project, vulnTitles: string[]): string {
  return `Gere um sumário executivo conciso (3–5 parágrafos em HTML <p>) para o cliente ${project.client}.
Engajamento: ${project.engagementType}, metodologia ${project.methodology}.
Escopo: ${project.scope.join(', ')}.
Findings (${vulnTitles.length}): ${vulnTitles.join('; ') || 'nenhum'}.
Não invente vulnerabilidades além da lista. Tom executivo para C-level.`;
}
